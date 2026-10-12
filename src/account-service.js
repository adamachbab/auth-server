const express = require('express');
const crypto = require('crypto');
const path = require('path');
const {
  client_ip,
  create_rate_limiter,
  digest,
  hash_password,
  metadata,
  normalize_email,
  random_token,
  request_id,
  safe_equal,
  validate_password,
  verify_password
} = require('./lib/security');
const { is_license_paused, remaining_seconds } = require('./lib/license-state');

const session_seconds = 12 * 60 * 60;
const device_code_seconds = 10 * 60;
const device_poll_seconds = 5;
const user_code_alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
const device_scopes = new Set(['account:read']);
const dummy_password_hash = hash_password(random_token(24));

function now_unix() {
  return Math.floor(Date.now() / 1000);
}

function license_digest(key) {
  return digest(key, 'auth-license-link:v1');
}

function cookie_value(req, name) {
  for (const part of String(req.get('cookie') || '').split(';')) {
    const separator = part.indexOf('=');

    if (separator > 0 && part.slice(0, separator).trim() === name) {
      try {
        return decodeURIComponent(part.slice(separator + 1));
      } catch {
        return null;
      }
    }
  }

  return null;
}

function user_code() {
  let value = '';

  for (let index = 0; index < 8; index++) {
    value += user_code_alphabet[crypto.randomInt(user_code_alphabet.length)];
  }

  return `${value.slice(0, 4)}-${value.slice(4)}`;
}

function public_device(record) {
  return {
    device_id: record.public_id,
    name: record.name,
    created_at: record.created_at,
    last_used_at: record.last_used_at || null,
    revoked_at: record.revoked_at || null,
    scopes: record.scopes
  };
}

function linked_licenses(db, user_id) {
  const digests = new Set(
    Object.values(db.account_license_links || {})
      .filter((link) => link.user_id === user_id)
      .map((link) => link.license_digest)
  );

  return Object.entries(db.keys || {}).filter(([key]) => digests.has(license_digest(key)));
}

function account_state(db, user) {
  const licenses = linked_licenses(db, user.id);
  const now = now_unix();
  let expiry = null;
  let remaining = 0;
  let subscription_paused = false;

  for (const [, license] of licenses) {
    if (Number.isSafeInteger(license.expiry_unix)) {
      expiry = Math.max(expiry || 0, license.expiry_unix);
    }

    remaining = Math.max(remaining, remaining_seconds(license, now));
    subscription_paused ||= is_license_paused(db, license);
  }

  return {
    email: user.email,
    email_verified: Boolean(user.email_verified),
    status: user.status,
    subscription_expiry: expiry,
    remaining_seconds: remaining,
    subscription_paused,
    linked_license_count: licenses.length
  };
}

function purge_expired(db, now = now_unix()) {
  for (const [hash, session] of Object.entries(db.sessions || {})) {
    if (session.expires_at <= now || session.revoked_at) {
      delete db.sessions[hash];
    }
  }

  for (const [id, entry] of Object.entries(db.device_authorizations || {})) {
    if (entry.expires_at <= now || entry.status === 'consumed') {
      delete db.device_authorizations[id];
    }
  }
}

function mount_account_service(app, options) {
  const project_root = path.join(__dirname, '..');
  const store = options.store;
  const rate = create_rate_limiter();
  const secure_cookie = options.secure_cookie !== false;
  const verification_url = options.verification_url || '/device';
  const allowed_origins = new Set(options.allowed_origins || []);

  function too_many(res, result) {
    res
      .set('Retry-After', String(result.retry_after))
      .status(429)
      .json({ success: false, error: 'Too many requests' });
  }

  function limited(req, res, category, maximum, window_ms, identity = '') {
    const result = rate(`${category}:${client_ip(req)}:${identity}`, maximum, window_ms);

    if (result.allowed) {
      return false;
    }

    too_many(res, result);
    return true;
  }

  function account_limited(res, category, maximum, window_ms, identity) {
    const result = rate(`${category}:account:${identity}`, maximum, window_ms);

    if (result.allowed) {
      return false;
    }

    too_many(res, result);
    return true;
  }

  function set_cookie(res, name, token, max_age, http_only) {
    const pieces = [
      `${name}=${encodeURIComponent(token)}`,
      'Path=/',
      'SameSite=Strict',
      `Max-Age=${max_age}`
    ];

    if (http_only) {
      pieces.push('HttpOnly');
    }

    if (secure_cookie) {
      pieces.push('Secure');
    }

    res.append('Set-Cookie', pieces.join('; '));
  }

  function clear_auth_cookies(res) {
    set_cookie(res, 'auth_session', '', 0, true);
    set_cookie(res, 'auth_csrf', '', 0, false);
  }

  function origin_allowed(req) {
    const origin = req.get('origin');
    const same_origin = `${req.protocol}://${req.get('host')}`;

    return !origin || origin === same_origin || allowed_origins.has(origin);
  }

  function session_middleware(req, res, next) {
    const raw = cookie_value(req, 'auth_session');

    if (!raw) {
      return res.status(401).json({ success: false, error: 'Authentication required' });
    }

    const db = store.read();
    const session_hash = digest(raw, 'session:v1');
    const session = db.sessions[session_hash];
    const user = session && db.users[session.user_id];

    if (
      !session ||
      !user ||
      session.expires_at <= now_unix() ||
      session.revoked_at ||
      user.status !== 'active'
    ) {
      clear_auth_cookies(res);
      return res.status(401).json({ success: false, error: 'Authentication required' });
    }

    req.account = { db, session, user, session_hash };
    next();
  }

  function csrf_middleware(req, res, next) {
    if (!origin_allowed(req)) {
      return res.status(403).json({ success: false, error: 'Request origin is not allowed' });
    }

    const supplied = req.get('x-csrf-token');
    const supplied_hash = digest(String(supplied || ''), 'csrf:v1');

    if (!safe_equal(supplied_hash, req.account.session.csrf_hash)) {
      return res.status(403).json({ success: false, error: 'Invalid CSRF token' });
    }

    next();
  }

  function require_role(...roles) {
    return (req, res, next) => {
      if (roles.includes(req.account.user.role)) {
        return next();
      }

      return res.status(403).json({ success: false, error: 'Insufficient permissions' });
    };
  }

  function audit(db, req, actor, target, action, reason, previous_value, new_value) {
    db.audit_events.push({
      id: crypto.randomUUID(),
      actor_user_id: actor?.id || null,
      actor_role: actor?.role || 'system',
      target,
      action,
      reason: String(reason).trim().slice(0, 500),
      previous_value,
      new_value,
      created_at: now_unix(),
      request_id: request_id(req),
      metadata: metadata(req)
    });
  }

  function require_reason(req, res) {
    if (
      typeof req.body?.reason !== 'string' ||
      req.body.reason.trim().length < 3 ||
      req.body.reason.trim().length > 500
    ) {
      res.status(400).json({
        success: false,
        error: 'A reason between 3 and 500 characters is required'
      });
      return null;
    }

    return req.body.reason.trim();
  }

  function find_pending_authorization(authorizations, code_hash) {
    return Object.values(authorizations).find((entry) => {
      return entry.user_code_hash === code_hash &&
        entry.status === 'pending' &&
        entry.expires_at > now_unix();
    });
  }

  function find_user_by_ref(db, ref) {
    return Object.values(db.users).find((entry) => entry.admin_ref === ref);
  }

  const auth = express.Router();

  auth.use(express.json({ limit: '16kb', strict: true }));

  auth.post('/register', async (req, res) => {
    const email = normalize_email(req.body?.email);

    if (limited(req, res, 'register', 5, 60 * 60 * 1000, email || 'invalid')) {
      return;
    }

    if (!email || !validate_password(req.body?.password)) {
      return res.status(400).json({
        success: false,
        error: 'Use a valid email and a 12–128 character password containing letters and non-letters'
      });
    }

    const password_hash = await hash_password(req.body.password);
    let created = false;

    store.transaction((db) => {
      if (Object.values(db.users).some((user) => user.email === email)) {
        return;
      }

      const id = crypto.randomUUID();
      const now = now_unix();

      db.users[id] = {
        id,
        admin_ref: random_token(18),
        email,
        password_hash,
        role: 'user',
        status: 'active',
        email_verified: false,
        failed_logins: 0,
        locked_until: 0,
        created_at: now,
        updated_at: now
      };
      created = true;
    });

    return res.status(202).json({
      success: true,
      message: 'If the address can be registered, the account is ready to sign in.',
      email_verification_available: Boolean(options.send_verification),
      created_for_testing: options.expose_test_state ? created : undefined
    });
  });

  auth.post('/login', async (req, res) => {
    const email = normalize_email(req.body?.email);

    if (limited(req, res, 'login', 10, 15 * 60 * 1000, email || 'invalid')) {
      return;
    }

    if (email && account_limited(res, 'login', 30, 60 * 60 * 1000, email)) {
      return;
    }

    const db = store.read();
    const user = email ? Object.values(db.users).find((entry) => entry.email === email) : null;
    const password = String(req.body?.password || '');
    const password_valid = await verify_password(
      password,
      user ? user.password_hash : await dummy_password_hash
    );
    const valid = Boolean(user) &&
      user.status === 'active' &&
      (user.locked_until || 0) <= now_unix() &&
      password_valid;

    if (!valid) {
      if (user) {
        store.transaction((current) => {
          const target = current.users[user.id];

          if (!target) {
            return;
          }

          target.failed_logins = (target.failed_logins || 0) + 1;

          if (target.failed_logins >= 5) {
            target.locked_until = now_unix() +
              Math.min(3600, 2 ** Math.min(target.failed_logins - 4, 12));
          }
        });
      }

      return res.status(401).json({ success: false, error: 'Invalid email or password' });
    }

    const token = random_token(32);
    const csrf = random_token(24);
    const session_hash = digest(token, 'session:v1');

    store.transaction((current) => {
      purge_expired(current);

      const target = current.users[user.id];

      target.failed_logins = 0;
      target.locked_until = 0;
      target.last_login_at = now_unix();

      current.sessions[session_hash] = {
        user_id: user.id,
        csrf_hash: digest(csrf, 'csrf:v1'),
        created_at: now_unix(),
        expires_at: now_unix() + session_seconds,
        metadata: metadata(req)
      };
    });

    set_cookie(res, 'auth_session', token, session_seconds, true);
    set_cookie(res, 'auth_csrf', csrf, session_seconds, false);
    res.json({ success: true, csrf_token: csrf, account: account_state(store.read(), user) });
  });

  auth.get('/session', session_middleware, (req, res) => {
    res.json({
      success: true,
      account: account_state(req.account.db, req.account.user),
      csrf_token_required: true
    });
  });

  auth.post('/logout', session_middleware, csrf_middleware, (req, res) => {
    store.transaction((db) => {
      if (db.sessions[req.account.session_hash]) {
        db.sessions[req.account.session_hash].revoked_at = now_unix();
      }
    });

    clear_auth_cookies(res);
    res.json({ success: true });
  });

  app.use('/api/auth', auth);

  const account = express.Router();

  account.use(express.json({ limit: '16kb', strict: true }), session_middleware);

  account.get('/', (req, res) => {
    res.json({ success: true, account: account_state(req.account.db, req.account.user) });
  });

  account.post('/password', csrf_middleware, async (req, res) => {
    if (limited(req, res, 'password', 5, 60 * 60 * 1000, req.account.user.id)) {
      return;
    }

    const current_valid = await verify_password(
      String(req.body?.current_password || ''),
      req.account.user.password_hash
    );

    if (!current_valid) {
      return res.status(400).json({ success: false, error: 'Password could not be changed' });
    }

    if (
      !validate_password(req.body?.new_password) ||
      req.body.new_password === req.body.current_password
    ) {
      return res.status(400).json({
        success: false,
        error: 'Choose a new 12–128 character password containing letters and non-letters'
      });
    }

    const password_hash = await hash_password(req.body.new_password);

    store.transaction((db) => {
      db.users[req.account.user.id].password_hash = password_hash;
      db.users[req.account.user.id].updated_at = now_unix();

      for (const session of Object.values(db.sessions)) {
        if (session.user_id === req.account.user.id) {
          session.revoked_at = now_unix();
        }
      }
    });

    clear_auth_cookies(res);
    res.json({ success: true, message: 'Password changed. Sign in again.' });
  });

  account.post('/licenses/redeem', csrf_middleware, (req, res) => {
    if (limited(req, res, 'license', 8, 60 * 60 * 1000, req.account.user.id)) {
      return;
    }

    const key = typeof req.body?.license_key === 'string' ? req.body.license_key.trim() : '';

    if (key.length < 8 || key.length > 256) {
      return res.status(400).json({ success: false, error: 'License could not be redeemed' });
    }

    let result = null;

    store.transaction((db) => {
      const license = db.keys[key];
      const value = license_digest(key);

      if (!license || Number.isSafeInteger(license.start_unix)) {
        return;
      }

      const already_linked = Object.values(db.account_license_links).some((link) => {
        return link.license_digest === value;
      });

      if (already_linked) {
        return;
      }

      const id = crypto.randomUUID();

      db.account_license_links[id] = {
        id,
        user_id: req.account.user.id,
        license_digest: value,
        redeemed_at: now_unix()
      };
      result = account_state(db, db.users[req.account.user.id]);
    });

    if (!result) {
      return res.status(400).json({
        success: false,
        error: 'License could not be redeemed. Only unactivated licenses can be linked to an account.'
      });
    }

    res.json({ success: true, account: result });
  });

  account.get('/devices', (req, res) => {
    const devices = Object.values(req.account.db.device_credentials)
      .filter((entry) => entry.user_id === req.account.user.id)
      .map(public_device);

    res.json({ success: true, devices });
  });

  account.post('/devices/revoke', csrf_middleware, (req, res) => {
    let revoked = false;

    store.transaction((db) => {
      const device = Object.values(db.device_credentials).find((entry) => {
        return entry.public_id === req.body?.device_id && entry.user_id === req.account.user.id;
      });

      if (device && !device.revoked_at) {
        device.revoked_at = now_unix();
        revoked = true;
      }
    });

    if (!revoked) {
      return res.status(404).json({ success: false, error: 'Device not found' });
    }

    res.json({ success: true });
  });

  account.post('/device/decision', csrf_middleware, (req, res) => {
    if (limited(req, res, 'user-code', 10, 15 * 60 * 1000, req.account.user.id)) {
      return;
    }

    const code_hash = digest(
      String(req.body?.user_code || '').toUpperCase(),
      'device-user-code:v1'
    );
    const decision = req.body?.decision;

    if (!['approve', 'deny'].includes(decision)) {
      return res.status(400).json({ success: false, error: 'Invalid decision' });
    }

    let device = null;

    store.transaction((db) => {
      const authorization = find_pending_authorization(db.device_authorizations, code_hash);

      if (!authorization) {
        return;
      }

      authorization.status = decision === 'approve' ? 'approved' : 'denied';
      authorization.user_id = req.account.user.id;
      authorization.decided_at = now_unix();
      authorization.user_code_hash = null;

      device = {
        name: authorization.device_name,
        scopes: authorization.scopes,
        status: authorization.status
      };
    });

    if (!device) {
      return res.status(400).json({ success: false, error: 'Code is invalid or expired' });
    }

    res.json({ success: true, device });
  });

  account.post('/device/review', csrf_middleware, (req, res) => {
    if (limited(req, res, 'user-code', 10, 15 * 60 * 1000, req.account.user.id)) {
      return;
    }

    const code_hash = digest(
      String(req.body?.user_code || '').toUpperCase(),
      'device-user-code:v1'
    );
    const authorization = find_pending_authorization(
      req.account.db.device_authorizations,
      code_hash
    );

    if (!authorization) {
      return res.status(400).json({ success: false, error: 'Code is invalid or expired' });
    }

    res.json({
      success: true,
      device: {
        name: authorization.device_name,
        scopes: authorization.scopes,
        expires_at: authorization.expires_at
      }
    });
  });

  app.use('/api/account', account);

  const device = express.Router();

  device.use(express.json({ limit: '8kb', strict: true }));

  device.post('/authorization', (req, res) => {
    if (limited(req, res, 'device-authorize', 20, 15 * 60 * 1000)) {
      return;
    }

    const name = typeof req.body?.device_name === 'string'
      ? req.body.device_name.trim().slice(0, 80)
      : '';
    const scopes = Array.isArray(req.body?.scopes)
      ? [...new Set(req.body.scopes)]
      : ['account:read'];

    if (
      !name ||
      scopes.length < 1 ||
      scopes.some((scope) => !device_scopes.has(scope))
    ) {
      return res.status(400).json({ success: false, error: 'Invalid device request' });
    }

    const raw_device_code = random_token(32);
    let raw_user_code;
    let capacity = true;

    store.transaction((db) => {
      purge_expired(db);

      const pending_count = Object.values(db.device_authorizations)
        .filter((entry) => entry.status === 'pending')
        .length;

      if (pending_count >= 1000) {
        capacity = false;
        return;
      }

      do {
        raw_user_code = user_code();
      } while (
        Object.values(db.device_authorizations).some((entry) => {
          return entry.user_code_hash === digest(raw_user_code, 'device-user-code:v1');
        })
      );

      const id = crypto.randomUUID();

      db.device_authorizations[id] = {
        id,
        device_code_hash: digest(raw_device_code, 'device-code:v1'),
        user_code_hash: digest(raw_user_code, 'device-user-code:v1'),
        device_name: name,
        scopes,
        status: 'pending',
        created_at: now_unix(),
        expires_at: now_unix() + device_code_seconds,
        interval: device_poll_seconds,
        last_poll_at: 0
      };
    });

    if (!capacity) {
      return res.status(503).json({
        success: false,
        error: 'Device authorization is temporarily unavailable'
      });
    }

    res.status(201).json({
      device_code: raw_device_code,
      user_code: raw_user_code,
      verification_uri: verification_url,
      expires_in: device_code_seconds,
      interval: device_poll_seconds
    });
  });

  device.post('/token', (req, res) => {
    const raw = String(req.body?.device_code || '');

    if (limited(req, res, 'device-poll-ip', 120, 15 * 60 * 1000)) {
      return;
    }

    let response = { status: 'invalid_request' };
    let http_status = 400;
    const code_hash = digest(raw, 'device-code:v1');

    store.transaction((db) => {
      const entry = Object.values(db.device_authorizations).find((item) => {
        return item.device_code_hash && safe_equal(item.device_code_hash, code_hash);
      });

      if (!entry || entry.status === 'consumed') {
        return;
      }

      const now = now_unix();

      if (entry.expires_at <= now) {
        entry.status = 'expired';
        response = { status: 'expired_token' };
        return;
      }

      if (entry.last_poll_at && now - entry.last_poll_at < entry.interval) {
        entry.interval = Math.min(30, entry.interval + 1);
        response = { status: 'slow_down', interval: entry.interval };
        http_status = 429;
        return;
      }

      entry.last_poll_at = now;

      if (entry.status === 'pending') {
        response = { status: 'authorization_pending' };
        http_status = 202;
        return;
      }

      if (entry.status === 'denied') {
        response = { status: 'access_denied' };
        return;
      }

      if (entry.status !== 'approved' || !entry.user_id) {
        return;
      }

      const credential = random_token(32);
      const credential_hash = digest(credential, 'device-credential:v1');

      db.device_credentials[credential_hash] = {
        public_id: random_token(18),
        user_id: entry.user_id,
        name: entry.device_name,
        scopes: entry.scopes,
        created_at: now,
        last_used_at: null,
        revoked_at: null
      };

      entry.status = 'consumed';
      entry.device_code_hash = null;

      response = {
        status: 'authorized',
        device_credential: credential,
        token_type: 'Device',
        scopes: entry.scopes
      };
      http_status = 200;
    });

    res.status(http_status).json(response);
  });

  function device_credential(req, res, next) {
    const authorization = String(req.get('authorization') || '');
    const raw = authorization.startsWith('Device ') ? authorization.slice(7) : '';

    if (!raw) {
      return res.status(401).json({ success: false, error: 'Unauthorized' });
    }

    const db = store.read();
    const credential_hash = digest(raw, 'device-credential:v1');
    const credential = db.device_credentials[credential_hash];
    const user = credential && db.users[credential.user_id];

    if (!credential || credential.revoked_at || !user || user.status !== 'active') {
      return res.status(401).json({ success: false, error: 'Unauthorized' });
    }

    req.device_context = { credential_hash, credential, user, db };
    next();
  }

  device.get('/account', device_credential, (req, res) => {
    if (!req.device_context.credential.scopes.includes('account:read')) {
      return res.status(403).json({ success: false, error: 'Insufficient scope' });
    }

    store.transaction((db) => {
      const stored = db.device_credentials[req.device_context.credential_hash];

      if (stored) {
        stored.last_used_at = now_unix();
      }
    });

    res.json({
      success: true,
      account: account_state(req.device_context.db, req.device_context.user)
    });
  });

  device.post('/rotate', device_credential, (req, res) => {
    const public_id = req.device_context.credential.public_id;

    if (limited(req, res, 'device-rotate', 5, 60 * 60 * 1000, public_id)) {
      return;
    }

    const raw = random_token(32);
    const next_hash = digest(raw, 'device-credential:v1');
    let rotated = false;

    store.transaction((db) => {
      const previous = db.device_credentials[req.device_context.credential_hash];

      if (!previous || previous.revoked_at) {
        return;
      }

      previous.revoked_at = now_unix();
      db.device_credentials[next_hash] = {
        ...previous,
        public_id: random_token(18),
        created_at: now_unix(),
        last_used_at: null,
        revoked_at: null,
        rotated_from: previous.public_id
      };
      rotated = true;
    });

    if (!rotated) {
      return res.status(401).json({ success: false, error: 'Unauthorized' });
    }

    res.json({
      success: true,
      device_credential: raw,
      token_type: 'Device',
      scopes: req.device_context.credential.scopes
    });
  });

  app.use('/api/device', device);

  const admin = express.Router();

  admin.use(
    express.json({ limit: '32kb', strict: true }),
    session_middleware,
    require_role('admin', 'support')
  );

  admin.use((req, res, next) => {
    if (
      req.method === 'GET' ||
      !limited(req, res, 'admin-operation', 60, 60 * 1000, req.account.user.id)
    ) {
      next();
    }
  });

  admin.get('/users', (req, res) => {
    const page = Math.max(1, Number.parseInt(req.query.page, 10) || 1);
    const page_size = Math.min(
      100,
      Math.max(1, Number.parseInt(req.query.page_size, 10) || 20)
    );
    const query = String(req.query.q || '').toLowerCase().slice(0, 128);
    const status = String(req.query.status || '');

    let users = Object.values(req.account.db.users).filter((user) => {
      return (!query || user.email.includes(query)) && (!status || user.status === status);
    });

    users.sort((a, b) => b.created_at - a.created_at);

    const total = users.length;

    users = users
      .slice((page - 1) * page_size, page * page_size)
      .map((user) => ({
        admin_ref: user.admin_ref,
        role: user.role,
        ...account_state(req.account.db, user)
      }));

    res.json({
      success: true,
      users,
      pagination: {
        page,
        page_size,
        total,
        pages: Math.ceil(total / page_size)
      }
    });
  });

  admin.get('/users/:ref', (req, res) => {
    const db = req.account.db;
    const user = find_user_by_ref(db, req.params.ref);

    if (!user) {
      return res.status(404).json({ success: false, error: 'User not found' });
    }

    const devices = Object.values(db.device_credentials)
      .filter((entry) => entry.user_id === user.id)
      .map(public_device);
    const show_metadata = req.account.user.role === 'admin';
    const history = db.audit_events
      .filter((entry) => entry.target === `user:${user.admin_ref}`)
      .slice(-100)
      .reverse()
      .map((entry) => ({
        action: entry.action,
        reason: entry.reason,
        previous_value: entry.previous_value,
        new_value: entry.new_value,
        created_at: entry.created_at,
        request_id: entry.request_id,
        metadata: show_metadata ? entry.metadata : undefined,
        actor: db.users[entry.actor_user_id]?.email || entry.actor_role
      }));

    res.json({
      success: true,
      user: {
        admin_ref: user.admin_ref,
        role: user.role,
        ...account_state(db, user)
      },
      devices,
      audit_history: history
    });
  });

  admin.post('/users/:ref/subscription', require_role('admin'), csrf_middleware, (req, res) => {
    const reason = require_reason(req, res);
    const seconds = req.body?.seconds;

    if (!reason) {
      return;
    }

    if (
      !Number.isSafeInteger(seconds) ||
      seconds === 0 ||
      Math.abs(seconds) > 10 * 365 * 86400
    ) {
      return res.status(400).json({ success: false, error: 'Invalid subscription adjustment' });
    }

    let changed = 0;

    store.transaction((db) => {
      const user = find_user_by_ref(db, req.params.ref);

      if (!user) {
        return;
      }

      if (!Array.isArray(db.subscription_ledger)) {
        db.subscription_ledger = [];
      }

      const now = now_unix();

      for (const [key, license] of linked_licenses(db, user.id)) {
        const active = Number.isSafeInteger(license.start_unix) &&
          Number.isSafeInteger(license.expiry_unix);
        const previous = active ? license.expiry_unix : license.duration_seconds;

        if (active) {
          const floor = Number.isSafeInteger(license.pause_started_at)
            ? license.pause_started_at
            : now;

          license.expiry_unix = Math.max(floor, license.expiry_unix + seconds);
        } else {
          const base = Number.isSafeInteger(license.duration_seconds)
            ? license.duration_seconds
            : 2592000;

          license.duration_seconds = Math.max(60, base + seconds);
        }

        const next = active ? license.expiry_unix : license.duration_seconds;

        db.subscription_ledger.push({
          id: crypto.randomUUID(),
          user_id: user.id,
          license_digest: license_digest(key),
          seconds,
          previous,
          next,
          field: active ? 'expiry_unix' : 'duration_seconds',
          reason,
          actor_user_id: req.account.user.id,
          created_at: now
        });
        changed += 1;
      }

      if (changed) {
        audit(
          db,
          req,
          req.account.user,
          `user:${user.admin_ref}`,
          'subscription.adjust',
          reason,
          null,
          { seconds, licenses: changed }
        );
      }
    });

    if (!changed) {
      return res.status(409).json({ success: false, error: 'Adjustment could not be applied' });
    }

    res.json({ success: true, licenses_updated: changed });
  });

  admin.post('/users/:ref/status', require_role('admin'), csrf_middleware, (req, res) => {
    const reason = require_reason(req, res);
    const status = req.body?.status;

    if (!reason) {
      return;
    }

    if (!['active', 'suspended'].includes(status)) {
      return res.status(400).json({ success: false, error: 'Invalid status' });
    }

    let changed = false;

    store.transaction((db) => {
      const user = find_user_by_ref(db, req.params.ref);

      if (!user || user.id === req.account.user.id) {
        return;
      }

      const active_admins = Object.values(db.users).filter((entry) => {
        return entry.role === 'admin' && entry.status === 'active';
      });

      if (user.role === 'admin' && status === 'suspended' && active_admins.length <= 1) {
        return;
      }

      const previous = user.status;

      user.status = status;

      if (status === 'suspended') {
        for (const session of Object.values(db.sessions)) {
          if (session.user_id === user.id) {
            session.revoked_at = now_unix();
          }
        }

        for (const credential of Object.values(db.device_credentials)) {
          if (credential.user_id === user.id) {
            credential.revoked_at = now_unix();
          }
        }
      }

      audit(
        db,
        req,
        req.account.user,
        `user:${user.admin_ref}`,
        `account.${status}`,
        reason,
        previous,
        status
      );
      changed = true;
    });

    if (!changed) {
      return res.status(409).json({ success: false, error: 'Status could not be changed' });
    }

    res.json({ success: true, status });
  });

  admin.post('/users/:ref/hwid-reset', require_role('admin'), csrf_middleware, (req, res) => {
    const reason = require_reason(req, res);

    if (!reason) {
      return;
    }

    let count = 0;

    store.transaction((db) => {
      const user = find_user_by_ref(db, req.params.ref);

      if (!user) {
        return;
      }

      for (const [, license] of linked_licenses(db, user.id)) {
        if (license.hwid || license.client_public_key) {
          license.hwid = null;
          license.client_public_key = null;
          count += 1;
        }
      }

      if (count) {
        audit(
          db,
          req,
          req.account.user,
          `user:${user.admin_ref}`,
          'hwid.reset',
          reason,
          { associations: count },
          { associations: 0 }
        );
      }
    });

    if (!count) {
      return res.status(409).json({ success: false, error: 'No HWID association was reset' });
    }

    res.json({ success: true, reset_count: count });
  });

  app.use('/api/admin', admin);

  app.use(
    express.static(path.join(project_root, 'public'), {
      index: false,
      dotfiles: 'deny',
      etag: true,
      maxAge: '1h'
    })
  );

  app.get(['/account', '/device'], (req, res) => {
    const page = req.path === '/device' ? 'device.html' : 'account.html';

    res.sendFile(path.join(project_root, 'public', page));
  });

  app.get('/admin', session_middleware, require_role('admin', 'support'), (req, res) => {
    res.sendFile(path.join(project_root, 'public', 'admin.html'));
  });

  app.use((error, req, res, next) => {
    if (res.headersSent) {
      return next(error);
    }

    const parser_error = error?.type === 'entity.parse.failed' ||
      error?.type === 'entity.too.large';
    let status = 500;

    if (parser_error) {
      status = error.type === 'entity.too.large' ? 413 : 400;
    }

    let message = 'Request failed';

    if (status === 413) {
      message = 'Request body is too large';
    } else if (status === 400) {
      message = 'Invalid request body';
    }

    console.error(`[REQUEST ${req.id || 'unknown'}]`, error.message);
    res.status(status).json({ success: false, error: message });
  });

  return {
    csrf_middleware,
    require_role,
    session_middleware,
    audit,
    require_reason
  };
}

module.exports = {
  device_code_seconds,
  device_poll_seconds,
  session_seconds,
  account_state,
  license_digest,
  linked_licenses,
  mount_account_service
};
