const express = require('express');
const path = require('path');
const crypto = require('crypto');
const { create_store } = require('./lib/data-store');
const { mount_account_service } = require('./account-service');
const {
  create_rate_limiter,
  digest,
  metadata,
  random_token,
  request_id
} = require('./lib/security');
const { is_license_paused, pause_license } = require('./lib/license-state');
const { create_client_proof_verifier } = require('./lib/client-proof');
const { mount_discord_member_route } = require('./discord/member-route');
const {
  issue_pairing_code,
  mount_discord_bot,
  register_discord_commands,
  start_discord_presence
} = require('./discord/bot');
const { create_native_server } = require('./native-server');

const content_security_policy = [
  "default-src 'self'",
  "script-src 'self'",
  "style-src 'self'",
  "img-src 'self' https: data:",
  "connect-src 'self'",
  "object-src 'none'",
  "base-uri 'none'",
  "form-action 'self'",
  "frame-ancestors 'none'"
].join('; ');

function configured_origins() {
  return String(process.env.AUTH_CORS_ORIGINS || '')
    .split(',')
    .map((value) => value.trim())
    .filter(Boolean);
}

const app = express();

app.disable('x-powered-by');

if (process.env.NODE_ENV === 'production') {
  app.set('trust proxy', String(process.env.AUTH_TRUST_PROXY || 'loopback'));
}

app.use((req, res, next) => {
  if (process.env.NODE_ENV === 'production' && !req.secure) {
    return res.status(426).json({ success: false, error: 'HTTPS is required' });
  }

  req.id = crypto.randomUUID();
  res.set('X-Request-ID', req.id);
  res.set('Cache-Control', 'no-store');
  res.set('X-Content-Type-Options', 'nosniff');
  res.set('Referrer-Policy', 'no-referrer');
  res.set('X-Frame-Options', 'DENY');
  res.set('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  res.set('Content-Security-Policy', content_security_policy);

  if (process.env.NODE_ENV === 'production') {
    res.set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  }

  const origin = req.get('origin');
  const allowed = configured_origins();

  if (origin && allowed.includes(origin)) {
    res.set('Access-Control-Allow-Origin', origin);
    res.set('Vary', 'Origin');
    res.set('Access-Control-Allow-Credentials', 'true');
  }

  if (req.method === 'OPTIONS') {
    if (!origin || !allowed.includes(origin)) {
      return res.sendStatus(403);
    }

    res.set('Access-Control-Allow-Methods', 'GET,POST,PATCH,DELETE');
    res.set('Access-Control-Allow-Headers', 'Content-Type,X-CSRF-Token');
    return res.sendStatus(204);
  }

  next();
});

const port = process.env.PORT || 1053;
const native_port = process.env.AUTH_NATIVE_PORT || 2230;
const project_root = path.join(__dirname, '..');
const production = process.env.NODE_ENV === 'production';

if (production && !process.env.DATABASE_PATH) {
  throw new Error(
    'DATABASE_PATH is required in production and must point to persistent storage outside the application checkout.'
  );
}

const db_path = process.env.DATABASE_PATH
  ? path.resolve(process.env.DATABASE_PATH)
  : path.join(project_root, 'database.json');
const store = create_store(db_path, { allow_create: !production });

store.initialize();

const admin_rate = create_rate_limiter();
const native_auth_rate = create_rate_limiter();
const client_proofs = create_client_proof_verifier();

const client_access_seconds = 5 * 60;
const client_access_limit = 10000;
const client_access_token = /^[A-Za-z0-9_-]{43}$/;
const client_access_sessions = new Map();
const client_access_by_license = new Map();

function load_database() {
  return store.read();
}

function secret_matches(expected, supplied) {
  if (typeof expected !== 'string' || expected.length < 32 || typeof supplied !== 'string') {
    return false;
  }

  const expected_hash = crypto.createHash('sha256').update(expected).digest();
  const supplied_hash = crypto.createHash('sha256').update(supplied).digest();

  return crypto.timingSafeEqual(expected_hash, supplied_hash);
}

function key_label(key) {
  return typeof key === 'string' && key.length > 4 ? `${key.slice(0, 4)}...` : '[redacted]';
}

function remove_access_session(token_hash, session) {
  client_access_sessions.delete(token_hash);

  if (client_access_by_license.get(session.license_id) === token_hash) {
    client_access_by_license.delete(session.license_id);
  }
}

function prune_access_sessions(now = Math.floor(Date.now() / 1000)) {
  for (const [token_hash, session] of client_access_sessions) {
    if (session.expires_at <= now) {
      remove_access_session(token_hash, session);
    }
  }
}

function issue_client_access(key, hwid, client_public_key, license_expiry) {
  const now = Math.floor(Date.now() / 1000);

  prune_access_sessions(now);

  const license_id = digest(key, 'client-access-license:v1');
  const previous_hash = client_access_by_license.get(license_id);
  const previous = previous_hash && client_access_sessions.get(previous_hash);

  if (previous) {
    remove_access_session(previous_hash, previous);
  }

  if (client_access_sessions.size >= client_access_limit) {
    throw new Error('Client access session capacity reached');
  }

  const expires_at = Math.min(license_expiry, now + client_access_seconds);
  const token = random_token(32);
  const token_hash = digest(token, 'client-access-token:v1');

  client_access_sessions.set(token_hash, {
    key,
    hwid,
    client_public_key,
    license_id,
    expires_at
  });
  client_access_by_license.set(license_id, token_hash);

  return {
    access_token: token,
    token_type: 'Bearer',
    access_token_expires_unix: expires_at,
    access_token_expires_in: Math.max(0, expires_at - now)
  };
}

function authenticate_access_token(token, proof, database = load_database()) {
  if (typeof token !== 'string' || !client_access_token.test(token)) {
    return null;
  }

  const token_hash = digest(token, 'client-access-token:v1');
  const session = client_access_sessions.get(token_hash);

  if (!session) {
    return null;
  }

  const now = Math.floor(Date.now() / 1000);
  const license = database.keys?.[session.key];

  if (
    session.expires_at <= now ||
    !license ||
    is_license_paused(database, license) ||
    license.hwid !== session.hwid ||
    license.client_public_key !== session.client_public_key ||
    !Number.isSafeInteger(license.expiry_unix) ||
    license.expiry_unix <= now
  ) {
    remove_access_session(token_hash, session);
    return null;
  }

  if (!client_proofs.verify_session(proof, token, session.client_public_key)) {
    return null;
  }

  return { key: session.key, license };
}

function native_error(status, error, extra = {}) {
  return { status, body: { success: false, error, ...extra } };
}

function license_response(license, now, extra = {}) {
  return {
    success: true,
    start_unix: license.start_unix,
    expiry_unix: license.expiry_unix,
    duration_seconds: license.expiry_unix - license.start_unix,
    remaining_seconds: license.expiry_unix - now,
    ...extra
  };
}

function authenticate_native(body, ip) {
  const request = body && typeof body === 'object' && !Array.isArray(body) ? body : {};
  const { key, hwid } = request;

  const rate = native_auth_rate(`native-auth:${ip || 'unknown'}`, 30, 60 * 1000);

  if (!rate.allowed) {
    return native_error(429, 'Too many authentication attempts', {
      retry_after: rate.retry_after
    });
  }

  if (typeof key !== 'string' || key.length < 8 || key.length > 256) {
    return native_error(400, 'Missing or invalid key');
  }

  if (typeof hwid !== 'string' || !/^[\x21-\x7e]{1,256}$/.test(hwid)) {
    return native_error(400, 'Missing or invalid hwid');
  }

  const client_profile_fields = ['discord_id', 'username', 'display_name', 'avatar_url'];
  const has_profile_field = client_profile_fields.some((field) => {
    return Object.prototype.hasOwnProperty.call(request, field);
  });

  if (has_profile_field) {
    return native_error(400, 'Discord identity must be linked with the server-issued pairing code');
  }

  const client_proof = client_proofs.verify_authentication(request);

  if (!client_proof) {
    return native_error(401, 'Client device proof required');
  }

  try {
    let status = 200;
    let response_body;
    const now = Math.floor(Date.now() / 1000);

    store.transaction((db) => {
      const license = db.keys?.[key];

      if (!license) {
        status = 401;
        response_body = { success: false, error: 'Invalid license' };
        return;
      }

      if (
        license.client_public_key &&
        license.client_public_key !== client_proof.encoded_public_key
      ) {
        status = 401;
        response_body = {
          success: false,
          error: 'Client device proof does not match this license'
        };
        return;
      }

      if (is_license_paused(db, license)) {
        status = 423;
        response_body = { success: false, error: 'Subscription is paused' };
        return;
      }

      if (license.start_unix === null || license.start_unix === undefined) {
        const duration = Number.isSafeInteger(license.duration_seconds)
          ? license.duration_seconds
          : 2592000;

        license.start_unix = now;
        license.expiry_unix = now + duration;
        license.hwid = hwid;
        license.client_public_key = client_proof.encoded_public_key;
        console.log(`[AUTH] First login: key=${key_label(key)}`);
      } else {
        if (license.hwid && license.hwid !== hwid) {
          status = 401;
          response_body = { success: false, error: 'HWID mismatch' };
          return;
        }

        if (!Number.isSafeInteger(license.expiry_unix) || now >= license.expiry_unix) {
          status = 403;
          response_body = {
            success: false,
            error: 'Key expired',
            expiry_unix: license.expiry_unix
          };
          return;
        }

        license.hwid = hwid;
        license.client_public_key = client_proof.encoded_public_key;
      }

      const pairing = !license.discord_id ? issue_pairing_code(db, key, now) : null;
      const pairing_fields = pairing
        ? { pairing_code: pairing.code, pairing_expires_in: pairing.expires_in }
        : {};

      response_body = license_response(license, now, pairing_fields);
    });

    if (response_body?.success) {
      Object.assign(
        response_body,
        issue_client_access(
          key,
          hwid,
          client_proof.encoded_public_key,
          response_body.expiry_unix
        )
      );
    }

    return { status, body: response_body };
  } catch (error) {
    console.error('[AUTH] Authentication failed:', error.message);
    return native_error(500, 'Authentication failed');
  }
}

function validate_native(body) {
  const request = body && typeof body === 'object' ? body : {};
  const access = authenticate_access_token(request.access_token, request);

  if (!access) {
    return native_error(401, 'Unauthorized');
  }

  const now = Math.floor(Date.now() / 1000);

  return { status: 200, body: license_response(access.license, now) };
}

function handle_native_request(frame, ip) {
  const op = String(frame?.json?.op || '');

  if (op === 'authenticate') {
    return authenticate_native(frame.json, ip);
  }

  if (op === 'validate') {
    return validate_native(frame.json);
  }

  return native_error(400, 'Unknown native operation');
}

function gone_native(req, res) {
  return res.status(410).json({
    success: false,
    error: 'Native authentication uses TCP sockets, not HTTP'
  });
}

app.get('/', (req, res) => {
  res.set('Allow', 'GET,POST');
  return res.status(405).json({
    success: false,
    error: 'Native authentication uses TCP sockets, not HTTP'
  });
});

app.post('/api/client/authenticate', gone_native);

mount_discord_member_route(app, { load_database });
mount_discord_bot(app, { store });

app.use(
  '/admin/create-key',
  express.json({ limit: '8kb', strict: true }),
  (req, res, next) => {
    const rate = admin_rate(`admin:${req.ip || 'unknown'}`, 20, 60 * 1000);

    if (!rate.allowed) {
      res.set('Retry-After', String(rate.retry_after));
      return res.status(429).json({ success: false, error: 'Too many requests' });
    }

    const configured = process.env.AUTH_ADMIN_SECRET;
    const bearer = req.get('authorization') || '';
    const supplied = req.get('x-auth-admin-secret') ||
      (bearer.startsWith('Bearer ') ? bearer.slice(7) : '');

    if (typeof configured !== 'string' || configured.length < 32) {
      return res.status(503).json({
        success: false,
        error: 'Admin API is disabled until AUTH_ADMIN_SECRET is configured'
      });
    }

    if (!secret_matches(configured, supplied)) {
      return res.status(403).json({ success: false, error: 'Admin authorization required' });
    }

    next();
  }
);

app.post('/admin/create-key', (req, res) => {
  const { key, duration_seconds, reason } = req.body || {};

  if (
    typeof key !== 'string' ||
    key.length < 8 ||
    key.length > 256 ||
    !Number.isSafeInteger(duration_seconds) ||
    duration_seconds < 60 ||
    duration_seconds > 10 * 365 * 86400 ||
    typeof reason !== 'string' ||
    reason.trim().length < 3 ||
    reason.trim().length > 500
  ) {
    return res.status(400).json({
      success: false,
      error: 'A valid key, duration_seconds, and reason are required'
    });
  }

  let created = false;

  store.transaction((db) => {
    if (db.keys[key]) {
      return;
    }

    const now = Math.floor(Date.now() / 1000);

    db.keys[key] = {
      duration_seconds,
      start_unix: null,
      expiry_unix: null,
      hwid: null,
      client_public_key: null,
      created_at: now,
      pause_reasons: [],
      pause_started_at: null
    };

    if (db.service_state?.keys_paused) {
      pause_license(db.keys[key], 'global');
    }

    db.audit_events.push({
      id: crypto.randomUUID(),
      actor_user_id: null,
      actor_role: 'license_issuer_service',
      target: `license:${digest(key, 'audit-license:v1')}`,
      action: 'license.create',
      reason: reason.trim(),
      previous_value: null,
      new_value: { duration_seconds },
      created_at: now,
      request_id: request_id(req),
      metadata: metadata(req)
    });
    created = true;
  });

  if (!created) {
    return res.status(409).json({ success: false, error: 'Key already exists' });
  }

  console.log(`[ADMIN] Created key: ${key_label(key)}, duration: ${duration_seconds}s`);
  return res.json({ success: true, message: 'Key created', key });
});

mount_account_service(app, {
  store,
  secure_cookie: process.env.AUTH_COOKIE_SECURE !== 'false',
  verification_url: process.env.AUTH_DEVICE_VERIFICATION_URL || '/device',
  allowed_origins: configured_origins()
});

function start_native_server(listen_port = native_port) {
  const server = create_native_server(handle_native_request);

  server.listen(listen_port, () => {
    const listening = server.address();
    const bound = typeof listening === 'object' && listening ? listening.port : listen_port;

    console.log(`Native TCP auth listening on port ${bound}`);
  });

  return server;
}

function start_server(listen_port = port, listen_native_port = native_port) {
  const native_server = start_native_server(listen_native_port);

  const server = app.listen(listen_port, () => {
    const license_count = Object.keys(store.read().keys || {}).length;
    const location = production
      ? 'HTTPS via trusted reverse proxy'
      : `http://localhost:${listen_port}`;
    const plural = license_count === 1 ? '' : 's';

    console.log(`Auth server running on ${location}`);
    console.log(`Database: ${db_path} (${license_count} license record${plural} loaded)`);
  });

  server.on('close', () => native_server.close());
  register_discord_commands().catch((error) => console.error('[DISCORD]', error.message));
  start_discord_presence().catch((error) => console.error('[DISCORD]', error.message));

  return server;
}

if (require.main === module) {
  start_server();
}

module.exports = {
  app,
  handle_native_request,
  load_database,
  start_native_server,
  start_server,
  store
};
