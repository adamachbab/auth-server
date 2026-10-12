const assert = require('assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');

const password = 'Correct horse 42!';

async function main() {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'auth-account-'));
  process.env.DATABASE_PATH = path.join(directory, 'database.json');
  process.env.AUTH_COOKIE_SECURE = 'false';
  fs.writeFileSync(process.env.DATABASE_PATH, JSON.stringify({
    keys: {
      'LICENSE-ONE': {
        duration_seconds: 3600,
        start_unix: null,
        expiry_unix: null,
        hwid: 'OLD-HWID',
        client_public_key: 'bound-device-key'
      }
    }
  }));

  const { app, store } = require('../server');
  const server = await new Promise((resolve) => {
    const value = app.listen(0, '127.0.0.1', () => resolve(value));
  });
  const base = `http://127.0.0.1:${server.address().port}`;
  const identities = new Map();

  async function request(route, options = {}) {
    const { method = 'GET', identity, headers = {}, csrf = true } = options;
    let { body } = options;
    const state = identities.get(identity) || { cookie: '', csrf: '' };

    if (state.cookie) {
      headers.Cookie = state.cookie;
    }
    if (!['GET', 'HEAD'].includes(method) && state.csrf && csrf) {
      headers['X-CSRF-Token'] = state.csrf;
    }
    if (body && !(body instanceof FormData)) {
      headers['Content-Type'] = 'application/json';
      body = JSON.stringify(body);
    }

    const response = await fetch(`${base}${route}`, { method, headers, body });
    const set_cookies = response.headers.getSetCookie ? response.headers.getSetCookie() : [];

    if (identity && set_cookies.length) {
      const values = {};

      for (const cookie of set_cookies) {
        const [pair] = cookie.split(';');
        const split = pair.indexOf('=');
        values[pair.slice(0, split)] = pair.slice(split + 1);
      }

      state.cookie = Object.entries(values)
        .filter(([, value]) => value)
        .map(([key, value]) => `${key}=${value}`)
        .join('; ');
      state.csrf = values.auth_csrf ? decodeURIComponent(values.auth_csrf) : state.csrf;
      identities.set(identity, state);
    }

    let payload = {};

    try {
      payload = await response.json();
    } catch {}

    return { status: response.status, body: payload, headers: response.headers };
  }

  function post(route, body, extra = {}) {
    return request(route, { method: 'POST', body, ...extra });
  }

  function device_headers(credential) {
    return { Authorization: `Device ${credential}` };
  }

  try {
    const registrations = [
      ['admin@example.com', 'admin', 'admin'],
      ['user@example.com', 'user', 'admin']
    ];

    for (const [email, identity, role] of registrations) {
      const registered = await post('/api/auth/register', { email, password, role }, { identity });
      assert.equal(registered.status, 202);
    }

    store.transaction((db) => {
      const admin = Object.values(db.users).find((user) => user.email === 'admin@example.com');
      admin.role = 'admin';
    });
    assert.equal(
      (await post(
        '/api/auth/login',
        { email: 'admin@example.com', password },
        { identity: 'admin' }
      )).status,
      200
    );
    assert.equal(
      (await post(
        '/api/auth/login',
        { email: 'user@example.com', password },
        { identity: 'user' }
      )).status,
      200
    );

    const normal_admin_attempt = await request('/api/admin/users', { identity: 'user' });
    assert.equal(normal_admin_attempt.status, 403, 'normal users cannot access admin endpoints');

    const csrf_attempt = await post(
      '/api/account/licenses/redeem',
      { license_key: 'LICENSE-ONE' },
      { identity: 'user', headers: { 'X-CSRF-Token': 'wrong' }, csrf: false }
    );
    assert.equal(csrf_attempt.status, 403, 'state changes reject invalid CSRF');
    assert.equal(
      (await post(
        '/api/account/licenses/redeem',
        { license_key: 'LICENSE-ONE' },
        { identity: 'user' }
      )).status,
      200
    );

    const authorization = await post('/api/device/authorization', {
      device_name: 'Test console',
      scopes: ['account:read']
    });
    assert.equal(authorization.status, 201);

    const review = await post(
      '/api/account/device/review',
      { user_code: authorization.body.user_code },
      { identity: 'user' }
    );
    assert.equal(review.status, 200);
    assert.deepEqual(review.body.device.scopes, ['account:read']);

    const decisions = await Promise.all([1, 2].map(() => post(
      '/api/account/device/decision',
      { user_code: authorization.body.user_code, decision: 'approve' },
      { identity: 'user' }
    )));
    assert.deepEqual(
      decisions.map((result) => result.status).sort(),
      [200, 400],
      'authorization can be linked only once'
    );

    const token = await post('/api/device/token', {
      device_code: authorization.body.device_code
    });
    assert.equal(token.status, 200);
    assert.equal(token.body.status, 'authorized');
    assert.equal(
      (await post('/api/device/token', { device_code: authorization.body.device_code })).status,
      400,
      'device code replay fails'
    );
    assert.equal(
      (await request('/api/device/account', {
        headers: device_headers(token.body.device_credential)
      })).status,
      200
    );

    const rotated = await post('/api/device/rotate', {}, {
      headers: device_headers(token.body.device_credential)
    });
    assert.equal(rotated.status, 200);
    assert.equal(
      (await request('/api/device/account', {
        headers: device_headers(token.body.device_credential)
      })).status,
      401,
      'rotated credentials are revoked'
    );
    assert.equal(
      (await request('/api/device/account', {
        headers: device_headers(rotated.body.device_credential)
      })).status,
      200
    );

    const pending = await post('/api/device/authorization', {
      device_name: 'Pending',
      scopes: ['account:read']
    });
    assert.equal(
      (await post('/api/device/token', { device_code: pending.body.device_code })).status,
      202
    );
    assert.equal(
      (await post('/api/device/token', { device_code: pending.body.device_code })).status,
      429,
      'polling interval is enforced'
    );

    const expired = await post('/api/device/authorization', {
      device_name: 'Expired',
      scopes: ['account:read']
    });
    store.transaction((db) => {
      Object.values(db.device_authorizations)
        .find((entry) => entry.device_name === 'Expired')
        .expires_at = 1;
    });
    const expired_poll = await post('/api/device/token', {
      device_code: expired.body.device_code
    });
    assert.equal(expired_poll.body.status, 'expired_token');

    const users = await request('/api/admin/users?q=user%40example.com', { identity: 'admin' });
    const ref = users.body.users[0].admin_ref;
    assert.equal(users.body.users[0].role, 'user', 'client-supplied roles are ignored');
    assert.equal(
      (await post(
        `/api/admin/users/${ref}/subscription`,
        { seconds: 86400, reason: 'Add one day' },
        { identity: 'admin' }
      )).status,
      200
    );
    assert.equal(
      (await post(
        `/api/admin/users/${ref}/hwid-reset`,
        { reason: 'New hardware' },
        { identity: 'admin' }
      )).status,
      200
    );
    assert.equal(
      store.read().keys['LICENSE-ONE'].client_public_key,
      null,
      'hardware reset also clears the proof-of-possession key'
    );

    const admins = await request('/api/admin/users?q=admin%40example.com', { identity: 'admin' });
    assert.equal(
      (await post(
        `/api/admin/users/${admins.body.users[0].admin_ref}/status`,
        { status: 'suspended', reason: 'Self suspension attempt' },
        { identity: 'admin' }
      )).status,
      409
    );

    const original = 'Original password 42!';
    const replacement = 'Replacement password 84!';
    const password_identity = { identity: 'password' };

    assert.equal(
      (await post(
        '/api/auth/register',
        { email: 'password@example.com', password: original },
        password_identity
      )).status,
      202
    );
    assert.equal(
      (await post(
        '/api/auth/login',
        { email: 'password@example.com', password: original },
        password_identity
      )).status,
      200
    );
    assert.equal(
      (await post(
        '/api/account/password',
        { current_password: original, new_password: replacement },
        password_identity
      )).status,
      200
    );
    assert.equal(
      (await post(
        '/api/auth/login',
        { email: 'password@example.com', password: original },
        password_identity
      )).status,
      401
    );
    assert.equal(
      (await post(
        '/api/auth/login',
        { email: 'password@example.com', password: replacement },
        password_identity
      )).status,
      200
    );

    const missing_login = { email: 'missing@example.com', password: 'wrong' };

    for (let index = 0; index < 11; index++) {
      await post('/api/auth/login', missing_login);
    }

    assert.equal(
      (await post('/api/auth/login', missing_login)).status,
      429,
      'login rate limit applies'
    );

    console.log('Account, CSRF, RBAC, device, and transaction security tests passed.');
  } finally {
    await new Promise((resolve) => server.close(resolve));
    fs.rmSync(directory, { recursive: true, force: true });
  }
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
