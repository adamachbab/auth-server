const assert = require('assert/strict');
const crypto = require('crypto');
const fs = require('fs');
const http = require('http');
const net = require('net');
const os = require('os');
const path = require('path');

const { auth_canonical, session_canonical } = require('../src/lib/client-proof');
const { decode_frame, encode_frame } = require('../src/lib/native-protocol');

function client_identity() {
  const pair = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const jwk = pair.publicKey.export({ format: 'jwk' });
  const blob = Buffer.alloc(72);

  blob.writeUInt32LE(0x31534345, 0);
  blob.writeUInt32LE(32, 4);
  Buffer.from(jwk.x, 'base64url').copy(blob, 8);
  Buffer.from(jwk.y, 'base64url').copy(blob, 40);

  return { pair, public_key: blob.toString('base64url') };
}

function sign(identity, canonical) {
  return crypto.sign('sha256', Buffer.from(canonical), {
    key: identity.pair.privateKey,
    dsaEncoding: 'ieee-p1363'
  }).toString('base64url');
}

function signed_authentication(identity, key, hwid, extra = {}) {
  const timestamp_unix = Math.floor(Date.now() / 1000);
  const nonce = crypto.randomBytes(32).toString('base64url');
  const signature = sign(identity, auth_canonical(key, hwid, timestamp_unix, nonce));

  return {
    op: 'authenticate',
    key,
    hwid,
    client_public_key: identity.public_key,
    timestamp_unix,
    nonce,
    signature,
    ...extra
  };
}

function validate_request(identity, access_token) {
  const timestamp_unix = Math.floor(Date.now() / 1000);
  const nonce = crypto.randomBytes(32).toString('base64url');
  const canonical = session_canonical('validate', access_token, timestamp_unix, nonce);

  return {
    op: 'validate',
    access_token,
    timestamp_unix,
    nonce,
    signature: sign(identity, canonical)
  };
}

function native_call(port, json) {
  return new Promise((resolve, reject) => {
    const socket = net.connect({ host: '127.0.0.1', port }, () => {
      socket.end(encode_frame(json, null, { request: true }));
    });
    const chunks = [];

    socket.on('data', (chunk) => chunks.push(chunk));
    socket.on('error', reject);
    socket.on('end', () => {
      const frame = decode_frame(Buffer.concat(chunks));

      if (!frame) {
        reject(new Error('invalid native response'));
        return;
      }

      resolve({ status: frame.json.status, body: frame.json });
    });
  });
}

function http_call(port, method, url_path, body, headers = {}) {
  return new Promise((resolve, reject) => {
    const payload = body === undefined ? '' : JSON.stringify(body);
    const content_headers = payload
      ? { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) }
      : {};
    const options = {
      hostname: '127.0.0.1',
      port,
      method,
      path: url_path,
      headers: { ...content_headers, ...headers }
    };
    const request = http.request(options, (response) => {
      const chunks = [];

      response.on('data', (chunk) => chunks.push(chunk));
      response.on('end', () => {
        resolve({
          status: response.statusCode,
          body: JSON.parse(Buffer.concat(chunks).toString('utf8'))
        });
      });
    });

    request.on('error', reject);
    request.end(payload);
  });
}

function close_server(server) {
  return new Promise((resolve, reject) => {
    server.close((error) => (error ? reject(error) : resolve()));
  });
}

async function main() {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'auth-login-'));
  const database_path = path.join(directory, 'database.json');

  fs.writeFileSync(database_path, JSON.stringify({
    keys: {
      'LOGIN-KEY': {
        duration_seconds: 3600,
        start_unix: null,
        expiry_unix: null,
        hwid: null,
        discord_id: '111111111111111111',
        created_at: 1
      },
      'PAIRING-KEY': {
        duration_seconds: 3600,
        start_unix: null,
        expiry_unix: null,
        hwid: null,
        created_at: 1
      }
    }
  }));
  process.env.DATABASE_PATH = database_path;

  const { app, start_native_server, store } = require('../server');
  const { pause_license, resume_license } = require('../src/lib/license-state');
  const server = await new Promise((resolve) => {
    const value = app.listen(0, '127.0.0.1', () => resolve(value));
  });
  const native_server = start_native_server(0);

  if (!native_server.listening) {
    await new Promise((resolve) => native_server.once('listening', resolve));
  }

  const port = server.address().port;
  const native_port = native_server.address().port;
  const login_identity = client_identity();
  const pairing_identity = client_identity();
  const attacker_identity = client_identity();

  try {
    assert.equal(
      (await http_call(port, 'GET', '/?key=LOGIN-KEY&hwid=HWID')).status,
      405,
      'license credentials are not accepted in URLs'
    );
    assert.equal(
      (await http_call(port, 'POST', '/api/client/authenticate', {
        key: 'LOGIN-KEY',
        hwid: 'HWID'
      })).status,
      410
    );

    let result = await native_call(native_port, {
      op: 'authenticate',
      key: 'LOGIN-KEY',
      hwid: 'HWID'
    });
    assert.equal(
      result.status,
      401,
      'a key and spoofable HWID cannot authenticate without device proof'
    );
    assert.equal(
      (await native_call(
        native_port,
        signed_authentication(login_identity, 'MISSING-KEY', 'HWID')
      )).status,
      401
    );

    result = await native_call(
      native_port,
      signed_authentication(login_identity, 'LOGIN-KEY', 'HWID')
    );
    assert.equal(result.status, 200);
    assert.equal(result.body.success, true);
    assert.match(result.body.access_token, /^[A-Za-z0-9_-]{43}$/);
    assert.ok(
      result.body.access_token_expires_in > 0
      && result.body.access_token_expires_in <= 300
    );
    assert.ok(result.body.expiry_unix > result.body.start_unix);
    assert.equal(result.body.games, undefined);
    const first_access_token = result.body.access_token;

    assert.equal(
      (await native_call(native_port, {
        op: 'validate',
        access_token: first_access_token
      })).status,
      401,
      'a stolen bearer token cannot validate without a fresh device signature'
    );
    assert.equal(
      (await native_call(
        native_port,
        validate_request(attacker_identity, first_access_token)
      )).status,
      401
    );

    const validation = validate_request(login_identity, first_access_token);
    assert.equal((await native_call(native_port, validation)).status, 200);
    assert.equal(
      (await native_call(native_port, validation)).status,
      401,
      'session proofs cannot be replayed'
    );
    assert.equal(
      (await native_call(native_port, {
        op: 'module',
        access_token: first_access_token
      })).status,
      400
    );

    assert.equal(
      (await native_call(
        native_port,
        signed_authentication(attacker_identity, 'LOGIN-KEY', 'HWID')
      )).status,
      401,
      'the license remains bound to the original device key even when its license key and HWID are known'
    );
    assert.equal(
      (await native_call(
        native_port,
        signed_authentication(login_identity, 'LOGIN-KEY', 'OTHER-HWID')
      )).status,
      401
    );

    const rotated = await native_call(
      native_port,
      signed_authentication(login_identity, 'LOGIN-KEY', 'HWID')
    );
    assert.equal(rotated.status, 200);
    assert.notEqual(rotated.body.access_token, first_access_token);
    assert.equal(
      (await native_call(
        native_port,
        validate_request(login_identity, first_access_token)
      )).status,
      401,
      'issuing a new token revokes the previous one'
    );
    const active_access_token = rotated.body.access_token;

    result = await native_call(
      native_port,
      signed_authentication(pairing_identity, 'PAIRING-KEY', 'PAIRING-HWID', {
        discord_id: '222222222222222222'
      })
    );
    assert.equal(result.status, 400, 'the native client cannot self-assert a Discord identity');
    assert.equal(store.read().keys['PAIRING-KEY'].start_unix, null);

    result = await native_call(
      native_port,
      signed_authentication(pairing_identity, 'PAIRING-KEY', 'PAIRING-HWID')
    );
    assert.equal(result.status, 200);
    assert.match(result.body.pairing_code, /^[A-Z2-9]{4}-[A-Z2-9]{4}-[A-Z2-9]{4}$/);
    assert.ok(result.body.pairing_expires_in > 0 && result.body.pairing_expires_in <= 900);

    store.transaction((db) => pause_license(db.keys['LOGIN-KEY'], 'test-pause'));
    result = await native_call(
      native_port,
      signed_authentication(login_identity, 'LOGIN-KEY', 'HWID')
    );
    assert.equal(result.status, 423);
    assert.equal(result.body.error, 'Subscription is paused');
    assert.equal(
      (await native_call(
        native_port,
        validate_request(login_identity, active_access_token)
      )).status,
      401
    );

    store.transaction((db) => resume_license(db.keys['LOGIN-KEY'], 'test-pause'));
    assert.equal(
      (await native_call(
        native_port,
        signed_authentication(login_identity, 'LOGIN-KEY', 'HWID')
      )).status,
      200
    );

    const create_key_body = {
      key: 'ADMIN-TEST',
      duration_seconds: 60,
      reason: 'Login flow test'
    };

    result = await http_call(port, 'POST', '/admin/create-key', create_key_body);
    assert.equal(result.status, 503);

    process.env.AUTH_ADMIN_SECRET = 'test-admin-secret-that-is-at-least-32-bytes';
    result = await http_call(port, 'POST', '/admin/create-key', create_key_body, {
      Authorization: 'Bearer wrong-secret-that-is-at-least-32-bytes'
    });
    assert.equal(result.status, 403);

    result = await http_call(port, 'POST', '/admin/create-key', create_key_body, {
      Authorization: `Bearer ${process.env.AUTH_ADMIN_SECRET}`
    });
    assert.equal(result.status, 200);
    assert.equal(store.read().keys['ADMIN-TEST'].duration_seconds, 60);

    console.log('Authenticated login flow tests passed.');
  } finally {
    await close_server(native_server);
    await close_server(server);
    fs.rmSync(directory, { recursive: true, force: true });
    delete process.env.AUTH_ADMIN_SECRET;
  }
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
