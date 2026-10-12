const assert = require('assert/strict');
const crypto = require('crypto');
const express = require('express');
const fs = require('fs');
const http = require('http');
const os = require('os');
const path = require('path');

const {
  create_discord_member_router,
  create_rate_limiter,
  create_replay_cache
} = require('../src/discord/member-route');
const {
  discord_api_error,
  discord_member_service,
  default_avatar_url
} = require('../src/discord/member-service');
const {
  cng_ecdh_public_p256_magic,
  decrypt,
  derive_key,
  encrypt
} = require('../src/discord/envelope');
const {
  base64url,
  canonical_request,
  discord_id_hash,
  hmac_sha256,
  hwid_hash,
  license_hash,
  request_auth_key
} = require('../src/discord/request-auth');
const {
  sign_discord_attestation,
  verify_discord_attestation
} = require('../src/discord/response-signing');

const now_unix = 1783800000;
const now_ms = now_unix * 1000;
const guild_id = '123456789012345678';
const discord_id = '987654321098765432';
const license_key = 'VALID-LICENSE';
const hwid = 'VALID-HWID';
const issuer = 'auth-server-discord-member-info';
const audience = 'windows-client';
const kid = 'test-es256-key';
const expected_claims = { issuer, audience, kid };

function fake_member(overrides = {}) {
  return {
    user: {
      id: discord_id,
      username: 'discord-user',
      global_name: 'Global name',
      avatar: 'user-avatar'
    },
    nick: 'Guild nickname',
    avatar: 'guild-avatar',
    roles: ['222222222222222222', '333333333333333333'],
    ...overrides
  };
}

function fake_roles() {
  return [
    {
      id: guild_id,
      name: '@everyone',
      position: 0,
      color: 0,
      hoist: false,
      managed: false,
      mentionable: false
    },
    {
      id: '222222222222222222',
      name: 'Premium',
      position: 12,
      color: 16711680,
      hoist: true,
      managed: false,
      mentionable: false
    },
    {
      id: '333333333333333333',
      name: 'Supporter',
      position: 12,
      color: 255,
      hoist: false,
      managed: false,
      mentionable: true
    },
    {
      id: '444444444444444444',
      name: 'Unused',
      position: 99,
      color: 0,
      hoist: false,
      managed: false,
      mentionable: false
    }
  ];
}

function response(status, body, headers = {}) {
  return { status, body, headers };
}

function create_fake_discord(mode = {}) {
  const calls = { members: 0, roles: 0 };
  const fetch_discord = async (request_path) => {
    if (request_path.endsWith('/roles')) {
      calls.roles += 1;

      if (mode.roles_error) {
        return mode.roles_error;
      }

      return response(200, mode.roles || fake_roles());
    }

    calls.members += 1;

    if (mode.member_error) {
      return mode.member_error;
    }

    return response(200, mode.member || fake_member());
  };

  return { fetch_discord, calls };
}

function test_database() {
  return {
    keys: {
      [license_key]: {
        start_unix: now_unix - 300,
        expiry_unix: now_unix + 3600,
        hwid,
        discord_id
      },
      'UNACTIVATED-LICENSE': { start_unix: null, expiry_unix: null, hwid: null },
      'EXPIRED-LICENSE': {
        start_unix: now_unix - 7200,
        expiry_unix: now_unix - 1,
        hwid,
        discord_id
      },
      'PAUSED-LICENSE': {
        start_unix: now_unix - 300,
        expiry_unix: now_unix + 3600,
        hwid,
        discord_id,
        pause_reasons: ['manual']
      }
    }
  };
}

let nonce_counter = 0;
let transport_public_key;

function make_nonce() {
  const nonce = Buffer.alloc(32, nonce_counter++ % 256);
  return nonce.toString('base64url');
}

function make_inner_request(options = {}) {
  const request_license_key = options.license_key || license_key;
  const request_hwid = options.hwid || hwid;
  const request_discord_id = options.discord_id || discord_id;
  const timestamp = options.timestamp === undefined ? now_unix : options.timestamp;
  const nonce = options.nonce || make_nonce();
  const license_hash_value = base64url(license_hash(request_license_key));
  const hwid_hash_value = base64url(hwid_hash(request_hwid));
  const discord_id_hash_value = base64url(discord_id_hash(
    request_discord_id,
    license_hash_value,
    hwid_hash_value,
    nonce,
    timestamp
  ));
  const body = {
    license_hash: license_hash_value,
    hwid_hash: hwid_hash_value,
    discord_id: request_discord_id,
    discord_id_hash: discord_id_hash_value,
    timestamp_unix: timestamp,
    nonce,
    request_mac: ''
  };

  body.request_mac = base64url(hmac_sha256(
    request_auth_key(request_license_key, request_hwid),
    Buffer.from(canonical_request(body), 'utf8')
  ));

  return { ...body, ...options.overrides };
}

function encrypt_request(inner) {
  const pair = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const public_jwk = pair.publicKey.export({ format: 'jwk' });
  const public_blob = Buffer.alloc(72);

  public_blob.writeUInt32LE(cng_ecdh_public_p256_magic, 0);
  public_blob.writeUInt32LE(32, 4);
  Buffer.from(public_jwk.x, 'base64url').copy(public_blob, 8);
  Buffer.from(public_jwk.y, 'base64url').copy(public_blob, 40);

  const shared_secret = crypto.diffieHellman({
    privateKey: pair.privateKey,
    publicKey: transport_public_key
  });

  return {
    outer: {
      e: public_blob.toString('base64url'),
      d: encrypt(
        derive_key('discord-envelope-request:v1', shared_secret),
        Buffer.from(JSON.stringify(inner), 'utf8'),
        Buffer.from('discord-member-info/v2/request', 'utf8')
      )
    },
    inner,
    shared_secret
  };
}

function make_request(options = {}) {
  return encrypt_request(make_inner_request(options));
}

function decrypt_attestation(result, request) {
  assert.equal(typeof result.body.d, 'string');

  const plaintext = decrypt(
    derive_key('discord-envelope-response:v1', request.shared_secret, request.inner.nonce),
    result.body.d,
    Buffer.from('discord-member-info/v2/response', 'utf8')
  );
  assert.ok(plaintext);

  return plaintext.toString('utf8');
}

async function start_route(options) {
  const app = express();
  app.use('/v2/discord/member-info', create_discord_member_router(options));

  const server = await new Promise((resolve) => {
    const instance = app.listen(0, '127.0.0.1', () => resolve(instance));
  });

  return {
    port: server.address().port,
    close: () => new Promise((resolve, reject) => {
      server.close((error) => (error ? reject(error) : resolve()));
    })
  };
}

function post_json(port, body, content_type = 'application/json') {
  const payload = typeof body === 'string' ? body : JSON.stringify(body);

  return new Promise((resolve, reject) => {
    const options = {
      hostname: '127.0.0.1',
      port,
      path: '/v2/discord/member-info',
      method: 'POST',
      headers: {
        'Content-Type': content_type,
        'Content-Length': Buffer.byteLength(payload)
      }
    };
    const request = http.request(options, (response_value) => {
      const chunks = [];

      response_value.on('data', (chunk) => chunks.push(chunk));
      response_value.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf8');
        resolve({
          status: response_value.statusCode,
          headers: response_value.headers,
          body: text ? JSON.parse(text) : null
        });
      });
    });

    request.on('error', reject);
    request.end(payload);
  });
}

async function expect_status(port, body, status) {
  const result = await post_json(port, body && body.outer ? body.outer : body);
  assert.equal(result.status, status, JSON.stringify(result.body));
  return result;
}

async function expect_reject(action) {
  await assert.rejects(action);
}

function route_options(config, service, limiter_options = {}) {
  return {
    load_database: test_database,
    get_config: () => config,
    discord_service: service,
    now: () => now_ms,
    rate_limiter: create_rate_limiter({
      now: () => now_ms,
      ip_limit: 1000,
      license_limit: 1000,
      ...limiter_options
    }),
    replay_cache: create_replay_cache({ now: () => now_ms })
  };
}

async function main() {
  const {
    privateKey: private_key,
    publicKey: public_key
  } = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const transport_pair = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  transport_public_key = transport_pair.publicKey;

  const key_directory = fs.mkdtempSync(path.join(os.tmpdir(), 'discord-member-info-'));
  const private_key_file = path.join(key_directory, 'signing-private-key.pem');
  const transport_key_file = path.join(key_directory, 'transport-private-key.pem');

  fs.writeFileSync(private_key_file, private_key.export({ type: 'pkcs8', format: 'pem' }));
  fs.writeFileSync(
    transport_key_file,
    transport_pair.privateKey.export({ type: 'pkcs8', format: 'pem' })
  );

  const public_key_pem = public_key.export({ type: 'spki', format: 'pem' });
  const config = {
    bot_token: 'test-bot-token-not-a-secret',
    guild_id,
    api_timeout_ms: 5000,
    role_cache_ms: 30000,
    signing_private_key_file: private_key_file,
    transport_private_key_file: transport_key_file,
    signing_key_id: kid,
    signing_issuer: issuer,
    signing_audience: audience
  };
  const fake = create_fake_discord();
  const service = new discord_member_service({
    fetch_discord: fake.fetch_discord,
    now: () => now_ms
  });
  const route = await start_route(route_options(config, service));

  try {
    const unavailable_route = await start_route({
      load_database: test_database,
      get_config: () => ({ guild_id }),
      now: () => now_ms
    });

    try {
      const unavailable = await expect_status(unavailable_route.port, make_request(), 503);
      assert.deepEqual(unavailable.body, {
        success: false,
        error: 'Discord service unavailable'
      });
    } finally {
      await unavailable_route.close();
    }

    let valid = make_request();
    let result = await expect_status(route.port, valid, 200);
    assert.deepEqual(Object.keys(result.body), ['d']);
    assert.equal(JSON.stringify(valid.outer).includes('license_hash'), false);
    assert.equal(JSON.stringify(valid.outer).includes(discord_id), false);
    assert.equal(JSON.stringify(result.body).includes('discord-user'), false);

    const verified = await verify_discord_attestation(
      decrypt_attestation(result, valid),
      public_key_pem,
      expected_claims,
      now_unix
    );
    assert.equal(verified.payload.member, true);
    assert.equal(verified.payload.discord_id, discord_id);
    assert.equal(verified.payload.username, 'discord-user');
    assert.equal(verified.payload.display_name, 'Guild nickname');
    assert.equal(
      verified.payload.pfp_url,
      `https://cdn.discordapp.com/guilds/${guild_id}/users/${discord_id}/avatars/guild-avatar.webp?size=256`
    );
    assert.equal(verified.payload.roles.length, 2);
    assert.equal(verified.payload.roles[0].id, '333333333333333333');
    assert.equal(verified.payload.highest_role.id, '333333333333333333');

    await expect_status(route.port, { ...make_request().outer, unexpected: true }, 400);
    await expect_status(
      route.port,
      make_request({ overrides: { discord_id: 123456789012345678 } }),
      400
    );
    await expect_status(route.port, make_request({ overrides: { discord_id: '1234abc' } }), 400);
    await expect_status(
      route.port,
      make_request({ overrides: { license_hash: 'not-base64url' } }),
      400
    );
    await expect_status(
      route.port,
      make_request({ overrides: { hwid_hash: Buffer.alloc(31).toString('base64url') } }),
      400
    );
    await expect_status(
      route.port,
      make_request({ overrides: { request_mac: Buffer.alloc(33).toString('base64url') } }),
      400
    );

    const tampered_envelope = make_request();
    const first = tampered_envelope.outer.d.startsWith('A') ? 'B' : 'A';
    tampered_envelope.outer.d = `${first}${tampered_envelope.outer.d.slice(1)}`;
    await expect_status(route.port, tampered_envelope, 401);
    await expect_status(route.port, make_request({ timestamp: now_unix - 61 }), 401);
    await expect_status(route.port, make_request({ timestamp: now_unix + 61 }), 401);

    const missing_nonce = make_inner_request();
    delete missing_nonce.nonce;
    await expect_status(route.port, encrypt_request(missing_nonce), 400);
    await expect_status(
      route.port,
      make_request({ overrides: { request_mac: Buffer.alloc(32).toString('base64url') } }),
      401
    );
    await expect_status(route.port, '{', 400);

    valid = make_request();
    await expect_status(route.port, valid, 200);
    await expect_status(route.port, valid, 401);
    await expect_status(route.port, make_request({ license_key: 'UNKNOWN-LICENSE' }), 401);
    await expect_status(route.port, make_request({ hwid: 'WRONG-HWID' }), 401);
    await expect_status(
      route.port,
      make_request({ license_key: 'UNACTIVATED-LICENSE', hwid: 'UNACTIVATED-HWID' }),
      401
    );
    await expect_status(route.port, make_request({ license_key: 'EXPIRED-LICENSE' }), 401);
    await expect_status(route.port, make_request({ license_key: 'PAUSED-LICENSE' }), 401);
    await expect_status(route.port, make_request({ discord_id: '111111111111111111' }), 401);

    const original_inner = make_inner_request();
    await expect_status(
      route.port,
      encrypt_request({ ...original_inner, discord_id: '111111111111111111' }),
      401
    );
    await expect_status(
      route.port,
      encrypt_request({ ...original_inner, nonce: make_nonce() }),
      401
    );
    await expect_status(
      route.port,
      encrypt_request({ ...original_inner, timestamp_unix: now_unix + 1 }),
      401
    );
    await expect_status(
      route.port,
      encrypt_request({ ...original_inner, discord_id_hash: make_nonce() }),
      401
    );

    const original_timing_safe_equal = crypto.timingSafeEqual;
    let timing_safe_calls = 0;

    crypto.timingSafeEqual = (...args) => {
      timing_safe_calls += 1;
      return original_timing_safe_equal(...args);
    };

    try {
      await expect_status(route.port, make_request(), 200);
    } finally {
      crypto.timingSafeEqual = original_timing_safe_equal;
    }
    assert.ok(timing_safe_calls >= 4);

    const absent_service = new discord_member_service({
      now: () => now_ms,
      fetch_discord: async () => response(404, { code: 10007 })
    });
    const absent_route = await start_route(route_options(config, absent_service));

    try {
      const absent_request = make_request();
      result = await expect_status(absent_route.port, absent_request, 200);

      const absent = await verify_discord_attestation(
        decrypt_attestation(result, absent_request),
        public_key_pem,
        expected_claims,
        now_unix
      );
      assert.equal(absent.payload.member, false);
      assert.deepEqual(absent.payload.roles, []);
      assert.equal(absent.payload.highest_role, null);
      assert.equal(absent.payload.pfp_url, null);
    } finally {
      await absent_route.close();
    }

    const mapping_fake = create_fake_discord();
    const mapping_service = new discord_member_service({
      fetch_discord: mapping_fake.fetch_discord,
      now: () => now_ms
    });
    let profile = await mapping_service.get_member_profile(config, discord_id);
    assert.equal(profile.display_name, 'Guild nickname');
    assert.equal(profile.global_display_name, 'Global name');
    assert.equal(profile.roles[0].id, '333333333333333333');
    assert.equal(profile.highest_role.id, '333333333333333333');

    await mapping_service.get_member_profile(config, discord_id);
    assert.equal(mapping_fake.calls.roles, 1);

    const global_fallback = new discord_member_service({
      fetch_discord: create_fake_discord({
        member: fake_member({ nick: null, avatar: null })
      }).fetch_discord,
      now: () => now_ms
    });
    profile = await global_fallback.get_member_profile(config, discord_id);
    assert.equal(profile.display_name, 'Global name');
    assert.equal(
      profile.pfp_url,
      `https://cdn.discordapp.com/avatars/${discord_id}/user-avatar.webp?size=256`
    );

    const username_fallback = new discord_member_service({
      fetch_discord: create_fake_discord({
        member: fake_member({
          nick: null,
          avatar: null,
          user: { id: discord_id, username: 'discord-user', global_name: null, avatar: null }
        })
      }).fetch_discord,
      now: () => now_ms
    });
    profile = await username_fallback.get_member_profile(config, discord_id);
    assert.equal(profile.display_name, 'discord-user');
    assert.equal(profile.global_display_name, 'discord-user');
    assert.equal(profile.pfp_url, default_avatar_url(discord_id));

    const no_roles = new discord_member_service({
      fetch_discord: create_fake_discord({ member: fake_member({ roles: [] }) }).fetch_discord,
      now: () => now_ms
    });
    profile = await no_roles.get_member_profile(config, discord_id);
    assert.deepEqual(profile.roles, []);
    assert.equal(profile.highest_role, null);

    const failure_modes = [
      {
        member_error: response(429, { retry_after: 1 }, { 'retry-after': '3' }),
        expected: 429
      },
      {
        member_error: response(500, { message: 'server error' }),
        expected: 503
      },
      {
        member_error: response(200, {
          user: { id: '111111111111111111', username: 'bad' },
          roles: []
        }),
        expected: 503
      },
      {
        roles_error: response(200, { not: 'an array' }),
        expected: 503
      }
    ];

    for (const mode of failure_modes) {
      const failure_service = new discord_member_service({
        fetch_discord: create_fake_discord(mode).fetch_discord,
        now: () => now_ms
      });
      const failure_route = await start_route(route_options(config, failure_service));

      try {
        result = await expect_status(failure_route.port, make_request(), mode.expected);
        assert.equal(result.body.d, undefined);

        if (mode.expected === 429) {
          assert.equal(result.headers['retry-after'], '3');
        }
      } finally {
        await failure_route.close();
      }
    }

    const timeout_service = new discord_member_service({
      fetch_discord: async () => {
        throw new discord_api_error('timeout');
      },
      now: () => now_ms
    });
    const timeout_route = await start_route(route_options(config, timeout_service));

    try {
      result = await expect_status(timeout_route.port, make_request(), 503);
      assert.equal(result.body.d, undefined);
    } finally {
      await timeout_route.close();
    }

    const signature_request = make_request();
    result = await expect_status(route.port, signature_request, 200);
    const token_parts = decrypt_attestation(result, signature_request).split('.');

    const changed_payload = [...token_parts];
    const last = changed_payload[1].endsWith('A') ? 'B' : 'A';
    changed_payload[1] = `${changed_payload[1].slice(0, -1)}${last}`;
    await expect_reject(() => verify_discord_attestation(
      changed_payload.join('.'),
      public_key_pem,
      expected_claims,
      now_unix
    ));

    const changed_signature = [...token_parts];
    const lead = changed_signature[2].startsWith('A') ? 'B' : 'A';
    changed_signature[2] = `${lead}${changed_signature[2].slice(1)}`;
    await expect_reject(() => verify_discord_attestation(
      changed_signature.join('.'),
      public_key_pem,
      expected_claims,
      now_unix
    ));

    const changed_header = [...token_parts];
    const header = JSON.parse(Buffer.from(changed_header[0], 'base64url').toString('utf8'));
    header.alg = 'none';
    changed_header[0] = Buffer.from(JSON.stringify(header)).toString('base64url');
    await expect_reject(() => verify_discord_attestation(
      changed_header.join('.'),
      public_key_pem,
      expected_claims,
      now_unix
    ));

    const jose = await import('jose');
    const signing_key = await jose.importPKCS8(fs.readFileSync(private_key_file, 'utf8'), 'ES256');
    const base_verified = await verify_discord_attestation(
      token_parts.join('.'),
      public_key_pem,
      expected_claims,
      now_unix
    );
    const base_claims = { ...base_verified.payload };

    async function signed_variant(claims, protected_header = {}) {
      return new jose.SignJWT(claims)
        .setProtectedHeader({
          alg: 'ES256',
          kid,
          typ: 'discord-member-info+jwt',
          ...protected_header
        })
        .setIssuer(claims.iss || issuer)
        .setAudience(claims.aud || audience)
        .setSubject(claims.sub || `discord:${discord_id}`)
        .setIssuedAt(claims.iat || now_unix)
        .setNotBefore(claims.nbf || now_unix - 5)
        .setExpirationTime(claims.exp || now_unix + 60)
        .setJti('test-jti')
        .sign(signing_key);
    }

    const variants = [
      [base_claims, { typ: 'wrong' }, expected_claims],
      [base_claims, { kid: 'wrong' }, expected_claims],
      [{ ...base_claims, iss: 'wrong' }, {}, expected_claims],
      [{ ...base_claims, aud: 'wrong' }, {}, expected_claims],
      [{ ...base_claims, exp: now_unix - 1 }, {}, expected_claims],
      [{ ...base_claims, nbf: now_unix + 1 }, {}, expected_claims]
    ];

    for (const [claims, header_override, expected] of variants) {
      await expect_reject(() => {
        return signed_variant(claims, header_override).then((token) => {
          return verify_discord_attestation(token, public_key_pem, expected, now_unix);
        });
      });
    }

    for (const field of ['nonce', 'discord_id', 'license_hash', 'hwid_hash', 'request_hash']) {
      const variant = await signed_variant({ ...base_claims, [field]: 'changed' });
      await expect_reject(() => verify_discord_attestation(variant, public_key_pem, {
        issuer,
        audience,
        kid,
        claims: { [field]: base_claims[field] }
      }, now_unix));
    }

    const limited_service = new discord_member_service({
      fetch_discord: fake.fetch_discord,
      now: () => now_ms
    });
    const limited = await start_route(route_options(config, limited_service, {
      ip_limit: 1,
      license_limit: 1,
      max_entries: 2
    }));

    try {
      await expect_status(limited.port, make_request(), 200);
      result = await expect_status(limited.port, make_request(), 429);
      assert.equal(result.headers['retry-after'], '60');
    } finally {
      await limited.close();
    }

    console.log('Discord member-info tests passed.');
  } finally {
    await route.close();
    fs.rmSync(key_directory, { recursive: true, force: true });
  }
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
