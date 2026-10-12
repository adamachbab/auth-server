const assert = require('assert/strict');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const test = require('node:test');

const { create_store } = require('../src/lib/data-store');
const {
  command_definitions,
  handle_command,
  is_admin,
  issue_pairing_code,
  start_discord_presence,
  validate_discord_application_configuration,
  verify_interaction
} = require('../src/discord/bot');

const user_id = '111111111111111111';
const admin_id = '222222222222222222';
const guild_id = '444444444444444444';
const role_id = '555555555555555555';

process.env.AUTH_DISCORD_ADMIN_USER_IDS = admin_id;

function interaction(name, options = [], admin = false, member_id = user_id) {
  return {
    data: { name, options },
    member: {
      permissions: admin ? '8' : '0',
      roles: [],
      user: {
        id: member_id,
        username: `user-${member_id.slice(-4)}`,
        global_name: 'Test User',
        avatar: null
      }
    }
  };
}

function dm_interaction(name, options = [], member_id = user_id) {
  return {
    data: { name, options },
    user: {
      id: member_id,
      username: `user-${member_id.slice(-4)}`,
      global_name: 'DM User',
      avatar: null
    }
  };
}

function content(result) {
  return result.data.content;
}

function option(name, value) {
  return { name, value };
}

function restore_env(name, value) {
  if (value === undefined) {
    delete process.env[name];
  } else {
    process.env[name] = value;
  }
}

test('Discord Gateway presence safely stays disabled without a bot token', async () => {
  const previous = process.env.AUTH_DISCORD_BOT_TOKEN;

  try {
    delete process.env.AUTH_DISCORD_BOT_TOKEN;
    assert.equal(await start_discord_presence(), null);
  } finally {
    restore_env('AUTH_DISCORD_BOT_TOKEN', previous);
  }
});

test('Discord startup preflight catches mismatched application credentials and endpoints', () => {
  const app_id = '123456789012345678';
  const public_key = 'ab'.repeat(32);
  const valid = {
    id: app_id,
    name: 'Helper',
    verify_key: public_key,
    interactions_endpoint_url: 'https://auth.example.com/api/discord/interactions'
  };

  assert.doesNotThrow(() => {
    validate_discord_application_configuration(valid, app_id, public_key);
  });
  assert.throws(
    () => validate_discord_application_configuration(
      { ...valid, verify_key: 'cd'.repeat(32) },
      app_id,
      public_key
    ),
    /PUBLIC_KEY/
  );
  assert.throws(
    () => validate_discord_application_configuration(
      { ...valid, interactions_endpoint_url: 'https://auth.example.com/wrong' },
      app_id,
      public_key
    ),
    /Endpoint URL/
  );
});

test('Administrator permission in a foreign guild does not grant bot admin', () => {
  const previous_guild = process.env.AUTH_DISCORD_GUILD_ID;
  const previous_roles = process.env.AUTH_DISCORD_ADMIN_ROLE_IDS;

  try {
    process.env.AUTH_DISCORD_GUILD_ID = guild_id;
    process.env.AUTH_DISCORD_ADMIN_ROLE_IDS = role_id;

    assert.equal(
      is_admin({ ...interaction('list', [], true), guild_id: '999999999999999999' }),
      false
    );
    assert.equal(is_admin({ ...interaction('list', [], true), guild_id }), false);

    const role_member = interaction('list');
    role_member.member.roles = [role_id];
    assert.equal(is_admin({ ...role_member, guild_id }), true);
    assert.equal(is_admin({ ...role_member, guild_id: '999999999999999999' }), false);
  } finally {
    restore_env('AUTH_DISCORD_GUILD_ID', previous_guild);
    restore_env('AUTH_DISCORD_ADMIN_ROLE_IDS', previous_roles);
  }
});

test('Discord pairing, status, time, and HWID approval workflows are authorized and audited', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'auth-discord-bot-'));

  try {
    const store = create_store(path.join(directory, 'database.json'));
    store.initialize();
    const now = Math.floor(Date.now() / 1000);

    store.transaction((db) => {
      db.keys['LICENSE-PAIR-001'] = {
        duration_seconds: 86400,
        start_unix: now,
        expiry_unix: now + 86400,
        hwid: 'BOUND-HWID',
        client_public_key: 'bound-device-key',
        created_at: now
      };
    });

    let pairing;
    store.transaction((db) => {
      pairing = issue_pairing_code(db, 'LICENSE-PAIR-001');
    });
    assert.match(pairing.code, /^[A-Z2-9]{4}-[A-Z2-9]{4}-[A-Z2-9]{4}$/);
    assert.ok(pairing.expires_in <= 15 * 60);
    assert.ok(
      Object.values(store.read().discord_pairing_codes)
        .every((record) => record.code === undefined),
      'pairing codes are stored only as digests'
    );

    const services = { store };
    const paired = handle_command(interaction('pair', [option('code', pairing.code)]), services);
    assert.match(content(paired), /Linked license/);
    assert.equal(store.read().keys['LICENSE-PAIR-001'].discord_id, user_id);

    const replay = handle_command(interaction('pair', [option('code', pairing.code)]), services);
    assert.match(content(replay), /invalid or expired/);

    const status = handle_command(interaction('key-status'), services);
    assert.match(content(status), /LICE…-001/);
    assert.doesNotMatch(content(status), /LICENSE-PAIR-001/);
    assert.match(content(status), /HWID bound/);

    const request = handle_command(
      interaction('hwid-reset-request', [option('reason', 'Replaced motherboard')]),
      services
    );
    const request_id = content(request).match(/[A-F0-9]{12}/)?.[0];
    assert.ok(request_id);

    const time_options = [
      option('user', user_id),
      option('days', 2),
      option('reason', 'Support extension')
    ];
    const denied_admin_action = handle_command(
      interaction('admin-time', time_options, true),
      services
    );
    assert.match(content(denied_admin_action), /Administrator permission/);

    const previous_expiry = store.read().keys['LICENSE-PAIR-001'].expiry_unix;
    const adjusted = handle_command(
      interaction('admin-time', time_options, true, admin_id),
      services
    );
    assert.match(content(adjusted), /Updated 1 license/);
    assert.equal(
      store.read().keys['LICENSE-PAIR-001'].expiry_unix,
      previous_expiry + 2 * 86400
    );

    const approved = handle_command(
      interaction('admin-reset-review', [
        option('request', request_id),
        option('decision', 'approve'),
        option('reason', 'Verified replacement')
      ], true, admin_id),
      services
    );
    assert.match(content(approved), /reset 1 HWID/);

    const database = store.read();
    assert.equal(database.keys['LICENSE-PAIR-001'].hwid, null);
    assert.equal(database.keys['LICENSE-PAIR-001'].client_public_key, null);
    assert.equal(database.hwid_reset_requests[request_id].status, 'approved');
    assert.ok(database.audit_events.some((entry) => entry.action === 'discord.pair'));
    assert.ok(database.audit_events.some((entry) => entry.action === 'hwid_reset.approved'));
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('Discord interaction verification rejects tampering and stale requests', () => {
  const { publicKey: public_key, privateKey: private_key } = crypto.generateKeyPairSync('ed25519');
  const raw_public_key = public_key
    .export({ format: 'der', type: 'spki' })
    .subarray(-32)
    .toString('hex');
  const body = Buffer.from(JSON.stringify({ type: 1 }));
  const timestamp = String(Math.floor(Date.now() / 1000));
  const signature = crypto
    .sign(null, Buffer.concat([Buffer.from(timestamp), body]), private_key)
    .toString('hex');
  const previous = process.env.AUTH_DISCORD_PUBLIC_KEY;

  process.env.AUTH_DISCORD_PUBLIC_KEY = raw_public_key;

  try {
    const request = {
      body,
      get: (name) => (name === 'x-signature-ed25519' ? signature : timestamp)
    };
    assert.equal(verify_interaction(request), true);
    assert.equal(verify_interaction({ ...request, body: Buffer.from('{}') }), false);

    const stale = String(Math.floor(Date.now() / 1000) - 301);
    const stale_signature = crypto
      .sign(null, Buffer.concat([Buffer.from(stale), body]), private_key)
      .toString('hex');
    assert.equal(
      verify_interaction({
        body,
        get: (name) => (name === 'x-signature-ed25519' ? stale_signature : stale)
      }),
      false
    );
  } finally {
    restore_env('AUTH_DISCORD_PUBLIC_KEY', previous);
  }
});

test('requested key-management commands generate and compose pause controls', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'auth-discord-admin-'));

  try {
    const store = create_store(path.join(directory, 'database.json'));
    store.initialize();
    const services = { store };
    const admin_command = (name, options = []) => {
      return handle_command(interaction(name, options, true, admin_id), services);
    };

    const generated = admin_command('generate', [option('length', 2), option('unit', 'days')]);
    const key = content(generated).match(/AUTH-[A-Z2-9-]+/)?.[0];
    assert.ok(key);
    assert.equal(store.read().keys[key].duration_seconds, 2 * 86400);
    assert.match(content(admin_command('list')), /AUTH…[A-Z2-9]{4}/);

    assert.match(content(admin_command('pause_key', [option('key', key)])), /Paused/);
    assert.deepEqual(store.read().keys[key].pause_reasons, ['key-admin']);
    assert.match(content(admin_command('pause_keys')), /Global freeze enabled/);
    assert.deepEqual(
      new Set(store.read().keys[key].pause_reasons),
      new Set(['key-admin', 'global'])
    );
    assert.match(content(admin_command('resume_keys')), /Global freeze removed/);
    assert.deepEqual(
      store.read().keys[key].pause_reasons,
      ['key-admin'],
      'global resume does not bypass a key pause'
    );
    assert.match(content(admin_command('resume_key', [option('key', key)])), /Resumed/);
    assert.deepEqual(store.read().keys[key].pause_reasons, []);

    const names = new Set(command_definitions().map((command) => command.name));
    const expected = [
      'generate',
      'list',
      'reset_user',
      'reset_key',
      'pause_keys',
      'resume_keys',
      'pause_key',
      'resume_key',
      'pause_user',
      'resume_user',
      'link',
      'request_hwid_reset',
      'time_left',
      'pause_subscription',
      'unpause_subscription',
      'pair'
    ];

    for (const name of expected) {
      assert.ok(names.has(name), name);
    }
    assert.equal(names.has('modules'), false);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('configured administrator user IDs authorize commands outside a guild', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'auth-discord-dm-admin-'));

  try {
    const store = create_store(path.join(directory, 'database.json'));
    store.initialize();
    const services = { store };
    const options = [option('length', 1), option('unit', 'hours')];

    const allowed = handle_command(dm_interaction('generate', options, admin_id), services);
    assert.match(content(allowed), /Generated 1 hours/);

    const denied = handle_command(dm_interaction('generate', options, user_id), services);
    assert.match(content(denied), /Administrator permission/);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});
