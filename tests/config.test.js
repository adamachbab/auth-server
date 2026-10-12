const assert = require('assert/strict');
const { spawnSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const test = require('node:test');

const { load_configuration, parse_env } = require('../src/lib/config');
const { empty_database } = require('../src/lib/data-store');

const project_root = path.join(__dirname, '..');

function run_node(arguments_, environment) {
  return spawnSync(process.execPath, arguments_, {
    cwd: project_root,
    env: { ...process.env, ...environment },
    encoding: 'utf8'
  });
}

test('simple .env values load once and map friendly Discord names', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'auth-config-'));
  const filename = path.join(directory, '.env');

  fs.writeFileSync(filename, [
    '# mock configuration',
    'DISCORD_BOT_TOKEN="mock.bot.token"',
    'DISCORD_CLIENT_ID=123456789012345678',
    'DISCORD_PUBLIC_KEY=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    'DISCORD_GUILD_ID=234567890123456789',
    'DISCORD_ADMIN_ROLE_IDS=345678901234567890,456789012345678901',
    'DISCORD_ADMIN_USER_IDS=222222222222222222',
    'ADMIN_EMAIL=mock-admin@example.com',
    'ADMIN_PASSWORD="Mock password 42!"'
  ].join('\n'));

  const names = [
    'DISCORD_BOT_TOKEN',
    'DISCORD_CLIENT_ID',
    'DISCORD_PUBLIC_KEY',
    'DISCORD_GUILD_ID',
    'DISCORD_ADMIN_ROLE_IDS',
    'DISCORD_ADMIN_USER_IDS',
    'AUTH_DISCORD_BOT_TOKEN',
    'AUTH_DISCORD_APP_ID',
    'AUTH_DISCORD_PUBLIC_KEY',
    'AUTH_DISCORD_GUILD_ID',
    'AUTH_DISCORD_ADMIN_ROLE_IDS',
    'AUTH_DISCORD_ADMIN_USER_IDS',
    'ADMIN_EMAIL',
    'ADMIN_PASSWORD'
  ];
  const previous = Object.fromEntries(names.map((name) => [name, process.env[name]]));

  for (const name of names) {
    delete process.env[name];
  }

  try {
    load_configuration(filename);
    assert.equal(process.env.AUTH_DISCORD_BOT_TOKEN, 'mock.bot.token');
    assert.equal(process.env.AUTH_DISCORD_APP_ID, '123456789012345678');
    assert.equal(
      process.env.AUTH_DISCORD_ADMIN_ROLE_IDS,
      '345678901234567890,456789012345678901'
    );
    assert.equal(process.env.AUTH_DISCORD_ADMIN_USER_IDS, '222222222222222222');
    assert.equal(process.env.ADMIN_EMAIL, 'mock-admin@example.com');

    process.env.DISCORD_BOT_TOKEN = 'real-environment-wins';
    load_configuration(filename);
    assert.equal(process.env.DISCORD_BOT_TOKEN, 'real-environment-wins');
  } finally {
    for (const name of names) {
      if (previous[name] === undefined) {
        delete process.env[name];
      } else {
        process.env[name] = previous[name];
      }
    }
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('env parser supports comments and quoted mock values', () => {
  const parsed = parse_env("ONE=value # comment\nTWO='two words'\nTHREE=\"line\\nvalue\"\n");

  assert.deepEqual(parsed, {
    ONE: 'value',
    TWO: 'two words',
    THREE: 'line\nvalue'
  });
});

test('manual server startup requires one absolute persistent database path', () => {
  const environment = { ...process.env };
  delete environment.DATABASE_PATH;

  const missing = spawnSync(process.execPath, ['server.js'], {
    cwd: project_root,
    env: environment,
    encoding: 'utf8'
  });
  assert.notEqual(missing.status, 0);
  assert.match(missing.stderr, /DATABASE_PATH is required/);

  const relative = run_node(['server.js'], { DATABASE_PATH: 'database.json' });
  assert.notEqual(relative.status, 0);
  assert.match(relative.stderr, /DATABASE_PATH must be absolute/);
});

test('configured database fails closed when missing and preserves keys across process restarts', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'auth-persistence-'));
  const database_path = path.join(directory, 'database.json');

  try {
    const absent = run_node(['server.js'], { DATABASE_PATH: database_path });
    assert.notEqual(absent.status, 0);
    assert.equal(
      fs.existsSync(database_path),
      false,
      'server startup must not create a replacement database'
    );

    const database = empty_database();
    database.keys['PERSISTENT-KEY'] = {
      duration_seconds: 3600,
      start_unix: 1,
      expiry_unix: 4102444800,
      hwid: 'HWID',
      created_at: 1
    };
    fs.writeFileSync(database_path, `${JSON.stringify(database, null, 2)}\n`);

    const verify = [
      "const { load_database } = require('./server');",
      "if (!load_database().keys['PERSISTENT-KEY']) process.exit(2);"
    ].join(' ');

    assert.equal(run_node(['-e', verify], { DATABASE_PATH: database_path }).status, 0);
    assert.equal(
      run_node(['-e', verify], { DATABASE_PATH: database_path }).status,
      0,
      'the same key must remain available after a fresh server process starts'
    );
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});
