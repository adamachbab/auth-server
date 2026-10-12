const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { create_store } = require('../src/lib/data-store');

test('Discord-generated licenses survive datastore and process recreation', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'auth-persistence-'));
  const filename = path.join(directory, 'database.json');

  try {
    const generated_key = 'PERSIST-RESTART-TEST-KEY';
    const first_process = create_store(filename);
    first_process.initialize();
    first_process.transaction((db) => {
      db.keys[generated_key] = {
        duration_seconds: 86400,
        start_unix: null,
        expiry_unix: null,
        hwid: null,
        created_at: 1,
        pause_reasons: [],
        pause_started_at: null
      };
    });

    const restarted_process = create_store(filename);
    const persisted = restarted_process.read().keys[generated_key];
    assert.ok(persisted);
    assert.equal(persisted.duration_seconds, 86400);

    restarted_process.transaction((db) => {
      db.keys[generated_key].start_unix = 100;
      db.keys[generated_key].expiry_unix = 86500;
      db.keys[generated_key].hwid = 'stable-volume-id';
    });

    const second_restart = create_store(filename).read().keys[generated_key];
    assert.equal(second_restart.hwid, 'stable-volume-id');
    assert.equal(second_restart.expiry_unix, 86500);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('startup, migration checks, and no-op transactions do not rewrite an unchanged database', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'auth-no-rewrite-'));
  const filename = path.join(directory, 'database.json');

  try {
    const store = create_store(filename);
    store.initialize();
    store.transaction((db) => {
      db.keys['UNCHANGED-KEY'] = {
        duration_seconds: 86400,
        start_unix: null,
        expiry_unix: null,
        hwid: null,
        created_at: 1,
        pause_reasons: [],
        pause_started_at: null
      };
    });

    const old_time = new Date('2001-01-01T00:00:00.000Z');
    fs.utimesSync(filename, old_time, old_time);
    const before = fs.readFileSync(filename, 'utf8');
    const modified_before = fs.statSync(filename).mtimeMs;

    create_store(filename).initialize();
    create_store(filename).transaction(() => {});

    assert.equal(fs.readFileSync(filename, 'utf8'), before);
    assert.equal(fs.statSync(filename).mtimeMs, modified_before);
    assert.ok(create_store(filename).read().keys['UNCHANGED-KEY']);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('a missing production datastore fails instead of restoring an empty example-shaped database', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'auth-missing-production-db-'));
  const filename = path.join(directory, 'database.json');

  try {
    const store = create_store(filename, { allow_create: false });
    assert.throws(() => store.initialize(), (error) => error?.code === 'ENOENT');
    assert.equal(fs.existsSync(filename), false);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});
