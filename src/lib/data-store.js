const fs = require('fs');
const path = require('path');

const migrations = [
  require('../../migrations/001-initialize-legacy'),
  require('../../migrations/002-accounts-devices-admin'),
  require('../../migrations/003-discord-bot-workflows'),
  require('../../migrations/004-license-pausing'),
  require('../../migrations/005-resellers')
];

const current_schema_version = 5;

function empty_database() {
  return {
    schema_version: current_schema_version,
    keys: {},
    users: {},
    sessions: {},
    device_authorizations: {},
    device_credentials: {},
    account_license_links: {},
    subscription_ledger: [],
    audit_events: [],
    discord_pairing_codes: {},
    hwid_reset_requests: {},
    resellers: {},
    reseller_ledger: [],
    service_state: {
      keys_paused: false,
      keys_paused_at: null
    }
  };
}

function migrate(database) {
  const db = database && typeof database === 'object' && !Array.isArray(database)
    ? database
    : {};

  if (!Number.isSafeInteger(db.schema_version)) {
    db.schema_version = 0;
  }

  for (const migration of migrations) {
    if (db.schema_version < migration.version) {
      migration.up(db);
      db.schema_version = migration.version;
    }
  }

  if (db.schema_version !== current_schema_version) {
    throw new Error(`Unsupported database schema ${db.schema_version}`);
  }

  return db;
}

function create_store(filename, options = {}) {
  const database_path = path.resolve(filename);
  const allow_create = options.allow_create !== false;
  let committing = false;

  function read() {
    try {
      return migrate(JSON.parse(fs.readFileSync(database_path, 'utf8')));
    } catch (error) {
      if (error.code === 'ENOENT' && allow_create) {
        return empty_database();
      }

      throw error;
    }
  }

  function write(database) {
    fs.mkdirSync(path.dirname(database_path), { recursive: true });

    const payload = `${JSON.stringify(migrate(database), null, 2)}\n`;
    const temporary = `${database_path}.${process.pid}.${Date.now()}.tmp`;

    try {
      try {
        if (fs.readFileSync(database_path, 'utf8') === payload) {
          return true;
        }
      } catch (error) {
        if (error.code !== 'ENOENT') {
          throw error;
        }
      }

      fs.writeFileSync(temporary, payload, {
        encoding: 'utf8',
        mode: 0o600,
        flag: 'wx'
      });
      fs.renameSync(temporary, database_path);

      return true;
    } catch (error) {
      try {
        fs.unlinkSync(temporary);
      } catch {}

      console.error('[DB] Atomic commit failed:', error.message);
      return false;
    }
  }

  function transaction(callback) {
    if (committing) {
      throw new Error('Nested database transactions are not supported');
    }

    committing = true;

    try {
      const database = read();
      const result = callback(database);

      if (result && typeof result.then === 'function') {
        throw new Error('Database transaction callbacks must be synchronous');
      }

      if (!write(database)) {
        throw new Error('Database commit failed');
      }

      return result;
    } finally {
      committing = false;
    }
  }

  function initialize() {
    const database = read();

    if (
      !fs.existsSync(database_path) ||
      database.schema_version !== JSON.parse(fs.readFileSync(database_path, 'utf8')).schema_version
    ) {
      write(database);
    }

    return database;
  }

  return {
    database_path,
    initialize,
    read,
    transaction,
    write
  };
}

module.exports = {
  current_schema_version,
  create_store,
  empty_database,
  migrate
};
