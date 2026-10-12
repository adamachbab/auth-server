module.exports = {
  version: 2,
  description: 'Add accounts, sessions, device authorization, ledgers, and audit events.',
  up(db) {
    const object_fields = [
      'users',
      'sessions',
      'device_authorizations',
      'device_credentials',
      'account_license_links'
    ];

    for (const field of object_fields) {
      if (!db[field] || typeof db[field] !== 'object' || Array.isArray(db[field])) {
        db[field] = {};
      }
    }

    for (const field of ['subscription_ledger', 'audit_events']) {
      if (!Array.isArray(db[field])) {
        db[field] = [];
      }
    }
  }
};
