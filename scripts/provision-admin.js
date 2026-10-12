const { create_store } = require('../src/lib/data-store');
const {
  hash_password,
  normalize_email,
  random_token,
  validate_password
} = require('../src/lib/security');
const crypto = require('crypto');
const path = require('path');

require('../src/lib/config').load_configuration();

async function main() {
  const email = normalize_email(process.env.ADMIN_EMAIL || process.argv[2]);
  const password = process.env.ADMIN_PASSWORD || process.env.AUTH_PROVISION_PASSWORD;

  if (!email || !validate_password(password) || /^CHANGE_ME/i.test(password)) {
    throw new Error('Set ADMIN_EMAIL and a unique ADMIN_PASSWORD in .env, then run: npm run setup');
  }

  const database_path = process.env.DATABASE_PATH
    ? path.resolve(process.env.DATABASE_PATH)
    : path.join(__dirname, '..', 'database.json');
  const store = create_store(database_path);
  const password_hash = await hash_password(password);
  let outcome = 'created';

  store.transaction((db) => {
    const now = Math.floor(Date.now() / 1000);
    const existing = Object.values(db.users).find((user) => user.email === email);

    if (existing) {
      existing.role = 'admin';
      existing.status = 'active';
      existing.password_hash = password_hash;
      existing.failed_logins = 0;
      existing.locked_until = 0;
      existing.updated_at = now;

      for (const session of Object.values(db.sessions || {})) {
        if (session.user_id === existing.id) {
          session.revoked_at = now;
        }
      }

      for (const credential of Object.values(db.device_credentials || {})) {
        if (credential.user_id === existing.id) {
          credential.revoked_at = now;
        }
      }

      outcome = 'updated (all previous sessions and device credentials revoked)';
      return;
    }

    const id = crypto.randomUUID();

    db.users[id] = {
      id,
      admin_ref: random_token(18),
      email,
      password_hash,
      role: 'admin',
      status: 'active',
      email_verified: false,
      failed_logins: 0,
      locked_until: 0,
      created_at: now,
      updated_at: now
    };
  });

  console.log(
    `Administrator ${outcome}: ${email}. Clear ADMIN_PASSWORD from .env now; the database retains only its password hash.`
  );
}

main().catch((error) => {
  console.error(error.message);
  process.exitCode = 1;
});
