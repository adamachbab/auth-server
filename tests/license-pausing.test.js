const assert = require('assert/strict');
const test = require('node:test');
const {
  is_license_paused,
  pause_all,
  pause_license,
  remaining_seconds,
  resume_all,
  resume_license
} = require('../src/lib/license-state');

test('overlapping pause reasons freeze time until the final reason is removed', () => {
  const license = {
    start_unix: 100,
    expiry_unix: 1100,
    pause_reasons: [],
    pause_started_at: null
  };
  const db = {
    keys: { TEST: license },
    service_state: { keys_paused: false, keys_paused_at: null }
  };

  assert.equal(pause_license(license, 'user-self', 200), true);
  assert.equal(remaining_seconds(license, 350), 900);
  assert.equal(pause_all(db, 300), 1);
  assert.equal(is_license_paused(db, license), true);

  assert.equal(resume_license(license, 'user-self', 400), true);
  assert.equal(license.expiry_unix, 1100, 'time is not restored while the global reason remains');
  assert.equal(resume_all(db, 500), 1);
  assert.equal(license.expiry_unix, 1400, 'all frozen time is restored exactly once');
  assert.equal(is_license_paused(db, license), false);
  assert.equal(remaining_seconds(license, 500), 900);
});
