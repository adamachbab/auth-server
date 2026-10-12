function now_unix() {
  return Math.floor(Date.now() / 1000);
}

function reasons(license) {
  return Array.isArray(license?.pause_reasons) ? license.pause_reasons : [];
}

function is_license_paused(db, license) {
  return Boolean(db?.service_state?.keys_paused) || reasons(license).length > 0;
}

function pause_license(license, reason, current = now_unix()) {
  if (!license || typeof reason !== 'string' || !reason) {
    return false;
  }

  if (!Array.isArray(license.pause_reasons)) {
    license.pause_reasons = [];
  }

  if (license.pause_reasons.includes(reason)) {
    return false;
  }

  if (!license.pause_reasons.length) {
    license.pause_started_at = current;
  }

  license.pause_reasons.push(reason);
  return true;
}

function resume_license(license, reason, current = now_unix()) {
  if (
    !license ||
    !Array.isArray(license.pause_reasons) ||
    !license.pause_reasons.includes(reason)
  ) {
    return false;
  }

  license.pause_reasons = license.pause_reasons.filter((value) => value !== reason);

  if (!license.pause_reasons.length) {
    if (
      Number.isSafeInteger(license.start_unix) &&
      Number.isSafeInteger(license.expiry_unix) &&
      Number.isSafeInteger(license.pause_started_at)
    ) {
      license.expiry_unix += Math.max(0, current - license.pause_started_at);
    }

    license.pause_started_at = null;
  }

  return true;
}

function remaining_seconds(license, current = now_unix()) {
  if (!Number.isSafeInteger(license?.expiry_unix)) {
    return Number.isSafeInteger(license?.duration_seconds) ? license.duration_seconds : 0;
  }

  const effective_now = reasons(license).length && Number.isSafeInteger(license.pause_started_at)
    ? license.pause_started_at
    : current;

  return Math.max(0, license.expiry_unix - effective_now);
}

function pause_all(db, current = now_unix()) {
  if (!db.service_state || typeof db.service_state !== 'object') {
    db.service_state = {};
  }

  if (db.service_state.keys_paused) {
    return 0;
  }

  db.service_state.keys_paused = true;
  db.service_state.keys_paused_at = current;

  let changed = 0;

  for (const license of Object.values(db.keys || {})) {
    if (pause_license(license, 'global', current)) {
      changed += 1;
    }
  }

  return changed;
}

function resume_all(db, current = now_unix()) {
  if (!db.service_state?.keys_paused) {
    return 0;
  }

  db.service_state.keys_paused = false;
  db.service_state.keys_paused_at = null;

  let changed = 0;

  for (const license of Object.values(db.keys || {})) {
    if (resume_license(license, 'global', current)) {
      changed += 1;
    }
  }

  return changed;
}

module.exports = {
  is_license_paused,
  pause_all,
  pause_license,
  reasons,
  remaining_seconds,
  resume_all,
  resume_license
};
