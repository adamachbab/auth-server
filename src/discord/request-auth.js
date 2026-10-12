const crypto = require('crypto');
const { is_license_paused } = require('../lib/license-state');

const request_fields = [
  'license_hash',
  'hwid_hash',
  'discord_id',
  'discord_id_hash',
  'timestamp_unix',
  'nonce',
  'request_mac'
];

const zero = Buffer.from([0]);
const base64url_pattern = /^[A-Za-z0-9_-]+$/;
const discord_snowflake = /^[0-9]{17,20}$/;

function sha256(parts) {
  const hash = crypto.createHash('sha256');

  for (const part of parts) {
    hash.update(part);
  }

  return hash.digest();
}

function hmac_sha256(key, value) {
  return crypto.createHmac('sha256', key).update(value).digest();
}

function delimited_utf8(...values) {
  const parts = [];

  values.forEach((value, index) => {
    parts.push(Buffer.from(value, 'utf8'));

    if (index !== values.length - 1) {
      parts.push(zero);
    }
  });

  return parts;
}

function base64url(value) {
  return Buffer.from(value).toString('base64url');
}

function decode_base64url32(value) {
  if (typeof value !== 'string' || value.length !== 43 || !base64url_pattern.test(value)) {
    return null;
  }

  try {
    const decoded = Buffer.from(value, 'base64url');

    if (decoded.length !== 32 || decoded.toString('base64url') !== value) {
      return null;
    }

    return decoded;
  } catch {
    return null;
  }
}

function timing_safe_equal(left, right) {
  return Buffer.isBuffer(left) &&
    Buffer.isBuffer(right) &&
    left.length === right.length &&
    crypto.timingSafeEqual(left, right);
}

function license_hash(license_key) {
  return sha256(delimited_utf8('discord-license:v2', license_key));
}

function hwid_hash(hwid) {
  return sha256(delimited_utf8('discord-hwid:v2', hwid));
}

function discord_id_hash(discord_id, license_hash_value, hwid_hash_value, nonce, timestamp_unix) {
  return sha256(delimited_utf8(
    'discord-user:v2',
    discord_id,
    license_hash_value,
    hwid_hash_value,
    nonce,
    String(timestamp_unix)
  ));
}

function request_auth_key(license_key, hwid) {
  return sha256(delimited_utf8('discord-request-auth:v2', license_key, hwid));
}

function canonical_request(body) {
  return [
    'POST',
    '/v2/discord/member-info',
    body.license_hash,
    body.hwid_hash,
    body.discord_id,
    body.discord_id_hash,
    String(body.timestamp_unix),
    body.nonce
  ].join('\n');
}

function validate_request_shape(body) {
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    return null;
  }

  const keys = Object.keys(body);

  if (
    keys.length !== request_fields.length ||
    keys.some((key) => !request_fields.includes(key))
  ) {
    return null;
  }

  if (request_fields.some((key) => !Object.prototype.hasOwnProperty.call(body, key))) {
    return null;
  }

  if (typeof body.discord_id !== 'string' || !discord_snowflake.test(body.discord_id)) {
    return null;
  }

  if (typeof body.timestamp_unix !== 'number' || !Number.isSafeInteger(body.timestamp_unix)) {
    return null;
  }

  const license_hash_bytes = decode_base64url32(body.license_hash);
  const hwid_hash_bytes = decode_base64url32(body.hwid_hash);
  const discord_id_hash_bytes = decode_base64url32(body.discord_id_hash);
  const nonce_bytes = decode_base64url32(body.nonce);
  const request_mac_bytes = decode_base64url32(body.request_mac);

  if (
    !license_hash_bytes ||
    !hwid_hash_bytes ||
    !discord_id_hash_bytes ||
    !nonce_bytes ||
    !request_mac_bytes
  ) {
    return null;
  }

  return {
    ...body,
    license_hash_bytes,
    hwid_hash_bytes,
    discord_id_hash_bytes,
    nonce_bytes,
    request_mac_bytes
  };
}

function authenticate_discord_request(request, database, now_unix) {
  if (Math.abs(now_unix - request.timestamp_unix) > 60) {
    return null;
  }

  if (!database || !database.keys || typeof database.keys !== 'object') {
    return null;
  }

  let matched_key = null;
  let matched_record = null;

  for (const [license_key, record] of Object.entries(database.keys)) {
    const candidate = license_hash(license_key);

    if (timing_safe_equal(candidate, request.license_hash_bytes) && matched_key === null) {
      matched_key = license_key;
      matched_record = record;
    }
  }

  if (
    !matched_record ||
    matched_record.start_unix === null ||
    matched_record.start_unix === undefined
  ) {
    return null;
  }

  if (is_license_paused(database, matched_record)) {
    return null;
  }

  if (typeof matched_record.expiry_unix !== 'number' || now_unix >= matched_record.expiry_unix) {
    return null;
  }

  if (typeof matched_record.hwid !== 'string' || !matched_record.hwid) {
    return null;
  }

  if (
    matched_record.discord_id !== request.discord_id ||
    !discord_snowflake.test(matched_record.discord_id)
  ) {
    return null;
  }

  const expected_hwid_hash = hwid_hash(matched_record.hwid);

  if (!timing_safe_equal(expected_hwid_hash, request.hwid_hash_bytes)) {
    return null;
  }

  const canonical = canonical_request(request);
  const expected_mac = hmac_sha256(
    request_auth_key(matched_key, matched_record.hwid),
    Buffer.from(canonical, 'utf8')
  );

  if (!timing_safe_equal(expected_mac, request.request_mac_bytes)) {
    return null;
  }

  const expected_discord_id_hash = discord_id_hash(
    request.discord_id,
    request.license_hash,
    request.hwid_hash,
    request.nonce,
    request.timestamp_unix
  );

  if (!timing_safe_equal(expected_discord_id_hash, request.discord_id_hash_bytes)) {
    return null;
  }

  return {
    canonical,
    request_hash: base64url(sha256([Buffer.from(canonical, 'utf8')])),
    license_key: matched_key,
    record: matched_record
  };
}

module.exports = {
  authenticate_discord_request,
  base64url,
  canonical_request,
  decode_base64url32,
  discord_id_hash,
  hmac_sha256,
  hwid_hash,
  license_hash,
  request_auth_key,
  sha256,
  timing_safe_equal,
  validate_request_shape
};
