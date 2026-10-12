const crypto = require('crypto');

const auth_domain = 'auth-client-auth:v1';
const session_domain = 'auth-session-proof:v1';
const public_blob_bytes = 72;
const public_blob_magic = 0x31534345;
const nonce_pattern = /^[A-Za-z0-9_-]{43}$/;
const signature_pattern = /^[A-Za-z0-9_-]{86}$/;
const public_key_pattern = /^[A-Za-z0-9_-]{96}$/;
const max_clock_skew_seconds = 60;
const max_replays = 20_000;

function decode_exact(value, pattern, bytes) {
  if (typeof value !== 'string' || !pattern.test(value)) {
    return null;
  }

  try {
    const decoded = Buffer.from(value, 'base64url');

    return decoded.length === bytes && decoded.toString('base64url') === value ? decoded : null;
  } catch {
    return null;
  }
}

function import_public_key(encoded) {
  const blob = decode_exact(encoded, public_key_pattern, public_blob_bytes);

  if (
    !blob ||
    blob.readUInt32LE(0) !== public_blob_magic ||
    blob.readUInt32LE(4) !== 32
  ) {
    return null;
  }

  try {
    return crypto.createPublicKey({
      key: {
        kty: 'EC',
        crv: 'P-256',
        x: blob.subarray(8, 40).toString('base64url'),
        y: blob.subarray(40, 72).toString('base64url')
      },
      format: 'jwk'
    });
  } catch {
    return null;
  }
}

function auth_canonical(key, hwid, timestamp, nonce) {
  return [auth_domain, String(timestamp), nonce, hwid, key].join('\n');
}

function session_canonical(operation, access_token, timestamp, nonce) {
  return [
    session_domain,
    String(operation || '').toLowerCase(),
    access_token,
    String(timestamp),
    nonce
  ].join('\n');
}

function verify_signature(public_key, canonical, encoded_signature) {
  const signature = decode_exact(encoded_signature, signature_pattern, 64);

  if (!public_key || !signature) {
    return false;
  }

  try {
    return crypto.verify(
      'sha256',
      Buffer.from(canonical, 'utf8'),
      { key: public_key, dsaEncoding: 'ieee-p1363' },
      signature
    );
  } catch {
    return false;
  }
}

function create_replay_cache(now = () => Math.floor(Date.now() / 1000)) {
  const entries = new Map();

  return function consume(scope, nonce, timestamp) {
    const current = now();

    if (
      !Number.isSafeInteger(timestamp) ||
      Math.abs(current - timestamp) > max_clock_skew_seconds ||
      !nonce_pattern.test(nonce || '')
    ) {
      return false;
    }

    for (const [key, expires_at] of entries) {
      if (expires_at <= current) {
        entries.delete(key);
      }
    }

    if (entries.size >= max_replays) {
      return false;
    }

    const replay_key = `${scope}\0${nonce}`;

    if (entries.has(replay_key)) {
      return false;
    }

    entries.set(replay_key, current + 2 * max_clock_skew_seconds + 1);
    return true;
  };
}

function create_client_proof_verifier(options = {}) {
  const consume = create_replay_cache(options.now);

  function verify_authentication(body) {
    if (!body || typeof body !== 'object') {
      return null;
    }

    if (
      typeof body.key !== 'string' ||
      typeof body.hwid !== 'string' ||
      typeof body.nonce !== 'string'
    ) {
      return null;
    }

    const public_key = import_public_key(body.client_public_key);
    const canonical = auth_canonical(body.key, body.hwid, body.timestamp_unix, body.nonce);

    if (!public_key || !verify_signature(public_key, canonical, body.signature)) {
      return null;
    }

    const fingerprint = crypto
      .createHash('sha256')
      .update(Buffer.from(body.client_public_key, 'base64url'))
      .digest('base64url');

    if (!consume(`auth:${fingerprint}`, body.nonce, body.timestamp_unix)) {
      return null;
    }

    return {
      encoded_public_key: body.client_public_key,
      public_key,
      fingerprint
    };
  }

  function verify_session(proof, access_token, encoded_public_key) {
    if (!proof || typeof proof !== 'object') {
      return false;
    }

    const operation = String(proof.op || '');
    const timestamp = Number(proof.timestamp_unix);
    const nonce = String(proof.nonce || '');
    const signature = String(proof.signature || '');

    if (operation !== 'validate') {
      return false;
    }

    const public_key = import_public_key(encoded_public_key);
    const canonical = session_canonical(operation, access_token, timestamp, nonce);

    if (!public_key || !verify_signature(public_key, canonical, signature)) {
      return false;
    }

    return consume(`session:${access_token}`, nonce, timestamp);
  }

  return {
    verify_authentication,
    verify_session
  };
}

module.exports = {
  auth_canonical,
  create_client_proof_verifier,
  import_public_key,
  session_canonical
};
