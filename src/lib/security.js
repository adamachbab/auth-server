const crypto = require('crypto');

const email_pattern = /^[^\s@]{1,64}@[^\s@]{1,190}$/;

function b64(value) {
  return Buffer.from(value).toString('base64url');
}

function digest(value, context = '') {
  return b64(
    crypto
      .createHash('sha256')
      .update(context)
      .update('\0')
      .update(value)
      .digest()
  );
}

function random_token(bytes = 32) {
  return crypto.randomBytes(bytes).toString('base64url');
}

function safe_equal(left, right) {
  if (typeof left !== 'string' || typeof right !== 'string') {
    return false;
  }

  const a = Buffer.from(left);
  const b = Buffer.from(right);

  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function normalize_email(value) {
  const email = typeof value === 'string' ? value.trim().toLowerCase() : '';

  return email_pattern.test(email) ? email : null;
}

function validate_password(value) {
  return typeof value === 'string' &&
    value.length >= 12 &&
    value.length <= 128 &&
    /[a-z]/i.test(value) &&
    /[^a-z]/i.test(value);
}

function scrypt(password, salt, options) {
  return new Promise((resolve, reject) => {
    crypto.scrypt(password, salt, 32, options, (error, key) => {
      if (error) {
        reject(error);
      } else {
        resolve(key);
      }
    });
  });
}

async function hash_password(password) {
  const salt = crypto.randomBytes(16);
  const options = {
    N: 32768,
    r: 8,
    p: 1,
    maxmem: 64 * 1024 * 1024
  };
  const key = await scrypt(password, salt, options);

  return `scrypt$32768$8$1$${b64(salt)}$${b64(key)}`;
}

async function verify_password(password, encoded) {
  try {
    const [name, n, r, p, salt, expected] = String(encoded).split('$');

    if (name !== 'scrypt' || n !== '32768' || r !== '8' || p !== '1') {
      return false;
    }

    const key = await scrypt(password, Buffer.from(salt, 'base64url'), {
      N: Number(n),
      r: Number(r),
      p: Number(p),
      maxmem: 64 * 1024 * 1024
    });

    return safe_equal(b64(key), expected);
  } catch {
    return false;
  }
}

function client_ip(req) {
  return String(req.ip || req.socket?.remoteAddress || 'unknown').slice(0, 64);
}

function request_id(req) {
  return String(req.id || req.get('x-request-id') || crypto.randomUUID()).slice(0, 128);
}

function metadata(req) {
  return {
    ip: client_ip(req),
    user_agent: String(req.get('user-agent') || '').slice(0, 256)
  };
}

function create_rate_limiter() {
  const buckets = new Map();

  return function limit(key, maximum, window_ms) {
    const now = Date.now();
    const clean_key = String(key).slice(0, 256);
    const entry = buckets.get(clean_key);

    if (!entry || entry.reset_at <= now) {
      buckets.set(clean_key, {
        count: 1,
        reset_at: now + window_ms
      });

      return { allowed: true };
    }

    if (entry.count >= maximum) {
      return {
        allowed: false,
        retry_after: Math.max(1, Math.ceil((entry.reset_at - now) / 1000))
      };
    }

    entry.count += 1;
    return { allowed: true };
  };
}

module.exports = {
  client_ip,
  create_rate_limiter,
  digest,
  hash_password,
  metadata,
  normalize_email,
  random_token,
  request_id,
  safe_equal,
  validate_password,
  verify_password
};
