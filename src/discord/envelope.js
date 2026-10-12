const crypto = require('crypto');
const fs = require('fs');

const cng_ecdh_public_p256_magic = 0x314B4345;
const ecdh_public_blob_bytes = 72;
const aes_gcm_iv_bytes = 12;
const aes_gcm_tag_bytes = 16;
const envelope_version = 1;
const max_request_ciphertext_bytes = 5800;
const max_response_ciphertext_bytes = 48 * 1024;
const base64url_pattern = /^[A-Za-z0-9_-]+$/;
const request_aad = Buffer.from('discord-member-info/v2/request', 'utf8');
const response_aad = Buffer.from('discord-member-info/v2/response', 'utf8');
const zero = Buffer.from([0]);
const envelope_overhead_bytes = 1 + aes_gcm_iv_bytes + aes_gcm_tag_bytes;

function decode_base64url(value, minimum, maximum) {
  if (typeof value !== 'string' || !value || !base64url_pattern.test(value)) {
    return null;
  }

  try {
    const bytes = Buffer.from(value, 'base64url');

    if (
      bytes.length < minimum ||
      bytes.length > maximum ||
      bytes.toString('base64url') !== value
    ) {
      return null;
    }

    return bytes;
  } catch {
    return null;
  }
}

function parse_request_envelope(body) {
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    return null;
  }

  const keys = Object.keys(body);

  if (
    keys.length !== 2 ||
    !Object.prototype.hasOwnProperty.call(body, 'e') ||
    !Object.prototype.hasOwnProperty.call(body, 'd')
  ) {
    return null;
  }

  const public_blob = decode_base64url(body.e, ecdh_public_blob_bytes, ecdh_public_blob_bytes);
  const encrypted = decode_base64url(
    body.d,
    envelope_overhead_bytes,
    max_request_ciphertext_bytes + envelope_overhead_bytes
  );

  if (
    !public_blob ||
    !encrypted ||
    public_blob.readUInt32LE(0) !== cng_ecdh_public_p256_magic ||
    public_blob.readUInt32LE(4) !== 32
  ) {
    return null;
  }

  return { public_blob, encrypted };
}

function load_transport_private_key(file) {
  const key = crypto.createPrivateKey(fs.readFileSync(file, 'utf8'));
  const jwk = key.export({ format: 'jwk' });

  if (key.asymmetricKeyType !== 'ec' || jwk.kty !== 'EC' || jwk.crv !== 'P-256') {
    throw new Error('Invalid Discord transport key');
  }

  return key;
}

function import_client_public_key(public_blob) {
  return crypto.createPublicKey({
    key: {
      kty: 'EC',
      crv: 'P-256',
      x: public_blob.subarray(8, 40).toString('base64url'),
      y: public_blob.subarray(40, 72).toString('base64url')
    },
    format: 'jwk'
  });
}

function derive_key(label, shared_secret, nonce) {
  const hash = crypto.createHash('sha256');

  hash.update(label, 'utf8');
  hash.update(zero);
  hash.update(shared_secret);

  if (nonce !== undefined) {
    hash.update(zero);
    hash.update(nonce, 'utf8');
  }

  return hash.digest();
}

function encrypt(key, plaintext, aad) {
  const iv = crypto.randomBytes(aes_gcm_iv_bytes);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);

  cipher.setAAD(aad);

  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();

  return Buffer
    .concat([Buffer.from([envelope_version]), iv, ciphertext, tag])
    .toString('base64url');
}

function decrypt(key, encoded, aad, maximum_ciphertext_bytes = max_response_ciphertext_bytes) {
  const payload = typeof encoded === 'string'
    ? decode_base64url(
      encoded,
      envelope_overhead_bytes,
      maximum_ciphertext_bytes + envelope_overhead_bytes
    )
    : encoded;

  if (!payload || payload[0] !== envelope_version) {
    return null;
  }

  const iv = payload.subarray(1, 1 + aes_gcm_iv_bytes);
  const tag = payload.subarray(payload.length - aes_gcm_tag_bytes);
  const ciphertext = payload.subarray(1 + aes_gcm_iv_bytes, payload.length - aes_gcm_tag_bytes);

  try {
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);

    decipher.setAAD(aad);
    decipher.setAuthTag(tag);

    return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  } catch {
    return null;
  }
}

function decrypt_request_envelope(envelope, transport_private_key) {
  try {
    const client_key = import_client_public_key(envelope.public_blob);
    const shared_secret = crypto.diffieHellman({
      privateKey: transport_private_key,
      publicKey: client_key
    });
    const plaintext = decrypt(
      derive_key('discord-envelope-request:v1', shared_secret),
      envelope.encrypted,
      request_aad,
      max_request_ciphertext_bytes
    );

    if (!plaintext) {
      return null;
    }

    return {
      body: JSON.parse(plaintext.toString('utf8')),
      shared_secret
    };
  } catch {
    return null;
  }
}

function encrypt_response_envelope(attestation, shared_secret, nonce) {
  return {
    d: encrypt(
      derive_key('discord-envelope-response:v1', shared_secret, nonce),
      Buffer.from(attestation, 'utf8'),
      response_aad
    )
  };
}

module.exports = {
  cng_ecdh_public_p256_magic,
  ecdh_public_blob_bytes,
  decrypt,
  decrypt_request_envelope,
  derive_key,
  encrypt,
  encrypt_response_envelope,
  load_transport_private_key,
  parse_request_envelope
};
