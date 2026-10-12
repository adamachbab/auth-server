const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { artifact_canonical, auth_canonical } = require('../../src/lib/client-proof');

function create_identity() {
  const filename = process.env.AUTH_TEST_DEVICE_KEY_FILE
    || path.join(os.homedir(), '.auth-client-test-device-key.pem');
  let private_key;

  if (fs.existsSync(filename)) {
    private_key = crypto.createPrivateKey(fs.readFileSync(filename));
  } else {
    private_key = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).privateKey;
    fs.writeFileSync(
      filename,
      private_key.export({ format: 'pem', type: 'pkcs8' }),
      { mode: 0o600, flag: 'wx' }
    );
  }

  const pair = {
    privateKey: private_key,
    publicKey: crypto.createPublicKey(private_key)
  };
  const jwk = pair.publicKey.export({ format: 'jwk' });
  const blob = Buffer.alloc(72);

  blob.writeUInt32LE(0x31534345, 0);
  blob.writeUInt32LE(32, 4);
  Buffer.from(jwk.x, 'base64url').copy(blob, 8);
  Buffer.from(jwk.y, 'base64url').copy(blob, 40);

  return { pair, public_key: blob.toString('base64url') };
}

function sign(identity, canonical) {
  return crypto.sign('sha256', Buffer.from(canonical, 'utf8'), {
    key: identity.pair.privateKey,
    dsaEncoding: 'ieee-p1363'
  }).toString('base64url');
}

function signed_authentication(identity, key, hwid) {
  const timestamp_unix = Math.floor(Date.now() / 1000);
  const nonce = crypto.randomBytes(32).toString('base64url');

  return {
    op: 'authenticate',
    key,
    hwid,
    client_public_key: identity.public_key,
    timestamp_unix,
    nonce,
    signature: sign(identity, auth_canonical(key, hwid, timestamp_unix, nonce))
  };
}

function artifact_request(identity, op, name, access_token) {
  const timestamp_unix = Math.floor(Date.now() / 1000);
  const nonce = crypto.randomBytes(32).toString('base64url');
  const canonical = artifact_canonical(op, name, access_token, timestamp_unix, nonce);

  return {
    op,
    name,
    access_token,
    timestamp_unix,
    nonce,
    signature: sign(identity, canonical)
  };
}

module.exports = { artifact_request, create_identity, signed_authentication };
