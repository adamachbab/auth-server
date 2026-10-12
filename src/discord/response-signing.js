const crypto = require('crypto');
const fs = require('fs');

async function load_jose() {
  return import('jose');
}

async function sign_discord_attestation(claims, config, now_unix) {
  const { importPKCS8, SignJWT } = await load_jose();
  const private_key_pem = fs.readFileSync(config.signing_private_key_file, 'utf8');
  const private_key = await importPKCS8(private_key_pem, 'ES256');
  const iat = now_unix;

  return new SignJWT(claims)
    .setProtectedHeader({
      alg: 'ES256',
      kid: config.signing_key_id,
      typ: 'discord-member-info+jwt'
    })
    .setIssuer(config.signing_issuer)
    .setAudience(config.signing_audience)
    .setSubject(`discord:${claims.discord_id}`)
    .setIssuedAt(iat)
    .setNotBefore(iat - 5)
    .setExpirationTime(iat + 60)
    .setJti(crypto.randomUUID())
    .sign(private_key);
}

async function verify_discord_attestation(token, public_key_pem, expected, now_unix) {
  const { importSPKI, jwtVerify } = await load_jose();
  const public_key = await importSPKI(public_key_pem, 'ES256');
  const result = await jwtVerify(token, public_key, {
    algorithms: ['ES256'],
    issuer: expected.issuer,
    audience: expected.audience,
    currentDate: new Date(now_unix * 1000)
  });

  if (
    result.protectedHeader.typ !== 'discord-member-info+jwt' ||
    result.protectedHeader.kid !== expected.kid
  ) {
    throw new Error('Unexpected attestation header');
  }

  if (expected.claims) {
    for (const [name, value] of Object.entries(expected.claims)) {
      if (result.payload[name] !== value) {
        throw new Error(`Unexpected attestation claim: ${name}`);
      }
    }
  }

  return result;
}

module.exports = {
  sign_discord_attestation,
  verify_discord_attestation
};
