const net = require('net');
const { create_identity, signed_authentication } = require('./device-proof');
const { decode_frame, encode_frame } = require('../../src/lib/native-protocol');

function log_error(message) {
  console.error(`[ERROR] ${message}`);
}

function parse_endpoint(value) {
  const text = String(value || '127.0.0.1:223');
  const split = text.lastIndexOf(':');

  if (split <= 0) {
    return { host: text, port: 223 };
  }

  return {
    host: text.slice(0, split),
    port: Number(text.slice(split + 1)) || 223
  };
}

function authenticate(endpoint, key, hwid, identity) {
  const { host, port } = parse_endpoint(endpoint);

  return new Promise((resolve, reject) => {
    const socket = net.connect({ host, port }, () => {
      const request = signed_authentication(identity, key, hwid);
      socket.end(encode_frame(request, null, { request: true }));
    });
    const chunks = [];

    socket.on('data', (chunk) => chunks.push(chunk));
    socket.on('error', reject);
    socket.on('end', () => {
      const frame = decode_frame(Buffer.concat(chunks));

      if (!frame) {
        reject(new Error('Invalid native response'));
      } else {
        resolve(frame.json);
      }
    });
  });
}

async function main() {
  const args = process.argv.slice(2);
  const key = args[0] || 'DEMO-KEY-001';
  const hwid = args[1] || 'HWID-123456789';
  const endpoint = args[2] || '127.0.0.1:223';

  console.log(`Testing TCP authenticate ${endpoint}`);

  try {
    const response = await authenticate(endpoint, key, hwid, create_identity());

    if (!response.success) {
      log_error(`Auth failed: ${response.error || 'Unknown reason'}`);
      process.exit(1);
    }

    const { start_unix: start, expiry_unix: expiry, access_token } = response;

    if (
      !Number.isSafeInteger(start)
      || !Number.isSafeInteger(expiry)
      || typeof access_token !== 'string'
    ) {
      log_error('Missing timestamps or access token in response');
      process.exit(1);
    }

    const now = Math.floor(Date.now() / 1000);

    if (now >= expiry) {
      log_error(`License expired at ${expiry} (current time: ${now})`);
      process.exit(1);
    }

    console.log('Successfully authenticated.');
    console.log(`  Start:     ${new Date(start * 1000).toISOString()}`);
    console.log(`  Expiry:    ${new Date(expiry * 1000).toISOString()}`);
    console.log(`  Duration:  ${expiry - start} seconds`);
    console.log(`  Remaining: ${expiry - now} seconds`);
    console.log(`  Access:    Bearer token valid for ${response.access_token_expires_in} seconds`);
  } catch (error) {
    log_error(`Request failed: ${error.message}`);
    process.exit(1);
  }
}

main();
