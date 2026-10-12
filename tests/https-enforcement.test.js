const assert = require('assert/strict');
const fs = require('fs');
const http = require('http');
const os = require('os');
const path = require('path');
const test = require('node:test');
const { create_store } = require('../src/lib/data-store');

function request(port, headers = {}) {
  return new Promise((resolve, reject) => {
    const options = { hostname: '127.0.0.1', port, path: '/', headers };
    const call = http.get(options, (response) => {
      const chunks = [];

      response.on('data', (chunk) => chunks.push(chunk));
      response.on('end', () => {
        resolve({
          status: response.statusCode,
          body: JSON.parse(Buffer.concat(chunks).toString('utf8'))
        });
      });
    });

    call.on('error', reject);
  });
}

test('production rejects plaintext requests and accepts trusted HTTPS proxy requests', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'auth-https-'));
  process.env.NODE_ENV = 'production';
  process.env.DATABASE_PATH = path.join(directory, 'database.json');
  create_store(process.env.DATABASE_PATH).initialize();

  const { app } = require('../server');
  const server = await new Promise((resolve) => {
    const value = app.listen(0, '127.0.0.1', () => resolve(value));
  });

  try {
    const plaintext = await request(server.address().port);
    assert.equal(plaintext.status, 426);
    assert.equal(plaintext.body.error, 'HTTPS is required');

    const proxied_tls = await request(server.address().port, { 'X-Forwarded-Proto': 'https' });
    assert.equal(proxied_tls.status, 405);
    assert.match(proxied_tls.body.error, /TCP/);
  } finally {
    await new Promise((resolve, reject) => {
      server.close((error) => (error ? reject(error) : resolve()));
    });
    fs.rmSync(directory, { recursive: true, force: true });
    delete process.env.NODE_ENV;
    delete process.env.DATABASE_PATH;
  }
});
