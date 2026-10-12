const assert = require('assert/strict');
const net = require('net');
const test = require('node:test');
const {
  header_size,
  create_frame_reader,
  decode_frame,
  encode_frame,
  is_loopback_address
} = require('../src/lib/native-protocol');

test('native frames round-trip JSON and optional binary payloads', () => {
  const json_only = encode_frame({ op: 'authenticate', ok: true }, null, { request: true });
  const decoded = decode_frame(json_only, { request: true });
  assert.equal(decoded.json.op, 'authenticate');
  assert.equal(decoded.binary.length, 0);

  const with_binary = encode_frame({ success: true }, Buffer.from('MZ'));
  const binary = decode_frame(with_binary);
  assert.equal(binary.json.success, true);
  assert.equal(binary.binary.toString('latin1'), 'MZ');
});

test('native frame reader rejects HTTP and truncated magic', () => {
  const reader = create_frame_reader({ request: true });
  const error = reader(Buffer.from('GET / HTTP/1.1\r\n'));
  assert.equal(error.error, 'Invalid native frame');

  const partial = create_frame_reader({ request: true });
  assert.deepEqual(partial(Buffer.from('CA')), []);
});

test('native frame reader reassembles split packets', () => {
  const frame = encode_frame(
    { op: 'authenticate', key: 'LOGIN-KEY-1' },
    null,
    { request: true }
  );
  const reader = create_frame_reader({ request: true });

  assert.deepEqual(reader(frame.subarray(0, 4)), []);
  assert.deepEqual(reader(frame.subarray(4, header_size + 3)), []);

  const complete = reader(frame.subarray(header_size + 3));
  assert.equal(complete.length, 1);
  assert.equal(complete[0].json.op, 'authenticate');
});

test('loopback detection covers IPv4-mapped IPv6', () => {
  assert.equal(is_loopback_address('127.0.0.1'), true);
  assert.equal(is_loopback_address('::1'), true);
  assert.equal(is_loopback_address('::ffff:127.0.0.1'), true);
  assert.equal(is_loopback_address('8.8.8.8'), false);
});

test('native server answers one request per TCP connection', async () => {
  const { create_native_server } = require('../src/native-server');
  const server = create_native_server((frame) => {
    assert.equal(frame.json.op, 'ping');
    return { status: 200, body: { success: true, pong: true } };
  });

  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;

  try {
    const response = await new Promise((resolve, reject) => {
      const socket = net.connect({ host: '127.0.0.1', port }, () => {
        socket.end(encode_frame({ op: 'ping' }, null, { request: true }));
      });
      const chunks = [];

      socket.on('data', (chunk) => chunks.push(chunk));
      socket.on('error', reject);
      socket.on('end', () => resolve(decode_frame(Buffer.concat(chunks))));
    });

    assert.equal(response.json.success, true);
    assert.equal(response.json.pong, true);
    assert.equal(response.json.status, 200);
  } finally {
    await new Promise((resolve, reject) => {
      server.close((error) => (error ? reject(error) : resolve()));
    });
  }
});
