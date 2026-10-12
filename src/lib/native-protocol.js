const magic = Buffer.from('CAUT', 'ascii');
const version = 1;
const flag_binary = 0x01;
const header_size = 16;
const max_request_json = 32 * 1024;
const max_response_json = 64 * 1024;
const max_binary = 64 * 1024 * 1024;

function encode_frame(json, binary = null, { request = false } = {}) {
  const payload = Buffer.from(JSON.stringify(json), 'utf8');
  const blob = binary && binary.length ? Buffer.from(binary) : Buffer.alloc(0);
  const json_limit = request ? max_request_json : max_response_json;

  if (payload.length === 0 || payload.length > json_limit) {
    throw new Error('Native frame JSON is invalid');
  }

  if (blob.length > max_binary) {
    throw new Error('Native frame binary is too large');
  }

  const header = Buffer.alloc(header_size);

  magic.copy(header, 0);
  header.writeUInt8(version, 4);
  header.writeUInt8(blob.length ? flag_binary : 0, 5);
  header.writeUInt16LE(0, 6);
  header.writeUInt32LE(payload.length, 8);
  header.writeUInt32LE(blob.length, 12);

  return Buffer.concat([header, payload, blob]);
}

function decode_header(buffer) {
  if (!Buffer.isBuffer(buffer) || buffer.length < header_size) {
    return null;
  }

  if (buffer.compare(magic, 0, 4, 0, 4) !== 0 || buffer.readUInt8(4) !== version) {
    return null;
  }

  const flags = buffer.readUInt8(5);

  if (buffer.readUInt16LE(6) !== 0) {
    return null;
  }

  if (flags & ~flag_binary) {
    return null;
  }

  const json_length = buffer.readUInt32LE(8);
  const binary_length = buffer.readUInt32LE(12);

  if (!json_length || json_length > max_response_json || binary_length > max_binary) {
    return null;
  }

  if (binary_length && !(flags & flag_binary)) {
    return null;
  }

  if (!binary_length && (flags & flag_binary)) {
    return null;
  }

  return {
    json_length,
    binary_length,
    total: header_size + json_length + binary_length
  };
}

function decode_frame(buffer, { request = false } = {}) {
  const header = decode_header(buffer);

  if (!header || buffer.length !== header.total) {
    return null;
  }

  const json_limit = request ? max_request_json : max_response_json;

  if (header.json_length > json_limit) {
    return null;
  }

  if (request && header.binary_length) {
    return null;
  }

  let json;

  try {
    const text = buffer
      .subarray(header_size, header_size + header.json_length)
      .toString('utf8');

    json = JSON.parse(text);
  } catch {
    return null;
  }

  if (!json || typeof json !== 'object' || Array.isArray(json)) {
    return null;
  }

  const binary = header.binary_length
    ? Buffer.from(buffer.subarray(header_size + header.json_length))
    : Buffer.alloc(0);

  return { json, binary };
}

function create_frame_reader({ request = false } = {}) {
  let pending = Buffer.alloc(0);

  return function push(chunk) {
    if (!chunk || !chunk.length) {
      return [];
    }

    pending = pending.length ? Buffer.concat([pending, chunk]) : Buffer.from(chunk);

    const frames = [];

    while (pending.length >= header_size) {
      const header = decode_header(pending.subarray(0, header_size));

      if (!header) {
        pending = Buffer.alloc(0);
        return { error: 'Invalid native frame' };
      }

      if (pending.length < header.total) {
        return frames;
      }

      const encoded = pending.subarray(0, header.total);

      pending = pending.subarray(header.total);

      const frame = decode_frame(encoded, { request });

      if (!frame) {
        return { error: 'Invalid native frame' };
      }

      frames.push(frame);
    }

    return frames;
  };
}

function is_loopback_address(address) {
  const value = String(address || '');

  return value === '127.0.0.1' || value === '::1' || value === '::ffff:127.0.0.1';
}

module.exports = {
  flag_binary,
  header_size,
  magic,
  max_binary,
  max_request_json,
  max_response_json,
  version,
  create_frame_reader,
  decode_frame,
  decode_header,
  encode_frame,
  is_loopback_address
};
