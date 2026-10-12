const net = require('net');
const { create_frame_reader, encode_frame } = require('./lib/native-protocol');

const socket_idle_ms = 30_000;
const max_connections = 256;

function remote_address(socket) {
  return String(socket.remoteAddress || '').replace(/^::ffff:/, '') || 'unknown';
}

function create_native_server(handle_request, options = {}) {
  const idle_ms = Number.isFinite(options.idle_ms) ? options.idle_ms : socket_idle_ms;
  const connection_limit = Number.isFinite(options.max_connections)
    ? options.max_connections
    : max_connections;

  let open_connections = 0;

  const server = net.createServer((socket) => {
    const ip = remote_address(socket);

    if (open_connections >= connection_limit) {
      socket.destroy();
      return;
    }

    open_connections += 1;

    let handled = false;
    const reader = create_frame_reader({ request: true });

    socket.setTimeout(idle_ms);
    socket.on('timeout', () => socket.destroy());
    socket.on('error', () => socket.destroy());
    socket.on('close', () => {
      open_connections -= 1;
    });

    socket.on('data', async (chunk) => {
      if (handled) {
        socket.destroy();
        return;
      }

      const frames = reader(chunk);

      if (frames && frames.error) {
        socket.destroy();
        return;
      }

      if (!frames.length) {
        return;
      }

      handled = true;
      socket.pause();

      try {
        const result = await handle_request(frames[0], ip);
        const status = Number.isSafeInteger(result?.status) ? result.status : 500;
        const body = result?.body && typeof result.body === 'object'
          ? result.body
          : { success: false, error: 'Native request failed' };

        if (body.status === undefined) {
          body.status = status;
        }

        if (body.success === undefined) {
          body.success = status < 400;
        }

        socket.end(encode_frame(body, result?.binary || null));
      } catch {
        try {
          socket.end(encode_frame({ success: false, status: 500, error: 'Native request failed' }));
        } catch {
          socket.destroy();
        }
      }
    });
  });

  return server;
}

module.exports = { create_native_server, remote_address };
