/**
 * tcp-proxy.mjs -- TCP-over-WebSocket proxy for the Canary x86-64 WASM emulator.
 *
 * The Canary harness (canary-host.mjs) emulates Linux TCP sockets by opening a
 * WebSocket from the browser.  This proxy sits in the middle: the browser opens
 * a WebSocket to us and we open a real TCP socket to the requested destination,
 * then pipe data bidirectionally.
 *
 * Architecture:
 *
 *   Browser (WebSocket client)
 *       ws://localhost:3001/tcp/{ip}/{port}
 *   tcp-proxy.mjs  (Node.js HTTP server + manual WS upgrade)
 *       TCP socket
 *   Remote host:port
 *
 * Usage:
 *   node harness/tcp-proxy.mjs
 *   PORT_PROXY=3001 node harness/tcp-proxy.mjs
 *
 * No npm packages -- only Node.js built-ins.
 */

import { createServer }     from 'node:http';
import { createConnection } from 'node:net';
import { createHash }       from 'node:crypto';

const PORT = parseInt(process.env.PORT_PROXY ?? '3001', 10);

// -- WebSocket constants

const WS_MAGIC  = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';
const OP_BINARY = 0x02;
const OP_CLOSE  = 0x08;
const OP_PING   = 0x09;
const OP_PONG   = 0x0a;

// -- WebSocket handshake (RFC 6455)

/**
 * Complete the RFC 6455 opening handshake.
 * Returns the upgraded socket, or null on failure.
 */
function upgradeToWebSocket(req, socket, head) {
  const key = req.headers['sec-websocket-key'];
  if (!key) {
    socket.end('HTTP/1.1 400 Bad Request

Missing Sec-WebSocket-Key');
    return null;
  }

  const accept = createHash('sha1')
    .update(key + WS_MAGIC)
    .digest('base64');

  socket.write(
    'HTTP/1.1 101 Switching Protocols
' +
    'Upgrade: websocket
' +
    'Connection: Upgrade
' +
    'Sec-WebSocket-Accept: ' + accept + '
' +
    '
'
  );

  if (head && head.length > 0) socket.unshift(head);

  return socket;
}

// -- WebSocket frame parser

/**
 * Returns a feed(chunk) function.  Invoke with raw socket data chunks.
 * Calls onFrame(opcode, payload) for each complete WebSocket frame.
 *
 * Handles:
 *   - Payload lengths: 7-bit (0-125), 16-bit extended (126), 64-bit (127)
 *   - Client-side masking (MASK=1, 4-byte masking key)
 *   - Opcodes: binary (2), close (8), ping (9), pong (10)
 *   - FIN=1 frames only (no fragmentation)
 *
 * @param {(opcode: number, payload: Buffer) => void} onFrame
 * @returns {(chunk: Buffer) => void}
 */
function makeFrameParser(onFrame) {
  let buf = Buffer.alloc(0);

  return function feed(chunk) {
    buf = Buffer.concat([buf, chunk]);

    // Consume as many complete frames as are buffered.
    while (buf.length >= 2) {
      const opcode       = buf[0] & 0x0f;
      const masked       = (buf[1] & 0x80) !== 0;
      const lenIndicator = buf[1] & 0x7f;

      let headerLen;
      let payloadLen;

      if (lenIndicator <= 125) {
        headerLen  = 2;
        payloadLen = lenIndicator;
      } else if (lenIndicator === 126) {
        if (buf.length < 4) break;       // need 2 more bytes for 16-bit len
        headerLen  = 4;
        payloadLen = buf.readUInt16BE(2);
      } else {
        // 127: 8-byte extended length stored as two 32-bit halves.
        // The high word is always 0 for realistic payload sizes.
        if (buf.length < 10) break;
        headerLen  = 10;
        const hi   = buf.readUInt32BE(2);
        const lo   = buf.readUInt32BE(6);
        payloadLen = hi * 0x100000000 + lo;
      }

      const maskLen  = masked ? 4 : 0;
      const frameLen = headerLen + maskLen + payloadLen;

      if (buf.length < frameLen) break;  // frame incomplete -- wait for more data

      // Extract and unmask the payload.
      let payload;
      if (masked) {
        const maskOffset = headerLen;
        const dataOffset = headerLen + 4;
        const maskKey    = buf.slice(maskOffset, dataOffset);
        payload = Buffer.allocUnsafe(payloadLen);
        for (let i = 0; i < payloadLen; i++) {
          payload[i] = buf[dataOffset + i] ^ maskKey[i & 3];
        }
      } else {
        payload = buf.slice(headerLen, headerLen + payloadLen);
      }

      onFrame(opcode, payload);
      buf = buf.slice(frameLen);
    }
  };
}

// -- WebSocket frame builder

/**
 * Build a server-to-client WebSocket frame (no masking from server per RFC 6455).
 *
 * @param {number} opcode   OP_BINARY, OP_CLOSE, or OP_PONG
 * @param {Buffer} payload
 * @returns {Buffer}
 */
function buildFrame(opcode, payload) {
  const len = payload.length;
  let header;

  if (len <= 125) {
    header = Buffer.allocUnsafe(2);
    header[0] = 0x80 | opcode;   // FIN=1, RSV=000, opcode
    header[1] = len;             // MASK=0, 7-bit length
  } else if (len <= 0xffff) {
    header = Buffer.allocUnsafe(4);
    header[0] = 0x80 | opcode;
    header[1] = 126;
    header.writeUInt16BE(len, 2);
  } else {
    header = Buffer.allocUnsafe(10);
    header[0] = 0x80 | opcode;
    header[1] = 127;
    header.writeUInt32BE(0, 2);           // high 32 bits (always 0)
    header.writeUInt32BE(len >>> 0, 6);  // low  32 bits
  }

  return Buffer.concat([header, payload]);
}

/**
 * Build a close frame carrying the given WebSocket status code.
 * @param {number} code  e.g. 1011 (internal server error)
 * @returns {Buffer}
 */
function buildCloseFrame(code) {
  const payload = Buffer.allocUnsafe(2);
  payload.writeUInt16BE(code, 0);
  return buildFrame(OP_CLOSE, payload);
}

// -- Session handler

/**
 * Relay data between one WebSocket client and one TCP connection.
 *
 * @param {string} ip        Target IPv4/IPv6 address or hostname
 * @param {number} port      Target TCP port
 * @param {import('node:net').Socket} wsSocket  Raw socket after WS upgrade
 * @param {string} tag       Label used in log lines
 */
function handleSession(ip, port, wsSocket, tag) {
  let closed = false;

  function teardown(reason) {
    if (closed) return;
    closed = true;
    console.log('[tcp-proxy] ' + tag + ' disconnected (' + reason + ')');
    tcpSocket.destroy();
    // Best-effort: send a WS close frame before dropping the socket.
    try { wsSocket.write(buildCloseFrame(1011)); } catch (_) {}
    wsSocket.end();
  }

  // Open the outbound TCP connection to the target host:port.
  const tcpSocket = createConnection({ host: ip, port }, () => {
    console.log('[tcp-proxy] ' + tag + ' TCP connected to ' + ip + ':' + port);
  });

  // TCP data -> forward to the browser as a WebSocket binary frame.
  tcpSocket.on('data', (chunk) => {
    if (closed) return;
    try {
      wsSocket.write(buildFrame(OP_BINARY, chunk));
    } catch (_) {
      teardown('ws write error');
    }
  });

  tcpSocket.on('end',   () => teardown('TCP FIN'));
  tcpSocket.on('close', () => teardown('TCP close'));
  tcpSocket.on('error', (err) => {
    console.error('[tcp-proxy] ' + tag + ' TCP error: ' + err.message);
    teardown('TCP error: ' + err.message);
  });

  // Parse incoming WebSocket frames from the browser.
  const feedFrame = makeFrameParser((opcode, payload) => {
    if (closed) return;

    if (opcode === OP_BINARY) {
      // Browser data -> write to remote TCP host.
      tcpSocket.write(payload);
    } else if (opcode === OP_CLOSE) {
      teardown('WS close frame');
    } else if (opcode === OP_PING) {
      // RFC 6455 s.5.5.2: respond with a pong.
      try { wsSocket.write(buildFrame(OP_PONG, payload)); } catch (_) {}
    }
    // Ignore continuation (0), text (1), pong (10), and reserved opcodes.
  });

  wsSocket.on('data',  feedFrame);
  wsSocket.on('end',   () => teardown('WS FIN'));
  wsSocket.on('close', () => teardown('WS close'));
  wsSocket.on('error', (err) => {
    console.error('[tcp-proxy] ' + tag + ' WS error: ' + err.message);
    teardown('WS error: ' + err.message);
  });
}

// -- HTTP server + upgrade handler

const server = createServer((_req, res) => {
  // Plain HTTP requests get a 426 Upgrade Required with a usage hint.
  res.writeHead(426, { 'Content-Type': 'text/plain' });
  res.end(
    'TCP-over-WebSocket proxy.
' +
    'Connect via ws://localhost:' + PORT + '/tcp/{ip}/{port}
'
  );
});

server.on('upgrade', (req, socket, head) => {
  // Validate URL path format: /tcp/<ip>/<port>
  const match = req.url.match(/^/tcp/([^/]+)/(d+)$/);
  if (!match) {
    socket.end(
      'HTTP/1.1 400 Bad Request
' +
      'Content-Type: text/plain

' +
      'Path must be /tcp/{ip}/{port}
'
    );
    return;
  }

  const ip   = match[1];
  const port = parseInt(match[2], 10);

  if (port < 1 || port > 65535) {
    socket.end(
      'HTTP/1.1 400 Bad Request
' +
      'Content-Type: text/plain

' +
      'Invalid port number
'
    );
    return;
  }

  const clientAddr = socket.remoteAddress + ':' + socket.remotePort;
  const tag        = '[' + clientAddr + ' -> ' + ip + ':' + port + ']';
  console.log('[tcp-proxy] ' + tag + ' new connection');

  // Complete the RFC 6455 opening handshake.
  const wsSocket = upgradeToWebSocket(req, socket, head);
  if (!wsSocket) return;

  // Disable Nagle algorithm for lower latency on the WS transport socket.
  wsSocket.setNoDelay(true);

  handleSession(ip, port, wsSocket, tag);
});

server.on('error', (err) => {
  console.error('[tcp-proxy] Server error: ' + err.message);
  process.exit(1);
});

server.listen(PORT, () => {
  console.log('[tcp-proxy] Listening on ws://localhost:' + PORT + '/tcp/{ip}/{port}');
  console.log('[tcp-proxy] Press Ctrl-C to stop.');
});
