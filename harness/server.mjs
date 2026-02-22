/**
 * server.mjs — Development HTTP server for Canary.
 *
 * Run from the repo root:
 *   node harness/server.mjs
 *
 * Routes:
 *   /               → harness/index.html
 *   /steam/*        → steam/* (ext2 images, launch scripts)
 *   /crates/*       → crates/* (WASM pkg output)
 *   /*              → harness/*
 */

import { createServer }           from 'node:http';
import { createReadStream, statSync, existsSync } from 'node:fs';
import { extname, join, resolve } from 'node:path';
import { fileURLToPath }          from 'node:url';

const __dirname = fileURLToPath(new URL('.', import.meta.url));
const ROOT      = resolve(__dirname, '..');
const PORT      = parseInt(process.env.PORT ?? '3000', 10);

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.mjs':  'application/javascript; charset=utf-8',
  '.js':   'application/javascript; charset=utf-8',
  '.ts':   'application/typescript; charset=utf-8',
  '.wasm': 'application/wasm',
  '.ext2': 'application/octet-stream',
  '.json': 'application/json; charset=utf-8',
  '.css':  'text/css; charset=utf-8',
  '.txt':  'text/plain; charset=utf-8',
};

function resolvePath(url) {
  const u = new URL(url, 'http://localhost');
  const p = decodeURIComponent(u.pathname);

  if (p === '/') return join(ROOT, 'harness', 'index.html');

  // steam images served from steam/
  if (p.startsWith('/steam/')) {
    const rel = p.slice('/steam/'.length);
    return join(ROOT, 'steam', rel);
  }

  // WASM pkg and crates
  if (p.startsWith('/crates/')) {
    return join(ROOT, p.slice(1));
  }

  // VkWebGPU-ICD assets (served from SteamWeb/VkWebGPU-ICD/pkg/)
  if (p.startsWith('/vkwebgpu/')) {
    return join(ROOT, '..', 'SteamWeb', 'VkWebGPU-ICD', 'pkg', p.slice('/vkwebgpu/'.length));
  }

  // harness assets
  const candidate = join(ROOT, 'harness', p.slice(1));
  if (existsSync(candidate)) return candidate;

  // fallback to repo root
  return join(ROOT, p.slice(1));
}

const server = createServer((req, res) => {
  const filePath = resolvePath(req.url);

  let stat;
  try { stat = statSync(filePath); } catch {
    res.writeHead(404, { 'Content-Type': 'text/plain' });
    return res.end(`404 Not Found: ${req.url}`);
  }

  const ext   = extname(filePath).toLowerCase();
  const mime  = MIME[ext] ?? 'application/octet-stream';
  const total = stat.size;

  // Support range requests (needed for large ext2 images).
  const range = req.headers['range'];
  if (range) {
    const [, start_s, end_s] = /bytes=(\d+)-(\d*)/.exec(range) ?? [];
    const start = parseInt(start_s, 10);
    const end   = end_s ? parseInt(end_s, 10) : total - 1;
    const chunk = end - start + 1;

    res.writeHead(206, {
      'Content-Range':  `bytes ${start}-${end}/${total}`,
      'Accept-Ranges':  'bytes',
      'Content-Length': chunk,
      'Content-Type':   mime,
      'Last-Modified':  stat.mtime.toUTCString(),
    });
    createReadStream(filePath, { start, end }).pipe(res);
    return;
  }

  res.writeHead(200, {
    'Content-Length': total,
    'Content-Type':   mime,
    'Accept-Ranges':  'bytes',
    'Last-Modified':  stat.mtime.toUTCString(),
    'Cache-Control':  'no-cache',
    // Required for SharedArrayBuffer (if used for stdin later).
    'Cross-Origin-Opener-Policy':   'same-origin',
    'Cross-Origin-Embedder-Policy': 'require-corp',
  });
  createReadStream(filePath).pipe(res);
});

server.listen(PORT, () => {
  console.log(`Canary dev server → http://localhost:${PORT}`);
  console.log('Press Ctrl-C to stop.');
});

// TCP-over-WebSocket proxy: node harness/tcp-proxy.mjs
// Connect via ws://localhost:3001/tcp/{ip}/{port}
