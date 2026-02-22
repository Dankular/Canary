/**
 * canary-host.mjs — Browser harness for the Canary x86-64 WASM emulator.
 *
 * Usage:
 *   1.  wasm-pack build crates/canary-wasm --target web --out-dir pkg
 *   2.  node harness/server.mjs          (serves the harness at :3000)
 *   3.  Open http://localhost:3000
 *
 * Configuration is read from the query string:
 *   ?image=/steam/rootfs-x64.ext2   (ext2 filesystem image, default below)
 *   ?bin=/bin/bash                   (binary to run, default /bin/true)
 *   ?args=-c,echo+hello              (comma-separated argv[1..])
 */

// ── DOM helpers ───────────────────────────────────────────────────────────────

const term   = document.getElementById('terminal');
const dot    = document.getElementById('status-dot');
const status = document.getElementById('status-text');
const canvas = document.getElementById('fb');
const ctx2d  = canvas ? canvas.getContext('2d') : null;

function setStatus(text, kind = 'loading') {
  status.textContent = text;
  dot.className = kind;
}

function print(text, cls = 'log-info') {
  const span = document.createElement('span');
  span.className = cls;
  span.textContent = text + '\n';
  term.appendChild(span);
  term.scrollTop = term.scrollHeight;
}

// ── Configuration from query string ───────────────────────────────────────────

const params   = new URLSearchParams(location.search);
const IMAGE_URL = params.get('image') ?? '/steam/rootfs-x64.ext2';
const BIN       = params.get('bin')   ?? '/bin/true';
const ARGS      = params.get('args')?.split(',') ?? [];
const ENV       = [
  'HOME=/root',
  'USER=root',
  'TERM=xterm-256color',
  'PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
  'LANG=en_US.UTF-8',
];

// ── WebSocket / TCP bridge ────────────────────────────────────────────────────
//
// The WASM module cannot open TCP connections directly.  We bridge via
// WebSocket: each connect() queues a {fd, ip, port} entry; JS opens a WS and
// calls socket_connected() / socket_recv_data() as events arrive.
//
// For real TCP you need a TCP-over-WS proxy (e.g. websockify) on the target
// host.  For servers that already speak WebSocket the connection works directly.
//
// wsMap  — fd (number) → WebSocket instance
// rtRef  — set once we have the runtime; used by pollNetwork closure

let _wsMap = new Map();   // fd → WebSocket
let _rtRef = null;

function startNetworkBridge(rt) {
  _rtRef = rt;
  _wsMap = new Map();
  scheduleNetworkPoll();
}

function scheduleNetworkPoll() {
  requestAnimationFrame(runNetworkPoll);
}

function runNetworkPoll() {
  if (!_rtRef) return;

  // 1. Drain any pending connect() requests and open WebSockets.
  let connectJson;
  try { connectJson = _rtRef.drain_connect_requests(); } catch (_) { connectJson = '[]'; }
  const connects = JSON.parse(connectJson || '[]');
  for (const req of connects) {
    if (_wsMap.has(req.fd)) continue;   // already connecting
    try {
      const url = `ws://${req.ip}:${req.port}`;
      const ws = new WebSocket(url);
      ws.binaryType = 'arraybuffer';
      ws.onopen = () => {
        _rtRef.socket_connected(BigInt(req.fd));
      };
      ws.onmessage = (e) => {
        _rtRef.socket_recv_data(BigInt(req.fd), new Uint8Array(e.data));
      };
      ws.onerror = () => { /* connection refused / failed — leave as Connecting */ };
      ws.onclose = () => { _wsMap.delete(req.fd); };
      _wsMap.set(req.fd, ws);
    } catch (_) { /* WebSocket constructor may throw on bad URLs */ }
  }

  // 2. Drain pending outbound data and forward over WebSocket.
  let sendJson;
  try { sendJson = _rtRef.drain_socket_sends(); } catch (_) { sendJson = '[]'; }
  const sends = JSON.parse(sendJson || '[]');
  for (const req of sends) {
    const ws = _wsMap.get(req.fd);
    if (ws && ws.readyState === WebSocket.OPEN) {
      // Decode base64 data and send as binary.
      try {
        const bin = atob(req.data);
        const buf = new Uint8Array(bin.length);
        for (let i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i);
        ws.send(buf);
      } catch (_) {}
    }
  }

  scheduleNetworkPoll();
}

// ── Main entry point ──────────────────────────────────────────────────────────

export async function canaryMain() {
  try {
    print('[canary] Loading WASM module…', 'log-info');
    setStatus('Loading WASM…');

    // Dynamically import the wasm-pack output.
    const wasmMod = await import('../crates/canary-wasm/pkg/canary_wasm.js');
    await wasmMod.default(); // initialise WASM (calls __wbg_init)

    const { CanaryRuntime } = wasmMod;
    const rt = new CanaryRuntime();

    // ── Start the WebSocket network bridge ────────────────────────────────
    // This RAF loop polls for connect/send events from the WASM module and
    // forwards them via WebSocket.  It starts immediately; it won't do
    // anything until the guest calls socket()/connect().
    startNetworkBridge(rt);

    // ── Framebuffer rendering loop ─────────────────────────────────────────
    // Reads BGRA pixels from the guest's /dev/fb0 mapping and blits them
    // to the <canvas> element every animation frame.
    let fbImageData = ctx2d ? ctx2d.createImageData(1024, 768) : null;
    let fbAnimFrame = null;

    function renderFramebuffer() {
      if (rt.has_framebuffer()) {
        if (canvas) canvas.style.display = 'block';
        const pixels = rt.get_framebuffer();
        if (pixels.length === 1024 * 768 * 4 && fbImageData) {
          // Convert BGRA (guest) → RGBA (ImageData)
          const rgba = fbImageData.data;
          for (let i = 0; i < pixels.length; i += 4) {
            rgba[i]     = pixels[i + 2]; // R ← B channel
            rgba[i + 1] = pixels[i + 1]; // G ← G channel
            rgba[i + 2] = pixels[i];     // B ← R channel
            rgba[i + 3] = 255;           // A = opaque
          }
          ctx2d.putImageData(fbImageData, 0, 0);
        }
      }
      fbAnimFrame = requestAnimationFrame(renderFramebuffer);
    }
    fbAnimFrame = requestAnimationFrame(renderFramebuffer);

    // ── Input event forwarding ────────────────────────────────────────────
    // Keyboard and mouse events on the canvas are forwarded to the runtime
    // (stub — extend when /dev/input emulation is added).
    if (canvas) {
      canvas.addEventListener('keydown', e => {
        // TODO: map KeyboardEvent.code → Linux key code and push to input queue.
        e.preventDefault();
      });
      canvas.addEventListener('mousemove', e => {
        const rect = canvas.getBoundingClientRect();
        const x = Math.round((e.clientX - rect.left) * (1024 / rect.width));
        const y = Math.round((e.clientY - rect.top)  * (768  / rect.height));
        if (rt.push_mouse_event) rt.push_mouse_event(x, y, 0);
      });
      canvas.addEventListener('mousedown', e => {
        if (rt.push_mouse_event) rt.push_mouse_event(0, 0, e.buttons);
      });
      canvas.addEventListener('mouseup', e => {
        if (rt.push_mouse_event) rt.push_mouse_event(0, 0, 0);
      });
    }

    print('[canary] WASM module ready.', 'log-ok');

    // ── Load the filesystem image ─────────────────────────────────────────
    setStatus(`Fetching ${IMAGE_URL}…`);
    print(`[canary] Fetching filesystem image: ${IMAGE_URL}`, 'log-info');

    let fsImageData;
    try {
      const resp = await fetch(IMAGE_URL);
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      const buf = await resp.arrayBuffer();
      fsImageData = new Uint8Array(buf);
      print(`[canary] Image fetched: ${(buf.byteLength / 1024 / 1024).toFixed(1)} MiB`, 'log-ok');
    } catch (e) {
      print(`[canary] WARNING: could not fetch image (${e.message}) — running without rootfs.`, 'log-warn');
      print('[canary] Only files added via add_file() will be available.', 'log-warn');
      fsImageData = null;
    }

    // ── Populate VFS ──────────────────────────────────────────────────────
    if (fsImageData) {
      setStatus('Populating VFS from ext2 image…');
      print('[canary] Loading ext2 image into VFS…', 'log-info');
      rt.load_fs_image(fsImageData);
      print('[canary] VFS ready.', 'log-ok');

      // Show a quick directory listing.
      const rootEntries = JSON.parse(rt.list_dir('/'));
      print(`[canary] / contains: ${rootEntries.map(e => e.name).join(', ')}`, 'log-info');
    }

    // ── Check that the binary exists ──────────────────────────────────────
    if (!rt.path_exists(BIN)) {
      print(`[canary] ERROR: binary '${BIN}' not found in VFS.`, 'log-err');
      print('[canary] Available paths in /bin:', 'log-info');
      try {
        const binEntries = JSON.parse(rt.list_dir('/bin'));
        print('  ' + binEntries.map(e => e.name).join('  '), 'log-info');
      } catch (_) {}
      setStatus('Binary not found', 'error');
      return;
    }

    // ── Execute ───────────────────────────────────────────────────────────
    setStatus(`Running ${BIN}…`);
    print(`[canary] Executing: ${BIN} ${ARGS.join(' ')}`, 'log-ok');

    const elfBytes = rt.read_file(BIN);
    if (!elfBytes) {
      print(`[canary] ERROR: read_file('${BIN}') returned null.`, 'log-err');
      setStatus('Read failed', 'error');
      return;
    }

    rt.add_file(BIN, elfBytes); // ensure it's in the VFS for the syscall layer

    const argvJson = JSON.stringify([BIN, ...ARGS]);
    const envpJson = JSON.stringify(ENV);

    const t0 = performance.now();
    const exitCode = rt.run_elf(elfBytes, argvJson, envpJson);
    const elapsed  = (performance.now() - t0).toFixed(0);

    // ── Flush output ──────────────────────────────────────────────────────
    const stdout = rt.drain_stdout();
    const stderr = rt.drain_stderr();

    if (stdout.length > 0) {
      const text = new TextDecoder().decode(stdout);
      print('[stdout]\n' + text, 'log-stdout');
    }
    if (stderr.length > 0) {
      const text = new TextDecoder().decode(stderr);
      print('[stderr]\n' + text, 'log-stderr');
    }

    // Stop the framebuffer render loop once the process has exited.
    if (fbAnimFrame !== null) cancelAnimationFrame(fbAnimFrame);

    print(`[canary] Process exited: ${exitCode}  (${elapsed} ms)`,
          exitCode === 0 ? 'log-ok' : 'log-err');
    setStatus(`Done (exit ${exitCode})`, exitCode === 0 ? '' : 'error');

    rt.free();
  } catch (err) {
    print(`[canary] FATAL: ${err}\n${err.stack ?? ''}`, 'log-err');
    setStatus('Error', 'error');
    console.error(err);
  }
}
