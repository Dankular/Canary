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
      const url = `ws://localhost:3001/tcp/${req.ip}/${req.port}`;
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

// ── WebX GPU bridge (port 0x7860) ─────────────────────────────────────────────
//
// The guest runs libvkwebx.so which communicates via x86 I/O port 0x7860.
// We relay OUT writes to a VkWebGPU-ICD WASM module and push IN responses
// back for the guest to read.
//
// Packet framing: see WebX protocol/commands.h
//   Header: [magic:4][cmd:4][seq:4][len:4]  (16 bytes, little-endian)
//   Response: [seq:4][result:4][len:4]       (12 bytes)
//
// The VkWebGPU-ICD module is loaded lazily on first GPU activity.

const WEBX_PORT = 0x7860;
let vkPlugin = null;  // Will be set to VkWebGPU-ICD when loaded.

// Buffer accumulating bytes from guest OUT writes.
let _ioWriteBuffer = [];

async function loadVkPlugin() {
  try {
    // Try to load the VkWebGPU-ICD WASM module.
    // The module is expected at /vkwebgpu/vkwebgpu.js (add to server routes if needed).
    const mod = await import('/vkwebgpu/vkwebgpu.js');
    vkPlugin = await mod.default();
    console.log('[canary] VkWebGPU-ICD loaded');
  } catch (e) {
    console.warn('[canary] VkWebGPU-ICD not found:', e.message);
    // Fall back to a null plugin that returns VK_ERROR_INITIALIZATION_FAILED.
    vkPlugin = {
      dispatch: (_cmd, _payload) => new Uint8Array([0, 0, 0, 0, 0xfa, 0xff, 0xff, 0xff, 0, 0, 0, 0])
    };
  }
}

function startWebXBridge(rt) {
  loadVkPlugin();
  scheduleIoPoll(rt);
}

function scheduleIoPoll(rt) {
  requestAnimationFrame(() => runIoPoll(rt));
}

function runIoPoll(rt) {
  if (!rt) return;

  try {
    const writesJson = rt.drain_io_writes();
    const writes = JSON.parse(writesJson || '[]');

    for (const w of writes) {
      if (w.port !== WEBX_PORT) continue;

      // Accumulate bytes written to port 0x7860.
      // The guest writes 4 bytes at a time (dword OUT).
      _ioWriteBuffer.push(
        (w.val) & 0xFF,
        (w.val >> 8) & 0xFF,
        (w.val >> 16) & 0xFF,
        (w.val >> 24) & 0xFF,
      );

      // Check if we have a complete packet header (16 bytes).
      if (_ioWriteBuffer.length >= 16) {
        const hdr = new DataView(new Uint8Array(_ioWriteBuffer.slice(0, 16)).buffer);
        const magic = hdr.getUint32(0, true);
        if (magic === 0x58574756) {  // "VGWX"
          const payloadLen = hdr.getUint32(12, true);
          const totalLen = 16 + payloadLen;
          if (_ioWriteBuffer.length >= totalLen) {
            const packet = new Uint8Array(_ioWriteBuffer.splice(0, totalLen));
            // Dispatch to VkWebGPU-ICD and get response.
            const cmd = hdr.getUint32(4, true);
            const seq = hdr.getUint32(8, true);
            const payload = packet.slice(16);

            if (vkPlugin) {
              const resp = vkPlugin.dispatch(cmd, payload, seq);
              // Push response back as IN reads.
              // Protocol: guest does inl (size=4) to read total byte count,
              // then inb (size=1) per byte for the response body.
              if (resp instanceof Uint8Array && resp.length > 0) {
                rt.push_io_read(WEBX_PORT, 4, resp.length);
                for (let i = 0; i < resp.length; i++) {
                  rt.push_io_read(WEBX_PORT, 1, resp[i]);
                }
              }
            }
          }
        } else {
          // Bad magic — discard one byte and retry.
          _ioWriteBuffer.shift();
        }
      }
    }
  } catch (e) { /* don't let errors stop the bridge */ }

  scheduleIoPoll(rt);
}

// ── Thread spawner ────────────────────────────────────────────────────────────
//
// When the guest calls clone(), the WASM runtime queues a CloneInfo record that
// the JS harness drains after each step batch.  spawnThread() creates a Web
// Worker, sends it the shared WASM module + memory, and starts its execution.

let _wasmModule = null;    // cached WebAssembly.Module for sharing with Workers
let _sharedMemory = null;  // cached shared WebAssembly.Memory (SAB-backed, or null)

const _workers = new Map();  // tid → Worker

async function spawnThread(cloneReq) {
  const { tid, child_stack, tls, child_tidptr } = cloneReq;

  const worker = new Worker(new URL('./worker.mjs', import.meta.url), { type: 'module' });
  _workers.set(tid, worker);

  worker.onmessage = (e) => {
    const msg = e.data;
    if (msg.type === 'stdout') {
      print(new TextDecoder().decode(msg.data), 'log-stdout');
    } else if (msg.type === 'stderr') {
      print(new TextDecoder().decode(msg.data), 'log-stderr');
    } else if (msg.type === 'clone') {
      const reqs = JSON.parse(msg.requests);
      for (const req of reqs) spawnThread(req).catch(console.error);
    } else if (msg.type === 'exit') {
      _workers.delete(tid);
    }
  };

  worker.postMessage({
    type: 'init',
    wasmModule: _wasmModule,
    sharedMemory: _sharedMemory,
    tid,
    childStack: child_stack,
    tls,
    childTidptr: child_tidptr,
  }, _sharedMemory ? [_sharedMemory] : []);

  // Wait for 'ready' then start running.
  await new Promise((resolve) => {
    const orig = worker.onmessage;
    worker.onmessage = (e) => {
      if (e.data.type === 'ready') {
        worker.onmessage = orig;
        resolve();
      } else {
        orig(e);
      }
    };
  });
  worker.postMessage({ type: 'run' });
}

// ── Main entry point ──────────────────────────────────────────────────────────

export async function canaryMain() {
  try {
    print('[canary] Loading WASM module…', 'log-info');
    setStatus('Loading WASM…');

    // Dynamically import the wasm-pack output.
    const wasmMod = await import('../crates/canary-wasm/pkg/canary_wasm.js');
    const wasmInitResult = await wasmMod.default(); // initialise WASM (calls __wbg_init)

    // Cache the compiled module and (optional) shared memory for Worker spawning.
    // wasmInitResult may be a WebAssembly.Instance; extract module if available.
    if (wasmInitResult && wasmInitResult.module) {
      _wasmModule = wasmInitResult.module;
    }
    if (wasmInitResult && wasmInitResult.memory) {
      _sharedMemory = wasmInitResult.memory;
    }

    const { CanaryRuntime } = wasmMod;
    const rt = new CanaryRuntime();

    // ── Pre-populate Vulkan ICD configuration ─────────────────────────────
    // The Vulkan loader (libvulkan.so) looks for ICDs in /etc/vulkan/icd.d/.
    // We point it at libvkwebx.so so the guest finds the WebX ICD automatically.
    const enc = new TextEncoder();
    rt.add_file('/etc/vulkan/icd.d/webx.json', enc.encode(JSON.stringify({
      file_format_version: '1.0.0',
      ICD: {
        library_path: '/usr/lib/x86_64-linux-gnu/libvkwebx.so',
        api_version: '1.3.0'
      }
    })));
    // ── /proc stubs needed by glibc / Wine / Vulkan loader ───────────────
    rt.add_file('/proc/version',
      enc.encode('Linux version 6.1.0-canary (gcc 12.3.0)\n'));
    // /proc/self/exe is handled as a special case in readlink() by the Rust
    // runtime (returns proc_exe = argv[0]).  We also add a regular file so
    // that open("/proc/self/exe") succeeds for programs that try to re-read
    // themselves.
    rt.add_file('/proc/self/exe', enc.encode(BIN));
    rt.add_file('/proc/self/cmdline',
      enc.encode([BIN, ...ARGS].join('\0') + '\0'));
    rt.add_file('/proc/self/comm',
      enc.encode(BIN.split('/').pop() + '\n'));
    rt.add_file('/proc/self/stat',
      enc.encode('1 (canary) R 0 1 1 0 -1 4194304 0 0 0 0 0 0 0 0 20 0 1 0 0 0 0 18446744073709551615 0 0 0 0 0 0 0 0 0 0 0 17 0 0 0\n'));
    rt.add_file('/proc/self/status',
      enc.encode('Name:\tcanary\nState:\tR (running)\nPid:\t1\nPPid:\t0\nUid:\t1000\t1000\t1000\t1000\nGid:\t1000\t1000\t1000\t1000\nVmRSS:\t65536 kB\nVmPeak:\t65536 kB\n'));
    rt.add_file('/proc/self/maps', enc.encode(''));  // empty; ntdll tolerates EOF
    rt.add_file('/proc/cpuinfo', enc.encode(
      'processor\t: 0\n' +
      'vendor_id\t: GenuineIntel\n' +
      'cpu family\t: 6\n' +
      'model\t\t: 142\n' +
      'model name\t: Intel(R) Core(TM) i7 (Canary Emulated)\n' +
      'cpu MHz\t\t: 2400.000\n' +
      'cache size\t: 8192 KB\n' +
      'flags\t\t: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat ' +
      'pse36 clflush mmx fxsr sse sse2 ht syscall nx rdtscp lm constant_tsc ' +
      'pni pclmulqdq ssse3 fma cx16 pcid sse4_1 sse4_2 movbe popcnt aes xsave ' +
      'avx f16c rdrand hypervisor lahf_lm abm 3dnowprefetch avx2 bmi1 bmi2\n'));

    // ── Start the WebSocket network bridge ────────────────────────────────
    // This RAF loop polls for connect/send events from the WASM module and
    // forwards them via WebSocket.  It starts immediately; it won't do
    // anything until the guest calls socket()/connect().
    startNetworkBridge(rt);

    // ── Start the WebX GPU IPC bridge ─────────────────────────────────────
    // Relays x86 IN/OUT port 0x7860 to the VkWebGPU-ICD WASM module.
    startWebXBridge(rt);

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
    // via the evdev /dev/input/event0 emulation layer.
    if (canvas) {
      canvas.addEventListener('keydown', e => {
        e.preventDefault();
        rt.push_key_event(e.code, true);
      });
      canvas.addEventListener('keyup', e => {
        e.preventDefault();
        rt.push_key_event(e.code, false);
      });
      canvas.addEventListener('mousemove', e => {
        const rect = canvas.getBoundingClientRect();
        const x = Math.round((e.clientX - rect.left) * (1024 / rect.width));
        const y = Math.round((e.clientY - rect.top)  * (768  / rect.height));
        rt.push_mouse_move(x, y);
      });
      canvas.addEventListener('mousedown', e => {
        rt.push_mouse_button(e.button, true);
      });
      canvas.addEventListener('mouseup', e => {
        rt.push_mouse_button(e.button, false);
      });
      // Capture keyboard focus when canvas is clicked.
      canvas.addEventListener('click', () => canvas.focus());
      canvas.setAttribute('tabindex', '0');
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

    const ok = rt.prepare_elf(elfBytes, argvJson, envpJson);
    if (!ok) {
      print('[canary] ERROR: prepare_elf() failed — check console for details.', 'log-err');
      setStatus('Prepare failed', 'error');
      return;
    }

    // ── Step loop ─────────────────────────────────────────────────────────
    // Drive execution via requestAnimationFrame batches so the browser can
    // render frames, process events, and run the I/O bridges between bursts.
    // This replaces the blocking rt.run_elf() call so long-running guests
    // (Wine, shells, servers) don't freeze the tab.
    const STEPS_PER_FRAME = 50_000;
    const dec = new TextDecoder();

    function stepLoop() {
      let alive = true;
      for (let i = 0; i < STEPS_PER_FRAME && alive; i++) {
        alive = rt.step();
      }

      // Stream stdout/stderr as it arrives rather than buffering until exit.
      const out = rt.drain_stdout();
      if (out.length > 0) print(dec.decode(out), 'log-stdout');
      const err = rt.drain_stderr();
      if (err.length > 0) print(dec.decode(err), 'log-stderr');

      // Spawn any threads the guest cloned during this batch.
      try {
        const cloneRequests = JSON.parse(rt.drain_clone_requests() || '[]');
        for (const req of cloneRequests) spawnThread(req).catch(console.error);
      } catch (_) {}

      if (alive) {
        requestAnimationFrame(stepLoop);
      } else {
        // Guest exited or hit a fatal error — tear down.
        if (fbAnimFrame !== null) cancelAnimationFrame(fbAnimFrame);
        print('[canary] Process stopped.', 'log-ok');
        setStatus('Done', '');
        rt.free();
      }
    }

    requestAnimationFrame(stepLoop);
    // canaryMain() returns here; stepLoop continues asynchronously.
  } catch (err) {
    print(`[canary] FATAL: ${err}\n${err.stack ?? ''}`, 'log-err');
    setStatus('Error', 'error');
    console.error(err);
  }
}
