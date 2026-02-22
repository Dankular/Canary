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
