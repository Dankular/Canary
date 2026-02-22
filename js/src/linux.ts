/**
 * Linux runtime — the core of Canary.
 *
 * Wraps the WASM `CanaryRuntime` and exposes a CheerpX-compatible API.
 */

import type { MountPointConfiguration, Device, HttpBytesDevice, OverlayDevice } from "./devices.js";
import { DataDevice, IDBDevice } from "./devices.js";

// Re-export device types for consumers.
export { DataDevice, IDBDevice } from "./devices.js";
export { HttpBytesDevice, WebDevice, OverlayDevice, CloudDevice, GitHubDevice } from "./devices.js";

// ── WASM module import ────────────────────────────────────────────────────────

let wasmReady: Promise<void> | null = null;
let CanaryRuntimeClass: typeof import("../../crates/canary-wasm/pkg/canary_wasm.js").CanaryRuntime | null = null;

async function ensureWasm() {
  if (wasmReady) return wasmReady;
  wasmReady = (async () => {
    const mod = await import("../../crates/canary-wasm/pkg/canary_wasm.js");
    await mod.default(); // run wasm-pack's init()
    CanaryRuntimeClass = mod.CanaryRuntime;
  })();
  return wasmReady;
}

// ── Networking ────────────────────────────────────────────────────────────────

export interface NetworkInterface {
  /** Tailscale auth key */
  authKey?:       string;
  controlUrl?:    string;
  loginUrlCb?:    (url: string) => void;
  stateUpdateCb?: (state: number) => void;
  netmapUpdateCb?:(map: unknown)  => void;
}

// ── Console callbacks ─────────────────────────────────────────────────────────

type ConsoleWriteFn = (buffer: Uint8Array, vt: number) => void;

// ── Linux runtime ─────────────────────────────────────────────────────────────

export interface LinuxCreateOptions {
  mounts?:           MountPointConfiguration[];
  networkInterface?: NetworkInterface;
  /** Starting directory inside the guest (default "/"). */
  cwd?:              string;
}

export interface RunResult {
  status: number;
}

export interface RunOptions {
  env?:  string[];
  cwd?:  string;
  uid?:  number;
  gid?:  number;
}

/**
 * The Canary Linux runtime.
 *
 * API is a superset of CheerpX's `Linux` class:
 *   - Full x86-64 ELF support (CheerpX only supports 32-bit)
 *   - Self-hosted WASM (no CDN dependency)
 *   - Same `create()` / `run()` / `setConsole()` surface
 */
export class Linux {
  private runtime: InstanceType<typeof CanaryRuntimeClass> | null = null;
  private mounts:  MountPointConfiguration[];
  private consoleEl: HTMLElement | null = null;
  private customConsoleFn: ConsoleWriteFn | null = null;
  private eventListeners: Map<string, Set<(state: string | number) => void>> = new Map();

  private constructor(mounts: MountPointConfiguration[]) {
    this.mounts = mounts;
  }

  /**
   * Create a new Linux runtime instance.
   *
   * @example
   * ```ts
   * const cx = await Linux.create({
   *   mounts: [
   *     { type: "ext2", path: "/", dev: await HttpBytesDevice.create("/disk.ext2") },
   *   ],
   * });
   * const result = await cx.run("/bin/bash", ["-c", "echo hello"]);
   * ```
   */
  static async create(options: LinuxCreateOptions = {}): Promise<Linux> {
    await ensureWasm();

    const linux = new Linux(options.mounts ?? []);
    linux.runtime = new CanaryRuntimeClass!();

    if (options.cwd) {
      linux.runtime.set_cwd(options.cwd);
    }

    // Mount devices into the virtual filesystem.
    for (const mount of options.mounts ?? []) {
      await linux._mountDevice(mount);
    }

    return linux;
  }

  private async _mountDevice(mount: MountPointConfiguration): Promise<void> {
    const runtime = this.runtime!;
    const dev = mount.dev as any;

    if (dev instanceof DataDevice) {
      for (const [path, data] of dev.getFiles()) {
        runtime.add_file(`${mount.path}/${path}`, data);
      }
    } else if ("fetchAll" in dev && typeof dev.fetchAll === "function") {
      // HttpBytesDevice or similar — load entire image if small enough.
      try {
        const data: Uint8Array = await dev.fetchAll();
        runtime.load_fs_image(data);
      } catch (e) {
        console.warn("Canary: failed to load fs image:", e);
      }
    }
    // Other device types (IDB, overlay) — TODO: implement lazy loading.
  }

  /**
   * Run an x86-64 ELF binary inside the virtual machine.
   *
   * @param fileName Path to the ELF binary inside the guest filesystem.
   * @param args     argv array (including argv[0]).
   * @param options  Optional: env vars, working directory, uid/gid.
   */
  async run(
    fileName: string,
    args:     string[],
    options:  RunOptions = {},
  ): Promise<RunResult> {
    if (!this.runtime) throw new Error("Linux runtime not initialised");

    const runtime = this.runtime;

    // Read the ELF binary from the VFS (if mounted) or fetch it.
    let elfBytes: Uint8Array;
    try {
      elfBytes = await this._readFile(fileName);
    } catch (e) {
      throw new Error(`Canary: cannot read ${fileName}: ${e}`);
    }

    const argv = [fileName, ...args.slice(1)];
    const envp = options.env ?? [
      "HOME=/root",
      "USER=user",
      `PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin`,
      "TERM=xterm-256color",
      "LANG=en_US.UTF-8",
    ];

    if (options.cwd) runtime.set_cwd(options.cwd);

    this._emit("progress", "loading");

    return new Promise<RunResult>((resolve) => {
      // Run in a micro-task to allow the event loop to update the UI.
      queueMicrotask(() => {
        const status = runtime.run_elf(
          elfBytes,
          JSON.stringify(argv),
          JSON.stringify(envp),
        );

        // Flush output.
        this._flushOutput();

        this._emit("progress", "ready");
        resolve({ status });
      });
    });
  }

  // ── Console plumbing ────────────────────────────────────────────────────────

  /** Attach a DOM element to receive stdout/stderr as text. */
  setConsole(el: HTMLElement): void {
    this.consoleEl = el;
  }

  /**
   * Attach a custom console function.
   * Returns a function that accepts key codes for stdin.
   */
  setCustomConsole(
    writeFn:  ConsoleWriteFn,
    columns:  number,
    rows:     number,
  ): (keyCode: number) => void {
    this.customConsoleFn = writeFn;
    // TODO: propagate terminal size to the guest via SIGWINCH / ioctl.
    return (keyCode: number) => {
      this.runtime?.write_stdin(new Uint8Array([keyCode]));
    };
  }

  /**
   * Activate a specific virtual console (VT).
   * Used by Xorg/KMS-based graphical environments.
   */
  setActivateConsole(activateFunc: (_: number) => void): EventListener {
    const handler = (e: Event) => {
      if (e instanceof CustomEvent) activateFunc(e.detail as number);
    };
    window.addEventListener("canary:activate-console", handler);
    return handler as EventListener;
  }

  // ── Event system (compatible with CheerpX callbacks) ───────────────────────

  registerCallback(eventName: string, callback: (state: string | number) => void): void {
    if (!this.eventListeners.has(eventName)) {
      this.eventListeners.set(eventName, new Set());
    }
    this.eventListeners.get(eventName)!.add(callback);
  }

  unregisterCallback(eventName: string, callback: (state: string | number) => void): void {
    this.eventListeners.get(eventName)?.delete(callback);
  }

  private _emit(event: string, state: string | number): void {
    this.eventListeners.get(event)?.forEach(cb => cb(state));
  }

  // ── Cleanup ─────────────────────────────────────────────────────────────────

  delete(): void {
    this.runtime?.free();
    this.runtime = null;
  }

  // ── Private helpers ─────────────────────────────────────────────────────────

  private async _readFile(path: string): Promise<Uint8Array> {
    // Check if this path exists as a mounted file (add_file'd).
    // For now we throw — callers must pre-load ELF bytes.
    throw new Error(`_readFile: ${path} not found in VFS (pre-load ELF bytes via add_file)`);
  }

  private _flushOutput(): void {
    if (!this.runtime) return;

    const stdout = this.runtime.drain_stdout();
    const stderr = this.runtime.drain_stderr();

    const combined = new Uint8Array(stdout.length + stderr.length);
    combined.set(stdout, 0);
    combined.set(stderr, stdout.length);

    if (combined.length === 0) return;

    if (this.customConsoleFn) {
      if (stdout.length > 0) this.customConsoleFn(stdout, 1);
      if (stderr.length > 0) this.customConsoleFn(stderr, 2);
    } else if (this.consoleEl) {
      const text = new TextDecoder().decode(combined);
      this.consoleEl.textContent += text;
    } else {
      // Default: write to browser console.
      if (stdout.length > 0) process?.stdout?.write?.(stdout);
      if (stderr.length > 0) process?.stderr?.write?.(stderr);
    }
  }
}

// ── Convenience re-export mirroring CheerpX default export ───────────────────

const Canary = {
  Linux,
  DataDevice,
  IDBDevice,
};

export default Canary;
