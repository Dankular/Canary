/**
 * Device abstractions — mirrors the CheerpX device API.
 *
 * Devices provide backing storage that the Linux runtime mounts
 * into the guest filesystem.
 */

// ── Base types ────────────────────────────────────────────────────────────────

export interface Device {
  delete(): void;
}

export type MountType = "ext2" | "dir" | "devs" | "proc" | "mem";

export interface MountPointConfiguration {
  type: MountType;
  path: string;
  dev:  Device;
}

// ── Block devices (read-only / read-write disk images) ───────────────────────

export interface BlockDevice extends Device {}

/**
 * Streams a remote disk image over HTTP with byte-range requests.
 * Compatible with CheerpX's HttpBytesDevice.
 */
export class HttpBytesDevice implements BlockDevice {
  private constructor(
    public readonly url:    string,
    public readonly _cache: Map<number, Uint8Array> = new Map(),
  ) {}

  static async create(url: string): Promise<HttpBytesDevice> {
    return new HttpBytesDevice(url);
  }

  /** Fetch a byte range from the remote URL. */
  async fetchRange(offset: number, length: number): Promise<Uint8Array> {
    const cached = this._cache.get(offset);
    if (cached) return cached;

    const res = await fetch(this.url, {
      headers: { Range: `bytes=${offset}-${offset + length - 1}` },
    });
    if (!res.ok) throw new Error(`HttpBytesDevice: HTTP ${res.status} fetching ${this.url}`);
    const buf = new Uint8Array(await res.arrayBuffer());
    this._cache.set(offset, buf);
    return buf;
  }

  /** Fetch the complete image. */
  async fetchAll(): Promise<Uint8Array> {
    const res = await fetch(this.url);
    if (!res.ok) throw new Error(`HttpBytesDevice: HTTP ${res.status} fetching ${this.url}`);
    return new Uint8Array(await res.arrayBuffer());
  }

  delete(): void { this._cache.clear(); }
}

// ── GitHub device ─────────────────────────────────────────────────────────────

export class GitHubDevice implements BlockDevice {
  private constructor(public readonly url: string) {}

  static async create(url: string): Promise<GitHubDevice> {
    return new GitHubDevice(url);
  }

  delete(): void {}
}

// ── Cloud device ──────────────────────────────────────────────────────────────

export class CloudDevice implements BlockDevice {
  private constructor(public readonly url: string) {}

  static async create(url: string): Promise<CloudDevice> {
    return new CloudDevice(url);
  }

  delete(): void {}
}

// ── CheerpOS devices (filesystem layers) ─────────────────────────────────────

export interface CheerpOSDevice extends Device {}

/**
 * In-memory data device for ephemeral file storage.
 */
export class DataDevice implements CheerpOSDevice {
  private files: Map<string, Uint8Array> = new Map();

  private constructor() {}

  static async create(): Promise<DataDevice> {
    return new DataDevice();
  }

  async writeFile(path: string, data: string): Promise<void> {
    this.files.set(path, new TextEncoder().encode(data));
  }

  getFiles(): Map<string, Uint8Array> { return this.files; }

  delete(): void { this.files.clear(); }
}

/**
 * IndexedDB-backed persistent device.
 * Stores file data in the browser's IndexedDB for persistence across page loads.
 */
export class IDBDevice implements CheerpOSDevice {
  private db: IDBDatabase | null = null;

  private constructor(public readonly devName: string) {}

  static async create(devName: string): Promise<IDBDevice> {
    const dev = new IDBDevice(devName);
    await dev._open();
    return dev;
  }

  private _open(): Promise<void> {
    return new Promise((resolve, reject) => {
      const req = indexedDB.open(`canary:${this.devName}`, 1);
      req.onupgradeneeded = () => {
        req.result.createObjectStore("files");
      };
      req.onsuccess = () => { this.db = req.result; resolve(); };
      req.onerror   = () => reject(req.error);
    });
  }

  async readFileAsBlob(path: string): Promise<Blob> {
    if (!this.db) throw new Error("IDBDevice not initialised");
    return new Promise((resolve, reject) => {
      const tx  = this.db!.transaction("files", "readonly");
      const req = tx.objectStore("files").get(path);
      req.onsuccess = () => resolve(new Blob([req.result ?? new Uint8Array()]));
      req.onerror   = () => reject(req.error);
    });
  }

  async reset(): Promise<void> {
    if (!this.db) return;
    return new Promise((resolve, reject) => {
      const tx  = this.db!.transaction("files", "readwrite");
      const req = tx.objectStore("files").clear();
      req.onsuccess = () => resolve();
      req.onerror   = () => reject(req.error);
    });
  }

  delete(): void { this.db?.close(); }
}

/**
 * Directory-backed device for exposing local server files.
 */
export class WebDevice implements CheerpOSDevice {
  private constructor(public readonly url: string) {}

  static async create(url: string): Promise<WebDevice> {
    return new WebDevice(url);
  }

  delete(): void {}
}

/**
 * Overlay device — writable layer over a read-only block device.
 * Equivalent to a union filesystem: reads fall through to src, writes go to idb.
 */
export class OverlayDevice implements BlockDevice {
  private constructor(
    public readonly src: BlockDevice,
    public readonly idb: IDBDevice,
  ) {}

  static async create(src: BlockDevice, idb: IDBDevice): Promise<OverlayDevice> {
    return new OverlayDevice(src, idb);
  }

  delete(): void {
    this.src.delete();
    this.idb.delete();
  }
}
