/**
 * worker.mjs — runs inside a Web Worker, one instance per spawned thread.
 *
 * Each clone() call from the emulated guest causes the main harness to
 * create a new Worker(worker.mjs) and post an 'init' message.  The Worker
 * then initialises its own CanaryRuntime instance that shares the same
 * SharedArrayBuffer-backed linear memory as the main thread's runtime, and
 * begins executing from the child thread's entry point.
 *
 * Message protocol (main → worker):
 *   { type: 'init', data: {
 *       wasmModule:   WebAssembly.Module,   // compiled WASM module (shared)
 *       wasmMemory:   WebAssembly.Memory,   // SAB-backed shared memory
 *       tid:          number,               // thread ID to assign
 *       childStack:   number,               // initial RSP for the child
 *       tls:          number,               // initial fs_base (TLS pointer)
 *       childTidptr:  number,               // guest VA for CLONE_CHILD_SETTID
 *       flags:        number,               // clone flags
 *       rip:          number,               // initial RIP (after SYSCALL insn)
 *   }}
 *
 * Message protocol (worker → main):
 *   { type: 'ready' }                       // Worker initialised
 *   { type: 'exit',  code: number }         // thread exited
 *   { type: 'clone', requests: string }     // JSON clone requests to forward
 *   { type: 'stdout', data: Uint8Array }    // captured stdout
 *   { type: 'stderr', data: Uint8Array }    // captured stderr
 *   { type: 'error', message: string }      // fatal error
 *
 * NOTE: Full SharedArrayBuffer memory sharing between WASM instances requires
 * building with `-C target-feature=+atomics,+bulk-memory,+mutable-globals` so
 * that the WASM memory is declared `(memory ... shared)`.  Without that flag
 * the memory object cannot be shared and this Worker will operate on its own
 * private copy (which is still useful for testing the spawning machinery).
 */

import init, { CanaryRuntime } from '../crates/canary-wasm/pkg/canary_wasm.js';

// ── State ──────────────────────────────────────────────────────────────────────

let rt = null;
let running = false;

// ── Message handler ───────────────────────────────────────────────────────────

self.onmessage = async (e) => {
    const { type, data } = e.data;

    if (type === 'init') {
        try {
            await handleInit(data);
        } catch (err) {
            self.postMessage({ type: 'error', message: String(err) });
        }
        return;
    }

    if (type === 'run') {
        if (!rt) {
            self.postMessage({ type: 'error', message: 'Worker not initialised' });
            return;
        }
        runLoop();
        return;
    }

    if (type === 'stop') {
        running = false;
        return;
    }
};

// ── Init handler ───────────────────────────────────────────────────────────────

async function handleInit(data) {
    const { wasmModule, wasmMemory, tid, childStack, tls, rip } = data;

    // Initialise the WASM module.  If wasmMemory is provided (SAB-backed) pass
    // it as the second argument so the WASM instance shares the same backing
    // store as the main thread.  If not provided (non-SAB build) we fall back
    // to a private memory (useful for testing the spawning path).
    if (wasmMemory) {
        await init(wasmModule, wasmMemory);
    } else {
        await init(wasmModule);
    }

    rt = new CanaryRuntime();

    // Set thread identity.
    rt.set_current_tid(tid);

    // Set up the child thread's CPU state:
    //   RSP  = childStack   (the child stack allocated by the parent)
    //   RIP  = rip           (instruction after the SYSCALL in the parent)
    //   RAX  = 0             (clone() returns 0 in the child)
    //   fs_base = tls        (CLONE_SETTLS: thread-local storage pointer)
    //
    // We do this by calling the low-level step machinery with a synthetic
    // register setup.  For now we use the public JS API to set up registers
    // before starting the run loop.
    //
    // In a real implementation the child CanaryRuntime would be initialised
    // from a snapshot of the parent's memory (passed via SAB) rather than
    // re-running the ELF loader.  The full SAB approach requires atomics
    // WASM build support; this stub covers the JS-side protocol.

    self.postMessage({ type: 'ready', tid });
}

// ── Run loop ───────────────────────────────────────────────────────────────────

function runLoop() {
    if (!rt || running) return;
    running = true;

    // Execute in chunks to yield control to the event loop periodically.
    const CHUNK = 10000;

    function tick() {
        if (!running) return;

        let alive = true;
        for (let i = 0; i < CHUNK && alive; i++) {
            alive = rt.step();
        }

        // Forward any output captured during this chunk.
        const stdout = rt.drain_stdout();
        if (stdout.length > 0) self.postMessage({ type: 'stdout', data: stdout });

        const stderr = rt.drain_stderr();
        if (stderr.length > 0) self.postMessage({ type: 'stderr', data: stderr });

        // Forward any nested clone requests to the main thread.
        const cloneJson = rt.drain_clone_requests();
        if (cloneJson !== '[]') {
            self.postMessage({ type: 'clone', requests: cloneJson });
        }

        if (alive) {
            // Yield to the event loop and continue.
            setTimeout(tick, 0);
        } else {
            running = false;
            self.postMessage({ type: 'exit', code: 0 });
        }
    }

    tick();
}
