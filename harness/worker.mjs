/**
 * worker.mjs — Web Worker for Canary thread execution.
 *
 * Message protocol from main thread:
 *   { type: 'init', wasmModule: WebAssembly.Module, sharedMemory: WebAssembly.Memory,
 *     tid: number, childStack: bigint, tls: bigint, childTidptr: bigint }
 *   { type: 'run' }
 *   { type: 'stop' }
 *
 * Messages sent to main thread:
 *   { type: 'ready' }
 *   { type: 'stdout', data: Uint8Array }
 *   { type: 'stderr', data: Uint8Array }
 *   { type: 'clone', requests: string }  -- JSON array of clone requests
 *   { type: 'exit', code: number }
 */

let rt = null;
let running = false;
let sharedMem = null;

self.onmessage = async (event) => {
    const msg = event.data;

    switch (msg.type) {
        case 'init': {
            // Import the canary WASM module. In the threads build, the module
            // was compiled with +atomics so it accepts a shared memory.
            sharedMem = msg.sharedMemory;

            try {
                // Dynamic import of the wasm-bindgen JS glue.
                // The pkg-threads/ build has shared memory support.
                const wasmJs = await import('../crates/canary-wasm/pkg-threads/canary_wasm.js');

                // Initialize with the SHARED memory object — same buffer as main thread.
                await wasmJs.default(msg.wasmModule, sharedMem);

                const { CanaryRuntime } = wasmJs;
                rt = new CanaryRuntime();

                // Set this Worker's TID so syscalls return the right gettid() value.
                rt.set_current_tid(msg.tid);

                // Initialize the thread's stack pointer and TLS.
                // The thread starts executing after the clone() syscall returns 0 in RAX.
                // child_stack is the new RSP; tls is the FS base (set via arch_prctl).
                rt.init_thread(
                    BigInt(msg.childStack),
                    BigInt(msg.tls),
                    BigInt(msg.childTidptr),
                );

                self.postMessage({ type: 'ready' });
            } catch (e) {
                self.postMessage({ type: 'exit', code: -1 });
                console.error('[worker] init failed:', e);
            }
            break;
        }

        case 'run': {
            if (!rt) return;
            running = true;

            // Run the thread's step loop.
            // We use setTimeout-sliced execution to avoid blocking the Worker.
            function runSlice() {
                if (!running || !rt) return;

                // Run ~1000 steps per slice.
                for (let i = 0; i < 1000 && running; i++) {
                    if (!rt.step()) {
                        running = false;
                        break;
                    }
                }

                // Flush stdout/stderr to main thread.
                const stdout = rt.drain_stdout();
                if (stdout.length > 0) self.postMessage({ type: 'stdout', data: stdout });
                const stderr = rt.drain_stderr();
                if (stderr.length > 0) self.postMessage({ type: 'stderr', data: stderr });

                // Forward any clone() requests to main thread.
                const clones = rt.drain_clone_requests();
                if (clones !== '[]') self.postMessage({ type: 'clone', requests: clones });

                if (running) {
                    setTimeout(runSlice, 0);
                } else {
                    self.postMessage({ type: 'exit', code: 0 });
                }
            }

            setTimeout(runSlice, 0);
            break;
        }

        case 'stop': {
            running = false;
            break;
        }
    }
};
