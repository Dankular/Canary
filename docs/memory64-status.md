# memory64 / wasm64 status

Investigated 2026-08-12 while adding "native memory64 support for Proton" to
WebX. Recorded here so it isn't re-investigated from scratch later.

## The actual problem

Canary's guest emulation (`canary-memory::GuestMemory`) already handles the
full 47-bit x86-64 *virtual* address space fine — it's a software page table
(`HashMap<page_num, frame_idx>`) that allocates physical frames lazily, one
4 KiB frame per guest page actually touched. Sparse VAs (stack at
`0x7FFF_FFFF_F000`, mmap regions anywhere) cost nothing extra.

The real ceiling is the *physical* backing store: all touched frames live in
one `Vec<u8>`, which lives inside the single WASM linear memory backing the
whole Canary instance (guest pages + Rust heap + JIT cache + wasm-bindgen
tables, all sharing it). On the standard `wasm32-unknown-unknown` target,
that memory is hard-capped at 4 GiB by the WASM spec itself (`usize` is
32-bit). A game with a working set bigger than ~3–3.5 GiB of touched guest
pages (common for modern AAA titles) will abort the whole Canary instance
when the backing `Vec<u8>` fails to grow further — not something the guest
can catch or recover from.

The `memory64` WASM proposal (64-bit-indexed linear memory) is the fix in
principle: build Canary for `wasm64-unknown-unknown` so `usize` is 64-bit and
`Vec<u8>` isn't capped at 4 GiB. Two things were checked before investing in
this: does the toolchain support it, and does it actually buy anything today.

## What was verified (Aug 2026 toolchain: rustc 1.99.0-nightly, wasm-bindgen 0.2.111, Chromium 141)

1. **`wasm64-unknown-unknown` exists as a Tier-3 rustc target** and every
   Canary crate — including `canary-wasm` and its full dependency tree
   (`wasm-bindgen` 0.2.111, `js-sys`/`web-sys` 0.3.88,
   `wasm-bindgen-futures` 0.4.61) — compiles cleanly against it via
   `-Z build-std=panic_abort,std` on nightly. The raw output module's memory
   section genuinely carries the memory64 flag (`flags=0x4`, i64 index).

2. **wasm-bindgen 0.2.111 does not actually support wasm64.** Its
   `#[wasm_bindgen]` macro codegen (`src/lib.rs`, `src/rt/*.rs`,
   `src/closure.rs`, `src/externref.rs`) is gated on
   `target_arch = "wasm32"`; anything else falls through to stub/host-test
   code paths. The build **compiles and links without error**, but the
   resulting `.wasm` exports only `memory`, `__wbindgen_externrefs`, and
   `__wbindgen_start` — none of `CanaryRuntime`'s actual methods are
   exported. Confirmed on both debug and release profiles, both pre- and
   post- `wasm-bindgen` CLI processing. This is an upstream wasm-bindgen
   gap, not something fixable from Canary's side.

3. **Even a working wasm64 build would need `table64`, which is patchy.**
   The `wasm64-unknown-unknown` codegen also emits an i64-indexed funcref
   table (used for indirect calls / vtables). Node 22's bundled V8 rejects
   it outright ("invalid table elements limits flags"), even with
   `--experimental-wasm-memory64`. Chromium 141 (the actual deployment
   target) does accept it — confirmed via Playwright against the real
   `chrome` binary, not just Node.

4. **Chromium currently clamps `WebAssembly.Memory` to 65536 pages (4 GiB)
   for ordinary web content even when `index: 'i64'` is requested.**
   `new WebAssembly.Memory({ initial: 1, maximum: 200000, index: 'i64' })`
   throws `Property 'maximum': value 200000 is above the upper bound 65536`
   in a stock Chromium 141 page — this is a browser-side safety default, not
   a spec limit (Node's V8 allows a much higher ceiling given
   `--wasm-max-mem-pages`, but that flag isn't available to ordinary web
   pages). So **even setting aside the wasm-bindgen gap, a memory64 build
   would not currently let a WebX guest exceed 4 GiB** — the practical
   ceiling is identical to today's wasm32 build.

## Conclusion

A genuine memory64 Canary build is blocked on two independent things outside
this repo's control:
- wasm-bindgen shipping real `wasm64-unknown-unknown` support upstream, and
- browsers raising the default memory64 ceiling for web content above 4 GiB.

Neither is under Canary's control, and there's no workaround from this side
— pursuing it further today would just produce a build that silently
doesn't do anything.

## What shipped instead

The guest-facing half of "the OS should support it too" was real and fixable
independent of any of the above: `sysinfo(2)` and `/proc/meminfo` were
hardcoded to report a fixed figure baked into two separate files
(`canary-syscall/src/dispatch.rs`, `canary-fs/src/lib.rs`). That's now a
single named constant (`canary_fs::DEFAULT_TOTAL_RAM_BYTES`) with a
JS-settable override (`CanaryRuntime::set_guest_ram_bytes()`), so:

- the two advertised values can't drift out of sync,
- WebX can size the figure dynamically (e.g. off a browser capability probe)
  instead of it being a Rust-side magic number, and
- the moment memory64 actually becomes viable (both gaps above close), only
  the JS-side call site needs to change — no further Rust changes.

The default value itself is **unchanged from before (3 GiB)** — see the doc
comment on `DEFAULT_TOTAL_RAM_BYTES` for why inflating it without genuine
>4 GiB backing would make things worse, not better (the guest would be
invited to allocate past the real ceiling, aborting the whole instance
instead of one allocation inside it).

## Revisiting this later

Re-run the checks in this doc (they're cheap — no full game boot needed):
1. `cargo +nightly build -p canary-wasm --target wasm64-unknown-unknown -Z build-std=panic_abort,std`
   then check exports on the resulting `.wasm` — real support means
   `CanaryRuntime`-related exports actually appear, not just `memory` /
   `__wbindgen_start`.
2. In a real browser (not just Node): does
   `new WebAssembly.Memory({initial:1, maximum: <bigger than 65536>, index:'i64'})`
   succeed for a plain page?

If both come back positive, `set_guest_ram_bytes()` and a real `pkg64` build
target are the only two things needed to light this up end-to-end.
