//! Async ext2/ext4 filesystem reader using HTTP Range requests.
//!
//! Traverses the on-disk directory tree block-by-block via server Range requests,
//! building a MemFs incrementally.  The full image (~7 GiB) is never allocated;
//! only the blocks actually needed (superblock, BGDT, inode tables, dir data,
//! small file data) are fetched and cached.
//!
//! Supports:
//!  - ext2-style direct / single-indirect / double-indirect block maps
//!  - ext4 extent trees (depth 0 inline, depth 1 via index blocks, depth 2 partial)
//!  - Short inline symlinks stored in i_block[]
//!  - Files > MAX_FILE_BYTES are inserted as empty placeholders

use std::collections::HashMap;

use wasm_bindgen::JsCast;
use wasm_bindgen::JsValue;
use wasm_bindgen_futures::JsFuture;
use web_sys::{Request, RequestInit, RequestMode, Response};

use canary_fs::MemFs;

/// Files larger than this are inserted as empty placeholders to bound RAM use.
const MAX_FILE_BYTES: usize = 128 * 1024 * 1024; // 128 MiB

/// ext4 extent tree header magic.
const EXT4_EXT_MAGIC: u16 = 0xF30A;

/// ext4 inode flag: i_block[] is an extent tree, not a block map.
const EXT4_EXTENTS_FL: u32 = 0x0008_0000;

// ── Byte helpers ─────────────────────────────────────────────────────────────

#[inline]
fn u16le(d: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([d[off], d[off + 1]])
}

#[inline]
fn u32le(d: &[u8], off: usize) -> u32 {
    let b: [u8; 4] = d[off..off + 4].try_into().unwrap_or([0; 4]);
    u32::from_le_bytes(b)
}

// ── HTTP Range fetch ──────────────────────────────────────────────────────────

/// Fetch `bytes=start–end_incl` from `url` and return the bytes.
async fn fetch_range(url: &str, start: u64, end_incl: u64) -> Result<Vec<u8>, JsValue> {
    let window = web_sys::window().ok_or_else(|| JsValue::from_str("no window"))?;

    let opts = RequestInit::new();
    opts.set_method("GET");
    opts.set_mode(RequestMode::SameOrigin);

    let req = Request::new_with_str_and_init(url, &opts)?;
    req.headers().set("Range", &format!("bytes={}-{}", start, end_incl))?;

    let resp_val = JsFuture::from(window.fetch_with_request(&req)).await?;
    let resp: Response = resp_val.dyn_into()?;

    // Both 200 OK and 206 Partial Content are valid.
    if resp.status() != 200 && resp.status() != 206 {
        return Err(JsValue::from_str(&format!("HTTP {}", resp.status())));
    }

    let buf = JsFuture::from(resp.array_buffer()?).await?;
    Ok(js_sys::Uint8Array::new(&buf).to_vec())
}

// ── Superblock info ───────────────────────────────────────────────────────────

struct Sb {
    block_size:       usize,
    inode_size:       usize,
    inodes_per_group: usize,
    _bgdt_offset:     usize,
}

// ── Remote reader ─────────────────────────────────────────────────────────────

pub struct RemoteExt2 {
    url:         String,
    sb:          Option<Sb>,
    bgdt:        Vec<u8>,          // raw block-group descriptor table
    block_cache: HashMap<u32, Vec<u8>>,
    /// Cache of absolute path → inode number for directory entries already resolved.
    dir_cache:   HashMap<String, u32>,
}

impl RemoteExt2 {
    pub fn new(url: String) -> Self {
        RemoteExt2 {
            url,
            sb:          None,
            bgdt:        Vec::new(),
            block_cache: HashMap::new(),
            dir_cache:   HashMap::new(),
        }
    }

    // ── Initialisation ────────────────────────────────────────────────────────

    /// Fetch and parse the superblock + block-group descriptor table.
    /// Must succeed before `populate_memfs` is called.
    pub async fn init(&mut self) -> bool {
        // Fetch the first 64 KiB; covers the superblock and BGDT for most images.
        let header = match fetch_range(&self.url, 0, 65535).await {
            Ok(d)  => d,
            Err(_) => return false,
        };
        if header.len() < 2048 { return false; }

        let sb = &header[1024..];
        if u16le(sb, 56) != 0xEF53 { return false; } // bad ext2 magic

        let log_bsz          = u32le(sb, 24) as usize;
        let block_size        = 1024usize << log_bsz;
        let inodes_per_group  = u32le(sb, 40) as usize;
        let first_data_block  = u32le(sb, 20) as usize;
        let rev_level         = u32le(sb, 76);
        let inode_size        = if rev_level >= 1 { u16le(sb, 88) as usize } else { 128 };

        let bgdt_block  = first_data_block + 1;
        let bgdt_offset = bgdt_block * block_size;

        // Derive BGDT size from block/group counts.
        let total_blocks     = u32le(sb, 4) as usize;
        let blocks_per_group = u32le(sb, 32) as usize;
        let num_groups = if blocks_per_group > 0 {
            (total_blocks + blocks_per_group - 1) / blocks_per_group
        } else {
            1
        };
        let bgdt_size = num_groups * 32;
        let bgdt_end  = bgdt_offset + bgdt_size;

        // Pull BGDT from the header we already fetched, or make a second request.
        let bgdt = if bgdt_end <= header.len() {
            header[bgdt_offset..bgdt_end].to_vec()
        } else {
            match fetch_range(&self.url, bgdt_offset as u64, (bgdt_end - 1) as u64).await {
                Ok(d)  => d,
                Err(_) => return false,
            }
        };

        self.bgdt = bgdt;
        self.sb   = Some(Sb { block_size, inode_size, inodes_per_group, _bgdt_offset: bgdt_offset });
        true
    }

    // ── Block cache ───────────────────────────────────────────────────────────

    /// Return the physical block `block`, fetching it from the server if needed.
    /// Returns an owned `Vec<u8>` to avoid borrow conflicts with `&mut self`.
    async fn fetch_block(&mut self, block: u32) -> Option<Vec<u8>> {
        let block_size = self.sb.as_ref()?.block_size;
        if !self.block_cache.contains_key(&block) {
            let start = block as u64 * block_size as u64;
            let end   = start + block_size as u64 - 1;
            let data  = fetch_range(&self.url, start, end).await.ok()?;
            self.block_cache.insert(block, data);
        }
        self.block_cache.get(&block).cloned()
    }

    // ── Inode access ──────────────────────────────────────────────────────────

    fn inode_table_block_for_group(&self, group: usize) -> u32 {
        let off = group * 32;
        if off + 12 > self.bgdt.len() { return 0; }
        u32le(&self.bgdt, off + 8) // bg_inode_table (lo 32 bits)
    }

    /// Fetch the raw inode bytes for inode number `ino` (1-based).
    pub async fn get_inode(&mut self, ino: u32) -> Option<Vec<u8>> {
        if ino == 0 { return None; }
        let (inode_size, block_size, inodes_per_group) = {
            let sb = self.sb.as_ref()?;
            (sb.inode_size, sb.block_size, sb.inodes_per_group)
        };

        let idx   = (ino as usize) - 1;
        let group = idx / inodes_per_group;
        let local = idx % inodes_per_group;

        let table_block  = self.inode_table_block_for_group(group);
        if table_block == 0 { return None; }

        let byte_off     = local * inode_size;
        let block_off    = byte_off / block_size;
        let off_in_block = byte_off % block_size;
        let block_no     = table_block + block_off as u32;

        let block = self.fetch_block(block_no).await?;
        if off_in_block + inode_size > block.len() { return None; }
        Some(block[off_in_block..off_in_block + inode_size].to_vec())
    }

    // ── Inode field accessors ─────────────────────────────────────────────────

    #[inline] fn inode_mode(inode: &[u8])      -> u16 { u16le(inode, 0) }
    #[inline] fn inode_flags(inode: &[u8])     -> u32 { u32le(inode, 32) }
    #[inline] fn inode_uses_extents(inode: &[u8]) -> bool {
        inode.len() >= 36 && (Self::inode_flags(inode) & EXT4_EXTENTS_FL) != 0
    }
    #[inline] fn inode_file_size(inode: &[u8]) -> usize {
        let lo = u32le(inode, 4) as u64;
        let hi = u32le(inode, 108) as u64;
        ((hi << 32) | lo) as usize
    }

    // ── File data: ext2 block-map path ────────────────────────────────────────

    /// Read file content using the ext2 direct/indirect block-pointer scheme.
    /// `iblock` is the 60-byte i_block[] array from the inode (at offset 40).
    async fn read_via_block_map(&mut self, iblock: &[u8; 60], file_size: usize) -> Vec<u8> {
        let block_size = match self.sb.as_ref() { Some(s) => s.block_size, None => return vec![] };
        let ptrs       = block_size / 4;
        let mut out       = Vec::with_capacity(file_size.min(MAX_FILE_BYTES));
        let mut remaining = file_size;

        // Prefetch direct blocks in parallel before reading.
        let direct: Vec<u32> = (0..12usize)
            .map(|i| u32le(iblock, i * 4))
            .take_while(|&b| b != 0)
            .collect();
        self.prefetch_blocks(&direct).await;

        // Direct blocks i_block[0..11]
        for i in 0..12usize {
            if remaining == 0 { break; }
            let blk = u32le(iblock, i * 4);
            if blk == 0 { break; }
            if let Some(data) = self.fetch_block(blk).await {
                let n = data.len().min(remaining);
                out.extend_from_slice(&data[..n]);
                remaining -= n;
            }
        }

        // Single indirect: i_block[12] at byte offset 48
        if remaining > 0 {
            let ind = u32le(iblock, 48);
            if ind != 0 {
                if let Some(ind_data) = self.fetch_block(ind).await {
                    for j in 0..ptrs {
                        if remaining == 0 { break; }
                        let blk = u32le(&ind_data, j * 4);
                        if blk == 0 { break; }
                        if let Some(data) = self.fetch_block(blk).await {
                            let n = data.len().min(remaining);
                            out.extend_from_slice(&data[..n]);
                            remaining -= n;
                        }
                    }
                }
            }
        }

        // Double indirect: i_block[13] at byte offset 52
        if remaining > 0 {
            let dbl = u32le(iblock, 52);
            if dbl != 0 {
                if let Some(dbl_data) = self.fetch_block(dbl).await {
                    for i in 0..ptrs {
                        if remaining == 0 { break; }
                        let ind = u32le(&dbl_data, i * 4);
                        if ind == 0 { break; }
                        if let Some(ind_data) = self.fetch_block(ind).await {
                            for j in 0..ptrs {
                                if remaining == 0 { break; }
                                let blk = u32le(&ind_data, j * 4);
                                if blk == 0 { break; }
                                if let Some(data) = self.fetch_block(blk).await {
                                    let n = data.len().min(remaining);
                                    out.extend_from_slice(&data[..n]);
                                    remaining -= n;
                                }
                            }
                        }
                    }
                }
            }
        }
        // Triple indirect skipped — files > ~2 GiB won't be needed (MAX_FILE_BYTES = 128 MiB).
        out
    }

    // ── File data: ext4 extent-tree path ─────────────────────────────────────

    /// Read file content using the ext4 extent tree embedded in i_block[].
    async fn read_via_extents(&mut self, iblock: &[u8; 60], file_size: usize) -> Vec<u8> {
        let eh_magic   = u16le(iblock, 0);
        if eh_magic != EXT4_EXT_MAGIC { return vec![]; }

        let eh_entries = u16le(iblock, 2) as usize;
        let eh_depth   = u16le(iblock, 6);

        // Collect (phys_start_block, num_blocks) pairs for all leaf extents.
        let mut leaf_extents: Vec<(u64, usize)> = Vec::new();

        if eh_depth == 0 {
            // Extent leaf entries are inline in the inode (max 4 fit in 48 bytes).
            for i in 0..eh_entries {
                let off = 12 + i * 12;
                if off + 12 > 60 { break; }
                let ee_len = (u16le(iblock, off + 4) & 0x7FFF) as usize;
                let ee_hi  = u16le(iblock, off + 6) as u64;
                let ee_lo  = u32le(iblock, off + 8) as u64;
                leaf_extents.push(((ee_hi << 32) | ee_lo, ee_len));
            }
        } else {
            // Index node: extent index entries in inode; child blocks hold leaves.
            // Collect child physical block numbers without holding a borrow on iblock.
            let mut index_blocks: Vec<u32> = Vec::with_capacity(eh_entries);
            for i in 0..eh_entries {
                let off = 12 + i * 12;
                if off + 12 > 60 { break; }
                let ei_lo = u32le(iblock, off + 4) as u64;
                let ei_hi = u16le(iblock, off + 8) as u64;
                index_blocks.push(((ei_hi << 32) | ei_lo) as u32);
            }
            // Prefetch ALL index blocks in parallel before sequential traversal.
            self.prefetch_blocks(&index_blocks).await;
            for idx_blk in index_blocks {
                if let Some(child) = self.fetch_block(idx_blk).await {
                    self.collect_leaf_extents_from_block(&child, &mut leaf_extents).await;
                }
            }
        }

        // Prefetch all leaf content blocks in one parallel batch.
        {
            let all_leaf_blocks: Vec<u32> = leaf_extents.iter()
                .flat_map(|&(phys_start, len)| (0..len).map(move |j| (phys_start + j as u64) as u32))
                .collect();
            self.prefetch_blocks(&all_leaf_blocks).await;
        }
        // Materialise file content from the ordered leaf extents.
        let mut out       = Vec::with_capacity(file_size.min(MAX_FILE_BYTES));
        let mut remaining = file_size;
        'outer: for (phys_start, len) in leaf_extents {
            for j in 0..len {
                if remaining == 0 { break 'outer; }
                let phys = (phys_start + j as u64) as u32;
                if let Some(data) = self.fetch_block(phys).await {
                    let n = data.len().min(remaining);
                    out.extend_from_slice(&data[..n]);
                    remaining -= n;
                }
            }
        }
        out
    }

    /// Parse an extent block (fetched from disk) and append its leaf extents.
    /// Handles depth-0 leaf blocks and depth-1 index blocks (one more level).
    async fn collect_leaf_extents_from_block(
        &mut self,
        block_data: &[u8],
        out: &mut Vec<(u64, usize)>,
    ) {
        if block_data.len() < 12 { return; }
        if u16le(block_data, 0) != EXT4_EXT_MAGIC { return; }

        let entries = u16le(block_data, 2) as usize;
        let depth   = u16le(block_data, 6);

        if depth == 0 {
            // Leaf: extent entries directly.
            for i in 0..entries {
                let off = 12 + i * 12;
                if off + 12 > block_data.len() { break; }
                let ee_len = (u16le(block_data, off + 4) & 0x7FFF) as usize;
                let ee_hi  = u16le(block_data, off + 6) as u64;
                let ee_lo  = u32le(block_data, off + 8) as u64;
                out.push(((ee_hi << 32) | ee_lo, ee_len));
            }
        } else {
            // Index: collect child block numbers, fetch each, process as leaves.
            let mut child_blocks: Vec<u32> = Vec::with_capacity(entries);
            for i in 0..entries {
                let off = 12 + i * 12;
                if off + 12 > block_data.len() { break; }
                let ei_lo = u32le(block_data, off + 4) as u64;
                let ei_hi = u16le(block_data, off + 8) as u64;
                child_blocks.push(((ei_hi << 32) | ei_lo) as u32);
            }
            // Prefetch all child index blocks in parallel.
            self.prefetch_blocks(&child_blocks).await;
            for child_blk in child_blocks {
                if let Some(child_data) = self.fetch_block(child_blk).await {
                    // Only process leaves (depth 0); deeper nesting is not needed
                    // because MAX_FILE_BYTES = 128 MiB limits file size.
                    if child_data.len() >= 12
                        && u16le(&child_data, 0) == EXT4_EXT_MAGIC
                        && u16le(&child_data, 6) == 0
                    {
                        let lentries = u16le(&child_data, 2) as usize;
                        for i in 0..lentries {
                            let off = 12 + i * 12;
                            if off + 12 > child_data.len() { break; }
                            let ee_len = (u16le(&child_data, off + 4) & 0x7FFF) as usize;
                            let ee_hi  = u16le(&child_data, off + 6) as u64;
                            let ee_lo  = u32le(&child_data, off + 8) as u64;
                            out.push(((ee_hi << 32) | ee_lo, ee_len));
                        }
                    }
                }
            }
        }
    }

    // ── Read inode content ────────────────────────────────────────────────────

    /// Read the full content of a file or symlink inode.
    pub async fn read_inode_data(&mut self, inode: &[u8]) -> Vec<u8> {
        let size = Self::inode_file_size(inode);
        let mode = Self::inode_mode(inode);

        if size > MAX_FILE_BYTES { return vec![]; }

        // Fast path: short symlink target stored inline in i_block[].
        if (mode >> 12) == 0xA {
            let i_blocks = u32le(inode, 28); // disk block count (units of 512 B)
            if i_blocks == 0 && size <= 60 {
                let buf: [u8; 60] = inode[40..100].try_into().unwrap_or([0; 60]);
                return buf[..size].to_vec();
            }
        }

        // Copy i_block[] to a local array so we can hold &mut self in the reader.
        let iblock: [u8; 60] = inode[40..100].try_into().unwrap_or([0; 60]);

        if Self::inode_uses_extents(inode) {
            self.read_via_extents(&iblock, size).await
        } else {
            self.read_via_block_map(&iblock, size).await
        }
    }

    // ── Directory parsing ─────────────────────────────────────────────────────

    /// Parse raw directory data into `(name, inode_number, file_type)` triples.
    /// Uses the dir_entry_2 format (ext2 rev1+, always present in ext4).
    /// file_type: 1=regular, 2=dir, 7=symlink, others=special.
    fn parse_dir_data(data: &[u8]) -> Vec<(String, u32, u8)> {
        let mut entries = Vec::new();
        let mut off = 0usize;
        while off + 8 <= data.len() {
            let ino       = u32le(data, off);
            let rec_len   = u16le(data, off + 4) as usize;
            let name_len  = data[off + 6] as usize;
            let file_type = data[off + 7];
            if rec_len == 0 { break; }
            if ino != 0 && name_len > 0 && off + 8 + name_len <= data.len() {
                if let Ok(name) = std::str::from_utf8(&data[off + 8..off + 8 + name_len]) {
                    if name != "." && name != ".." {
                        entries.push((name.to_string(), ino, file_type));
                    }
                }
            }
            off += rec_len;
        }
        entries
    }

    // ── Filesystem traversal ──────────────────────────────────────────────────

    /// Fetch the full content of inode `ino`.  Used for on-demand file loading
    /// after `populate_memfs` has already built the directory skeleton.
    pub async fn fetch_file(&mut self, ino: u32) -> Option<Vec<u8>> {
        let inode = self.get_inode(ino).await?;
        Some(self.read_inode_data(&inode).await)
    }

    // ── Parallel prefetch helpers ─────────────────────────────────────────────

    /// Compute which physical block the inode table entry for `ino` lives in,
    /// without performing any network fetch.  Returns `None` if the superblock
    /// has not been loaded yet or `ino` is 0.
    fn inode_block_for(&self, ino: u32) -> Option<u32> {
        if ino == 0 { return None; }
        let sb = self.sb.as_ref()?;
        let idx   = (ino as usize) - 1;
        let group = idx / sb.inodes_per_group;
        let local = idx % sb.inodes_per_group;
        let table_block = self.inode_table_block_for_group(group);
        if table_block == 0 { return None; }
        let byte_off  = local * sb.inode_size;
        let block_off = byte_off / sb.block_size;
        Some(table_block + block_off as u32)
    }

    /// Fetch multiple blocks concurrently via parallel HTTP Range requests.
    ///
    /// Consecutive block numbers are coalesced into a single Range request to
    /// reduce round-trips and maximise throughput.  Each coalesced run is
    /// capped at `MAX_COALESCE_BLOCKS` blocks (≤ 1 MiB for 4 KiB blocks) to
    /// bound individual response size.  All runs are issued in parallel via
    /// `futures::future::join_all`; with HTTP/2 the server can serve dozens of
    /// streams concurrently over one connection.
    ///
    /// Blocks already present in `block_cache` are skipped.  Successfully
    /// fetched blocks are inserted into `block_cache` before returning.
    async fn prefetch_blocks(&mut self, block_nos: &[u32]) {
        let block_size = match self.sb.as_ref() { Some(s) => s.block_size, None => return };

        let mut needed: Vec<u32> = block_nos.iter()
            .filter(|&&b| b != 0 && !self.block_cache.contains_key(&b))
            .copied()
            .collect();
        needed.sort_unstable();
        needed.dedup();
        if needed.is_empty() { return; }

        // Merge consecutive block numbers into runs; cap each run to 256 blocks.
        const MAX_COALESCE: u32 = 256;
        let mut runs: Vec<(u32, u32)> = Vec::new(); // (first_block, count)
        let mut run_start = needed[0];
        let mut run_len   = 1u32;
        for &b in &needed[1..] {
            if b == run_start + run_len && run_len < MAX_COALESCE {
                run_len += 1;
            } else {
                runs.push((run_start, run_len));
                run_start = b;
                run_len   = 1;
            }
        }
        runs.push((run_start, run_len));

        let url = self.url.clone();
        let bs  = block_size as u64;

        // Fire all run-fetches in parallel (no reference to `self` in closures).
        let fetches: Vec<_> = runs.iter().map(|&(first, count)| {
            let url   = url.clone();
            let start = first as u64 * bs;
            let end   = start + count as u64 * bs - 1;
            async move { (first, count, fetch_range(&url, start, end).await) }
        }).collect();

        let results = futures::future::join_all(fetches).await;
        for (first, count, result) in results {
            if let Ok(data) = result {
                // Slice the coalesced response back into individual cached blocks.
                let bs = block_size as usize;
                for i in 0..count as usize {
                    let s = i * bs;
                    let e = (s + bs).min(data.len());
                    if s < data.len() {
                        self.block_cache.insert(first + i as u32, data[s..e].to_vec());
                    }
                }
            }
        }
    }

    /// Traverse the ext2/ext4 image and populate `fs` with directory structure,
    /// symlinks, and empty file stubs.  File *content* is NOT fetched here —
    /// use `fetch_file` to load specific files on demand.
    ///
    /// `inode_map` is populated with path → inode number for every regular file,
    /// allowing callers to fetch content via `fetch_file(ino)` later.
    pub async fn populate_memfs(&mut self, fs: &mut MemFs, inode_map: &mut std::collections::HashMap<String, u32>) -> bool {
        let root_inode = match self.get_inode(2).await {
            Some(i) => i,
            None    => return false,
        };
        let root_data    = self.read_inode_data(&root_inode).await;
        let root_entries = Self::parse_dir_data(&root_data);

        // Pre-warm the block cache for root's immediate children before the loop.
        {
            let blocks: Vec<u32> = root_entries.iter()
                .filter_map(|(_, ino, _)| self.inode_block_for(*ino))
                .collect();
            self.prefetch_blocks(&blocks).await;
        }

        // Stack: (current_dir_path, remaining_entries_to_process)
        let mut stack: Vec<(String, Vec<(String, u32, u8)>)> =
            vec![("/".to_string(), root_entries)];

        loop {
            // Peek + pop one entry without holding a long-lived borrow on `stack`.
            let (dir_path, entry) = match stack.last_mut() {
                None => break,
                Some((dir_path, entries)) => (dir_path.clone(), entries.pop()),
            };
            // `stack` is no longer borrowed — we can call await + stack.push/pop freely.

            let (name, child_ino, file_type) = match entry {
                None    => { stack.pop(); continue; } // directory fully processed
                Some(e) => e,
            };

            if name.contains('/') || name.contains('\0') { continue; }

            let child_path = if dir_path == "/" {
                format!("/{name}")
            } else {
                format!("{dir_path}/{name}")
            };

            match file_type {
                2 => {
                    // Directory
                    if stack.len() >= 32 { continue; } // depth guard against loops
                    fs.mkdir_p(&child_path).ok();
                    if let Some(inode) = self.get_inode(child_ino).await {
                        let dir_data      = self.read_inode_data(&inode).await;
                        let child_entries = Self::parse_dir_data(&dir_data);
                        // Prefetch all inode table blocks for the new directory's
                        // children concurrently before pushing them onto the stack.
                        // This turns N serial round-trips into one parallel batch.
                        let blocks: Vec<u32> = child_entries.iter()
                            .filter_map(|(_, ino, _)| self.inode_block_for(*ino))
                            .collect();
                        self.prefetch_blocks(&blocks).await;
                        stack.push((child_path, child_entries));
                    }
                }
                1 => {
                    // Regular file — empty stub; content fetched on demand via fetch_file().
                    fs.write_file(&child_path, vec![]).ok();
                    inode_map.insert(child_path.clone(), child_ino);
                }
                7 => {
                    // Symbolic link — must read target to create the symlink entry.
                    if let Some(inode) = self.get_inode(child_ino).await {
                        let target_bytes = self.read_inode_data(&inode).await;
                        let target = String::from_utf8_lossy(&target_bytes).into_owned();
                        fs.symlink(&child_path, &target).ok();
                    }
                    inode_map.insert(child_path.clone(), child_ino);
                }
                _ => {
                    // char/block device, socket, FIFO — empty placeholder
                    fs.write_file(&child_path, vec![]).ok();
                }
            }
        }
        true
    }

    /// Resolve `path` by walking the ext2 directory tree one component at a
    /// time, fetching only the inodes on the path.  Returns the inode number
    /// of the final component if found, `None` otherwise.
    ///
    /// This is orders of magnitude cheaper than `populate_memfs` when you only
    /// need a single file — it fetches O(depth) inodes instead of O(filesystem).
    pub async fn lookup_path(&mut self, path: &str) -> Option<u32> {
        // Start from inode 2 (ext2 root directory).
        let mut cur_ino: u32 = 2;

        let components: Vec<&str> = path
            .trim_start_matches('/')
            .split('/')
            .filter(|c| !c.is_empty())
            .collect();

        if components.is_empty() {
            return Some(cur_ino);
        }

        // Fast-path: check if any prefix of path is already in dir_cache.
        // Walk backwards from the longest prefix to find the deepest cached point.
        let mut start_idx = 0;
        for end in (1..=components.len()).rev() {
            let prefix = "/".to_string() + &components[..end].join("/");
            if let Some(&ino) = self.dir_cache.get(&prefix) {
                cur_ino = ino;
                start_idx = end;
                break;
            }
        }

        for (i, component) in components[start_idx..].iter().enumerate() {
            let abs_i = start_idx + i;
            let inode_data = self.get_inode(cur_ino).await?;
            let dir_data   = self.read_inode_data(&inode_data).await;
            let entries    = Self::parse_dir_data(&dir_data);

            // Cache inode of current directory for future lookups.
            let cur_path = "/".to_string() + &components[..abs_i].join("/");
            self.dir_cache.insert(cur_path, cur_ino);

            // Find this component in the directory.
            let found = entries.into_iter().find(|(name, _, _)| name == component);
            let (_, child_ino, file_type) = found?;

            let is_last = abs_i == components.len() - 1;

            if is_last {
                return Some(child_ino);
            }

            // Must be a directory (or symlink we'll treat as opaque) to descend.
            if file_type == 2 {
                cur_ino = child_ino;
            } else if file_type == 7 {
                // Symlink — resolve relative to parent and restart.
                let link_inode = self.get_inode(child_ino).await?;
                let target_bytes = self.read_inode_data(&link_inode).await;
                let target = String::from_utf8_lossy(&target_bytes).into_owned();
                // Resolve absolute or relative symlink.
                let resolved_target = if target.starts_with('/') {
                    target
                } else {
                    // Relative symlink: resolve against the parent directory.
                    // e.g. /bin → usr/bin  means the symlink is at / pointing to usr/bin.
                    let parent = if abs_i == 0 {
                        "/".to_string()
                    } else {
                        "/".to_string() + &components[..abs_i].join("/")
                    };
                    let combined = format!("{}/{}", parent, target);
                    // Normalise: remove . and collapse ..
                    let mut parts: Vec<&str> = Vec::new();
                    for seg in combined.split('/') {
                        match seg {
                            "" | "." => {}
                            ".." => { parts.pop(); }
                            s => parts.push(s),
                        }
                    }
                    "/".to_string() + &parts.join("/")
                };
                let remaining = components[abs_i+1..].join("/");
                let resolved = if remaining.is_empty() {
                    resolved_target
                } else {
                    format!("{resolved_target}/{remaining}")
                };
                return Box::pin(self.lookup_path(&resolved)).await;
            } else {
                return None;
            }
        }

        Some(cur_ino)
    }

}
