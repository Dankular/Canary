//! Minimal read-only ext2 filesystem image parser.
//!
//! Reads an ext2 image byte-slice and populates a `MemFs` with all files,
//! directories, and symlinks.  Files larger than `MAX_FILE_BYTES` are
//! inserted as empty placeholders to save memory.

use super::MemFs;

/// Files larger than this are skipped (content left empty) to bound RAM use.
const MAX_FILE_BYTES: usize = 128 * 1024 * 1024; // 128 MiB

// ── Low-level helpers ─────────────────────────────────────────────────────────

#[inline]
fn u16le(data: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([data[off], data[off + 1]])
}

#[inline]
fn u32le(data: &[u8], off: usize) -> u32 {
    let b: [u8; 4] = data[off..off + 4].try_into().unwrap_or([0; 4]);
    u32::from_le_bytes(b)
}

// ── Superblock ────────────────────────────────────────────────────────────────

struct Sb {
    block_size:        usize,
    inode_size:        usize,
    inodes_per_group:  usize,
    bgdt_offset:       usize,   // byte offset of block-group descriptor table
}

fn parse_sb(image: &[u8]) -> Option<Sb> {
    if image.len() < 2048 {
        return None;
    }
    let sb = &image[1024..]; // superblock is always at byte 1024

    if u16le(sb, 56) != 0xEF53 {
        return None; // bad magic
    }

    let log_bsz          = u32le(sb, 24) as usize;
    let block_size        = 1024 << log_bsz;
    let inodes_per_group  = u32le(sb, 40) as usize;
    let first_data_block  = u32le(sb, 20) as usize;
    let rev_level         = u32le(sb, 76);
    let inode_size        = if rev_level >= 1 { u16le(sb, 88) as usize } else { 128 };

    // Block group descriptor table starts at the block immediately after
    // the first data block (which holds the superblock for 1 KiB block size).
    let bgdt_block  = first_data_block + 1;
    let bgdt_offset = bgdt_block * block_size;

    Some(Sb { block_size, inode_size, inodes_per_group, bgdt_offset })
}

// ── Block-group descriptor ────────────────────────────────────────────────────

fn bg_inode_table_block(image: &[u8], sb: &Sb, group: usize) -> usize {
    let desc_off = sb.bgdt_offset + group * 32;
    u32le(image, desc_off + 8) as usize // bg_inode_table
}

// ── Inode access ──────────────────────────────────────────────────────────────

/// Return a slice of the raw on-disk inode for inode number `ino` (1-based).
fn get_inode<'a>(image: &'a [u8], sb: &Sb, ino: u32) -> Option<&'a [u8]> {
    if ino == 0 {
        return None;
    }
    let idx   = (ino as usize) - 1;
    let group = idx / sb.inodes_per_group;
    let local = idx % sb.inodes_per_group;
    let table_block = bg_inode_table_block(image, sb, group);
    let off = table_block * sb.block_size + local * sb.inode_size;
    image.get(off..off + sb.inode_size)
}

fn inode_mode(inode: &[u8]) -> u16 { u16le(inode, 0) }

fn inode_size(inode: &[u8]) -> usize {
    let lo = u32le(inode, 4) as u64;
    let hi = u32le(inode, 108) as u64;
    ((hi << 32) | lo) as usize
}

fn inode_block(inode: &[u8], n: usize) -> u32 {
    // i_block[15] starts at inode offset 40.
    u32le(inode, 40 + n * 4)
}

// ── Data-block reading ────────────────────────────────────────────────────────

fn read_block<'a>(image: &'a [u8], sb: &Sb, block: u32) -> Option<&'a [u8]> {
    if block == 0 {
        return None;
    }
    let off = (block as usize) * sb.block_size;
    image.get(off..off + sb.block_size)
}

/// Resolve one level of indirection: read `ptrs_per_block` u32 block numbers
/// from the indirect block at `indirect_block`, then read each data block.
fn read_indirect(image: &[u8], sb: &Sb, indirect_block: u32, remaining: &mut usize, out: &mut Vec<u8>) {
    let ptrs = sb.block_size / 4;
    if let Some(blk_data) = read_block(image, sb, indirect_block) {
        let blk_data = blk_data.to_vec(); // avoid aliasing
        for j in 0..ptrs {
            if *remaining == 0 { break; }
            let blk = u32::from_le_bytes(blk_data[j*4..j*4+4].try_into().unwrap_or([0;4]));
            if blk == 0 { break; }
            if let Some(data) = read_block(image, sb, blk) {
                let n = data.len().min(*remaining);
                out.extend_from_slice(&data[..n]);
                *remaining -= n;
            }
        }
    }
}

/// Read the full data content of an inode (direct + single + double indirect).
fn read_file_data(image: &[u8], sb: &Sb, inode: &[u8]) -> Vec<u8> {
    let size = inode_size(inode);
    let mode = inode_mode(inode);

    // Short symlinks: target stored inline in i_block[] bytes.
    if (mode >> 12) == 0xA {
        let i_blocks = u32le(inode, 28);
        if i_blocks == 0 && size <= 60 {
            let mut buf = [0u8; 60];
            for i in 0..15 {
                let ptr = inode_block(inode, i);
                buf[i*4..i*4+4].copy_from_slice(&ptr.to_le_bytes());
            }
            return buf[..size].to_vec();
        }
    }

    let mut out       = Vec::with_capacity(size.min(MAX_FILE_BYTES));
    let mut remaining = size;
    let ptrs          = sb.block_size / 4;

    // Direct blocks (i_block[0..11])
    for i in 0..12 {
        if remaining == 0 { break; }
        let blk = inode_block(inode, i);
        if blk == 0 { break; }
        if let Some(data) = read_block(image, sb, blk) {
            let n = data.len().min(remaining);
            out.extend_from_slice(&data[..n]);
            remaining -= n;
        }
    }

    // Single indirect (i_block[12])
    if remaining > 0 {
        let ind = inode_block(inode, 12);
        if ind != 0 {
            read_indirect(image, sb, ind, &mut remaining, &mut out);
        }
    }

    // Double indirect (i_block[13])
    if remaining > 0 {
        let dbl = inode_block(inode, 13);
        if dbl != 0 {
            if let Some(dbl_data) = read_block(image, sb, dbl) {
                let dbl_data = dbl_data.to_vec();
                for i in 0..ptrs {
                    if remaining == 0 { break; }
                    let ind = u32::from_le_bytes(dbl_data[i*4..i*4+4].try_into().unwrap_or([0;4]));
                    if ind == 0 { break; }
                    read_indirect(image, sb, ind, &mut remaining, &mut out);
                }
            }
        }
    }

    // Triple indirect (i_block[14]) — for files > ~2 GiB, skipped.
    // (Wine libraries are far smaller than this.)

    out
}

// ── Directory reading ─────────────────────────────────────────────────────────

/// Returns `(name, inode_number)` pairs for entries in a directory inode.
/// Skips `.` and `..`.
fn read_dir_entries(image: &[u8], sb: &Sb, inode: &[u8]) -> Vec<(String, u32)> {
    let data = read_file_data(image, sb, inode);
    let mut entries = Vec::new();
    let mut off = 0;

    while off + 8 <= data.len() {
        let ino     = u32::from_le_bytes(data[off..off+4].try_into().unwrap_or([0;4]));
        let rec_len = u16::from_le_bytes(data[off+4..off+6].try_into().unwrap_or([0;2])) as usize;
        let name_len= data[off+6] as usize;

        if rec_len == 0 { break; }

        if ino != 0 && name_len > 0 && off + 8 + name_len <= data.len() {
            let name_bytes = &data[off+8..off+8+name_len];
            if let Ok(name) = std::str::from_utf8(name_bytes) {
                if name != "." && name != ".." {
                    entries.push((name.to_string(), ino));
                }
            }
        }
        off += rec_len;
    }

    entries
}

// ── Recursive directory traversal ────────────────────────────────────────────

fn traverse(image: &[u8], sb: &Sb, ino: u32, dir_path: &str, fs: &mut MemFs, depth: usize) {
    if depth > 32 { return; } // guard against symlink loops in dir tree

    let inode_bytes = match get_inode(image, sb, ino) {
        Some(b) => b.to_vec(),
        None    => return,
    };

    let entries = read_dir_entries(image, sb, &inode_bytes);

    for (name, child_ino) in entries {
        // Reject filenames with embedded slashes or NUL.
        if name.contains('/') || name.contains('\0') { continue; }

        let path = if dir_path == "/" {
            format!("/{name}")
        } else {
            format!("{dir_path}/{name}")
        };

        let child_inode = match get_inode(image, sb, child_ino) {
            Some(b) => b.to_vec(),
            None    => continue,
        };

        let mode      = inode_mode(&child_inode);
        let file_type = (mode >> 12) & 0xF;

        match file_type {
            0x4 => {
                // Directory
                fs.mkdir_p(&path).ok();
                traverse(image, sb, child_ino, &path, fs, depth + 1);
            }
            0x8 => {
                // Regular file
                let size = inode_size(&child_inode);
                if size > MAX_FILE_BYTES {
                    // Insert empty placeholder so stat/open work.
                    fs.write_file(&path, vec![]).ok();
                } else {
                    let data = read_file_data(image, sb, &child_inode);
                    fs.write_file(&path, data).ok();
                }
            }
            0xA => {
                // Symlink
                let target_bytes = read_file_data(image, sb, &child_inode);
                let target = String::from_utf8_lossy(&target_bytes).into_owned();
                fs.symlink(&path, &target).ok();
            }
            _ => {
                // Char device, block device, socket, FIFO — empty placeholder.
                fs.write_file(&path, vec![]).ok();
            }
        }
    }
}

// ── Public entry point ────────────────────────────────────────────────────────

/// Parse an ext2 image and populate `fs` with all files and directories.
///
/// Returns `true` on success, `false` if the image is not a valid ext2 fs.
pub fn populate_memfs(image: &[u8], fs: &mut MemFs) -> bool {
    let sb = match parse_sb(image) {
        Some(s) => s,
        None    => return false,
    };

    // Root inode is always inode 2.
    traverse(image, &sb, 2, "/", fs, 0);
    true
}
