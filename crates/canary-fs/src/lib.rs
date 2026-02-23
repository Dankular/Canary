//! Virtual filesystem for Canary.
//!
//! Provides a unified VFS interface over multiple backing stores:
//! - `MemFs`   — in-memory (for /proc, /dev, tmpfs)
//! - `Ext2Fs`  — ext2 disk image loaded from a byte slice
//! - `OverlayFs` — writable layer over a read-only base

pub mod ext2;

use thiserror::Error;
use std::collections::HashMap;

// ── Errors ────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum FsError {
    #[error("no such file or directory: {0}")]
    NotFound(String),
    #[error("not a directory: {0}")]
    NotADirectory(String),
    #[error("is a directory: {0}")]
    IsADirectory(String),
    #[error("permission denied")]
    PermissionDenied,
    #[error("file already exists: {0}")]
    AlreadyExists(String),
    #[error("no space left on device")]
    NoSpace,
    #[error("io error: {0}")]
    Io(String),
    #[error("invalid argument")]
    InvalidArgument,
    #[error("operation not supported")]
    NotSupported,
    #[error("bad file descriptor")]
    BadFd,
    #[error("end of file")]
    Eof,
}

pub type FsResult<T> = Result<T, FsError>;

// ── File kind ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileKind {
    Regular,
    Directory,
    Symlink,
    CharDevice,
    BlockDevice,
    Fifo,
    Socket,
}

// ── File stat (mirrors Linux `struct stat64`) ─────────────────────────────────

#[derive(Debug, Clone, Default)]
pub struct FileStat {
    pub dev:     u64,
    pub ino:     u64,
    pub mode:    u32,
    pub nlink:   u64,
    pub uid:     u32,
    pub gid:     u32,
    pub rdev:    u64,
    pub size:    i64,
    pub blksize: i64,
    pub blocks:  i64,
    pub atime:   i64,
    pub mtime:   i64,
    pub ctime:   i64,
}

impl FileStat {
    pub fn from_content(content: &[u8], kind: FileKind, ino: u64) -> Self {
        let mode = match kind {
            FileKind::Regular    => 0o100644u32,
            FileKind::Directory  => 0o040755u32,
            FileKind::Symlink    => 0o120777u32,
            FileKind::CharDevice => 0o020666u32,
            _                    => 0o100644u32,
        };
        FileStat {
            dev: 1, ino, mode, nlink: 1, uid: 1000, gid: 1000,
            rdev: 0,
            size:    content.len() as i64,
            blksize: 4096,
            blocks:  ((content.len() as i64 + 511) / 512),
            atime: 0, mtime: 0, ctime: 0,
        }
    }
}

// ── Open file flags ───────────────────────────────────────────────────────────

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct OpenFlags: u32 {
        const RDONLY   = 0o0;
        const WRONLY   = 0o1;
        const RDWR     = 0o2;
        const CREAT    = 0o100;
        const EXCL     = 0o200;
        const TRUNC    = 0o1000;
        const APPEND   = 0o2000;
        const NONBLOCK = 0o4000;
        const CLOEXEC  = 0o2000000;
        const DIRECTORY= 0o200000;
    }
}

// ── VFS node ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct VNode {
    pub kind:    FileKind,
    pub content: Vec<u8>,
    /// For symlinks: the target path.
    pub link_target: Option<String>,
    /// For directories: child name → inode index.
    pub children: HashMap<String, usize>,
    pub stat:    FileStat,
}

impl VNode {
    pub fn new_file(content: Vec<u8>, ino: usize) -> Self {
        let stat = FileStat::from_content(&content, FileKind::Regular, ino as u64);
        VNode { kind: FileKind::Regular, content, link_target: None, children: HashMap::new(), stat }
    }
    pub fn new_dir(ino: usize) -> Self {
        let stat = FileStat::from_content(&[], FileKind::Directory, ino as u64);
        VNode { kind: FileKind::Directory, content: vec![], link_target: None, children: HashMap::new(), stat }
    }
    pub fn new_symlink(target: String, ino: usize) -> Self {
        let stat = FileStat::from_content(target.as_bytes(), FileKind::Symlink, ino as u64);
        VNode { kind: FileKind::Symlink, content: target.as_bytes().to_vec(), link_target: Some(target), children: HashMap::new(), stat }
    }
}

// ── In-memory filesystem ──────────────────────────────────────────────────────

pub struct MemFs {
    nodes: Vec<VNode>,
    // Root inode is always 0.
}

impl MemFs {
    pub fn new() -> Self {
        let root = VNode::new_dir(0);
        MemFs { nodes: vec![root] }
    }

    fn alloc_node(&mut self, node: VNode) -> usize {
        let idx = self.nodes.len();
        self.nodes.push(node);
        idx
    }

    /// Resolve an absolute path to an inode index.
    pub fn lookup(&self, path: &str) -> FsResult<usize> {
        let current = 0usize;
        let parts: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        let mut followed = 0;
        self.lookup_from(current, &parts, &mut followed)
    }

    fn lookup_from(&self, start: usize, parts: &[&str], followed: &mut usize) -> FsResult<usize> {
        let mut current = start;
        for part in parts {
            let node = &self.nodes[current];
            if node.kind != FileKind::Directory {
                return Err(FsError::NotADirectory(part.to_string()));
            }
            match *part {
                "." | "" => {},
                ".." => {
                    // We'd need parent tracking for this; for now stay put.
                }
                name => {
                    current = *node.children.get(name)
                        .ok_or_else(|| FsError::NotFound(name.to_string()))?;
                    // Follow symlinks.
                    if self.nodes[current].kind == FileKind::Symlink {
                        *followed += 1;
                        if *followed > 40 { return Err(FsError::Io("symlink loop".into())); }
                        let target = self.nodes[current].link_target.clone().unwrap();
                        current = self.lookup(&target)?;
                    }
                }
            }
        }
        Ok(current)
    }

    /// Create all intermediate directories and return the leaf dir inode.
    pub fn mkdir_p(&mut self, path: &str) -> FsResult<usize> {
        let mut current = 0usize;
        for part in path.split('/').filter(|s| !s.is_empty()) {
            let node = &self.nodes[current];
            if let Some(&child) = node.children.get(part) {
                current = child;
            } else {
                let new_ino = self.alloc_node(VNode::new_dir(self.nodes.len()));
                self.nodes[current].children.insert(part.to_string(), new_ino);
                current = new_ino;
            }
        }
        Ok(current)
    }

    /// Write a file at `path` (creates intermediate dirs).
    pub fn write_file(&mut self, path: &str, content: Vec<u8>) -> FsResult<()> {
        let (dir_path, file_name) = split_path(path);
        let dir_ino = self.mkdir_p(dir_path)?;
        let _file_ino = if let Some(&existing) = self.nodes[dir_ino].children.get(file_name) {
            self.nodes[existing].content = content.clone();
            self.nodes[existing].stat.size = content.len() as i64;
            existing
        } else {
            let ino = self.alloc_node(VNode::new_file(content, self.nodes.len()));
            self.nodes[dir_ino].children.insert(file_name.to_string(), ino);
            ino
        };
        Ok(())
    }

    pub fn symlink(&mut self, path: &str, target: &str) -> FsResult<()> {
        let (dir_path, name) = split_path(path);
        let dir_ino = self.mkdir_p(dir_path)?;
        let ino = self.alloc_node(VNode::new_symlink(target.to_string(), self.nodes.len()));
        self.nodes[dir_ino].children.insert(name.to_string(), ino);
        Ok(())
    }

    pub fn node(&self, ino: usize) -> &VNode { &self.nodes[ino] }
    pub fn node_mut(&mut self, ino: usize) -> &mut VNode { &mut self.nodes[ino] }

    /// Merge all entries from `self` into `target` using target's public write API.
    /// Existing entries in `target` are overwritten; new entries are created.
    pub fn apply_to(&self, target: &mut MemFs) {
        self.apply_node_to(0, "/", target);
    }

    fn apply_node_to(&self, ino: usize, path: &str, target: &mut MemFs) {
        // Collect children first to avoid holding a borrow on self.nodes while recursing.
        let children: Vec<(String, usize, FileKind)> = {
            let node = self.node(ino);
            node.children.iter()
                .map(|(name, &child_ino)| (name.clone(), child_ino, self.node(child_ino).kind))
                .collect()
        };
        for (name, child_ino, kind) in children {
            if name.contains('/') || name.contains('\0') { continue; }
            let child_path = if path == "/" {
                format!("/{name}")
            } else {
                format!("{path}/{name}")
            };
            match kind {
                FileKind::Directory => {
                    target.mkdir_p(&child_path).ok();
                    self.apply_node_to(child_ino, &child_path, target);
                }
                FileKind::Regular => {
                    let content = self.node(child_ino).content.clone();
                    target.write_file(&child_path, content).ok();
                }
                FileKind::Symlink => {
                    if let Some(ref link_target) = self.node(child_ino).link_target {
                        target.symlink(&child_path, link_target).ok();
                    }
                }
                _ => {
                    let content = self.node(child_ino).content.clone();
                    target.write_file(&child_path, content).ok();
                }
            }
        }
    }
}

fn split_path(path: &str) -> (&str, &str) {
    match path.rfind('/') {
        Some(pos) if pos == 0 => ("/", &path[1..]),
        Some(pos) => (&path[..pos], &path[pos+1..]),
        None      => (".", path),
    }
}

// ── Open file handle ──────────────────────────────────────────────────────────

pub struct FileHandle {
    pub ino:    usize,
    pub offset: u64,
    pub flags:  OpenFlags,
}

// ── VFS (unified) ─────────────────────────────────────────────────────────────

/// The virtual filesystem — one MemFs per mount point (simplified).
pub struct Vfs {
    pub mem: MemFs,
    /// Next inode number for new files.
    _next_ino: usize,
}

impl Vfs {
    pub fn new() -> Self {
        let mut vfs = Vfs { mem: MemFs::new(), _next_ino: 2 };
        vfs.setup_proc();
        vfs.setup_dev();
        vfs
    }

    fn setup_proc(&mut self) {
        let _ = self.mem.write_file("/proc/self/maps",  b"".to_vec());
        let _ = self.mem.write_file("/proc/self/status", b"Name:\tcanary\nPid:\t1\n".to_vec());
        let _ = self.mem.write_file("/proc/cpuinfo",
            b"processor\t: 0\nvendor_id\t: GenuineIntel\ncpu family\t: 6\nmodel\t\t: 15\n".to_vec());
        let _ = self.mem.write_file("/proc/meminfo",
            b"MemTotal:\t3145728 kB\nMemFree:\t2097152 kB\n".to_vec());
        let _ = self.mem.write_file("/proc/version",
            b"Linux version 5.15.0-canary (canary@build) (gcc 12.0)\n".to_vec());
    }

    fn setup_dev(&mut self) {
        // Pseudo-device files.
        let _ = self.mem.write_file("/dev/null",  b"".to_vec());
        let _ = self.mem.write_file("/dev/zero",  b"".to_vec());
        let _ = self.mem.write_file("/dev/urandom", b"".to_vec());
        let _ = self.mem.write_file("/dev/tty",   b"".to_vec());
        let _ = self.mem.write_file("/dev/stdin",  b"".to_vec());
        let _ = self.mem.write_file("/dev/stdout", b"".to_vec());
        let _ = self.mem.write_file("/dev/stderr", b"".to_vec());
    }

    pub fn open(&self, path: &str, flags: OpenFlags) -> FsResult<FileHandle> {
        let ino = self.mem.lookup(path)
            .map_err(|_| FsError::NotFound(path.to_string()))?;
        Ok(FileHandle { ino, offset: 0, flags })
    }

    pub fn read(&self, fh: &mut FileHandle, buf: &mut [u8]) -> FsResult<usize> {
        let node = self.mem.node(fh.ino);
        let content = &node.content;
        let start = fh.offset as usize;
        if start >= content.len() { return Ok(0); }
        let end = (start + buf.len()).min(content.len());
        let n = end - start;
        buf[..n].copy_from_slice(&content[start..end]);
        fh.offset += n as u64;
        Ok(n)
    }

    pub fn write(&mut self, fh: &mut FileHandle, data: &[u8]) -> FsResult<usize> {
        let node = self.mem.node_mut(fh.ino);
        let pos = fh.offset as usize;
        if pos + data.len() > node.content.len() {
            node.content.resize(pos + data.len(), 0);
        }
        node.content[pos..pos + data.len()].copy_from_slice(data);
        fh.offset += data.len() as u64;
        node.stat.size = node.content.len() as i64;
        Ok(data.len())
    }

    pub fn stat(&self, path: &str) -> FsResult<FileStat> {
        let ino = self.mem.lookup(path)
            .map_err(|_| FsError::NotFound(path.to_string()))?;
        Ok(self.mem.node(ino).stat.clone())
    }

    pub fn fstat(&self, fh: &FileHandle) -> FsResult<FileStat> {
        Ok(self.mem.node(fh.ino).stat.clone())
    }

    pub fn getdents(&self, fh: &FileHandle) -> FsResult<Vec<(String, FileKind)>> {
        let node = self.mem.node(fh.ino);
        if node.kind != FileKind::Directory {
            return Err(FsError::NotADirectory(String::new()));
        }
        Ok(node.children.iter()
            .map(|(name, &ino)| (name.clone(), self.mem.node(ino).kind))
            .collect())
    }
}
