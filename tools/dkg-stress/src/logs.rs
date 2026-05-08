use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

/// Read up to `max_bytes` from the end of `path`, returning the trailing
/// portion as a UTF-8 string (lossily decoded). Returns None on any I/O
/// error or if the path doesn't exist.
pub fn read_tail(path: &Path, max_bytes: u64) -> Option<String> {
    let mut f = File::open(path).ok()?;
    let len = f.metadata().ok()?.len();
    let start = len.saturating_sub(max_bytes);
    f.seek(SeekFrom::Start(start)).ok()?;
    let mut buf = Vec::with_capacity(max_bytes.min(64 * 1024) as usize);
    f.take(max_bytes).read_to_end(&mut buf).ok()?;
    Some(String::from_utf8_lossy(&buf).into_owned())
}

/// Enumerate node-* subdirectories of `run_dir`, sorted by name. Empty if
/// the run directory doesn't exist yet (pending) or has been pruned (passed
/// run with KEEP_PASSED off).
pub fn enumerate_nodes(run_dir: &Path) -> Vec<PathBuf> {
    let Ok(entries) = fs::read_dir(run_dir) else {
        return Vec::new();
    };
    let mut nodes: Vec<PathBuf> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.is_dir()
                && p.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.starts_with("node-"))
        })
        .collect();
    nodes.sort();
    nodes
}
