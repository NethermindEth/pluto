//! File and environment helpers.

use std::{env, fs, io, path::Path};

/// Reads an environment variable, treating unset, empty and non-UTF-8 values
/// as absent.
pub fn env_non_empty(var: impl AsRef<str>) -> Option<String> {
    env::var(var.as_ref())
        .ok()
        .filter(|value| !value.is_empty())
}

/// Writes `data` to `path`, creating or truncating it.
///
/// On unix the file is created with `mode` (subject to the umask); the mode
/// of an existing file is left unchanged.
pub(crate) fn write_file(
    path: impl AsRef<Path>,
    data: impl AsRef<[u8]>,
    mode: u32,
) -> io::Result<()> {
    let path = path.as_ref();
    let data = data.as_ref();

    #[cfg(unix)]
    {
        use std::{io::Write as _, os::unix::fs::OpenOptionsExt as _};

        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(mode)
            .open(path)?;
        file.write_all(data)
    }

    #[cfg(not(unix))]
    {
        let _ = mode;
        fs::write(path, data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_file_sets_mode_on_creation() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("f.sh");
        write_file(&path, b"echo", 0o755).expect("write");
        assert_eq!(fs::read(&path).expect("read"), b"echo");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;

            let mode = fs::metadata(&path).expect("metadata").permissions().mode() & 0o777;
            // The umask may clear group/other bits but never the owner's.
            assert_eq!(mode & 0o700, 0o700);
        }
    }
}
