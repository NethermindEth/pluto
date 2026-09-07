//! File and path helpers with Go `os`/`path` semantics where the generated
//! output depends on them.

use std::{fs, io, path::Path};

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

/// Lexically cleans a slash-separated path: collapses repeated separators,
/// drops `.` elements, resolves `..` against preceding elements (or the root)
/// and returns `.` for an empty result.
pub(crate) fn go_path_clean(path: &str) -> String {
    if path.is_empty() {
        return ".".to_string();
    }

    let rooted = path.starts_with('/');
    let mut out: Vec<&str> = Vec::new();

    for elem in path.split('/') {
        match elem {
            "" | "." => {}
            ".." => match out.last() {
                Some(&last) if last != ".." => {
                    out.pop();
                }
                _ if rooted => {}
                _ => out.push(".."),
            },
            other => out.push(other),
        }
    }

    let body = out.join("/");
    if rooted {
        format!("/{body}")
    } else if body.is_empty() {
        ".".to_string()
    } else {
        body
    }
}

/// Joins two path elements the way Go's `path.Join` does: empty elements are
/// ignored and the result is cleaned.
pub(crate) fn go_path_join(a: &str, b: &str) -> String {
    match (a.is_empty(), b.is_empty()) {
        (true, true) => String::new(),
        (true, false) => go_path_clean(b),
        (false, true) => go_path_clean(a),
        (false, false) => go_path_clean(&format!("{a}/{b}")),
    }
}

/// Returns the absolute, cleaned form of `path` (Go's `filepath.Abs`).
pub(crate) fn go_abs(path: impl AsRef<Path>) -> io::Result<String> {
    let abs = std::path::absolute(path.as_ref())?;
    Ok(go_path_clean(&abs.to_string_lossy()))
}

/// Returns `target` expressed relative to `base` using only lexical
/// processing. Both must be cleaned absolute paths as produced by [`go_abs`].
/// Returns `None` when `base` contains `..` elements that cannot be
/// resolved, in which case no relative path exists.
pub(crate) fn go_rel(base: &str, target: &str) -> Option<String> {
    if base == target {
        return Some(".".to_string());
    }

    let base_elems: Vec<&str> = base.split('/').filter(|e| !e.is_empty()).collect();
    let target_elems: Vec<&str> = target.split('/').filter(|e| !e.is_empty()).collect();

    let common = base_elems
        .iter()
        .zip(target_elems.iter())
        .take_while(|(b, t)| b == t)
        .count();

    let base_rest: Vec<&str> = base_elems.iter().skip(common).copied().collect();
    if base_rest.contains(&"..") {
        return None;
    }

    let mut parts: Vec<&str> = vec![".."; base_rest.len()];
    parts.extend(target_elems.iter().skip(common).copied());

    Some(parts.join("/"))
}

#[cfg(test)]
mod tests {
    use test_case::test_case;

    use super::*;

    #[test_case("", "." ; "empty")]
    #[test_case(".", "." ; "dot")]
    #[test_case("a/b/c", "a/b/c" ; "already_clean")]
    #[test_case("a//b/./c/", "a/b/c" ; "collapse")]
    #[test_case("a/b/../c", "a/c" ; "dotdot")]
    #[test_case("a/../..", ".." ; "dotdot_escapes")]
    #[test_case("/..", "/" ; "rooted_dotdot")]
    #[test_case("/tmp/x/", "/tmp/x" ; "trailing_slash")]
    #[test_case("./config.json", "config.json" ; "leading_dot")]
    fn path_clean(input: &str, want: &str) {
        assert_eq!(go_path_clean(input), want);
    }

    #[test_case("", "*", "*" ; "empty_dir")]
    #[test_case(".", "*", "*" ; "dot_dir")]
    #[test_case("/compose", "keys", "/compose/keys" ; "abs")]
    #[test_case("/compose", "./keys/", "/compose/keys" ; "cleans")]
    #[test_case("dir/", "node0", "dir/node0" ; "trailing_slash")]
    fn path_join(a: &str, b: &str, want: &str) {
        assert_eq!(go_path_join(a, b), want);
    }

    #[test_case("/a/b", "/a/b", Some(".") ; "same")]
    #[test_case("/a/b", "/a/b/c", Some("c") ; "child")]
    #[test_case("/a/b", "/a/b/c/d", Some("c/d") ; "grandchild")]
    #[test_case("/a/b", "/a", Some("..") ; "parent")]
    #[test_case("/a/b", "/c", Some("../../c") ; "sibling_tree")]
    #[test_case("/", "/a", Some("a") ; "from_root")]
    fn rel(base: &str, target: &str, want: Option<&str>) {
        assert_eq!(go_rel(base, target), want.map(str::to_string));
    }

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
