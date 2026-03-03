use std::{fs, io, path};

/// Error type for util operations.
#[derive(Debug, thiserror::Error)]
pub enum UtilsError {
    /// Underlying IO error occurred.
    #[error("IO error: {0}")]
    IOError(#[from] io::Error),

    /// File exceeds the maximum allowed size during extraction.
    #[error("File too large: {0}")]
    FileTooLarge(path::PathBuf),

    /// Directories have different number of entries.
    #[error("Directory entry count mismatch: expected {0}, found {1}")]
    DirectoryEntryCountMismatch(usize, usize),

    /// Unexpected file contents.
    #[error("File content mismatch: {0} vs {1}")]
    FileContentMismatch(path::PathBuf, path::PathBuf),

    /// Unexpected path.
    #[error("File name mismatch: expected {0}, found {1}")]
    FileNameMismatch(String, String),

    /// One entry is a file and the other is a directory for a given path.
    #[error("Type mismatch: {0} vs {1}")]
    PathTypeMismatch(path::PathBuf, path::PathBuf),
}

type Result<T> = std::result::Result<T, UtilsError>;

/// Returns the first 7 (or less) hex chars of the provided bytes.
pub fn hex_7(input: &[u8]) -> String {
    let as_string = hex::encode(input);
    as_string.chars().take(7).collect()
}

/// Archives `target_path` into a gzipped tarball named `filename` in
/// `target_path`. After successfully creating the archive, it deletes the
/// original files from disk.
pub fn bundle_output(
    target_path: impl AsRef<path::Path>,
    filename: impl AsRef<path::Path>,
) -> Result<()> {
    // Create output file
    let tar_file = tempfile::NamedTempFile::new()?;
    let tar_file_path = tar_file.path().to_owned();

    // Compress and encode
    let encoder = flate2::write::GzEncoder::new(tar_file, flate2::Compression::default());
    let mut tar = tar::Builder::new(encoder);
    tar.append_dir_all("", &target_path)?;
    tar.finish()?;

    // Delete all files from the `target_dir`
    fs::remove_dir_all(&target_path)?;
    fs::create_dir_all(&target_path)?;

    // Move the created tarball to the target location
    let output_path = path::Path::new(target_path.as_ref()).join(filename.as_ref());
    fs::rename(tar_file_path, output_path)?;

    Ok(())
}

/// Extracts a `.tar.gz` archive to the target path.
pub fn extract_archive(
    archive_path: impl AsRef<path::Path>,
    target_path: impl AsRef<path::Path>,
) -> Result<()> {
    // Create the decompressor.
    let tar_gz = fs::File::open(archive_path)?;
    let decompressor = flate2::read::GzDecoder::new(tar_gz);
    let mut archive = tar::Archive::new(decompressor);

    // Extract each file, verifying that it does not exceed a reasonable size limit
    // to prevent DoS attacks.
    const MAX_FILE: u64 = 100 * 1024 * 1024; // 100MB limit per file
    for entry in archive.entries()? {
        let mut entry = entry?;
        if entry.size() > MAX_FILE {
            return Err(UtilsError::FileTooLarge(entry.path()?.to_path_buf()));
        }
        entry.unpack_in(&target_path)?;
    }

    Ok(())
}

/// Recursively compares two directories and their contents.
pub fn compare_directories(
    dir1: impl AsRef<path::Path>,
    dir2: impl AsRef<path::Path>,
) -> Result<()> {
    let mut entries1 = fs::read_dir(dir1)?.collect::<std::result::Result<Vec<_>, _>>()?;
    let mut entries2 = fs::read_dir(dir2)?.collect::<std::result::Result<Vec<_>, _>>()?;

    entries1.sort_by_key(|e| e.file_name());
    entries2.sort_by_key(|e| e.file_name());

    if entries1.len() != entries2.len() {
        return Err(UtilsError::DirectoryEntryCountMismatch(
            entries1.len(),
            entries2.len(),
        ));
    }

    for (entry1, entry2) in entries1.iter().zip(entries2.iter()) {
        let path1 = entry1.path();
        let path2 = entry2.path();

        if path1.is_dir() && path2.is_dir() {
            compare_directories(&path1, &path2)?;
        } else if path1.is_file() && path2.is_file() {
            let name1 = entry1.file_name();
            let name2 = entry2.file_name();
            if name1 != name2 {
                return Err(UtilsError::FileNameMismatch(
                    name1.display().to_string(),
                    name2.display().to_string(),
                ));
            }

            let content1 = fs::read(&path1)?;
            let content2 = fs::read(&path2)?;
            if content1 != content2 {
                return Err(UtilsError::FileContentMismatch(path1, path2));
            }
        } else {
            return Err(UtilsError::PathTypeMismatch(path1, path2));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, fs, io, path};
    use test_case::test_case;

    #[test_case(&hex::decode("433287d255abf237992d2279af5b1a1bb2c3d7124c97906edd848ebbb541a1c7").unwrap(), "433287d")]
    #[test_case("aaa".as_bytes(), "616161")]
    #[test_case("".as_bytes(), "")]
    fn hex_7(bytes: &[u8], expected: &str) {
        let actual = super::hex_7(bytes);
        assert_eq!(actual, expected);
    }

    #[test]
    fn bundle_output() {
        // Create a temporary directory for testing
        let test_dir = tempfile::tempdir().unwrap();

        // Create a complex file tree structure
        let test_files = HashMap::from([
            ("root_file.txt", "This is a root file content".as_bytes()),
            (
                "nested/level1.json",
                r#"{"key": "value", "number": 42}"#.as_bytes(),
            ),
            (
                "nested/deep/level2.md",
                "# Deep Nested File\n\nThis is markdown content.".as_bytes(),
            ),
            (
                "nested/deep/deeper/level3.yaml",
                "key: value\nlist:\n  - item1\n  - item2".as_bytes(),
            ),
            (
                "validator_keys/keystore-1.json",
                r#"{"crypto": {"cipher": "test"}, "pubkey": "0x123"}"#.as_bytes(),
            ),
            (
                "validator_keys/keystore-2.json",
                r#"{"crypto": {"cipher": "test"}, "pubkey": "0x456"}"#.as_bytes(),
            ),
            (
                "cluster-lock.json",
                r#"{"lock_hash": "0xabc", "definition": {}}"#.as_bytes(),
            ),
            (
                "deposit_data.json",
                r#"[{"pubkey": "0x123", "amount": 32000000000}]"#.as_bytes(),
            ),
            ("empty_dir/placeholder.txt", b""),
            ("binary_file.bin", b"\x00\x01\x02\x03\xFF\xFE\xFD"),
            (
                "special_chars_äöü.txt",
                "File with special characters: äöüß".as_bytes(),
            ),
        ]);

        // Create all test files and directories
        for (rel_path, content) in &test_files {
            let full_path = test_dir.path().join(rel_path);
            fs::create_dir_all(full_path.parent().unwrap()).unwrap();
            fs::write(full_path, content).unwrap();
        }

        // Create a backup of the original structure for comparison
        let backup_dir = tempfile::tempdir().unwrap();
        copy_dir_all(test_dir.path(), backup_dir.path()).unwrap();

        // Call `bundle_output` to create the tar.gz archive
        let archive_name = "test_bundle.tar.gz";
        super::bundle_output(test_dir.path(), archive_name).unwrap();

        // Verify that the archive file exists
        let archive_path = test_dir.path().join(archive_name);
        assert!(archive_path.exists(), "Archive file should exist");

        // Verify that original files are deleted (except the archive)
        let entries: Vec<_> = fs::read_dir(test_dir.path()).unwrap().collect();
        assert!(entries.len() == 1, "Only the archive file should remain");
        let actual_archive_name = entries[0].as_ref().unwrap().file_name();
        assert_eq!(actual_archive_name, archive_name);

        // Extract the archive to a new directory
        let extract_dir = tempfile::tempdir().unwrap();
        super::extract_archive(archive_path, extract_dir.path()).unwrap();

        // Compare the extracted content with the original backup
        super::compare_directories(backup_dir.path(), extract_dir.path())
            .expect("Extracted directory should match original structure");
    }

    #[test]
    fn compare_directories_identical() {
        let dir1 = tempfile::tempdir().unwrap();
        let test_files = HashMap::from([
            ("file1.txt", "content1".as_bytes()),
            ("nested/file2.json", r#"{"key": "value"}"#.as_bytes()),
            ("nested/deep/file3.md", "# Header\nContent".as_bytes()),
            ("binary.bin", b"\x00\x01\x02\x03"),
            (
                "special_chars_äöü.txt",
                "Special characters: äöüß".as_bytes(),
            ),
        ]);
        for (rel_path, content) in test_files {
            let full_path = dir1.path().join(rel_path);
            fs::create_dir_all(full_path.parent().unwrap()).unwrap();
            fs::write(full_path, content).unwrap();
        }

        let dir2 = tempfile::tempdir().unwrap();
        copy_dir_all(dir1.path(), dir2.path()).unwrap();

        let result = super::compare_directories(dir1.path(), dir2.path());

        assert!(result.is_ok());
    }

    #[test]
    fn compare_directories_missing_file() {
        let dir1 = tempfile::tempdir().unwrap();
        let some_file_path = dir1.path().join("file.txt");
        fs::create_dir_all(some_file_path.parent().unwrap()).unwrap();
        fs::write(some_file_path, b"content").unwrap();

        let dir2 = tempfile::tempdir().unwrap();

        let result = super::compare_directories(dir1.path(), dir2.path());

        assert!(matches!(
            result,
            Err(super::UtilsError::DirectoryEntryCountMismatch(1, 0))
        ));
    }

    #[test]
    fn compare_directories_different_content() {
        let dir1 = tempfile::tempdir().unwrap();
        {
            let some_file_path = dir1.path().join("file.txt");
            fs::create_dir_all(some_file_path.parent().unwrap()).unwrap();
            fs::write(some_file_path, b"content1").unwrap();
        }

        let dir2 = tempfile::tempdir().unwrap();
        {
            let some_file_path = dir2.path().join("file.txt");
            fs::create_dir_all(some_file_path.parent().unwrap()).unwrap();
            fs::write(some_file_path, b"content2").unwrap();
        }

        let result = super::compare_directories(dir1.path(), dir2.path());

        assert!(matches!(
            result,
            Err(super::UtilsError::FileContentMismatch(_, _))
        ));
    }

    #[test]
    fn compare_directories_different_sizes() {
        let dir1 = tempfile::tempdir().unwrap();
        {
            let some_file_path = dir1.path().join("file.txt");
            fs::create_dir_all(some_file_path.parent().unwrap()).unwrap();
            fs::write(some_file_path, b"short").unwrap();
        }

        let dir2 = tempfile::tempdir().unwrap();
        {
            let some_file_path = dir2.path().join("file.txt");
            fs::create_dir_all(some_file_path.parent().unwrap()).unwrap();
            fs::write(some_file_path, b"much longer content").unwrap();
        }

        let result = super::compare_directories(dir1.path(), dir2.path());

        assert!(matches!(
            result,
            Err(super::UtilsError::FileContentMismatch(_, _))
        ));
    }

    #[test]
    fn compare_directories_missing_directory() {
        let dir1 = tempfile::tempdir().unwrap();
        {
            let some_file_path = dir1.path().join("nested").join("deep").join("file.txt");
            fs::create_dir_all(some_file_path.parent().unwrap()).unwrap();
            fs::write(some_file_path, b"content").unwrap();
        }

        let dir2 = tempfile::tempdir().unwrap();

        let result = super::compare_directories(dir1.path(), dir2.path());

        assert!(matches!(
            result,
            Err(super::UtilsError::DirectoryEntryCountMismatch(_, _))
        ));
    }

    #[test]
    fn compare_directories_file_vs_directory() {
        let dir1 = tempfile::tempdir().unwrap();
        {
            let some_file_path = dir1.path().join("item");
            fs::create_dir_all(some_file_path.parent().unwrap()).unwrap();
            fs::write(some_file_path, b"content").unwrap();
        }

        let dir2 = tempfile::tempdir().unwrap();
        {
            let some_dir_path = dir2.path().join("item");
            fs::create_dir_all(some_dir_path).unwrap();
        }

        let result = super::compare_directories(dir1.path(), dir2.path());

        assert!(matches!(
            result,
            Err(super::UtilsError::PathTypeMismatch(_, _))
        ));
    }

    #[test]
    fn compare_directories_directory_vs_file() {
        let dir1 = tempfile::tempdir().unwrap();
        {
            let some_dir_path = dir1.path().join("item");
            fs::create_dir_all(some_dir_path).unwrap();
        }

        let dir2 = tempfile::tempdir().unwrap();
        {
            let some_file_path = dir2.path().join("item");
            fs::create_dir_all(some_file_path.parent().unwrap()).unwrap();
            fs::write(some_file_path, b"content").unwrap();
        }

        let result = super::compare_directories(dir1.path(), dir2.path());

        assert!(matches!(
            result,
            Err(super::UtilsError::PathTypeMismatch(_, _))
        ));
    }

    /// Recursively copies all files and directories from `from` to `to`.
    fn copy_dir_all(from: impl AsRef<path::Path>, to: impl AsRef<path::Path>) -> io::Result<()> {
        fs::create_dir_all(&to)?; // Create the destination directory and all its parents
        for entry in fs::read_dir(from)? {
            let entry = entry?;
            let file_type = entry.file_type()?;
            if file_type.is_dir() {
                copy_dir_all(entry.path(), to.as_ref().join(entry.file_name()))?;
            } else {
                fs::copy(entry.path(), to.as_ref().join(entry.file_name()))?; // Copy the file
            }
        }
        Ok(())
    }
}
