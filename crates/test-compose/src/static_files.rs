//! Static configuration files copied into every compose directory.
//!
//! The files are embedded at build time from the crate's `static/` directory,
//! so the generator has no runtime dependency on the source tree. A test checks
//! the table against the directory so a file added or removed there fails
//! the build's test run instead of silently drifting.

/// One embedded static file.
#[derive(Debug)]
pub(crate) struct StaticFile {
    /// Directory under the compose dir (and under `static/`).
    pub(crate) dir: &'static str,
    /// File name within `dir`.
    pub(crate) name: &'static str,
    /// File contents.
    pub(crate) bytes: &'static [u8],
}

macro_rules! static_file {
    ($dir:literal, $name:literal) => {
        StaticFile {
            dir: $dir,
            name: $name,
            bytes: include_bytes!(concat!("../static/", $dir, "/", $name)),
        }
    };
}

/// All static files, sorted by directory then name.
pub(crate) const STATIC_FILES: &[StaticFile] = &[
    static_file!("grafana", "dash_alerts.json"),
    static_file!("grafana", "dash_charon_overview.json"),
    static_file!("grafana", "dash_duty_details.json"),
    static_file!("grafana", "dashboards.yml"),
    static_file!("grafana", "datasource.yml"),
    static_file!("grafana", "grafana.ini"),
    static_file!("grafana", "notifiers.yml"),
    static_file!("lighthouse", "Dockerfile"),
    static_file!("lighthouse", "run.sh"),
    static_file!("lodestar", "Dockerfile"),
    static_file!("lodestar", "run.sh"),
    static_file!("loki", "loki.yml"),
    static_file!("tempo", "tempo.yaml"),
    static_file!("vouch", "Dockerfile"),
    static_file!("vouch", "run.sh"),
    static_file!("vouch", "vouch.yml"),
];

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, fs, path::Path};

    use super::*;

    const STATIC_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/static");

    #[test]
    fn table_matches_static_dir() {
        let mut on_disk = BTreeMap::new();
        for dir_entry in fs::read_dir(STATIC_DIR).expect("read static dir") {
            let dir_entry = dir_entry.expect("dir entry");
            assert!(
                dir_entry.file_type().expect("file type").is_dir(),
                "static files at the top level are not supported: {:?}",
                dir_entry.path()
            );
            let dir_name = dir_entry.file_name().to_string_lossy().into_owned();

            for file_entry in fs::read_dir(dir_entry.path()).expect("read static sub dir") {
                let file_entry = file_entry.expect("file entry");
                assert!(
                    file_entry.file_type().expect("file type").is_file(),
                    "child static dirs are not supported: {:?}",
                    file_entry.path()
                );
                let file_name = file_entry.file_name().to_string_lossy().into_owned();
                let bytes = fs::read(file_entry.path()).expect("read static file");
                on_disk.insert(format!("{dir_name}/{file_name}"), bytes);
            }
        }

        let embedded: BTreeMap<String, Vec<u8>> = STATIC_FILES
            .iter()
            .map(|f| (format!("{}/{}", f.dir, f.name), f.bytes.to_vec()))
            .collect();

        let disk_names: Vec<&String> = on_disk.keys().collect();
        let embedded_names: Vec<&String> = embedded.keys().collect();
        assert_eq!(
            embedded_names, disk_names,
            "STATIC_FILES must list exactly the files under static/"
        );
        assert_eq!(embedded, on_disk, "embedded bytes must match static/");
        assert_eq!(STATIC_FILES.len(), 16);
        assert!(Path::new(STATIC_DIR).is_dir());
    }
}
