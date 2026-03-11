use std::{
    collections::{HashMap, HashSet},
    path::{self, PathBuf},
};

use crate::{dkg, share};
use rand::RngCore;
use tracing::{info, warn};

/// Error type for DKG disk operations.
#[derive(Debug, thiserror::Error)]
pub(crate) enum DiskError {
    /// Invalid URL.
    #[error("Invalid URL: {0}")]
    InvalidUrl(#[from] url::ParseError),

    /// I/O error.
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    /// JSON parsing error.
    #[error("JSON parsing error: {0}")]
    JsonError(#[from] serde_json::Error),

    /// Cluster definition verification error.
    #[error(
        "Cluster definition verification failed. Run with `--no-verify` to bypass verification at own risk: {0}"
    )]
    ClusterDefinitionVerificationError(pluto_cluster::definition::DefinitionError),

    /// Cluster definition error.
    #[error("Cluster definition error: {0}")]
    ClusterDefinitionError(#[from] pluto_cluster::definition::DefinitionError),

    /// Deposit amounts verification error.
    #[error("Deposit amounts verification failed: {0}")]
    DepositAmountsVerificationError(#[from] pluto_eth2util::deposit::DepositError),

    #[error("Keystore error: {0}")]
    KeystoreError(#[from] pluto_eth2util::keystore::KeystoreError),

    #[error("Keymanager error: {0}")]
    KeymanagerClientError(#[from] pluto_eth2util::keymanager::KeymanagerError),

    /// Data directory does not exist.
    #[error("data directory doesn't exist, cannot continue")]
    DataDirNotFound(PathBuf),

    /// Data directory path points to a file, not a directory.
    #[error("data directory already exists and is a file, cannot continue")]
    DataDirIsFile(PathBuf),

    /// Data directory contains disallowed entries.
    #[error("data directory not clean, cannot continue")]
    DataDirNotClean {
        disallowed_entity: String,
        data_dir: PathBuf,
    },

    /// Data directory is missing required files.
    #[error("missing required files, cannot continue")]
    MissingRequiredFiles {
        file_name: String,
        data_dir: PathBuf,
    },
}

type Result<T> = std::result::Result<T, DiskError>;

/// Returns the [`pluto_cluster::definition::Definition`] from disk or an HTTP
/// URL. It returns the test definition if configured.
pub(crate) async fn load_definition(
    conf: &dkg::Config,
    eth1cl: Option<&pluto_eth1wrap::EthClient>,
) -> Result<pluto_cluster::definition::Definition> {
    if let Some(definition) = &conf.test_config.def {
        return Ok(definition.clone());
    }

    // Fetch definition from URI or disk

    let parsed_url = url::Url::parse(&conf.def_file)?;
    let mut def = if parsed_url.has_host() {
        if parsed_url.scheme() != "https" {
            warn!(
                addr = conf.def_file,
                "Definition file URL does not use https protocol"
            );
        }

        let def: pluto_cluster::definition::Definition =
            todo!("requires `cluster.FetchDefinition`");
        let definition_hash = pluto_cluster::helpers::to_0x_hex(&def.definition_hash);

        info!(
            url = conf.def_file,
            definition_hash, "Cluster definition downloaded from URL"
        );

        def
    } else {
        let buf = tokio::fs::read_to_string(&conf.def_file).await?;

        let def: pluto_cluster::definition::Definition = serde_json::from_str(&buf)?;
        let definition_hash = pluto_cluster::helpers::to_0x_hex(&def.definition_hash);

        info!(
            path = conf.def_file,
            definition_hash, "Cluster definition loaded from disk"
        );

        def
    };

    // Verify
    if let Err(error) = def.verify_hashes() {
        if conf.no_verify {
            warn!(
                error = %error,
                "Ignoring failed cluster definition hashes verification due to --no-verify flag"
            );
        } else {
            return Err(DiskError::ClusterDefinitionVerificationError(error));
        }
    }
    if let Err(error) = def.verify_signatures(eth1cl).await {
        if conf.no_verify {
            warn!(
                error = %error,
                "Ignoring failed cluster definition signatures verification due to --no-verify flag"
            );
        } else {
            return Err(DiskError::ClusterDefinitionVerificationError(error));
        }
    }

    // Ensure we have a definition hash in case of no-verify.
    if def.definition_hash.is_empty() {
        def.set_definition_hashes()?;
    }

    pluto_eth2util::deposit::verify_deposit_amounts(&def.deposit_amounts, def.compounding)?;

    Ok(def)
}

/// Writes validator private keyshares for the node to the provided keymanager
/// address.
pub(crate) async fn write_to_keymanager(
    keymanager_url: impl AsRef<str>,
    auth_token: impl AsRef<str>,
    shares: &[share::Share],
) -> Result<()> {
    let mut keystores = Vec::new();
    let mut passwords = Vec::new();

    for share in shares {
        let password = random_hex64();
        let store = pluto_eth2util::keystore::encrypt(
            &share.secret_share,
            &password,
            None, // TODO: What to use here as argument?
            &mut rand::rngs::OsRng,
        )?;

        passwords.push(password);
        keystores.push(store);
    }

    let cl = pluto_eth2util::keymanager::Client::new(keymanager_url, auth_token)?;
    cl.import_keystores(&keystores, &passwords).await?;

    Ok(())
}

pub(crate) async fn write_keys_to_disk(
    conf: &dkg::Config,
    shares: &[share::Share],
    insecure: bool,
) -> Result<()> {
    let secret_shares = shares.iter().map(|s| s.secret_share).collect::<Vec<_>>();

    let keys_dir: String = todo!("requires `cluster.CreateValidatorKeysDir`");

    if insecure {
        pluto_eth2util::keystore::store_keys_insecure(
            &secret_shares,
            keys_dir,
            &pluto_eth2util::keystore::CONFIRM_INSECURE_KEYS,
        )
        .await?;
    } else {
        pluto_eth2util::keystore::store_keys(&secret_shares, keys_dir).await?;
    }

    Ok(())
}

pub(crate) async fn write_lock(
    data_dir: impl AsRef<str>,
    lock: &pluto_cluster::lock::Lock,
) -> Result<()> {
    use serde::Serialize;
    use tokio::io::AsyncWriteExt;

    let b = {
        let mut buf = Vec::new();
        let formatter = serde_json::ser::PrettyFormatter::with_indent(b" ");
        let mut ser = serde_json::Serializer::with_formatter(&mut buf, formatter);

        lock.serialize(&mut ser)?;
        buf
    };

    let path = path::Path::new(data_dir.as_ref()).join("cluster-lock.json");

    let mut file = tokio::fs::File::open(path).await?;
    file.write_all(&b).await?;
    file.metadata().await?.permissions().set_readonly(true); // File needs to be read-only for everybody

    Ok(())
}

/// Ensures `data_dir` exists, is a directory, and does not contain any
/// disallowed entries, while checking for the presence of necessary files.
pub(crate) async fn check_clear_data_dir(data_dir: impl AsRef<path::Path>) -> Result<()> {
    let path = path::PathBuf::from(data_dir.as_ref());

    match tokio::fs::metadata(&path).await {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(DiskError::DataDirNotFound(path));
        }
        Err(e) => {
            return Err(DiskError::IoError(e));
        }
        Ok(meta) if !meta.is_dir() => {
            return Err(DiskError::DataDirIsFile(path));
        }
        Ok(_) => {}
    }

    let disallowed = HashSet::from(["validator_keys", "cluster-lock.json"]);
    let mut necessary = HashMap::from([("cluster-lock.json", false)]);

    let mut read_dir = tokio::fs::read_dir(&path).await?;
    while let Some(entry) = read_dir.next_entry().await? {
        let os_string = entry.file_name();
        let name = os_string.to_string_lossy();

        let is_deposit_data = name.starts_with("deposit-data");

        if disallowed.contains(name.as_ref()) || is_deposit_data {
            return Err(DiskError::DataDirNotClean {
                disallowed_entity: name.into(),
                data_dir: path,
            });
        }

        if let Some(found) = necessary.get_mut(name.as_ref()) {
            *found = true;
        }
    }

    for (file_name, found) in &necessary {
        if !found {
            return Err(DiskError::MissingRequiredFiles {
                file_name: file_name.to_string(),
                data_dir: path,
            });
        }
    }

    Ok(())
}

/// Writes sample files to check disk writes and removes sample files after
/// verification.
pub(crate) async fn check_writes(data_dir: impl AsRef<str>) -> Result<()> {
    const CHECK_BODY: &str = "delete me: dummy file used to check write permissions";

    let base = path::Path::new(data_dir.as_ref());

    for file in [
        "cluster-lock.json",
        "deposit-data.json",
        "validator_keys/keystore-0.json",
    ] {
        let file_path = path::Path::new(file);
        let subdir = file_path.parent().filter(|p| !p.as_os_str().is_empty());

        if let Some(subdir) = subdir {
            tokio::fs::create_dir_all(base.join(subdir)).await?;
        }

        let full_path = base.join(file_path);
        tokio::fs::write(&full_path, CHECK_BODY).await?;

        let mut perms = tokio::fs::metadata(&full_path).await?.permissions();
        perms.set_readonly(true);
        tokio::fs::set_permissions(&full_path, perms).await?;

        tokio::fs::remove_file(&full_path).await?;

        if let Some(subdir) = subdir {
            tokio::fs::remove_dir_all(base.join(subdir)).await?;
        }
    }

    Ok(())
}

pub(crate) fn random_hex64() -> String {
    let mut rng = rand::rngs::OsRng;

    let mut bytes = [0u8; 32];
    rng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn clear_data_dir_does_not_exist() {
        let temp_dir = tempfile::tempdir().unwrap();
        let data_dir = temp_dir.path().join("nonexistent");

        let result = super::check_clear_data_dir(&data_dir).await;
        assert!(matches!(result, Err(super::DiskError::DataDirNotFound(_))));
    }

    #[tokio::test]
    async fn clear_data_dir_is_file() {
        let temp_file = tempfile::NamedTempFile::new().unwrap();
        tokio::fs::write(temp_file.path(), [0x0, 0x1, 0x2])
            .await
            .unwrap();

        let result = super::check_clear_data_dir(temp_file.path()).await;
        assert!(matches!(result, Err(super::DiskError::DataDirIsFile(_))));
    }

    #[tokio::test]
    async fn clear_data_dir_contains_validator_keys_file() {
        let temp_dir = tempfile::tempdir().unwrap();
        let data_dir = temp_dir.path();
        tokio::fs::write(data_dir.join("validator_keys"), [0x0, 0x1, 0x2])
            .await
            .unwrap();

        let result = super::check_clear_data_dir(data_dir).await;
        assert!(matches!(
            result,
            Err(super::DiskError::DataDirNotClean { .. })
        ));
    }

    #[tokio::test]
    async fn clear_data_dir_contains_validator_keys_dir() {
        let temp_dir = tempfile::tempdir().unwrap();
        let data_dir = temp_dir.path();
        tokio::fs::create_dir_all(data_dir.join("validator_keys"))
            .await
            .unwrap();

        let result = super::check_clear_data_dir(data_dir).await;
        assert!(matches!(
            result,
            Err(super::DiskError::DataDirNotClean { .. })
        ));
    }

    #[tokio::test]
    async fn clear_data_dir_contains_cluster_lock() {
        let temp_dir = tempfile::tempdir().unwrap();
        let data_dir = temp_dir.path();
        tokio::fs::write(data_dir.join("cluster-lock.json"), [0x0, 0x1, 0x2])
            .await
            .unwrap();

        let result = super::check_clear_data_dir(data_dir).await;
        assert!(matches!(
            result,
            Err(super::DiskError::DataDirNotClean { .. })
        ));
    }
}
