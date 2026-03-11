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

        let def: pluto_cluster::definition::Definition = todo!();
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

pub(crate) fn random_hex64() -> String {
    let mut rng = rand::rngs::OsRng;

    let mut bytes = [0u8; 32];
    rng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}
