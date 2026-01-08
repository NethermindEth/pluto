use charon_core::version::{self};
use std::sync::LazyLock;
use tracing::warn;

type Result<T> = std::result::Result<T, BeaconNodeVersionError>;

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
enum BeaconNodeVersionError {
    #[error("Version string has an unexpected format")]
    InvalidFormat,

    #[error("Unknown beacon node client")]
    UnknownClient,

    #[error("Beacon node client version is too old")]
    TooOld {
        client: version::SemVer,
        minimum: version::SemVer,
    },
}

fn minimum_beacon_node_version(name: &str) -> Option<version::SemVer> {
    let name = name.to_lowercase();
    match name.as_str() {
        "lighthouse" => Some(version::SemVer::try_from("v8.0.0-rc.0").unwrap()),
        "teku" => Some(version::SemVer::try_from("v25.9.3").unwrap()),
        "lodestar" => Some(version::SemVer::try_from("v1.35.0-rc.1").unwrap()),
        "nimbus" => Some(version::SemVer::try_from("v25.9.2").unwrap()),
        "prysm" => Some(version::SemVer::try_from("v6.1.0").unwrap()),
        "grandine" => Some(version::SemVer::try_from("v2.0.0-rc0").unwrap()),
        _ => None,
    }
}

static VERSION_EXTRACT_REGEX: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(r"^([^/]+)/v?([0-9]+\.[0-9]+\.[0-9]+)").expect("invalid regex")
});

fn check_beacon_node_version_status(bn_version: &str) -> Result<()> {
    let matches = VERSION_EXTRACT_REGEX
        .captures(bn_version)
        .ok_or(BeaconNodeVersionError::InvalidFormat)?;

    if matches.len() != 3 {
        return Err(BeaconNodeVersionError::InvalidFormat);
    }

    let client = version::SemVer::parse(&format!("v{}", &matches[2]))
        .map_err(|_| BeaconNodeVersionError::InvalidFormat)?;

    let name = &matches[1];
    let minimum = minimum_beacon_node_version(name).ok_or(BeaconNodeVersionError::UnknownClient)?;

    if client < minimum {
        return Err(BeaconNodeVersionError::TooOld { client, minimum });
    }

    Ok(())
}

/// Checks the version of the beacon node client and logs a warning if the
/// version is below the minimum or if the client is not recognized.
pub fn check_beacon_node_version(bn_version: &str) {
    match check_beacon_node_version_status(bn_version) {
        Err(BeaconNodeVersionError::InvalidFormat) => {
            warn!(
                input = bn_version,
                "Failed to parse beacon node version string due to unexpected format"
            );
        }
        Err(BeaconNodeVersionError::UnknownClient) => {
            warn!(
                client = bn_version,
                "Unknown beacon node client not in supported client list"
            );
        }
        Err(BeaconNodeVersionError::TooOld { client, minimum }) => {
            warn!(
              client_version = %client,
              minimum_required = %minimum,
              "Beacon node client version is below the minimum supported version. Please upgrade your beacon node."
            );
        }
        Ok(()) => { /* Do nothing */ }
    }
}
