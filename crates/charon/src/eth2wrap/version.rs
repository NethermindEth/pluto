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

static MINIMUM_BEACON_NODE_VERSIONS: LazyLock<std::collections::HashMap<&str, version::SemVer>> =
    LazyLock::new(|| {
        #[allow(clippy::unwrap_used, reason = "literals should be valid semver")]
        std::collections::HashMap::from([
            ("lighthouse", version::SemVer::parse("v8.0.0-rc.0").unwrap()),
            ("teku", version::SemVer::parse("v25.9.3").unwrap()),
            ("lodestar", version::SemVer::parse("v1.35.0-rc.1").unwrap()),
            ("nimbus", version::SemVer::parse("v25.9.2").unwrap()),
            ("prysm", version::SemVer::parse("v6.1.0").unwrap()),
            ("grandine", version::SemVer::parse("v2.0.0-rc0").unwrap()),
        ])
    });

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

    let client = version::SemVer::parse(format!("v{}", &matches[2]))
        .map_err(|_| BeaconNodeVersionError::InvalidFormat)?;

    let name = &matches[1];
    let minimum = MINIMUM_BEACON_NODE_VERSIONS
        .get(&name.to_lowercase().as_str())
        .ok_or(BeaconNodeVersionError::UnknownClient)?
        .clone();

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_beacon_node_version_status() {
        let tc = vec![
            // Teku
            (
                "teku/v25.9.3/linux-x86_64/-eclipseadoptium-openjdk64bitservervm-java-21",
                Ok(()),
            ),
            (
                "teku/vUNKNOWN+g40561a9/linux-x86_64/-eclipseadoptium-openjdk64bitservervm-java-21",
                Err(BeaconNodeVersionError::InvalidFormat),
            ),
            // Lighthouse
            ("Lighthouse/v8.0.1-e42406d/x86_64-linux", Ok(())),
            ("Lighthouse/v8.0.0-54f7bc5/aarch64-linux", Ok(())),
            // Lodestar
            ("Lodestar/v1.35.0/8335180", Ok(())),
            ("Lodestar/v1.36.0/1a34f98", Ok(())),
            // Nimbus
            ("Nimbus/v26.4.1-77cfa7-stateofus", Ok(())),
            ("Nimbus/v26.5.0-d2f233-stateofus", Ok(())),
            (
                "Nimbus/v25.9.0-c7e5ca-stateofus",
                Err(BeaconNodeVersionError::TooOld {
                    client: version::SemVer::parse("v25.9.0").unwrap(),
                    minimum: version::SemVer::parse("v25.9.2").unwrap(),
                }),
            ),
            // Prysm
            (
                "Prysm/v5.3.2 (linux amd64)",
                Err(BeaconNodeVersionError::TooOld {
                    client: version::SemVer::parse("v5.3.2").unwrap(),
                    minimum: version::SemVer::parse("v6.1.0").unwrap(),
                }),
            ),
            ("Prysm/v6.1.2 (linux amd64)", Ok(())),
            ("Prysm/v6.2.0 (linux amd64)", Ok(())),
            // Grandine
            ("Grandine/2.1.0-29cb5c1/x86_64-linux2025-05-19", Ok(())),
            // Additional error cases
            ("", Err(BeaconNodeVersionError::InvalidFormat)),
            ("justastring", Err(BeaconNodeVersionError::InvalidFormat)),
            ("/v7.0.0", Err(BeaconNodeVersionError::InvalidFormat)),
            (
                "UnknownClient/v7.0.0",
                Err(BeaconNodeVersionError::UnknownClient),
            ),
            ("Lighthouse/", Err(BeaconNodeVersionError::InvalidFormat)),
            (
                "Lighthouse/vBAD",
                Err(BeaconNodeVersionError::InvalidFormat),
            ),
        ];

        for (input, expected) in tc {
            let result = super::check_beacon_node_version_status(input);
            assert_eq!(result, expected, "input = {input}");
        }
    }
}
