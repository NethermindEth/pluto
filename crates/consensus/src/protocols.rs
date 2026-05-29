use libp2p::StreamProtocol;

const PROTOCOL_ID_PREFIX: &str = "/charon/consensus/";

/// QBFT v2 protocol ID.
pub const QBFT_V2_PROTOCOL_ID: &str = "/charon/consensus/qbft/2.0.0";

/// Protocols supported by the Charon core.
pub fn protocols() -> Vec<StreamProtocol> {
    vec![StreamProtocol::new(QBFT_V2_PROTOCOL_ID)]
}

/// Returns the most preferred consensus protocol from the list of protocols.
pub fn most_preferred_consensus_protocol<'a>(protocols: &[&'a str]) -> &'a str {
    protocols
        .iter()
        .find(|p| p.to_string().starts_with(PROTOCOL_ID_PREFIX))
        .cloned()
        .unwrap_or(QBFT_V2_PROTOCOL_ID)
}

/// Returns true if the protocol name is supported by the Charon core.
pub fn is_supported_protocol_name(name: &str) -> bool {
    let normalized_name = name.to_lowercase();

    protocols().iter().any(|protocol| {
        protocol
            .to_string()
            .strip_prefix(PROTOCOL_ID_PREFIX)
            .and_then(|name_and_version| name_and_version.split('/').next())
            .is_some_and(|protocol_name| protocol_name == normalized_name)
    })
}

/// Prioritizes protocols matching the given name by moving them to the front.
pub fn prioritize_protocols_by_name(
    protocol_name: &str,
    all_protocols: &[StreamProtocol],
) -> Vec<StreamProtocol> {
    let target_prefix = format!("{}{}/", PROTOCOL_ID_PREFIX, protocol_name);

    let (matching, others): (Vec<_>, Vec<_>) = all_protocols
        .iter()
        .cloned()
        .partition(|p| p.to_string().starts_with(&target_prefix));

    matching.into_iter().chain(others).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_supported_protocol_name_works() {
        assert!(is_supported_protocol_name("qbft"));
        assert!(!is_supported_protocol_name("unreal"));
    }

    #[test]
    fn protocols_works() {
        let protocols = protocols();
        assert_eq!(protocols, vec![StreamProtocol::new(QBFT_V2_PROTOCOL_ID)]);
    }

    #[test]
    fn most_preferred_consensus_protocol_default_is_qbft() {
        assert_eq!(
            most_preferred_consensus_protocol(&["unreal"]),
            QBFT_V2_PROTOCOL_ID
        );
        assert_eq!(most_preferred_consensus_protocol(&[]), QBFT_V2_PROTOCOL_ID);
    }

    #[test]
    fn most_preferred_consensus_protocol_latest_abft_is_preferred() {
        let pp = vec![
            "/charon/consensus/abft/3.0.0",
            "/charon/consensus/abft/1.0.0",
            "/charon/consensus/qbft/1.0.0",
        ];

        assert_eq!(
            most_preferred_consensus_protocol(&pp),
            "/charon/consensus/abft/3.0.0"
        );
    }

    #[test]
    fn prioritize_protocols_by_name_works() {
        let initial = vec![
            StreamProtocol::new("/charon/consensus/hotstuff/1.0.0"),
            StreamProtocol::new("/charon/consensus/abft/3.0.0"),
            StreamProtocol::new("/charon/consensus/abft/1.0.0"),
            StreamProtocol::new("/charon/consensus/qbft/1.0.0"),
        ];

        let bumped = prioritize_protocols_by_name("abft", &initial);

        assert_eq!(
            bumped,
            vec![
                StreamProtocol::new("/charon/consensus/abft/3.0.0"),
                StreamProtocol::new("/charon/consensus/abft/1.0.0"),
                StreamProtocol::new("/charon/consensus/hotstuff/1.0.0"),
                StreamProtocol::new("/charon/consensus/qbft/1.0.0"),
            ]
        );
    }
}
