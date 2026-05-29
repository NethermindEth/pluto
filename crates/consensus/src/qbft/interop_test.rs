use futures::io::Cursor;
use prost::{Message, bytes::Bytes};
use prost_types::Any;
use tokio_util::sync::CancellationToken;

use crate::qbft::{component::tests, msg};
use pluto_core::{
    corepb::v1::{consensus as pbconsensus, core as pbcore},
    qbft::SomeMsg,
};

const REFERENCE_VALUE_HASH: &str =
    "0a0c0a0430783939120401020304000000000000000000000000000000000000";
const REFERENCE_SIGNATURE: &str = "4cf90756a4241bce7b71e18c6fb9cf91dc96abc6ef1739218974d96e75faf0a15921d47997210232cf064b5e401c6de800fb1f654fcadca0e293dea335fe924200";
const REFERENCE_PAYLOAD: &str = "0a6f08021204082a1002200142414cf90756a4241bce7b71e18c6fb9cf91dc96abc6ef1739218974d96e75faf0a15921d47997210232cf064b5e401c6de800fb1f654fcadca0e293dea335fe9242005a200a0c0a04307839391204010203040000000000000000000000000000000000001a440a32747970652e676f6f676c65617069732e636f6d2f636f72652e636f726570622e76312e556e7369676e656444617461536574120e0a0c0a0430783939120401020304";
const REFERENCE_FRAME: &str = "b7010a6f08021204082a1002200142414cf90756a4241bce7b71e18c6fb9cf91dc96abc6ef1739218974d96e75faf0a15921d47997210232cf064b5e401c6de800fb1f654fcadca0e293dea335fe9242005a200a0c0a04307839391204010203040000000000000000000000000000000000001a440a32747970652e676f6f676c65617069732e636f6d2f636f72652e636f726570622e76312e556e7369676e656444617461536574120e0a0c0a0430783939120401020304";

#[tokio::test]
async fn reference_framed_message_decodes() {
    let mut cursor = Cursor::new(hex::decode(REFERENCE_FRAME).expect("valid fixture hex"));

    let decoded =
        pluto_p2p::proto::read_protobuf_with_max_size::<pbconsensus::QbftConsensusMsg, _>(
            &mut cursor,
            pluto_p2p::proto::MAX_MESSAGE_SIZE,
        )
        .await
        .expect("reference frame should decode");

    assert_eq!(decoded, reference_consensus_msg());
}

#[tokio::test]
async fn reference_signed_message_is_admitted() {
    let consensus = tests::consensus(0, true);
    let mut recv_rx = consensus
        .get_instance_io(tests::duty())
        .take_recv_rx()
        .expect("recv receiver should be available");

    consensus
        .handle(&CancellationToken::new(), Some(reference_consensus_msg()))
        .await
        .expect("reference message should be admitted");

    let received = recv_rx.recv().await.expect("admitted message");
    assert_eq!(received.source(), 0);
    assert_eq!(hex::encode(received.value()), REFERENCE_VALUE_HASH);
    assert_eq!(
        received.value_source().expect("value source should exist"),
        reference_any_value()
    );
}

#[tokio::test]
async fn rust_rebuilds_reference_message_and_frame() {
    let rebuilt = build_reference_consensus_msg();
    let mut frame = Cursor::new(Vec::new());

    pluto_p2p::proto::write_protobuf(&mut frame, &rebuilt)
        .await
        .expect("frame write should succeed");

    assert_eq!(rebuilt, reference_consensus_msg());
    assert_eq!(hex::encode(rebuilt.encode_to_vec()), REFERENCE_PAYLOAD);
    assert_eq!(hex::encode(frame.into_inner()), REFERENCE_FRAME);
}

fn build_reference_consensus_msg() -> pbconsensus::QbftConsensusMsg {
    let value = reference_value();
    let value_hash = msg::hash_proto(&value).expect("value should hash");
    let signed = msg::sign_msg(
        &pbconsensus::QbftMsg {
            r#type: i64::from(pluto_core::qbft::MSG_PREPARE),
            duty: Some(pbcore::Duty {
                slot: 42,
                r#type: 2,
            }),
            peer_idx: 0,
            round: 1,
            value_hash: value_hash.to_vec().into(),
            ..Default::default()
        },
        &tests::secret_key(1),
    )
    .expect("message should sign");

    assert_eq!(hex::encode(&signed.signature), REFERENCE_SIGNATURE);

    pbconsensus::QbftConsensusMsg {
        msg: Some(signed),
        justification: vec![],
        values: vec![Any::from_msg(&value).expect("value should pack")],
    }
}

fn reference_consensus_msg() -> pbconsensus::QbftConsensusMsg {
    pbconsensus::QbftConsensusMsg::decode(
        hex::decode(REFERENCE_PAYLOAD)
            .expect("valid fixture hex")
            .as_slice(),
    )
    .expect("reference payload should decode")
}

fn reference_value() -> pbcore::UnsignedDataSet {
    let mut set = std::collections::BTreeMap::new();
    set.insert("0x99".to_string(), Bytes::from_static(&[1, 2, 3, 4]));
    pbcore::UnsignedDataSet { set }
}

fn reference_any_value() -> Any {
    Any::from_msg(&reference_value()).expect("value should pack")
}
