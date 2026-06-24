//! Real-TCP proof that the priority protocol negotiates the exact slash-less
//! wire token `charon/priority/2.0.0` (matching the reference implementation),
//! exercising the patched multistream-select end-to-end.
//!
//! This is the negotiation that runs over every transport (TCP here); a stock
//! multistream-select would reject the slash-less token at propose/advertise/
//! decode, so a successful handshake proves the patch works on a real socket.

use std::time::Duration;

use futures::future;
use multistream_select::{Version, dialer_select_proto, listener_select_proto};
use tokio::{
    net::{TcpListener, TcpStream},
    time::timeout,
};
use tokio_util::compat::TokioAsyncReadCompatExt;

/// The token both nodes negotiate — Pluto's priority protocol id.
const PROTO: &str = pluto_priority::PROTOCOL_ID;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn negotiates_slashless_priority_protocol_over_tcp() {
    // The id must carry NO leading slash, byte-identical to Charon's wire token.
    assert!(
        !PROTO.starts_with('/'),
        "priority protocol id must be slash-less, got {PROTO:?}"
    );
    println!(
        "priority PROTOCOL_ID = {PROTO:?}  (leading '/': {})",
        PROTO.starts_with('/')
    );

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local addr");

    // Listener node: accept one connection and negotiate the priority protocol.
    let server = tokio::spawn(async move {
        let (sock, _peer) = listener.accept().await.expect("accept");
        let (proto, _io) = listener_select_proto(sock.compat(), std::iter::once(PROTO))
            .await
            .expect("listener negotiation");
        proto
    });

    // Dialer node: connect and propose the priority protocol.
    let client = tokio::spawn(async move {
        let sock = TcpStream::connect(addr).await.expect("connect");
        let (proto, _io) = dialer_select_proto(sock.compat(), std::iter::once(PROTO), Version::V1)
            .await
            .expect("dialer negotiation");
        proto
    });

    let (server_res, client_res) = timeout(Duration::from_secs(10), future::join(server, client))
        .await
        .expect("negotiation completed within timeout");
    let server_proto = server_res.expect("server task");
    let client_proto = client_res.expect("client task");

    println!("negotiated over TCP — listener: {server_proto:?}, dialer: {client_proto:?}");

    // Both ends agreed on the exact slash-less token over the real socket.
    assert_eq!(server_proto, PROTO);
    assert_eq!(client_proto, PROTO);
    assert_eq!(server_proto, "charon/priority/2.0.0");
    assert!(!server_proto.starts_with('/'));
}
