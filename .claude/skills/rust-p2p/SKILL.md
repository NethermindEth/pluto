---
name: rust-p2p
description: Use when implementing, reviewing, debugging, or explaining Pluto Rust libp2p code: Node/P2PContext ownership, PlutoBehaviour composition, NetworkBehaviour and ConnectionHandler protocols, relay/force-direct/quic-upgrade behaviours, peerinfo/parsigex protocol handlers, DKG protocol handlers, and P2P tests.
---

# Rust P2P

Use this skill for Pluto Rust libp2p work. Bias toward the existing networking
architecture; do not invent a parallel swarm, context, or handler model.

## Start Here

Classify the task and read the matching implementation first.

| Area | Files | Look for |
| --- | --- | --- |
| Node runtime | `crates/p2p/src/p2p.rs` | `Node`, builder closure, listen/dial setup |
| Shared peer state | `crates/p2p/src/p2p_context.rs` | local peer binding, known peers, peer store |
| Common wrapper | `crates/p2p/src/behaviours/pluto.rs` | common behaviours plus `inner` |
| Connection tracking | `crates/p2p/src/conn_logger.rs` | peer-store updates on connection lifecycle |
| Connection gating | `crates/p2p/src/gater.rs` | allow/deny policy |
| Bootnode | `crates/p2p/src/bootnode.rs` | bootnode run loop and shutdown |
| Relay | `crates/p2p/src/relay.rs` | reservations and relay-route dialing |
| Direct routing | `crates/p2p/src/force_direct.rs` | direct-connection enforcement |
| QUIC upgrade | `crates/p2p/src/quic_upgrade.rs` | TCP-to-QUIC retry/close flow |
| Optional wrapper | `crates/p2p/src/behaviours/optional.rs` | enabled/disabled behaviour routing |
| Framing | `crates/p2p/src/proto.rs` | protobuf read/write helpers and limits |
| Peer info | `crates/peerinfo/src/` | simple behaviour/handler protocol |
| Parsigex | `crates/parsigex/src/` | handle -> behaviour -> handler broadcast protocol |
| DKG broadcast | `crates/dkg/src/bcast/` | command-driven behaviour/handler protocol |
| DKG sync | `crates/dkg/src/sync/` | long-lived stream, waiters, cancellation |
| Examples | `crates/*/examples/` | expected public construction patterns |

Before editing, draw the ownership path for the specific protocol:

```text
application / protocol flow
  |
  | handle, command channel, waiter, or event consumer
  v
feature Behaviour             shared P2PContext
  |                            ^
  | ToSwarm::{Dial, ListenOn,  | conn_logger + identify update it
  | NotifyHandler, GenerateEvent}
  v
PlutoBehaviour wrapper
  |
  v
libp2p Swarm
  |
  | connection events + negotiated substreams
  v
feature ConnectionHandler
  |
  | async stream read/write futures
  v
protocol state / protocol event
```

## Core Ownership

- `Node` owns the `Swarm`.
- `PlutoBehaviour<B>` wraps common networking behaviours around feature
  behaviour `B`.
- One node must have one canonical `P2PContext` shared by `Node`,
  `PlutoBehaviour`, and inner behaviours that read peer state.
- Feature `Behaviour` owns swarm-level protocol orchestration.
- Feature `ConnectionHandler` owns one connection's negotiated streams.
- User-facing handles do not own the swarm; they use channels, waiters, shared
  protocol state, or emitted events.

## Node And Context

Use `Node::new` for normal client nodes. It builds TCP/QUIC transports and
includes relay-client support. Use `Node::new_server` for server-style nodes
that should not include relay-client behaviour.

Rules:

- Pass the intended `P2PContext` into `Node` construction.
- Inside the builder closure, use `builder.p2p_context()` for inner behaviours
  that need peer state.
- Do not create a fresh/default `P2PContext` inside a node builder closure.
- Treat `P2PContext::default()` as only suitable at standalone node construction
  when no known-peer state is needed and no component must share peer state.
- Do not reintroduce replaceable-context APIs after the builder is created.
- Let `Node` bind the local peer ID and preserve `LocalPeerIdMismatch` fail-fast
  behaviour.
- `filter_private_addrs` affects advertised addresses, not listen addresses.

`P2PContext` is for runtime peer connectivity:

- known peer set,
- local peer ID once bound,
- active/inactive connection records,
- peer addresses learned from identify.

Do not store protocol progress in `P2PContext`.

**Critical failure mode:** if `conn_logger` writes context A while an inner
behaviour reads context B, the inner behaviour will treat connected peers as
disconnected.

## PlutoBehaviour

`PlutoBehaviour<B>` composes common behaviour with feature behaviour:

- `conn_logger`: lifecycle logging, peer-store updates, metrics,
- `gater`: connection allow/deny policy,
- `identify`: address/protocol exchange; `Node` stores listen addresses,
- `ping`: latency/keepalive metrics,
- `autonat`: reachability,
- `quic_upgrade`: optional TCP -> QUIC upgrade attempts,
- `inner`: feature-specific behaviour.

**Composition invariant:** `#[derive(NetworkBehaviour)]` delegates behaviour
methods in struct field order. Keep `conn_logger` before behaviours that may
read `P2PContext.peer_store`, so connection events update shared peer state
before later fields handle the same swarm event or get polled afterward.

## Behaviour Pattern

A feature `Behaviour` is a swarm-level coordinator.

Common responsibilities:

- receive user commands through `tokio::sync::mpsc`,
- queue `ToSwarm` events in `VecDeque`,
- create a real handler for peers in protocol scope,
- return `dummy::ConnectionHandler` when the behaviour has no per-connection
  protocol work or when a peer is out of scope,
- inspect `FromSwarm` connection/dial events,
- poll retry/routing timers,
- translate handler events into feature events.

`poll` rules:

- never `.await`,
- never block,
- never spin on an immediately failing condition,
- drain ready commands before sleeping,
- emit at most one queued `ToSwarm` event per poll,
- return `Poll::Pending` when no work is ready.

Use `ToSwarm::NotifyHandler` when an existing handler should open a substream.
Use `ToSwarm::GenerateEvent` for application-visible events.

## Handler Pattern

A `ConnectionHandler` is per connection, not per peer.

Common responsibilities:

- define inbound and outbound protocol upgrades,
- handle `FullyNegotiatedInbound` by starting inbound stream work,
- handle `FullyNegotiatedOutbound` by starting matching outbound stream work,
- report results with `ConnectionHandlerEvent::NotifyBehaviour`,
- request outbound streams with
  `ConnectionHandlerEvent::OutboundSubstreamRequest`,
- translate negotiation, timeout, and I/O failures into typed protocol failures.

Do not block in handler `poll`. Store async stream work as boxed futures or a
`FuturesUnordered`, then poll them.

Do not assume only one handler exists for a peer. If a protocol requires one
outbound loop per peer, keep an explicit claim in shared protocol state and
release it on every terminal path.

## Handles, Waiters, Cancellation

Keep user-facing APIs small and keep swarm internals inside `Node`.

Existing shapes:

- command handle -> `mpsc` -> behaviour (`parsigex::Handle`,
  `bcast::Component`, `sync::Client`),
- behaviour event -> caller observes completion/failure (`parsigex`, `bcast`),
- shared protocol state -> wait API (`sync::Server`).

Waiter rules:

- Use `Notify` to wake waiters after state changes.
- Check terminal error and cancellation before awaiting another notification.
- Use `CancellationToken` for long-running waits and protocol tasks that must
  stop during shutdown.
- Tests around waiters should still use `tokio::time::timeout`; cancellation is
  part of the contract, not a replacement for test bounds.

## Stream And Framing

Choose the protocol primitive intentionally:

- one stream protocol -> `ReadyUpgrade<StreamProtocol>`,
- multiple stream protocols on one handler -> `SelectUpgrade`,
- request/response over a negotiated stream -> helpers in `pluto_p2p::proto`.

Framing variants:

- varint length framing: `write_protobuf` /
  `read_protobuf_with_max_size`,
- fixed `i64` little-endian length framing: `write_fixed_size_protobuf` /
  `read_fixed_size_protobuf_with_max_size`.

Safety rules:

- Use explicit protocol-specific max sizes where practical.
- Do not allocate from an untrusted frame length before checking the max.
- Add per-message `tokio::time::timeout` when a slow peer can otherwise hold a
  stream task indefinitely.
- Preserve `io::ErrorKind` until retry/terminal decisions are made.

## Dialing And Retry

Prefer swarm-owned dialing through `ToSwarm::Dial`.

Use `PeerCondition::DisconnectedAndNotDialing` when activation should not open
duplicate dials.

Typical dial-failure handling:

- `Transport(_)`: retry only if the protocol still wants reconnect.
- `NoAddresses`: retry only after a delay; identify, relay routing, or
  bootstrap may populate addresses later.
- `DialBackoff`: usually let libp2p backoff stand unless the protocol has a
  specific recovery path.
- `NegotiationFailed`: usually terminal for that stream protocol; the peer does
  not support it.

Reconnect loops need a wakeup path. If a handler releases an outbound claim,
ensure another handler can eventually retry by timer, notification, or a new
swarm event.

## Relay And Routing

Relay reservation and relay routing are separate:

- `MutableRelayReservation` dials relay servers directly, waits for relay
  connection establishment, then listens on `/p2p-circuit` addresses.
- `RelayRouter` periodically builds relay circuit addresses for known peers and
  queues dials through those relays.

Address rules:

- Dialing a relay server directly: append `/p2p/<relay-id>`, not
  `/p2p-circuit`.
- Listening through a relay or dialing a target through a relay: include
  `/p2p-circuit`.
- Do not assume relay peer data is available at startup; mutable relay peers can
  resolve later.

## Testing

Use the smallest test that exercises the real boundary.

Good boundaries:

- behaviour queueing/retry: unit-test `NetworkBehaviour::poll` with
  `noop_waker_ref`,
- handler state machines: poll handlers/futures directly where possible,
- real connectivity: use `Node` and real swarms,
- multi-swarm tests: use `#[tokio::test(flavor = "multi_thread")]`,
- async barriers and shutdown: wrap waits in `tokio::time::timeout`,
- ports: prefer `/ip4/127.0.0.1/tcp/0` plus `SwarmEvent::NewListenAddr`.

Regression tests should cover the contract boundary:

- success path,
- error propagation to waiters or events,
- cancellation/teardown,
- retry or dial-failure behaviour,
- protocol validation failure for authenticated peers.
