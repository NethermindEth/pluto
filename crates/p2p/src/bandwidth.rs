use std::{
    convert::TryFrom as _,
    io,
    pin::Pin,
    task::{Context, Poll},
};

use futures::{
    future::{MapOk, TryFutureExt as _},
    io::{IoSlice, IoSliceMut},
    prelude::*,
    ready,
};
use libp2p::{
    Multiaddr, PeerId,
    core::{
        muxing::{StreamMuxer, StreamMuxerEvent},
        transport::{DialOpts, ListenerId, TransportError, TransportEvent},
    },
};
use vise::{Counter, EncodeLabelSet, Family, Global, Metrics};

#[derive(EncodeLabelSet, Hash, Clone, Eq, PartialEq, Debug)]
struct PeerLabel {
    peer: String,
    peer_cluster: String,
}

#[derive(Debug, Metrics)]
#[metrics(prefix = "relay_p2p")]
struct BandwidthMetrics {
    /// Bytes sent to peer and cluster.
    network_sent_bytes: Family<PeerLabel, Counter>,
    /// Bytes received from peer and cluster.
    network_receive_bytes: Family<PeerLabel, Counter>,
}

#[vise::register]
static BANDWIDTH_METRICS: Global<BandwidthMetrics> = Global::new();

#[derive(Clone)]
struct PeerConnectionMetrics {
    sent: Counter,
    received: Counter,
}

impl PeerConnectionMetrics {
    fn for_peer(peer_id: &PeerId) -> Self {
        let label = PeerLabel {
            peer: peer_id.to_string(),
            peer_cluster: String::new(),
        };
        Self {
            sent: BANDWIDTH_METRICS.network_sent_bytes[&label].clone(),
            received: BANDWIDTH_METRICS.network_receive_bytes[&label].clone(),
        }
    }
}

/// Per-peer bandwidth tracking transport wrapper.
///
/// Populates `relay_p2p_network_sent_bytes_total` and
/// `relay_p2p_network_receive_bytes_total` with `{peer, peer_cluster}` labels,
/// matching Charon's metric names.
#[pin_project::pin_project]
pub(crate) struct PeerBandwidthTransport<T> {
    #[pin]
    inner: T,
}

impl<T> PeerBandwidthTransport<T> {
    pub(crate) fn new(inner: T) -> Self {
        PeerBandwidthTransport { inner }
    }
}

impl<T, M> libp2p::core::Transport for PeerBandwidthTransport<T>
where
    T: libp2p::core::Transport<Output = (PeerId, M)>,
    M: StreamMuxer + Send + 'static,
    M::Substream: Send + 'static,
    M::Error: Send + Sync + 'static,
{
    type Dial = MapOk<T::Dial, Box<dyn FnOnce((PeerId, M)) -> (PeerId, PeerMuxer<M>) + Send>>;
    type Error = T::Error;
    type ListenerUpgrade =
        MapOk<T::ListenerUpgrade, Box<dyn FnOnce((PeerId, M)) -> (PeerId, PeerMuxer<M>) + Send>>;
    type Output = (PeerId, PeerMuxer<M>);

    fn listen_on(
        &mut self,
        id: ListenerId,
        addr: Multiaddr,
    ) -> Result<(), TransportError<Self::Error>> {
        self.inner.listen_on(id, addr)
    }

    fn remove_listener(&mut self, id: ListenerId) -> bool {
        self.inner.remove_listener(id)
    }

    fn dial(
        &mut self,
        addr: Multiaddr,
        dial_opts: DialOpts,
    ) -> Result<Self::Dial, TransportError<Self::Error>> {
        Ok(self
            .inner
            .dial(addr, dial_opts)?
            .map_ok(Box::new(move |(peer_id, muxer)| {
                let metrics = PeerConnectionMetrics::for_peer(&peer_id);
                (peer_id, PeerMuxer::new(muxer, metrics))
            })))
    }

    fn poll(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<TransportEvent<Self::ListenerUpgrade, Self::Error>> {
        match self.project().inner.poll(cx) {
            Poll::Ready(TransportEvent::Incoming {
                listener_id,
                upgrade,
                local_addr,
                send_back_addr,
            }) => Poll::Ready(TransportEvent::Incoming {
                listener_id,
                upgrade: upgrade.map_ok(Box::new(move |(peer_id, muxer)| {
                    let metrics = PeerConnectionMetrics::for_peer(&peer_id);
                    (peer_id, PeerMuxer::new(muxer, metrics))
                })),
                local_addr,
                send_back_addr,
            }),
            Poll::Ready(other) => {
                Poll::Ready(other.map_upgrade(|_| unreachable!("case already matched")))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

#[pin_project::pin_project]
pub(crate) struct PeerMuxer<M> {
    #[pin]
    inner: M,
    metrics: PeerConnectionMetrics,
}

impl<M> PeerMuxer<M> {
    fn new(inner: M, metrics: PeerConnectionMetrics) -> Self {
        Self { inner, metrics }
    }
}

impl<M: StreamMuxer> StreamMuxer for PeerMuxer<M> {
    type Error = M::Error;
    type Substream = PeerInstrumentedStream<M::Substream>;

    fn poll(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<StreamMuxerEvent, Self::Error>> {
        self.project().inner.poll(cx)
    }

    fn poll_inbound(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::Substream, Self::Error>> {
        let this = self.project();
        let inner = ready!(this.inner.poll_inbound(cx)?);
        Poll::Ready(Ok(PeerInstrumentedStream {
            inner,
            metrics: this.metrics.clone(),
        }))
    }

    fn poll_outbound(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::Substream, Self::Error>> {
        let this = self.project();
        let inner = ready!(this.inner.poll_outbound(cx)?);
        Poll::Ready(Ok(PeerInstrumentedStream {
            inner,
            metrics: this.metrics.clone(),
        }))
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.project().inner.poll_close(cx)
    }
}

#[pin_project::pin_project]
pub(crate) struct PeerInstrumentedStream<S> {
    #[pin]
    inner: S,
    metrics: PeerConnectionMetrics,
}

impl<S: AsyncRead> AsyncRead for PeerInstrumentedStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.project();
        let num_bytes = ready!(this.inner.poll_read(cx, buf))?;
        this.metrics
            .received
            .inc_by(u64::try_from(num_bytes).unwrap_or(u64::MAX));
        Poll::Ready(Ok(num_bytes))
    }

    fn poll_read_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = self.project();
        let num_bytes = ready!(this.inner.poll_read_vectored(cx, bufs))?;
        this.metrics
            .received
            .inc_by(u64::try_from(num_bytes).unwrap_or(u64::MAX));
        Poll::Ready(Ok(num_bytes))
    }
}

impl<S: AsyncWrite> AsyncWrite for PeerInstrumentedStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.project();
        let num_bytes = ready!(this.inner.poll_write(cx, buf))?;
        this.metrics
            .sent
            .inc_by(u64::try_from(num_bytes).unwrap_or(u64::MAX));
        Poll::Ready(Ok(num_bytes))
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = self.project();
        let num_bytes = ready!(this.inner.poll_write_vectored(cx, bufs))?;
        this.metrics
            .sent
            .inc_by(u64::try_from(num_bytes).unwrap_or(u64::MAX));
        Poll::Ready(Ok(num_bytes))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.project().inner.poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.project().inner.poll_close(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::io::{AsyncReadExt, AsyncWriteExt};

    struct MockStream {
        read_data: Vec<u8>,
        write_buffer: Vec<u8>,
        read_pos: usize,
    }

    impl MockStream {
        fn new(read_data: Vec<u8>) -> Self {
            Self {
                read_data,
                write_buffer: Vec::new(),
                read_pos: 0,
            }
        }
    }

    impl AsyncRead for MockStream {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut [u8],
        ) -> Poll<io::Result<usize>> {
            let remaining = self.read_data.len() - self.read_pos;
            let to_read = std::cmp::min(buf.len(), remaining);
            if to_read > 0 {
                buf[..to_read]
                    .copy_from_slice(&self.read_data[self.read_pos..self.read_pos + to_read]);
                self.read_pos += to_read;
            }
            Poll::Ready(Ok(to_read))
        }
    }

    impl AsyncWrite for MockStream {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.write_buffer.extend_from_slice(buf);
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[test]
    fn test_bandwidth_received() {
        let peer_id = PeerId::random();
        let metrics = PeerConnectionMetrics::for_peer(&peer_id);
        let initial = metrics.received.get();

        let mock = MockStream::new(vec![1, 2, 3, 4, 5]);
        let mut stream = PeerInstrumentedStream {
            inner: mock,
            metrics: metrics.clone(),
        };

        let mut buf = [0u8; 3];
        let mut cx = Context::from_waker(futures::task::noop_waker_ref());
        let _ = Pin::new(&mut stream).poll_read(&mut cx, &mut buf);

        assert_eq!(metrics.received.get(), initial + 3);
    }

    #[test]
    fn test_bandwidth_sent() {
        let peer_id = PeerId::random();
        let metrics = PeerConnectionMetrics::for_peer(&peer_id);
        let initial = metrics.sent.get();

        let mock = MockStream::new(Vec::new());
        let mut stream = PeerInstrumentedStream {
            inner: mock,
            metrics: metrics.clone(),
        };

        let data = b"hello";
        let mut cx = Context::from_waker(futures::task::noop_waker_ref());
        let _ = Pin::new(&mut stream).poll_write(&mut cx, data);

        assert_eq!(metrics.sent.get(), initial + 5);
    }

    #[test]
    fn test_bandwidth_multiple_operations() {
        let peer_id = PeerId::random();
        let metrics = PeerConnectionMetrics::for_peer(&peer_id);
        let initial_recv = metrics.received.get();
        let initial_sent = metrics.sent.get();

        let mock = MockStream::new(vec![1, 2, 3, 4, 5, 6, 7, 8]);
        let mut stream = PeerInstrumentedStream {
            inner: mock,
            metrics: metrics.clone(),
        };

        let mut cx = Context::from_waker(futures::task::noop_waker_ref());

        // Read 3 bytes
        let mut buf = [0u8; 3];
        let _ = Pin::new(&mut stream).poll_read(&mut cx, &mut buf);

        // Write 5 bytes
        let _ = Pin::new(&mut stream).poll_write(&mut cx, b"hello");

        // Read 2 bytes
        let mut buf2 = [0u8; 2];
        let _ = Pin::new(&mut stream).poll_read(&mut cx, &mut buf2);

        // Write 4 bytes
        let _ = Pin::new(&mut stream).poll_write(&mut cx, b"test");

        assert_eq!(metrics.received.get(), initial_recv + 5);
        assert_eq!(metrics.sent.get(), initial_sent + 9);
    }
}
