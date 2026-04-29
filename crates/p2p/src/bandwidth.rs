use std::{
    convert::TryFrom as _,
    io,
    pin::Pin,
    sync::Arc,
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
use vise::Counter;

/// Per-peer bandwidth counters injected into [`PeerBandwidthTransport`].
pub struct PeerConnectionMetrics {
    /// Bytes sent to the peer.
    pub sent: Counter,
    /// Bytes received from the peer.
    pub received: Counter,
}

/// Factory that creates [`PeerConnectionMetrics`] for a given peer.
pub type BandwidthFactory = Arc<dyn Fn(&PeerId) -> PeerConnectionMetrics + Send + Sync>;

/// Per-peer bandwidth tracking transport wrapper.
///
/// Calls the supplied [`BandwidthFactory`] for every established connection and
/// records bytes through the returned [`PeerConnectionMetrics`] counters.
#[pin_project::pin_project]
pub(crate) struct PeerBandwidthTransport<T> {
    #[pin]
    inner: T,
    factory: BandwidthFactory,
}

impl<T> PeerBandwidthTransport<T> {
    pub(crate) fn new(inner: T, factory: BandwidthFactory) -> Self {
        PeerBandwidthTransport { inner, factory }
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
        let factory = Arc::clone(&self.factory);
        Ok(self
            .inner
            .dial(addr, dial_opts)?
            .map_ok(Box::new(move |(peer_id, muxer)| {
                let metrics = factory(&peer_id);
                (peer_id, PeerMuxer::new(muxer, metrics))
            })))
    }

    fn poll(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<TransportEvent<Self::ListenerUpgrade, Self::Error>> {
        let this = self.project();
        let factory = Arc::clone(this.factory);
        match this.inner.poll(cx) {
            Poll::Ready(TransportEvent::Incoming {
                listener_id,
                upgrade,
                local_addr,
                send_back_addr,
            }) => Poll::Ready(TransportEvent::Incoming {
                listener_id,
                upgrade: upgrade.map_ok(Box::new(move |(peer_id, muxer)| {
                    let metrics = factory(&peer_id);
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
            sent: this.metrics.sent.clone(),
            received: this.metrics.received.clone(),
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
            sent: this.metrics.sent.clone(),
            received: this.metrics.received.clone(),
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
    sent: Counter,
    received: Counter,
}

impl<S: AsyncRead> AsyncRead for PeerInstrumentedStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.project();
        let num_bytes = ready!(this.inner.poll_read(cx, buf))?;
        this.received
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
        this.received
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
        this.sent
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
        this.sent
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
#[allow(clippy::arithmetic_side_effects)]
mod tests {
    use super::*;

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

    fn make_stream() -> (PeerInstrumentedStream<MockStream>, Counter, Counter) {
        let sent = Counter::default();
        let received = Counter::default();
        let stream = PeerInstrumentedStream {
            inner: MockStream::new(vec![1, 2, 3, 4, 5]),
            sent: sent.clone(),
            received: received.clone(),
        };
        (stream, sent, received)
    }

    #[test]
    fn bandwidth_received() {
        let (mut stream, _, received) = make_stream();
        let initial = received.get();

        let mut buf = [0u8; 3];
        let mut cx = Context::from_waker(futures::task::noop_waker_ref());
        let _ = Pin::new(&mut stream).poll_read(&mut cx, &mut buf);

        assert_eq!(received.get(), initial + 3);
    }

    #[test]
    fn bandwidth_sent() {
        let (mut stream, sent, _) = make_stream();
        let initial = sent.get();

        let data = b"hello";
        let mut cx = Context::from_waker(futures::task::noop_waker_ref());
        let _ = Pin::new(&mut stream).poll_write(&mut cx, data);

        assert_eq!(sent.get(), initial + 5);
    }

    #[test]
    fn bandwidth_multiple_operations() {
        let (mut stream, sent, received) = make_stream();
        let mut stream2 = PeerInstrumentedStream {
            inner: MockStream::new(vec![1, 2, 3, 4, 5, 6, 7, 8]),
            sent: sent.clone(),
            received: received.clone(),
        };

        let initial_recv = received.get();
        let initial_sent = sent.get();

        let mut cx = Context::from_waker(futures::task::noop_waker_ref());

        let mut buf = [0u8; 3];
        let _ = Pin::new(&mut stream2).poll_read(&mut cx, &mut buf);

        let _ = Pin::new(&mut stream).poll_write(&mut cx, b"hello");

        let mut buf2 = [0u8; 2];
        let _ = Pin::new(&mut stream2).poll_read(&mut cx, &mut buf2);

        let _ = Pin::new(&mut stream).poll_write(&mut cx, b"test");

        assert_eq!(received.get(), initial_recv + 5);
        assert_eq!(sent.get(), initial_sent + 9);
    }
}
