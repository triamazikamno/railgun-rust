use crate::config::{NodeConfig, WakuNetworkConfig, WakuTorClientProvider, WakuTransportProfile};
use crate::error::TransportInitError;
use crate::proto;
use crate::protocols;
use crate::protocols::codec::ProstLengthDelimitedCodec;
use crate::tasks::TaskTracker;
use futures::StreamExt;
use futures::future::{BoxFuture, FutureExt};
use libp2p::core::multiaddr::Protocol;
use libp2p::core::transport::Boxed;
use libp2p::core::transport::{
    DialOpts, ListenerId, TransportError, TransportEvent as CoreTransportEvent,
};
use libp2p::core::upgrade;
use libp2p::dns;
use libp2p::identify;
use libp2p::identity;
use libp2p::noise;
use libp2p::ping;
use libp2p::request_response::{self, OutboundRequestId, ResponseChannel};
use libp2p::swarm::{DialError, NetworkBehaviour, Swarm, SwarmEvent};
use libp2p::tcp;
use libp2p::websocket;
use libp2p::yamux;
use libp2p::{Multiaddr, PeerId, StreamProtocol, Transport as _};
use libp2p_mplex as mplex;
use std::collections::HashMap;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::sync::{mpsc, watch};
use tracing::{debug, error};

/// Internal request ID used by the coordinator to correlate responses.
pub(crate) type ReqId = u64;
type WakuBoxedTransport = Boxed<(PeerId, libp2p::core::muxing::StreamMuxerBox)>;

/// Commands sent from coordinator to transport.
#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub(crate) enum TransportCmd {
    Dial {
        peer_id: PeerId,
        addrs: Vec<Multiaddr>,
    },
    DisconnectPeers {
        peers: Vec<PeerId>,
    },
    SendLightPush {
        req_id: ReqId,
        peer_id: PeerId,
        request: proto::light_push::LightPushRequestV3,
    },
    SendPeerExchange {
        req_id: ReqId,
        peer_id: PeerId,
        request: proto::peer_exchange::PeerExchangeRpc,
    },
    SendMetadataResponse {
        channel: ResponseChannel<proto::metadata::WakuMetadataResponse>,
        response: proto::metadata::WakuMetadataResponse,
    },
    // Filter commands
    SendFilterSubscribe {
        req_id: ReqId,
        peer_id: PeerId,
        request: proto::filter::FilterSubscribeRequest,
    },
    SendStoreQuery {
        req_id: ReqId,
        peer_id: PeerId,
        request: proto::store::StoreQueryRequest,
    },
}

/// Events emitted from transport to coordinator.
#[derive(Debug)]
pub(crate) enum TransportEvent {
    ConnectionEstablished {
        peer_id: PeerId,
    },
    ConnectionClosed {
        peer_id: PeerId,
    },
    DialError {
        peer_id: PeerId,
        error: DialError,
    },
    IdentifyReceived {
        peer_id: PeerId,
        protocols: Vec<String>,
        addrs: Vec<Multiaddr>,
    },
    MetadataRequest {
        peer_id: PeerId,
        channel: ResponseChannel<proto::metadata::WakuMetadataResponse>,
    },
    LightPushResponse {
        req_id: ReqId,
        peer_id: PeerId,
        result: Result<proto::light_push::LightPushResponseV3, request_response::OutboundFailure>,
    },
    PeerExchangeResponse {
        req_id: ReqId,
        result: Result<proto::peer_exchange::PeerExchangeRpc, request_response::OutboundFailure>,
    },
    // Filter events
    FilterSubscribeResponse {
        req_id: ReqId,
        peer_id: PeerId,
        result: Result<proto::filter::FilterSubscribeResponse, request_response::OutboundFailure>,
    },
    StoreQueryResponse {
        req_id: ReqId,
        result: Result<protocols::store::StoreQueryPage, request_response::OutboundFailure>,
    },
}

#[derive(Debug)]
pub(crate) struct FilterPushEvent {
    pub(crate) peer_id: PeerId,
    pub(crate) push: Box<proto::filter::MessagePush>,
}

#[derive(NetworkBehaviour)]
pub(crate) struct Behaviour {
    identify: identify::Behaviour,
    ping: ping::Behaviour,
    metadata: request_response::Behaviour<protocols::metadata::MetadataCodec>,
    lightpush: request_response::Behaviour<protocols::lightpush::LightPushCodec>,
    peer_exchange: request_response::Behaviour<protocols::peer_exchange::PeerExchangeCodec>,
    filter_subscribe: request_response::Behaviour<protocols::filter::FilterSubscribeCodec>,
    store_query: request_response::Behaviour<protocols::store::StoreQueryCodec>,
    filter_push: libp2p_stream::Behaviour,
}

fn new_behaviour(local_key: &identity::Keypair) -> Behaviour {
    Behaviour {
        identify: identify::Behaviour::new(
            identify::Config::new("waku-rust/0.1.0".to_string(), local_key.public())
                .with_push_listen_addr_updates(true),
        ),
        ping: ping::Behaviour::new(ping::Config::new()),
        metadata: protocols::metadata::behaviour(),
        lightpush: protocols::lightpush::behaviour(),
        peer_exchange: protocols::peer_exchange::behaviour(),
        filter_subscribe: protocols::filter::filter_subscribe_behaviour(),
        store_query: protocols::store::behaviour(),
        filter_push: libp2p_stream::Behaviour::new(),
    }
}

/// Transport layer that owns the libp2p Swarm.
/// Receives commands from coordinator, emits raw events back.
pub(crate) struct Transport {
    swarm: Swarm<Behaviour>,
    pending_lightpush: HashMap<OutboundRequestId, (ReqId, PeerId)>,
    pending_px: HashMap<OutboundRequestId, ReqId>,
    pending_filter: HashMap<OutboundRequestId, (ReqId, PeerId)>,
    pending_store: HashMap<OutboundRequestId, ReqId>,
    tasks: TaskTracker,
}

impl Transport {
    /// Create a new transport whose swarm spawns connection and dial tasks through `tasks`.
    pub(crate) fn new(
        config: &NodeConfig,
        network: &WakuNetworkConfig,
        tasks: TaskTracker,
    ) -> Result<Self, TransportInitError> {
        let local_key = identity::Keypair::generate_ed25519();
        let local_peer_id = PeerId::from(local_key.public());

        let transport = build_transport(&local_key, network)?;

        let executor_tasks = tasks.clone();
        let swarm = Swarm::new(
            transport,
            new_behaviour(&local_key),
            local_peer_id,
            libp2p::swarm::Config::with_executor(
                move |future: Pin<Box<dyn Future<Output = ()> + Send>>| {
                    executor_tasks.spawn(future);
                },
            )
            .with_idle_connection_timeout(Duration::from_secs(config.idle_timeout_secs)),
        );

        Ok(Self {
            swarm,
            pending_lightpush: HashMap::new(),
            pending_px: HashMap::new(),
            pending_filter: HashMap::new(),
            pending_store: HashMap::new(),
            tasks,
        })
    }

    pub(crate) fn local_peer_id(&self) -> PeerId {
        *self.swarm.local_peer_id()
    }

    /// Run the transport loop.
    /// Polls swarm events and handles commands from the coordinator.
    pub(crate) async fn run(
        mut self,
        mut cmd_rx: mpsc::Receiver<TransportCmd>,
        event_tx: mpsc::Sender<TransportEvent>,
        filter_push_tx: mpsc::Sender<FilterPushEvent>,
        mut shutdown: watch::Receiver<bool>,
    ) {
        let mut filter_push_control = self.swarm.behaviour().filter_push.new_control();
        let Ok(mut filter_push_streams) =
            filter_push_control.accept(StreamProtocol::new(protocols::filter::FILTER_PUSH_CODEC))
        else {
            error!("failed to register filter push stream protocol");
            return;
        };

        loop {
            tokio::select! {
                should_shutdown = Self::shutdown_changed_or_requested(&mut shutdown) => {
                    if should_shutdown {
                        debug!("transport loop shutting down");
                        break;
                    }
                }
                stream = filter_push_streams.next() => {
                    let Some((peer_id, stream)) = stream else {
                        error!("filter push stream acceptor closed, stopping transport loop");
                        break;
                    };
                    self.tasks.spawn(handle_filter_push_stream(
                        peer_id,
                        stream,
                        filter_push_tx.clone(),
                        shutdown.clone(),
                    ));
                }
                cmd = cmd_rx.recv() => {
                    let Some(cmd) = cmd else {
                        error!("transport command channel closed, stopping transport loop");
                        break;
                    };
                    self.handle_cmd(cmd, &event_tx).await;
                }
                ev = self.swarm.select_next_some() => {
                    if let Some(te) = self.map_event(ev)
                        && event_tx.send(te).await.is_err()
                    {
                        error!("transport event channel closed, stopping transport loop");
                        break;
                    }
                }
            }
        }
    }

    async fn shutdown_changed_or_requested(shutdown: &mut watch::Receiver<bool>) -> bool {
        if *shutdown.borrow() {
            return true;
        }
        shutdown.changed().await.is_err() || *shutdown.borrow()
    }

    async fn handle_cmd(&mut self, cmd: TransportCmd, event_tx: &mpsc::Sender<TransportEvent>) {
        match cmd {
            TransportCmd::Dial { peer_id, addrs } => {
                let opts = libp2p::swarm::dial_opts::DialOpts::peer_id(peer_id)
                    .addresses(addrs)
                    .build();
                if let Err(e) = self.swarm.dial(opts) {
                    debug!(?peer_id, error=?e, "dial failed");
                    if event_tx
                        .send(TransportEvent::DialError { peer_id, error: e })
                        .await
                        .is_err()
                    {
                        error!(%peer_id, "transport event channel closed after dial failure");
                    }
                }
            }
            TransportCmd::DisconnectPeers { peers } => {
                for peer_id in peers {
                    if self.swarm.disconnect_peer_id(peer_id).is_err() {
                        debug!(%peer_id, "peer already disconnected");
                        if event_tx
                            .send(TransportEvent::ConnectionClosed { peer_id })
                            .await
                            .is_err()
                        {
                            error!(%peer_id, "transport event channel closed after disconnect");
                        }
                    }
                }
            }
            TransportCmd::SendLightPush {
                req_id,
                peer_id,
                request,
            } => {
                let out_id = self
                    .swarm
                    .behaviour_mut()
                    .lightpush
                    .send_request(&peer_id, request);
                self.pending_lightpush.insert(out_id, (req_id, peer_id));
            }
            TransportCmd::SendPeerExchange {
                req_id,
                peer_id,
                request,
            } => {
                let out_id = self
                    .swarm
                    .behaviour_mut()
                    .peer_exchange
                    .send_request(&peer_id, request);
                self.pending_px.insert(out_id, req_id);
            }
            TransportCmd::SendMetadataResponse { channel, response } => {
                if let Err(error) = self
                    .swarm
                    .behaviour_mut()
                    .metadata
                    .send_response(channel, response)
                {
                    debug!(?error, "failed to send metadata response");
                }
            }
            TransportCmd::SendFilterSubscribe {
                req_id,
                peer_id,
                request,
            } => {
                let out_id = self
                    .swarm
                    .behaviour_mut()
                    .filter_subscribe
                    .send_request(&peer_id, request);
                self.pending_filter.insert(out_id, (req_id, peer_id));
            }
            TransportCmd::SendStoreQuery {
                req_id,
                peer_id,
                request,
            } => {
                let out_id = self
                    .swarm
                    .behaviour_mut()
                    .store_query
                    .send_request(&peer_id, request);
                self.pending_store.insert(out_id, req_id);
            }
        }
    }

    fn map_event(&mut self, ev: SwarmEvent<BehaviourEvent>) -> Option<TransportEvent> {
        match ev {
            SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                Some(TransportEvent::ConnectionEstablished { peer_id })
            }
            SwarmEvent::ConnectionClosed { peer_id, .. } => {
                Some(TransportEvent::ConnectionClosed { peer_id })
            }
            SwarmEvent::OutgoingConnectionError {
                peer_id: Some(peer_id),
                error,
                ..
            } => Some(TransportEvent::DialError { peer_id, error }),
            SwarmEvent::Behaviour(BehaviourEvent::Identify(identify::Event::Received {
                peer_id,
                info,
                ..
            })) => Some(TransportEvent::IdentifyReceived {
                peer_id,
                protocols: info.protocols.iter().map(ToString::to_string).collect(),
                addrs: info.listen_addrs,
            }),
            SwarmEvent::Behaviour(BehaviourEvent::Metadata(request_response::Event::Message {
                peer,
                message: request_response::Message::Request { channel, .. },
                ..
            })) => Some(TransportEvent::MetadataRequest {
                peer_id: peer,
                channel,
            }),
            SwarmEvent::Behaviour(BehaviourEvent::Lightpush(
                request_response::Event::Message {
                    message:
                        request_response::Message::Response {
                            request_id,
                            response,
                        },
                    ..
                },
            )) => {
                let (req_id, peer_id) = self.pending_lightpush.remove(&request_id)?;
                Some(TransportEvent::LightPushResponse {
                    req_id,
                    peer_id,
                    result: Ok(response),
                })
            }
            SwarmEvent::Behaviour(BehaviourEvent::Lightpush(
                request_response::Event::OutboundFailure {
                    request_id, error, ..
                },
            )) => {
                let (req_id, peer_id) = self.pending_lightpush.remove(&request_id)?;
                Some(TransportEvent::LightPushResponse {
                    req_id,
                    peer_id,
                    result: Err(error),
                })
            }
            SwarmEvent::Behaviour(BehaviourEvent::PeerExchange(
                request_response::Event::Message {
                    message:
                        request_response::Message::Response {
                            request_id,
                            response,
                        },
                    ..
                },
            )) => {
                let req_id = self.pending_px.remove(&request_id)?;
                Some(TransportEvent::PeerExchangeResponse {
                    req_id,
                    result: Ok(response),
                })
            }
            SwarmEvent::Behaviour(BehaviourEvent::PeerExchange(
                request_response::Event::OutboundFailure {
                    request_id, error, ..
                },
            )) => {
                let req_id = self.pending_px.remove(&request_id)?;
                Some(TransportEvent::PeerExchangeResponse {
                    req_id,
                    result: Err(error),
                })
            }
            // Filter subscribe events
            SwarmEvent::Behaviour(BehaviourEvent::FilterSubscribe(
                request_response::Event::Message {
                    message:
                        request_response::Message::Response {
                            request_id,
                            response,
                        },
                    ..
                },
            )) => {
                let (req_id, peer_id) = self.pending_filter.remove(&request_id)?;
                Some(TransportEvent::FilterSubscribeResponse {
                    req_id,
                    peer_id,
                    result: Ok(response),
                })
            }
            SwarmEvent::Behaviour(BehaviourEvent::FilterSubscribe(
                request_response::Event::OutboundFailure {
                    request_id, error, ..
                },
            )) => {
                let (req_id, peer_id) = self.pending_filter.remove(&request_id)?;
                Some(TransportEvent::FilterSubscribeResponse {
                    req_id,
                    peer_id,
                    result: Err(error),
                })
            }
            SwarmEvent::Behaviour(BehaviourEvent::StoreQuery(
                request_response::Event::Message {
                    message:
                        request_response::Message::Response {
                            request_id,
                            response,
                        },
                    ..
                },
            )) => {
                let req_id = self.pending_store.remove(&request_id)?;
                Some(TransportEvent::StoreQueryResponse {
                    req_id,
                    result: Ok(response),
                })
            }
            SwarmEvent::Behaviour(BehaviourEvent::StoreQuery(
                request_response::Event::OutboundFailure {
                    request_id, error, ..
                },
            )) => {
                let req_id = self.pending_store.remove(&request_id)?;
                Some(TransportEvent::StoreQueryResponse {
                    req_id,
                    result: Err(error),
                })
            }
            _ => None,
        }
    }
}

/// Forward pushes from one inbound filter-push stream until it ends or shutdown is requested.
///
/// Shutdown drops the stream: an idle remote would otherwise keep the substream, and with
/// mplex or QUIC its connection, alive after the swarm is gone.
async fn handle_filter_push_stream<S>(
    peer_id: PeerId,
    mut stream: S,
    event_tx: mpsc::Sender<FilterPushEvent>,
    mut shutdown: watch::Receiver<bool>,
) where
    S: futures::AsyncRead + Unpin + Send + 'static,
{
    let forward = async {
        while let Ok(push) =
            ProstLengthDelimitedCodec::<
                proto::filter::MessagePush,
                proto::filter::FilterSubscribeResponse,
            >::read_request(&mut stream, protocols::filter::FILTER_PUSH_MAX_BYTES)
            .await
        {
            if event_tx
                .send(FilterPushEvent {
                    peer_id,
                    push: Box::new(push),
                })
                .await
                .is_err()
            {
                error!(%peer_id, "transport event channel closed, stopping filter push stream");
                break;
            }
        }
    };
    tokio::select! {
        () = forward => {}
        // Also completes when the sender is dropped.
        _ = shutdown.wait_for(|stop| *stop) => {}
    }
}

fn build_transport(
    local_key: &identity::Keypair,
    network: &WakuNetworkConfig,
) -> Result<WakuBoxedTransport, TransportInitError> {
    match network.transport_profile {
        WakuTransportProfile::Direct => build_direct_transport(local_key),
        WakuTransportProfile::Tor => build_tor_transport(local_key, network),
    }
}

fn build_direct_transport(
    local_key: &identity::Keypair,
) -> Result<WakuBoxedTransport, TransportInitError> {
    let tcp_transport = dns::tokio::Transport::system(tcp::tokio::Transport::new(
        tcp::Config::default().nodelay(true),
    ))?
    .upgrade(upgrade::Version::V1)
    .authenticate(noise::Config::new(local_key)?)
    .multiplex(upgrade::SelectUpgrade::new(
        yamux::Config::default(),
        mplex::Config::new(),
    ))
    .timeout(Duration::from_secs(20))
    .boxed();

    // Secure websockets must own DNS resolution so TLS validates the DNS name,
    // not the resolved IP address.
    let ws_transport = websocket::Config::new(dns::tokio::Transport::system(
        tcp::tokio::Transport::new(tcp::Config::default().nodelay(true)),
    )?)
    .upgrade(upgrade::Version::V1)
    .authenticate(noise::Config::new(local_key)?)
    .multiplex(upgrade::SelectUpgrade::new(
        yamux::Config::default(),
        mplex::Config::new(),
    ))
    .timeout(Duration::from_secs(20))
    .boxed();

    let quic_transport = {
        let config = libp2p::quic::Config::new(local_key);
        libp2p::quic::tokio::Transport::new(config)
            .map(|(peer_id, conn), _| (peer_id, libp2p::core::muxing::StreamMuxerBox::new(conn)))
            .boxed()
    };

    let ws_quic = combine_transports(ws_transport, quic_transport);

    Ok(combine_transports(ws_quic, tcp_transport))
}

fn build_tor_transport(
    local_key: &identity::Keypair,
    network: &WakuNetworkConfig,
) -> Result<WakuBoxedTransport, TransportInitError> {
    let tor_client = network
        .tor_client
        .clone()
        .ok_or(TransportInitError::MissingTorClient)?;
    let arti_transport = ArtiTcpTransport::new(tor_client);

    let tcp_transport = arti_transport
        .clone()
        .upgrade(upgrade::Version::V1)
        .authenticate(noise::Config::new(local_key)?)
        .multiplex(upgrade::SelectUpgrade::new(
            yamux::Config::default(),
            mplex::Config::new(),
        ))
        .timeout(Duration::from_secs(20))
        .boxed();

    let ws_transport = websocket::Config::new(arti_transport)
        .upgrade(upgrade::Version::V1)
        .authenticate(noise::Config::new(local_key)?)
        .multiplex(upgrade::SelectUpgrade::new(
            yamux::Config::default(),
            mplex::Config::new(),
        ))
        .timeout(Duration::from_secs(20))
        .boxed();

    Ok(combine_transports(ws_transport, tcp_transport))
}

fn combine_transports(left: WakuBoxedTransport, right: WakuBoxedTransport) -> WakuBoxedTransport {
    left.or_transport(right)
        .map(|either, _| match either {
            futures::future::Either::Left(v) | futures::future::Either::Right(v) => v,
        })
        .boxed()
}

#[derive(Clone)]
struct ArtiTcpTransport {
    tor_client: WakuTorClientProvider,
}

impl ArtiTcpTransport {
    const fn new(tor_client: WakuTorClientProvider) -> Self {
        Self { tor_client }
    }
}

impl libp2p::Transport for ArtiTcpTransport {
    type Output = arti_client::DataStream;
    type Error = io::Error;
    type ListenerUpgrade = std::future::Pending<Result<Self::Output, Self::Error>>;
    type Dial = BoxFuture<'static, Result<Self::Output, Self::Error>>;

    fn listen_on(
        &mut self,
        _id: ListenerId,
        addr: Multiaddr,
    ) -> Result<(), TransportError<Self::Error>> {
        Err(TransportError::MultiaddrNotSupported(addr))
    }

    fn remove_listener(&mut self, _id: ListenerId) -> bool {
        false
    }

    fn dial(
        &mut self,
        addr: Multiaddr,
        _opts: DialOpts,
    ) -> Result<Self::Dial, TransportError<Self::Error>> {
        let target = ArtiDialTarget::from_multiaddr(&addr)?;
        let tor_client = self.tor_client.clone();
        Ok(async move {
            let tor_client = tor_client()
                .ok_or_else(|| io::Error::other("Tor client is unavailable for Waku dial"))?;
            tor_client
                .connect((target.host.as_str(), target.port))
                .await
                .map_err(io::Error::other)
        }
        .boxed())
    }

    fn poll(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<CoreTransportEvent<Self::ListenerUpgrade, Self::Error>> {
        Poll::Pending
    }
}

struct ArtiDialTarget {
    host: String,
    port: u16,
}

impl ArtiDialTarget {
    fn from_multiaddr(addr: &Multiaddr) -> Result<Self, TransportError<io::Error>> {
        let mut protocols = addr.iter();
        let host = match protocols.next() {
            Some(Protocol::Dns(host) | Protocol::Dns4(host) | Protocol::Dns6(host)) => {
                host.to_string()
            }
            Some(Protocol::Ip4(host)) => host.to_string(),
            Some(Protocol::Ip6(host)) => host.to_string(),
            _ => return Err(TransportError::MultiaddrNotSupported(addr.clone())),
        };
        let Some(Protocol::Tcp(port)) = protocols.next() else {
            return Err(TransportError::MultiaddrNotSupported(addr.clone()));
        };
        Ok(Self { host, port })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dial_target(value: &str) -> Result<ArtiDialTarget, TransportError<io::Error>> {
        let addr = value.parse().expect("valid multiaddr");
        ArtiDialTarget::from_multiaddr(&addr)
    }

    #[test]
    fn arti_dial_target_accepts_dns_and_ip_tcp_addrs() {
        let dns = dial_target("/dns4/support-4.rootedinprivacy.com/tcp/30304/p2p/12D3KooWPZAXp2aXSq7hh5iy8pxziTv1bxU8cg4pc4YEgkFiiixv")
            .expect("dns target");
        assert_eq!(dns.host, "support-4.rootedinprivacy.com");
        assert_eq!(dns.port, 30304);

        let ip4 = dial_target("/ip4/203.0.113.10/tcp/30304").expect("ip4 target");
        assert_eq!(ip4.host, "203.0.113.10");
        assert_eq!(ip4.port, 30304);

        let ip6 = dial_target("/ip6/2001:db8::1/tcp/30304").expect("ip6 target");
        assert_eq!(ip6.host, "2001:db8::1");
        assert_eq!(ip6.port, 30304);
    }

    #[test]
    fn arti_dial_target_rejects_non_tcp_addrs() {
        assert!(dial_target("/ip4/203.0.113.10/udp/30304/quic-v1").is_err());
    }

    fn memory_swarm<B: NetworkBehaviour>(key: &identity::Keypair, behaviour: B) -> Swarm<B> {
        let transport = libp2p::core::transport::MemoryTransport::default()
            .upgrade(upgrade::Version::V1)
            .authenticate(noise::Config::new(key).expect("noise config"))
            .multiplex(yamux::Config::default())
            .boxed();
        Swarm::new(
            transport,
            behaviour,
            PeerId::from(key.public()),
            libp2p::swarm::Config::with_tokio_executor()
                .with_idle_connection_timeout(Duration::from_secs(60)),
        )
    }

    #[tokio::test]
    async fn wallet_behaviour_accepts_only_metadata_and_filter_push_inbound() {
        let listener_key = identity::Keypair::generate_ed25519();
        let listener_peer = PeerId::from(listener_key.public());
        let mut listener = memory_swarm(&listener_key, new_behaviour(&listener_key));
        // Production registers filter push in `Transport::run`; keep the acceptor alive likewise.
        let _filter_push_streams = listener
            .behaviour()
            .filter_push
            .new_control()
            .accept(StreamProtocol::new(protocols::filter::FILTER_PUSH_CODEC))
            .expect("register filter push");
        let addr = Multiaddr::empty().with(Protocol::Memory(rand::random()));
        listener.listen_on(addr.clone()).expect("listen");
        tokio::spawn(async move {
            loop {
                listener.select_next_some().await;
            }
        });

        let dialer_key = identity::Keypair::generate_ed25519();
        let mut dialer = memory_swarm(&dialer_key, libp2p_stream::Behaviour::new());
        let mut control = dialer.behaviour().new_control();

        tokio::time::timeout(Duration::from_secs(30), async move {
            dialer
                .dial(addr.with(Protocol::P2p(listener_peer)))
                .expect("dial");
            loop {
                if let SwarmEvent::ConnectionEstablished { peer_id, .. } =
                    dialer.select_next_some().await
                    && peer_id == listener_peer
                {
                    break;
                }
            }
            tokio::spawn(async move {
                loop {
                    dialer.select_next_some().await;
                }
            });

            for protocol in [
                protocols::lightpush::LIGHTPUSH_V3_CODEC,
                protocols::peer_exchange::PEER_EXCHANGE_CODEC,
                protocols::filter::FILTER_SUBSCRIBE_CODEC,
            ] {
                let result = control
                    .open_stream(listener_peer, StreamProtocol::new(protocol))
                    .await;
                assert!(
                    matches!(
                        result,
                        Err(libp2p_stream::OpenStreamError::UnsupportedProtocol(_))
                    ),
                    "{protocol} must not be accepted inbound"
                );
            }
            for protocol in [
                protocols::metadata::METADATA_CODEC,
                protocols::filter::FILTER_PUSH_CODEC,
            ] {
                control
                    .open_stream(listener_peer, StreamProtocol::new(protocol))
                    .await
                    .unwrap_or_else(|error| panic!("{protocol} must be accepted inbound: {error}"));
            }
        })
        .await
        .expect("test timed out");
    }

    /// A remote that never sends; the `Arc` shows when the stream is dropped.
    struct IdleStream(
        #[expect(dead_code, reason = "held only to observe the drop")] std::sync::Arc<()>,
    );

    impl futures::AsyncRead for IdleStream {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut [u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Pending
        }
    }

    #[tokio::test]
    async fn filter_push_handler_drops_idle_stream_on_shutdown() {
        let alive = std::sync::Arc::new(());
        let (event_tx, _event_rx) = mpsc::channel(1);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let handler = tokio::spawn(handle_filter_push_stream(
            PeerId::random(),
            IdleStream(std::sync::Arc::clone(&alive)),
            event_tx,
            shutdown_rx,
        ));

        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(
            !handler.is_finished(),
            "an idle stream keeps the handler waiting"
        );
        shutdown_tx.send(true).expect("handler watches shutdown");
        tokio::time::timeout(Duration::from_secs(1), handler)
            .await
            .expect("handler stops on shutdown")
            .expect("handler does not panic");
        assert_eq!(
            std::sync::Arc::strong_count(&alive),
            1,
            "shutdown drops the stream"
        );
    }
}
