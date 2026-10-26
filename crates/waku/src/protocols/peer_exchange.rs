use crate::proto;
use crate::protocols::codec::ProstLengthDelimitedCodec;
use async_trait::async_trait;
use libp2p::request_response;

pub(crate) const PEER_EXCHANGE_CODEC: &str = "/vac/waku/peer-exchange/2.0.0-alpha1";
// 60 requested records at EIP-778's 300-byte ENR limit (enforced by `enr`) fit well within 64 KiB.
pub(crate) const PEER_EXCHANGE_RESPONSE_MAX_BYTES: usize = 65_536;

#[derive(Clone, Default)]
pub(crate) struct PeerExchangeCodec;

#[derive(Clone)]
pub(crate) struct PeerExchangeProtocol;

impl AsRef<str> for PeerExchangeProtocol {
    fn as_ref(&self) -> &str {
        PEER_EXCHANGE_CODEC
    }
}

#[async_trait]
impl request_response::Codec for PeerExchangeCodec {
    type Protocol = PeerExchangeProtocol;
    type Request = proto::peer_exchange::PeerExchangeRpc;
    type Response = proto::peer_exchange::PeerExchangeRpc;

    async fn read_request<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
    ) -> std::io::Result<Self::Request>
    where
        T: futures::AsyncRead + Unpin + Send,
    {
        // Outbound-only protocol, so this path is never taken.
        ProstLengthDelimitedCodec::<Self::Request, Self::Response>::read_request(
            io,
            PEER_EXCHANGE_RESPONSE_MAX_BYTES,
        )
        .await
    }

    async fn read_response<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
    ) -> std::io::Result<Self::Response>
    where
        T: futures::AsyncRead + Unpin + Send,
    {
        ProstLengthDelimitedCodec::<Self::Request, Self::Response>::read_response(
            io,
            PEER_EXCHANGE_RESPONSE_MAX_BYTES,
        )
        .await
    }

    async fn write_request<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        req: Self::Request,
    ) -> std::io::Result<()>
    where
        T: futures::AsyncWrite + Unpin + Send,
    {
        ProstLengthDelimitedCodec::<Self::Request, Self::Response>::write_request(io, req).await
    }

    async fn write_response<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        resp: Self::Response,
    ) -> std::io::Result<()>
    where
        T: futures::AsyncWrite + Unpin + Send,
    {
        ProstLengthDelimitedCodec::<Self::Request, Self::Response>::write_response(io, resp).await
    }
}

#[must_use]
pub(crate) fn behaviour() -> request_response::Behaviour<PeerExchangeCodec> {
    request_response::Behaviour::new(
        [(
            PeerExchangeProtocol,
            request_response::ProtocolSupport::Outbound,
        )],
        request_response::Config::default(),
    )
}
