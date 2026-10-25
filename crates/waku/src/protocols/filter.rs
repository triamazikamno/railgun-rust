use crate::proto;
use crate::protocols::codec::ProstLengthDelimitedCodec;
use async_trait::async_trait;
use libp2p::request_response;

pub(crate) const FILTER_SUBSCRIBE_CODEC: &str = "/vac/waku/filter-subscribe/2.0.0-beta1";
pub(crate) const FILTER_PUSH_CODEC: &str = "/vac/waku/filter-push/2.0.0-beta1";
// nwaku a0087c1 waku_filter_v2/rpc_codec.nim DefaultMaxPushSize (10 * 153_600 + 65_536).
pub(crate) const FILTER_PUSH_MAX_BYTES: usize = 1_601_536;
// nwaku a0087c1 waku_filter_v2/rpc_codec.nim DefaultMaxSubscribeResponseSize.
pub(crate) const FILTER_SUBSCRIBE_RESPONSE_MAX_BYTES: usize = 65_536;

// ─────────────────────────────────────────────────────────────────────────────
// Filter Subscribe Protocol (client → server, request/response)
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Clone, Default)]
pub(crate) struct FilterSubscribeCodec;

#[derive(Clone)]
pub(crate) struct FilterSubscribeProtocol;

impl AsRef<str> for FilterSubscribeProtocol {
    fn as_ref(&self) -> &str {
        FILTER_SUBSCRIBE_CODEC
    }
}

#[async_trait]
impl request_response::Codec for FilterSubscribeCodec {
    type Protocol = FilterSubscribeProtocol;
    type Request = proto::filter::FilterSubscribeRequest;
    type Response = proto::filter::FilterSubscribeResponse;

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
            FILTER_SUBSCRIBE_RESPONSE_MAX_BYTES,
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
            FILTER_SUBSCRIBE_RESPONSE_MAX_BYTES,
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
pub(crate) fn filter_subscribe_behaviour() -> request_response::Behaviour<FilterSubscribeCodec> {
    request_response::Behaviour::new(
        [(
            FilterSubscribeProtocol,
            request_response::ProtocolSupport::Outbound,
        )],
        request_response::Config::default(),
    )
}

// Filter Push is stream-oriented: the server may keep one negotiated stream open
// and write many length-delimited MessagePush frames to the client.
