use crate::proto;
use crate::protocols::codec::ProstLengthDelimitedCodec;
use async_trait::async_trait;
use libp2p::request_response;

pub(crate) const STORE_QUERY_CODEC: &str = "/vac/waku/store-query/3.0.0";
// nwaku a0087c1 waku_store/rpc_codec.nim MaxPageSize * (153_600 + 65_536), MaxPageSize = 100.
pub(crate) const STORE_QUERY_RESPONSE_MAX_BYTES: usize = 21_913_600;

#[derive(Clone, Default)]
pub(crate) struct StoreQueryCodec;

#[derive(Clone)]
pub(crate) struct StoreQueryProtocol;

impl AsRef<str> for StoreQueryProtocol {
    fn as_ref(&self) -> &str {
        STORE_QUERY_CODEC
    }
}

#[async_trait]
impl request_response::Codec for StoreQueryCodec {
    type Protocol = StoreQueryProtocol;
    type Request = proto::store::StoreQueryRequest;
    type Response = proto::store::StoreQueryResponse;

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
            STORE_QUERY_RESPONSE_MAX_BYTES,
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
            STORE_QUERY_RESPONSE_MAX_BYTES,
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
pub(crate) fn behaviour() -> request_response::Behaviour<StoreQueryCodec> {
    request_response::Behaviour::new(
        [(
            StoreQueryProtocol,
            request_response::ProtocolSupport::Outbound,
        )],
        request_response::Config::default(),
    )
}
