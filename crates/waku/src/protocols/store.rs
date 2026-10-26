use crate::proto;
use crate::protocols::codec::ProstLengthDelimitedCodec;
use async_trait::async_trait;
use libp2p::request_response;
use prost::Message;
use prost::encoding::{DecodeContext, decode_key, skip_field};
use std::io;

pub(crate) const STORE_QUERY_CODEC: &str = "/vac/waku/store-query/3.0.0";
// nwaku a0087c1 waku_store/rpc_codec.nim MaxPageSize * (153_600 + 65_536), MaxPageSize = 100.
pub(crate) const STORE_QUERY_RESPONSE_MAX_BYTES: usize = 21_913_600;
// nwaku MaxPageSize, which is also the page size the wallet requests.
pub(crate) const MAX_STORE_RESPONSE_ENTRIES: usize = 100;
// `StoreQueryResponse.messages`
const STORE_RESPONSE_MESSAGES_TAG: u32 = 20;

type Prost =
    ProstLengthDelimitedCodec<proto::store::StoreQueryRequest, proto::store::StoreQueryResponse>;

/// A decoded Store response and the length of the frame body it was read from.
#[derive(Debug)]
pub(crate) struct StoreQueryPage {
    pub(crate) response: proto::store::StoreQueryResponse,
    pub(crate) frame_len: usize,
}

/// Decode a Store response frame body, rejecting it before decode if it has too many entries.
///
/// # Errors
/// Returns `InvalidData` when the frame holds more than `MAX_STORE_RESPONSE_ENTRIES` entries,
/// has a malformed field, or fails protobuf decode.
pub(crate) fn decode_store_query_page(frame: &[u8]) -> io::Result<StoreQueryPage> {
    let invalid = |e: prost::DecodeError| io::Error::new(io::ErrorKind::InvalidData, e);
    let mut buf = frame;
    let mut entries = 0usize;
    while !buf.is_empty() {
        let (tag, wire_type) = decode_key(&mut buf).map_err(invalid)?;
        if tag == STORE_RESPONSE_MESSAGES_TAG {
            entries += 1;
            if entries > MAX_STORE_RESPONSE_ENTRIES {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("store response has more than {MAX_STORE_RESPONSE_ENTRIES} entries"),
                ));
            }
        }
        skip_field(wire_type, tag, &mut buf, DecodeContext::default()).map_err(invalid)?;
    }
    let response = proto::store::StoreQueryResponse::decode(frame).map_err(invalid)?;
    Ok(StoreQueryPage {
        response,
        frame_len: frame.len(),
    })
}

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
    type Response = StoreQueryPage;

    async fn read_request<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
    ) -> std::io::Result<Self::Request>
    where
        T: futures::AsyncRead + Unpin + Send,
    {
        // Outbound-only protocol, so this path is never taken.
        Prost::read_request(io, STORE_QUERY_RESPONSE_MAX_BYTES).await
    }

    async fn read_response<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
    ) -> std::io::Result<Self::Response>
    where
        T: futures::AsyncRead + Unpin + Send,
    {
        let frame = Prost::read_length_prefixed(io, STORE_QUERY_RESPONSE_MAX_BYTES).await?;
        decode_store_query_page(&frame)
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
        Prost::write_request(io, req).await
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
        // Outbound-only protocol, so this path is never taken.
        Prost::write_response(io, resp.response).await
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

#[cfg(test)]
mod tests {
    use super::*;
    use futures::io::Cursor;
    use libp2p::request_response::Codec as _;

    // Field 20, length-delimited, zero length: an empty entry that decodes fine.
    const EMPTY_ENTRY: [u8; 3] = [0xA2, 0x01, 0x00];

    fn entries(count: usize) -> Vec<u8> {
        EMPTY_ENTRY.repeat(count)
    }

    async fn read(body: &[u8]) -> io::Result<StoreQueryPage> {
        let mut len_buf = unsigned_varint::encode::usize_buffer();
        let mut bytes = unsigned_varint::encode::usize(body.len(), &mut len_buf).to_vec();
        bytes.extend_from_slice(body);
        StoreQueryCodec
            .read_response(&StoreQueryProtocol, &mut Cursor::new(bytes))
            .await
    }

    #[tokio::test]
    async fn entry_count_is_checked_before_decode() {
        let err = read(&entries(MAX_STORE_RESPONSE_ENTRIES + 1))
            .await
            .expect_err("101 entries");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);

        let body = entries(MAX_STORE_RESPONSE_ENTRIES);
        let page = read(&body).await.expect("100 entries");
        assert_eq!(page.response.messages.len(), MAX_STORE_RESPONSE_ENTRIES);
        assert_eq!(page.frame_len, body.len());
    }

    #[tokio::test]
    async fn other_and_unknown_fields_are_skipped() {
        let mut body = proto::store::StoreQueryResponse {
            request_id: "id".to_string(),
            status_code: Some(200),
            status_desc: Some("OK".to_string()),
            pagination_cursor: Some(vec![1, 2, 3]),
            ..Default::default()
        }
        .encode_to_vec();
        prost::encoding::uint64::encode(99, &7, &mut body);
        body.extend(entries(MAX_STORE_RESPONSE_ENTRIES));
        // An unknown field whose contents look like a 101st entry if the scan descended into it.
        prost::encoding::bytes::encode(98, &entries(1), &mut body);

        let page = read(&body).await.expect("unknown fields skipped");
        assert_eq!(page.response.messages.len(), MAX_STORE_RESPONSE_ENTRIES);
        assert_eq!(page.response.status_code, Some(200));
        assert_eq!(page.response.pagination_cursor, Some(vec![1, 2, 3]));
    }

    #[tokio::test]
    async fn truncated_field_is_invalid_data() {
        let mut body = entries(1);
        // Field 98, length-delimited, claiming 10 bytes with only 2 following.
        body.extend([0x92, 0x06, 10, 0, 0]);
        let err = read(&body).await.expect_err("truncated field");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }
}
