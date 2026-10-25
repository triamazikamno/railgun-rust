use futures::prelude::*;
use prost::Message;
use std::io;
use std::marker::PhantomData;

pub(crate) struct ProstLengthDelimitedCodec<Req, Resp> {
    _marker: PhantomData<(Req, Resp)>,
}

impl<Req, Resp> Default for ProstLengthDelimitedCodec<Req, Resp> {
    fn default() -> Self {
        Self {
            _marker: PhantomData,
        }
    }
}

impl<Req, Resp> Clone for ProstLengthDelimitedCodec<Req, Resp> {
    fn clone(&self) -> Self {
        Self::default()
    }
}

impl<Req, Resp> ProstLengthDelimitedCodec<Req, Resp>
where
    Req: Message + Default,
    Resp: Message + Default,
{
    async fn read_length_prefixed<T>(io: &mut T, cap: usize) -> io::Result<Vec<u8>>
    where
        T: AsyncRead + Unpin,
    {
        let len = unsigned_varint::aio::read_usize(&mut *io)
            .await
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        if len > cap {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("frame length {len} exceeds cap {cap}"),
            ));
        }
        // Grow with the bytes that actually arrive instead of trusting the peer's length.
        let mut buf = Vec::new();
        (&mut *io).take(len as u64).read_to_end(&mut buf).await?;
        if buf.len() < len {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        Ok(buf)
    }

    async fn write_length_prefixed<T>(io: &mut T, bytes: &[u8]) -> io::Result<()>
    where
        T: AsyncWrite + Unpin,
    {
        let mut len_buf = unsigned_varint::encode::usize_buffer();
        let len_bytes = unsigned_varint::encode::usize(bytes.len(), &mut len_buf);
        io.write_all(len_bytes).await?;
        io.write_all(bytes).await?;
        io.flush().await?;
        Ok(())
    }

    /// Read a length-delimited protobuf request of at most `cap` bytes.
    ///
    /// # Errors
    /// Returns an `io::Error` on EOF, framing errors, frames over `cap`, or protobuf decode errors.
    pub(crate) async fn read_request<T>(io: &mut T, cap: usize) -> io::Result<Req>
    where
        T: AsyncRead + Unpin,
    {
        let buf = Self::read_length_prefixed(io, cap).await?;
        Req::decode(buf.as_slice()).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    /// Read a length-delimited protobuf response of at most `cap` bytes.
    ///
    /// # Errors
    /// Returns an `io::Error` on EOF, framing errors, frames over `cap`, or protobuf decode errors.
    pub(crate) async fn read_response<T>(io: &mut T, cap: usize) -> io::Result<Resp>
    where
        T: AsyncRead + Unpin,
    {
        let buf = Self::read_length_prefixed(io, cap).await?;
        Resp::decode(buf.as_slice()).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    /// Write a length-delimited protobuf request.
    ///
    /// # Errors
    /// Returns an `io::Error` on write errors.
    pub(crate) async fn write_request<T>(io: &mut T, req: Req) -> io::Result<()>
    where
        T: AsyncWrite + Unpin,
    {
        let bytes = req.encode_to_vec();
        Self::write_length_prefixed(io, &bytes).await
    }

    /// Write a length-delimited protobuf response.
    ///
    /// # Errors
    /// Returns an `io::Error` on write errors.
    pub(crate) async fn write_response<T>(io: &mut T, resp: Resp) -> io::Result<()>
    where
        T: AsyncWrite + Unpin,
    {
        let bytes = resp.encode_to_vec();
        Self::write_length_prefixed(io, &bytes).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::io::Cursor;

    const CAP: usize = 16;

    type Codec = ProstLengthDelimitedCodec<(), ()>;

    fn frame(len: usize, body: &[u8]) -> Cursor<Vec<u8>> {
        let mut len_buf = unsigned_varint::encode::usize_buffer();
        let mut bytes = unsigned_varint::encode::usize(len, &mut len_buf).to_vec();
        bytes.extend_from_slice(body);
        Cursor::new(bytes)
    }

    #[tokio::test]
    async fn rejects_oversized_prefix_before_reading_body() {
        let err = Codec::read_length_prefixed(&mut frame(CAP + 1, &[]), CAP)
            .await
            .expect_err("oversized frame");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn reads_frame_at_cap() {
        let body = [7u8; CAP];
        let buf = Codec::read_length_prefixed(&mut frame(CAP, &body), CAP)
            .await
            .expect("frame at cap");
        assert_eq!(buf, body);
    }

    #[tokio::test]
    async fn short_body_is_unexpected_eof() {
        let err = Codec::read_length_prefixed(&mut frame(CAP, &[7u8; CAP - 1]), CAP)
            .await
            .expect_err("short body");
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }
}
