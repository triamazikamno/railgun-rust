/// Errors from [`read_limited_body`].
#[derive(Debug, thiserror::Error)]
pub enum BodyLimitError {
    #[error("response body exceeds {limit} bytes")]
    TooLarge { limit: usize },
    #[error("response body read failed: {0}")]
    Read(#[source] reqwest::Error),
}

/// Reads `response`'s body, stopping as soon as it would exceed `limit` bytes.
///
/// reqwest yields chunks after content decoding, so the limit counts decompressed bytes.
/// Read errors drop their URL so credential-bearing endpoints never escape.
///
/// # Errors
///
/// Returns [`BodyLimitError::TooLarge`] when the body is longer than `limit`, and
/// [`BodyLimitError::Read`] when reading or decoding the body fails.
pub async fn read_limited_body(
    mut response: reqwest::Response,
    limit: usize,
) -> Result<Vec<u8>, BodyLimitError> {
    if response
        .content_length()
        .is_some_and(|len| len > limit as u64)
    {
        return Err(BodyLimitError::TooLarge { limit });
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|error| BodyLimitError::Read(error.without_url()))?
    {
        if chunk.len() > limit - body.len() {
            return Err(BodyLimitError::TooLarge { limit });
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::{BodyLimitError, read_limited_body};
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;

    const LIMIT: usize = 1024;

    /// Serves `response` to one request. With `hold_open` the connection stays open until the
    /// returned sender is dropped; otherwise it closes after writing.
    fn serve_once(response: Vec<u8>, hold_open: bool) -> (String, mpsc::Sender<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock HTTP server");
        let addr = listener.local_addr().expect("mock HTTP addr");
        let (release_tx, release_rx) = mpsc::channel::<()>();
        thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = [0_u8; 1024];
                let _ = stream.read(&mut buf);
                let _ = stream.write_all(&response);
                if hold_open {
                    let _ = release_rx.recv();
                }
            }
        });
        (format!("http://{addr}/"), release_tx)
    }

    async fn fetch(url: &str) -> Result<Vec<u8>, BodyLimitError> {
        let response = reqwest::Client::new()
            .get(url)
            .send()
            .await
            .expect("mock HTTP request");
        read_limited_body(response, LIMIT).await
    }

    fn with_content_length(extra_headers: &str, body: &[u8]) -> Vec<u8> {
        let mut response = format!(
            "HTTP/1.1 200 OK\r\n{extra_headers}content-length: {}\r\n\r\n",
            body.len()
        )
        .into_bytes();
        response.extend_from_slice(body);
        response
    }

    #[tokio::test]
    async fn body_at_limit_is_read() {
        let (url, _release) = serve_once(with_content_length("", &[7; LIMIT]), false);
        let body = fetch(&url).await.expect("body at limit");
        assert_eq!(body.len(), LIMIT);
    }

    #[tokio::test]
    async fn close_delimited_body_over_limit_is_rejected() {
        let mut response = b"HTTP/1.1 200 OK\r\nconnection: close\r\n\r\n".to_vec();
        response.extend_from_slice(&[7; LIMIT + 1]);
        let (url, _release) = serve_once(response, false);
        assert!(matches!(
            fetch(&url).await,
            Err(BodyLimitError::TooLarge { limit: LIMIT })
        ));
    }

    #[tokio::test]
    async fn oversized_content_length_is_rejected_before_reading() {
        let header = format!("HTTP/1.1 200 OK\r\ncontent-length: {}\r\n\r\n", LIMIT + 1);
        let (url, _release) = serve_once(header.into_bytes(), true);
        let result = tokio::time::timeout(Duration::from_secs(1), fetch(&url))
            .await
            .expect("oversized Content-Length must not wait for the body");
        assert!(matches!(
            result,
            Err(BodyLimitError::TooLarge { limit: LIMIT })
        ));
    }

    #[tokio::test]
    async fn limit_counts_decompressed_bytes() {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&[0; LIMIT + 1]).expect("gzip body");
        let compressed = encoder.finish().expect("finish gzip body");
        assert!(compressed.len() <= LIMIT);
        let (url, _release) = serve_once(
            with_content_length("content-encoding: gzip\r\n", &compressed),
            false,
        );
        assert!(matches!(
            fetch(&url).await,
            Err(BodyLimitError::TooLarge { limit: LIMIT })
        ));
    }
}
