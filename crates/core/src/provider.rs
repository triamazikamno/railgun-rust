use std::time::Duration;

use alloy::rpc::client::ClientBuilder;
use alloy::transports::http::{Http, HttpTransportSettings};
use alloy_provider::{ConnectionConfig, DynProvider, Provider, ProviderBuilder};
use alloy_transport::{TransportError, TransportErrorKind};
use url::Url;

const RPC_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Largest decompressed HTTP RPC response body accepted; timeouts alone don't
/// bound memory. 64 MiB leaves ample room for sync's `eth_getLogs` pages.
#[cfg(not(test))]
const MAX_RPC_RESPONSE_BYTES: usize = 64 * 1024 * 1024;
#[cfg(test)]
const MAX_RPC_RESPONSE_BYTES: usize = 1024;

pub async fn build_provider(url: &Url) -> Result<DynProvider, TransportError> {
    build_provider_with_http_client(url, None).await
}

pub async fn build_provider_with_http_client(
    url: &Url,
    http_client: Option<&reqwest::Client>,
) -> Result<DynProvider, TransportError> {
    let config = ConnectionConfig::new()
        .with_max_retries(20)
        .with_retry_interval(Duration::from_secs(5));

    match url.scheme() {
        "http" | "https" => {
            let client = match http_client {
                Some(client) => client.clone(),
                None => reqwest::Client::builder()
                    .connect_timeout(RPC_CONNECT_TIMEOUT)
                    .build()
                    .map_err(TransportErrorKind::custom)?,
            };
            Ok(connect_reqwest_capped(client, url.clone()))
        }
        _ => ProviderBuilder::new()
            .connect_with_config(url.as_str(), config)
            .await
            .map(Provider::erased),
    }
}

/// Like [`ProviderBuilder::connect_reqwest`], but rejects any response body
/// larger than 64 MiB after decompression.
#[must_use]
pub fn connect_reqwest_capped(client: reqwest::Client, url: Url) -> DynProvider {
    let transport = Http::with_client(client, url)
        .with_settings(HttpTransportSettings::new().with_max_response_size(MAX_RPC_RESPONSE_BYTES));
    let is_local = transport.guess_local();
    ProviderBuilder::new()
        .connect_client(ClientBuilder::default().transport(transport, is_local))
        .erased()
}

/// Whether `err` is [`connect_reqwest_capped`]'s rejection of an oversized
/// response body, which alloy reports only as a custom error message.
#[must_use]
pub fn is_response_size_limit(err: &TransportError) -> bool {
    matches!(err, TransportError::Transport(TransportErrorKind::Custom(source))
        if source.to_string() == format!("response body exceeds {MAX_RPC_RESPONSE_BYTES} bytes"))
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::TcpListener;

    use super::*;

    #[tokio::test]
    async fn http_provider_rejects_streamed_body_over_cap() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind rpc server");
        let url = Url::parse(&format!("http://{}", listener.local_addr().expect("addr")))
            .expect("rpc url");
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            // Replies only once the request has started arriving.
            stream.read_exact(&mut [0; 1]).expect("read request");
            // Chunked with no Content-Length, so only the streaming check can reject it.
            let body = " ".repeat(MAX_RPC_RESPONSE_BYTES + 1);
            let _ = write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n{:x}\r\n{body}\r\n0\r\n\r\n",
                body.len()
            );
            // Drains the request until the client hangs up; closing on unread bytes would reset.
            let _ = std::io::copy(&mut stream, &mut std::io::sink());
        });

        let provider = build_provider_with_http_client(&url, None)
            .await
            .expect("provider");
        let error = provider
            .get_chain_id()
            .await
            .expect_err("oversized response");
        assert!(is_response_size_limit(&error), "{error}");
    }
}
