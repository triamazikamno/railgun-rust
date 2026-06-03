use std::time::Duration;

use alloy_provider::{ConnectionConfig, DynProvider, Provider, ProviderBuilder};
use alloy_transport::{TransportError, TransportErrorKind};
use url::Url;

const RPC_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

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
            Ok(ProviderBuilder::new()
                .connect_reqwest(client, url.clone())
                .erased())
        }
        _ => ProviderBuilder::new()
            .connect_with_config(url.as_str(), config)
            .await
            .map(Provider::erased),
    }
}
