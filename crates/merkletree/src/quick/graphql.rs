use std::num::NonZeroUsize;
use std::time::Duration;

use reqwest::{Client, Response, StatusCode};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::time::{sleep, timeout};
use tracing::warn;
use url::Url;

use crate::errors::SyncError;
use crate::quick::types::{
    Commitment, IndexedLegacyEncryptedCommitment, IndexedLegacyGeneratedCommitment,
    IndexedNullifier, IndexedRailgunTransaction, IndexedShieldCommitment,
    IndexedTransactCommitment,
};

pub const DEFAULT_PAGE_SIZE: NonZeroUsize =
    NonZeroUsize::new(10_000).expect("default page size is non-zero");
const GRAPHQL_MAX_ATTEMPTS: usize = 4;
// A stream that stops without closing never errors on its own, so these bound
// stalls rather than total duration and hand them to the retry policy.
#[cfg(not(test))]
const SQUID_HEADER_TIMEOUT: Duration = Duration::from_secs(30);
#[cfg(test)]
const SQUID_HEADER_TIMEOUT: Duration = Duration::from_millis(500);
#[cfg(not(test))]
const SQUID_BODY_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
#[cfg(test)]
const SQUID_BODY_IDLE_TIMEOUT: Duration = Duration::from_millis(500);

pub(crate) const COMMITMENTS_QUERY: &str = r"
query Commitments($blockNumber: BigInt = 0, $limit: Int = 10000) {
  commitments(
    orderBy: [blockNumber_ASC, treePosition_ASC]
    where: {blockNumber_gte: $blockNumber}
    limit: $limit
  ) {
    id
    treeNumber
    treePosition
    batchStartTreePosition
    blockNumber
    hash
  }
}
";

pub(crate) const SQUID_STATUS_QUERY: &str = r"
query SquidStatus {
  squidStatus {
    height
  }
}
";

pub(crate) const WALLET_PROBE_QUERY: &str = r"
query WalletProbe($fromBlock: BigInt = 0, $toBlock: BigInt = 0, $limit: Int = 1) {
  squidStatus {
    height
  }
  transactCommitments(
    orderBy: [blockNumber_ASC, treePosition_ASC]
    where: {blockNumber_gte: $fromBlock, blockNumber_lte: $toBlock}
    limit: $limit
  ) {
    id
    transactionHash
    blockNumber
    blockTimestamp
    treeNumber
    treePosition
    hash
    ciphertext {
      ciphertext {
        iv
        tag
        data
      }
      blindedSenderViewingKey
      blindedReceiverViewingKey
      annotationData
      memo
    }
  }
  shieldCommitments(
    orderBy: [blockNumber_ASC, treePosition_ASC]
    where: {blockNumber_gte: $fromBlock, blockNumber_lte: $toBlock}
    limit: $limit
  ) {
    id
    transactionHash
    blockNumber
    blockTimestamp
    treeNumber
    treePosition
    preimage {
      npk
      token {
        tokenType
        tokenAddress
        tokenSubID
      }
      value
    }
    shieldKey
    encryptedBundle
  }
  nullifiers(
    orderBy: [blockNumber_ASC, nullifier_DESC]
    where: {blockNumber_gte: $fromBlock, blockNumber_lte: $toBlock}
    limit: $limit
  ) {
    id
    transactionHash
    blockNumber
    blockTimestamp
    treeNumber
    nullifier
  }
  legacyEncryptedCommitments(
    orderBy: [blockNumber_ASC, treePosition_ASC]
    where: {blockNumber_gte: $fromBlock, blockNumber_lte: $toBlock}
    limit: $limit
  ) {
    id
    transactionHash
    blockNumber
    blockTimestamp
    treeNumber
    treePosition
    hash
    ciphertext {
      ciphertext {
        iv
        tag
        data
      }
      ephemeralKeys
      memo
    }
  }
  legacyGeneratedCommitments(
    orderBy: [blockNumber_ASC, treePosition_ASC]
    where: {blockNumber_gte: $fromBlock, blockNumber_lte: $toBlock}
    limit: $limit
  ) {
    id
    transactionHash
    blockNumber
    blockTimestamp
    treeNumber
    treePosition
    hash
    preimage {
      npk
      token {
        tokenType
        tokenAddress
        tokenSubID
      }
      value
    }
    encryptedRandom
  }
}
";

pub(crate) const INDEXED_WALLET_PAGE_QUERY: &str = r"
query IndexedWalletPage($fromBlock: BigInt = 0, $toBlock: BigInt = 0, $limit: Int = 10000) {
  transactCommitments(
    orderBy: [blockNumber_ASC, treePosition_ASC]
    where: {blockNumber_gte: $fromBlock, blockNumber_lte: $toBlock}
    limit: $limit
  ) {
    id
    transactionHash
    blockNumber
    blockTimestamp
    treeNumber
    treePosition
    hash
    ciphertext {
      ciphertext {
        iv
        tag
        data
      }
      blindedSenderViewingKey
      blindedReceiverViewingKey
      annotationData
      memo
    }
  }
  shieldCommitments(
    orderBy: [blockNumber_ASC, treePosition_ASC]
    where: {blockNumber_gte: $fromBlock, blockNumber_lte: $toBlock}
    limit: $limit
  ) {
    id
    transactionHash
    blockNumber
    blockTimestamp
    treeNumber
    treePosition
    preimage {
      npk
      token {
        tokenType
        tokenAddress
        tokenSubID
      }
      value
    }
    shieldKey
    encryptedBundle
  }
  nullifiers(
    orderBy: [blockNumber_ASC, nullifier_DESC]
    where: {blockNumber_gte: $fromBlock, blockNumber_lte: $toBlock}
    limit: $limit
  ) {
    id
    transactionHash
    blockNumber
    blockTimestamp
    treeNumber
    nullifier
  }
}
";

pub(crate) const INDEXED_LEGACY_WALLET_PAGE_QUERY: &str = r"
query IndexedLegacyWalletPage($fromBlock: BigInt = 0, $toBlock: BigInt = 0, $limit: Int = 10000) {
  legacyEncryptedCommitments(
    orderBy: [blockNumber_ASC, treePosition_ASC]
    where: {blockNumber_gte: $fromBlock, blockNumber_lte: $toBlock}
    limit: $limit
  ) {
    id
    transactionHash
    blockNumber
    blockTimestamp
    treeNumber
    treePosition
    hash
    ciphertext {
      ciphertext {
        iv
        tag
        data
      }
      ephemeralKeys
      memo
    }
  }
  legacyGeneratedCommitments(
    orderBy: [blockNumber_ASC, treePosition_ASC]
    where: {blockNumber_gte: $fromBlock, blockNumber_lte: $toBlock}
    limit: $limit
  ) {
    id
    transactionHash
    blockNumber
    blockTimestamp
    treeNumber
    treePosition
    hash
    preimage {
      npk
      token {
        tokenType
        tokenAddress
        tokenSubID
      }
      value
    }
    encryptedRandom
  }
  nullifiers(
    orderBy: [blockNumber_ASC, nullifier_DESC]
    where: {blockNumber_gte: $fromBlock, blockNumber_lte: $toBlock}
    limit: $limit
  ) {
    id
    transactionHash
    blockNumber
    blockTimestamp
    treeNumber
    nullifier
  }
}
";

pub(crate) const TRANSACT_COMMITMENTS_QUERY: &str = r"
query TransactCommitments($fromBlock: BigInt = 0, $toBlock: BigInt = 0, $limit: Int = 10000) {
  transactCommitments(
    orderBy: [blockNumber_ASC, treePosition_ASC]
    where: {blockNumber_gte: $fromBlock, blockNumber_lte: $toBlock}
    limit: $limit
  ) {
    id
    transactionHash
    blockNumber
    blockTimestamp
    treeNumber
    treePosition
    hash
    ciphertext {
      ciphertext {
        iv
        tag
        data
      }
      blindedSenderViewingKey
      blindedReceiverViewingKey
      annotationData
      memo
    }
  }
}
";

pub(crate) const SHIELD_COMMITMENTS_QUERY: &str = r"
query ShieldCommitments($fromBlock: BigInt = 0, $toBlock: BigInt = 0, $limit: Int = 10000) {
  shieldCommitments(
    orderBy: [blockNumber_ASC, treePosition_ASC]
    where: {blockNumber_gte: $fromBlock, blockNumber_lte: $toBlock}
    limit: $limit
  ) {
    id
    transactionHash
    blockNumber
    blockTimestamp
    treeNumber
    treePosition
    preimage {
      npk
      token {
        tokenType
        tokenAddress
        tokenSubID
      }
      value
    }
    shieldKey
    encryptedBundle
  }
}
";

pub(crate) const INDEXED_NULLIFIERS_QUERY: &str = r"
query IndexedNullifiers($fromBlock: BigInt = 0, $toBlock: BigInt = 0, $limit: Int = 10000) {
  nullifiers(
    orderBy: [blockNumber_ASC, nullifier_DESC]
    where: {blockNumber_gte: $fromBlock, blockNumber_lte: $toBlock}
    limit: $limit
  ) {
    id
    transactionHash
    blockNumber
    blockTimestamp
    treeNumber
    nullifier
  }
}
";

pub(crate) const PUBLIC_TXID_PAGE_QUERY: &str = r"
query PublicTxidPage($offset: Int!, $limit: Int!) {
  transactions(orderBy: id_ASC, offset: $offset, limit: $limit) {
    id
    blockNumber
    blockTimestamp
    transactionHash
    merkleRoot
    nullifiers
    commitments
    boundParamsHash
    hasUnshield
    unshieldToken {
      tokenType
      tokenAddress
      tokenSubID
    }
    unshieldToAddress
    unshieldValue
    utxoTreeIn
    utxoTreeOut
    utxoBatchStartPositionOut
  }
}
";

#[derive(Debug, Clone)]
pub struct QuickSyncClient {
    endpoint: Url,
    client: Client,
}

impl QuickSyncClient {
    #[must_use]
    pub fn new(endpoint: Url) -> Self {
        Self {
            endpoint,
            client: Client::new(),
        }
    }

    /// Creates a client that routes all traffic through the given
    /// pre-configured [`reqwest::Client`] (e.g. one with a SOCKS proxy).
    #[must_use]
    pub const fn with_http_client(endpoint: Url, client: Client) -> Self {
        Self { endpoint, client }
    }

    pub(crate) async fn fetch_list<D>(
        &self,
        query: &str,
        block_number: u64,
        page_size: NonZeroUsize,
    ) -> Result<Vec<D::Item>, SyncError>
    where
        D: DeserializeOwned + GraphList,
    {
        let limit = page_size.get();
        let variables = GraphVariables {
            block_number: block_number.to_string(),
            limit: limit.min(i32::MAX as usize) as i32,
        };
        let data: D = self.post_graph(query, &variables).await?;
        Ok(data.items())
    }

    pub async fn fetch_squid_height(&self) -> Result<u64, SyncError> {
        let variables = EmptyVariables {};
        let data: SquidStatusData = self.post_graph(SQUID_STATUS_QUERY, &variables).await?;
        Ok(data.squid_status.height.to())
    }

    pub async fn probe_indexed_wallet_support(&self) -> Result<IndexedWalletProbe, SyncError> {
        let variables = GraphRangeVariables {
            from_block: "0".to_string(),
            to_block: "0".to_string(),
            limit: 1,
        };
        let data: IndexedWalletProbeData = self.post_graph(WALLET_PROBE_QUERY, &variables).await?;
        Ok(IndexedWalletProbe {
            height: data.squid_status.height.to(),
        })
    }

    pub async fn fetch_transact_commitments(
        &self,
        from_block: u64,
        to_block: u64,
        page_size: NonZeroUsize,
    ) -> Result<Vec<IndexedTransactCommitment>, SyncError> {
        self.fetch_range::<IndexedTransactCommitmentsData>(
            TRANSACT_COMMITMENTS_QUERY,
            from_block,
            to_block,
            page_size,
        )
        .await
    }

    pub async fn fetch_indexed_wallet_page(
        &self,
        from_block: u64,
        to_block: u64,
        page_size: NonZeroUsize,
    ) -> Result<IndexedWalletPageData, SyncError> {
        let limit = page_size.get();
        let variables = GraphRangeVariables {
            from_block: from_block.to_string(),
            to_block: to_block.to_string(),
            limit: limit.min(i32::MAX as usize) as i32,
        };
        self.post_graph(INDEXED_WALLET_PAGE_QUERY, &variables).await
    }

    pub async fn fetch_indexed_legacy_wallet_page(
        &self,
        from_block: u64,
        to_block: u64,
        page_size: NonZeroUsize,
    ) -> Result<IndexedLegacyWalletPageData, SyncError> {
        let limit = page_size.get();
        let variables = GraphRangeVariables {
            from_block: from_block.to_string(),
            to_block: to_block.to_string(),
            limit: limit.min(i32::MAX as usize) as i32,
        };
        self.post_graph(INDEXED_LEGACY_WALLET_PAGE_QUERY, &variables)
            .await
    }

    pub async fn fetch_shield_commitments(
        &self,
        from_block: u64,
        to_block: u64,
        page_size: NonZeroUsize,
    ) -> Result<Vec<IndexedShieldCommitment>, SyncError> {
        self.fetch_range::<IndexedShieldCommitmentsData>(
            SHIELD_COMMITMENTS_QUERY,
            from_block,
            to_block,
            page_size,
        )
        .await
    }

    pub async fn fetch_indexed_nullifiers(
        &self,
        from_block: u64,
        to_block: u64,
        page_size: NonZeroUsize,
    ) -> Result<Vec<IndexedNullifier>, SyncError> {
        self.fetch_range::<IndexedNullifiersData>(
            INDEXED_NULLIFIERS_QUERY,
            from_block,
            to_block,
            page_size,
        )
        .await
    }

    pub async fn fetch_public_txid_page(
        &self,
        offset: u64,
        page_size: NonZeroUsize,
    ) -> Result<Vec<IndexedRailgunTransaction>, SyncError> {
        let limit = page_size.get();
        let offset = i32::try_from(offset).map_err(|_| {
            SyncError::UnexpectedFormat(format!(
                "public TXID page offset {offset} exceeds GraphQL Int max {}",
                i32::MAX
            ))
        })?;
        let variables = GraphOffsetVariables {
            offset,
            limit: limit.min(i32::MAX as usize) as i32,
        };
        let data: PublicTxidPageData = self.post_graph(PUBLIC_TXID_PAGE_QUERY, &variables).await?;
        Ok(data.transactions)
    }

    pub(crate) async fn fetch_range<D>(
        &self,
        query: &str,
        from_block: u64,
        to_block: u64,
        page_size: NonZeroUsize,
    ) -> Result<Vec<D::Item>, SyncError>
    where
        D: DeserializeOwned + GraphList,
    {
        let limit = page_size.get();
        let variables = GraphRangeVariables {
            from_block: from_block.to_string(),
            to_block: to_block.to_string(),
            limit: limit.min(i32::MAX as usize) as i32,
        };
        let data: D = self.post_graph(query, &variables).await?;
        Ok(data.items())
    }

    async fn post_graph<T, V>(&self, query: &str, variables: &V) -> Result<T, SyncError>
    where
        T: DeserializeOwned,
        V: Serialize,
    {
        post_graphql_data(&self.client, &self.endpoint, query, variables)
            .await
            .map_err(SyncError::from)
    }
}

pub async fn post_graphql_data<T, V>(
    client: &Client,
    endpoint: &Url,
    query: &str,
    variables: &V,
) -> Result<T, GraphPostError>
where
    T: DeserializeOwned,
    V: Serialize,
{
    for attempt in 1..=GRAPHQL_MAX_ATTEMPTS {
        match post_graphql_data_once(client, endpoint, query, variables).await {
            Ok(data) => return Ok(data),
            Err(error) if attempt < GRAPHQL_MAX_ATTEMPTS && error.is_retryable() => {
                let delay = graphql_retry_delay(attempt);
                // Custom endpoints may carry credentials, and transport error
                // text embeds the URL, so only the error class is logged.
                warn!(
                    attempt,
                    max_attempts = GRAPHQL_MAX_ATTEMPTS,
                    delay_ms = delay.as_millis(),
                    error_class = error.class(),
                    "quick-sync GraphQL request failed; retrying"
                );
                sleep(delay).await;
            }
            Err(error) => return Err(error),
        }
    }
    unreachable!("quick-sync GraphQL retry loop always returns")
}

async fn post_graphql_data_once<T, V>(
    client: &Client,
    endpoint: &Url,
    query: &str,
    variables: &V,
) -> Result<T, GraphPostError>
where
    T: DeserializeOwned,
    V: Serialize,
{
    let request = GraphRequest { query, variables };
    let response = timeout(
        SQUID_HEADER_TIMEOUT,
        client.post(endpoint.clone()).json(&request).send(),
    )
    .await
    .map_err(|_| GraphPostError::Timeout {
        phase: GraphTimeoutPhase::Headers,
    })?
    .map_err(GraphPostError::Request)?;
    let status = response.status();
    let body = read_body_with_idle_timeout(response).await?;
    let body = String::from_utf8_lossy(&body);
    if !status.is_success() {
        return Err(GraphPostError::HttpStatus {
            status,
            body: body.into_owned(),
        });
    }
    let parsed: GraphResponse<T> = serde_json::from_str(&body).map_err(GraphPostError::Json)?;
    if let Some(errors) = parsed.errors {
        let message = errors
            .iter()
            .map(|error| error.message.as_str())
            .collect::<Vec<_>>()
            .join("; ");
        return Err(GraphPostError::Graphql(message));
    }
    parsed.data.ok_or(GraphPostError::MissingData)
}

/// Reads the body chunk by chunk, failing when no bytes arrive for
/// `SQUID_BODY_IDLE_TIMEOUT`; a slow body that keeps arriving completes.
async fn read_body_with_idle_timeout(mut response: Response) -> Result<Vec<u8>, GraphPostError> {
    let mut body = Vec::new();
    while let Some(chunk) = timeout(SQUID_BODY_IDLE_TIMEOUT, response.chunk())
        .await
        .map_err(|_| GraphPostError::Timeout {
            phase: GraphTimeoutPhase::Body,
        })?
        .map_err(GraphPostError::ReadBody)?
    {
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

#[cfg(not(test))]
const fn graphql_retry_delay(failed_attempt: usize) -> Duration {
    Duration::from_secs(1 << (failed_attempt - 1))
}

#[cfg(test)]
const fn graphql_retry_delay(_failed_attempt: usize) -> Duration {
    Duration::from_millis(1)
}

#[derive(Debug, Error)]
pub enum GraphPostError {
    #[error("graphql request failed: {0}")]
    Request(reqwest::Error),
    #[error("read graphql response failed: {0}")]
    ReadBody(reqwest::Error),
    #[error("graphql response {phase} timed out")]
    Timeout { phase: GraphTimeoutPhase },
    #[error("graphql request failed with status {status}: {body}")]
    HttpStatus { status: StatusCode, body: String },
    #[error("invalid graphql response: {0}")]
    Json(serde_json::Error),
    #[error("graphql errors: {0}")]
    Graphql(String),
    #[error("graphql response missing data field")]
    MissingData,
}

/// The response stage that stalled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GraphTimeoutPhase {
    Headers,
    Body,
}

impl std::fmt::Display for GraphTimeoutPhase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Headers => "headers",
            Self::Body => "body",
        })
    }
}

impl GraphPostError {
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Request(error) => error.is_timeout() || error.is_connect() || error.is_request(),
            Self::ReadBody(_) | Self::Timeout { .. } => true,
            Self::HttpStatus { status, .. } => matches!(
                *status,
                StatusCode::REQUEST_TIMEOUT
                    | StatusCode::TOO_MANY_REQUESTS
                    | StatusCode::INTERNAL_SERVER_ERROR
                    | StatusCode::BAD_GATEWAY
                    | StatusCode::SERVICE_UNAVAILABLE
                    | StatusCode::GATEWAY_TIMEOUT
            ),
            Self::Json(_) | Self::Graphql(_) | Self::MissingData => false,
        }
    }

    /// Names the failure kind without the endpoint or error text, for
    /// diagnostics that must not expose endpoint credentials.
    #[must_use]
    pub fn class(&self) -> &'static str {
        match self {
            Self::Request(error) if error.is_connect() => "connect",
            Self::Request(_) => "request",
            Self::ReadBody(_) => "read_body",
            Self::Timeout {
                phase: GraphTimeoutPhase::Headers,
            } => "timeout_headers",
            Self::Timeout {
                phase: GraphTimeoutPhase::Body,
            } => "timeout_body",
            Self::HttpStatus { .. } => "status",
            Self::Json(_) => "decode",
            Self::Graphql(_) => "graphql",
            Self::MissingData => "missing_data",
        }
    }
}

impl From<GraphPostError> for SyncError {
    fn from(error: GraphPostError) -> Self {
        match error {
            GraphPostError::Request(error) | GraphPostError::ReadBody(error) => {
                Self::Request(error)
            }
            GraphPostError::MissingData => Self::MissingData,
            GraphPostError::Timeout { .. }
            | GraphPostError::HttpStatus { .. }
            | GraphPostError::Json(_)
            | GraphPostError::Graphql(_) => Self::UnexpectedFormat(error.to_string()),
        }
    }
}

#[derive(Debug, Serialize)]
struct GraphRequest<'a, V> {
    query: &'a str,
    variables: &'a V,
}

#[derive(Debug, Serialize)]
struct EmptyVariables {}

#[derive(Debug, Serialize)]
struct GraphVariables {
    #[serde(rename = "blockNumber")]
    block_number: String,
    limit: i32,
}

#[derive(Debug, Serialize)]
struct GraphRangeVariables {
    #[serde(rename = "fromBlock")]
    from_block: String,
    #[serde(rename = "toBlock")]
    to_block: String,
    limit: i32,
}

#[derive(Debug, Serialize)]
struct GraphOffsetVariables {
    offset: i32,
    limit: i32,
}

#[derive(Debug, Deserialize)]
struct GraphResponse<T> {
    data: Option<T>,
    errors: Option<Vec<GraphError>>,
}

#[derive(Debug, Deserialize)]
struct GraphError {
    message: String,
}

pub(crate) trait GraphList {
    type Item;

    fn items(self) -> Vec<Self::Item>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IndexedWalletProbe {
    pub height: u64,
}

#[derive(Debug, Deserialize)]
pub(crate) struct SquidStatusData {
    #[serde(rename = "squidStatus")]
    squid_status: SquidStatus,
}

#[derive(Debug, Deserialize)]
struct SquidStatus {
    height: alloy::primitives::U256,
}

#[derive(Debug, Deserialize)]
pub(crate) struct IndexedWalletProbeData {
    #[serde(rename = "squidStatus")]
    squid_status: SquidStatus,
    #[allow(dead_code)]
    #[serde(rename = "transactCommitments")]
    transact_commitments: Vec<IndexedTransactCommitment>,
    #[allow(dead_code)]
    #[serde(rename = "shieldCommitments")]
    shield_commitments: Vec<IndexedShieldCommitment>,
    #[allow(dead_code)]
    nullifiers: Vec<IndexedNullifier>,
    #[allow(dead_code)]
    #[serde(rename = "legacyEncryptedCommitments")]
    legacy_encrypted_commitments: Vec<IndexedLegacyEncryptedCommitment>,
    #[allow(dead_code)]
    #[serde(rename = "legacyGeneratedCommitments")]
    legacy_generated_commitments: Vec<IndexedLegacyGeneratedCommitment>,
}

#[derive(Debug, Deserialize)]
pub struct IndexedWalletPageData {
    #[serde(rename = "transactCommitments")]
    pub transact_commitments: Vec<IndexedTransactCommitment>,
    #[serde(rename = "shieldCommitments")]
    pub shield_commitments: Vec<IndexedShieldCommitment>,
    pub nullifiers: Vec<IndexedNullifier>,
}

#[derive(Debug, Deserialize)]
pub struct IndexedLegacyWalletPageData {
    #[serde(rename = "legacyEncryptedCommitments")]
    pub legacy_encrypted_commitments: Vec<IndexedLegacyEncryptedCommitment>,
    #[serde(rename = "legacyGeneratedCommitments")]
    pub legacy_generated_commitments: Vec<IndexedLegacyGeneratedCommitment>,
    pub nullifiers: Vec<IndexedNullifier>,
}

#[derive(Debug, Deserialize)]
struct PublicTxidPageData {
    transactions: Vec<IndexedRailgunTransaction>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct CommitmentsData {
    commitments: Vec<Commitment>,
}

impl GraphList for CommitmentsData {
    type Item = Commitment;

    fn items(self) -> Vec<Self::Item> {
        self.commitments
    }
}

#[derive(Debug, Deserialize)]
pub(crate) struct IndexedTransactCommitmentsData {
    #[serde(rename = "transactCommitments")]
    transact_commitments: Vec<IndexedTransactCommitment>,
}

impl GraphList for IndexedTransactCommitmentsData {
    type Item = IndexedTransactCommitment;

    fn items(self) -> Vec<Self::Item> {
        self.transact_commitments
    }
}

#[derive(Debug, Deserialize)]
pub(crate) struct IndexedShieldCommitmentsData {
    #[serde(rename = "shieldCommitments")]
    shield_commitments: Vec<IndexedShieldCommitment>,
}

impl GraphList for IndexedShieldCommitmentsData {
    type Item = IndexedShieldCommitment;

    fn items(self) -> Vec<Self::Item> {
        self.shield_commitments
    }
}

#[derive(Debug, Deserialize)]
pub(crate) struct IndexedNullifiersData {
    nullifiers: Vec<IndexedNullifier>,
}

impl GraphList for IndexedNullifiersData {
    type Item = IndexedNullifier;

    fn items(self) -> Vec<Self::Item> {
        self.nullifiers
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::sync::{Arc, Mutex, mpsc};
    use std::thread;
    use std::time::{Duration as StdDuration, Instant};

    use reqwest::Client;
    use serde::Deserialize;

    use super::{
        EmptyVariables, GraphPostError, GraphTimeoutPhase, SQUID_BODY_IDLE_TIMEOUT,
        post_graphql_data, post_graphql_data_once,
    };

    #[derive(Debug, Deserialize)]
    struct TestData {
        ok: bool,
    }

    #[tokio::test]
    async fn post_graphql_data_retries_request_stage_eof() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test server");
        let endpoint = url::Url::parse(&format!(
            "http://{}/graphql",
            listener.local_addr().expect("read test server address")
        ))
        .expect("parse test server URL");
        let (done_tx, done_rx) = mpsc::channel();

        let server = thread::spawn(move || {
            let (first_stream, _) = listener.accept().expect("accept first request");
            drop(first_stream);

            let (mut second_stream, _) = listener.accept().expect("accept retry request");
            second_stream
                .set_read_timeout(Some(StdDuration::from_secs(5)))
                .expect("set retry read timeout");
            read_http_request(&mut second_stream);

            let body = r#"{"data":{"ok":true}}"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            second_stream
                .write_all(response.as_bytes())
                .expect("write retry response");
            done_tx.send(()).expect("send server completion");
        });

        let client = Client::builder().no_proxy().build().expect("build client");
        let data: TestData =
            post_graphql_data(&client, &endpoint, "query Test { ok }", &EmptyVariables {})
                .await
                .expect("request should succeed after retry");

        assert!(data.ok);
        done_rx
            .recv_timeout(StdDuration::from_secs(5))
            .expect("server should observe retry request");
        server.join().expect("server thread should finish");
    }

    /// A response whose headers never arrive times out and is retried, and
    /// retry warnings carry the error class but not the credential-bearing
    /// endpoint, even for a transport error whose text embeds the URL.
    #[tokio::test]
    async fn post_graphql_data_retries_header_stall_without_logging_endpoint() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test server");
        let port = listener
            .local_addr()
            .expect("read test server address")
            .port();
        let endpoint = url::Url::parse(&format!(
            "http://user:secret@127.0.0.1:{port}/graphql?key=secret"
        ))
        .expect("parse test server URL");

        let server = thread::spawn(move || {
            // Reads the first request and never answers it.
            let (mut stalled_stream, _) = listener.accept().expect("accept stalled request");
            stalled_stream
                .set_read_timeout(Some(StdDuration::from_secs(5)))
                .expect("set stalled read timeout");
            read_http_request(&mut stalled_stream);

            let (dropped_stream, _) = listener.accept().expect("accept dropped request");
            drop(dropped_stream);

            let (mut stream, _) = listener.accept().expect("accept final retry");
            stream
                .set_read_timeout(Some(StdDuration::from_secs(5)))
                .expect("set retry read timeout");
            read_http_request(&mut stream);
            let body = r#"{"data":{"ok":true}}"#;
            stream
                .write_all(format!("{}{body}", json_response_head(body.len())).as_bytes())
                .expect("write retry response");
            drop(stalled_stream);
        });

        let events = CapturedEvents::default();
        let guard = events.capture();
        let client = Client::builder().no_proxy().build().expect("build client");
        let data: TestData =
            post_graphql_data(&client, &endpoint, "query Test { ok }", &EmptyVariables {})
                .await
                .expect("request should succeed after retries");
        drop(guard);

        assert!(data.ok);
        server.join().expect("server thread should finish");

        let retries = events
            .events()
            .into_iter()
            .filter(|event| {
                event
                    .get("message")
                    .is_some_and(|message| message == "quick-sync GraphQL request failed; retrying")
            })
            .collect::<Vec<_>>();
        assert_eq!(
            retries.len(),
            2,
            "one retry per failed attempt: {retries:?}"
        );
        assert_eq!(retries[0].get("attempt").map(String::as_str), Some("1"));
        assert_eq!(
            retries[0].get("error_class").map(String::as_str),
            Some("timeout_headers")
        );
        assert!(
            retries
                .iter()
                .all(|retry| retry.contains_key("delay_ms") && retry.contains_key("error_class")),
            "retry warnings carry the delay and error class: {retries:?}"
        );
        let forbidden = ["127.0.0.1", "user", "secret"];
        for event in events.events() {
            for value in event.values() {
                assert!(
                    forbidden.iter().all(|needle| !value.contains(needle)),
                    "log value {value:?} exposes the endpoint"
                );
            }
        }
    }

    #[tokio::test]
    async fn post_graphql_data_once_times_out_stalled_body() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test server");
        let endpoint = url::Url::parse(&format!(
            "http://{}/graphql",
            listener.local_addr().expect("read test server address")
        ))
        .expect("parse test server URL");
        let (done_tx, done_rx) = mpsc::channel::<()>();

        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept request");
            stream
                .set_read_timeout(Some(StdDuration::from_secs(5)))
                .expect("set read timeout");
            read_http_request(&mut stream);
            let body = r#"{"data":{"ok":true}}"#;
            stream
                .write_all(format!("{}{}", json_response_head(body.len()), &body[..8]).as_bytes())
                .expect("write partial response");
            // Holds the connection open without sending the rest of the body.
            let _ = done_rx.recv();
        });

        let client = Client::builder().no_proxy().build().expect("build client");
        let error = post_graphql_data_once::<TestData, _>(
            &client,
            &endpoint,
            "query Test { ok }",
            &EmptyVariables {},
        )
        .await
        .expect_err("stalled body should time out");
        drop(done_tx);

        assert!(
            matches!(
                error,
                GraphPostError::Timeout {
                    phase: GraphTimeoutPhase::Body
                }
            ),
            "unexpected error: {error}"
        );
        assert!(error.is_retryable());
        server.join().expect("server thread should finish");
    }

    #[tokio::test]
    async fn post_graphql_data_once_completes_body_that_keeps_arriving() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test server");
        let endpoint = url::Url::parse(&format!(
            "http://{}/graphql",
            listener.local_addr().expect("read test server address")
        ))
        .expect("parse test server URL");

        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept request");
            stream
                .set_read_timeout(Some(StdDuration::from_secs(5)))
                .expect("set read timeout");
            stream.set_nodelay(true).expect("disable Nagle");
            read_http_request(&mut stream);
            let body = r#"{"data":{"ok":true}}"#;
            stream
                .write_all(json_response_head(body.len()).as_bytes())
                .expect("write response head");
            // Seven gaps of a fifth of the idle timeout outlast it in total.
            for piece in body.as_bytes().chunks(3) {
                thread::sleep(SQUID_BODY_IDLE_TIMEOUT / 5);
                stream.write_all(piece).expect("write body piece");
            }
        });

        let client = Client::builder().no_proxy().build().expect("build client");
        let started = Instant::now();
        let data = post_graphql_data_once::<TestData, _>(
            &client,
            &endpoint,
            "query Test { ok }",
            &EmptyVariables {},
        )
        .await
        .expect("a body that keeps arriving should complete");

        assert!(data.ok);
        assert!(started.elapsed() > SQUID_BODY_IDLE_TIMEOUT);
        server.join().expect("server thread should finish");
    }

    fn json_response_head(content_length: usize) -> String {
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {content_length}\r\nConnection: close\r\n\r\n"
        )
    }

    /// Records `merkletree` tracing events as field-name to value maps.
    #[derive(Clone, Default)]
    struct CapturedEvents(Arc<Mutex<Vec<BTreeMap<String, String>>>>);

    impl CapturedEvents {
        fn capture(&self) -> CaptureGuard {
            // With one registered dispatcher, tracing-core resolves a callsite
            // first hit on another test thread against that thread's empty
            // default and caches it as disabled. A second live dispatcher keeps
            // interest computed across every registered dispatcher, including
            // this thread's capture.
            let registered = tracing::Dispatch::new(CaptureSubscriber(self.clone()));
            CaptureGuard {
                _default: tracing::subscriber::set_default(CaptureSubscriber(self.clone())),
                _registered: registered,
            }
        }

        fn events(&self) -> Vec<BTreeMap<String, String>> {
            self.0.lock().expect("captured events lock").clone()
        }
    }

    struct CaptureGuard {
        _default: tracing::subscriber::DefaultGuard,
        _registered: tracing::Dispatch,
    }

    struct CaptureSubscriber(CapturedEvents);

    struct CapturedFields<'a>(&'a mut BTreeMap<String, String>);

    impl tracing::field::Visit for CapturedFields<'_> {
        fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
            self.0.insert(field.name().to_owned(), value.to_owned());
        }

        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            self.0.insert(field.name().to_owned(), format!("{value:?}"));
        }
    }

    impl tracing::Subscriber for CaptureSubscriber {
        fn register_callsite(
            &self,
            _metadata: &'static tracing::Metadata<'static>,
        ) -> tracing::subscriber::Interest {
            tracing::subscriber::Interest::sometimes()
        }

        fn enabled(&self, metadata: &tracing::Metadata<'_>) -> bool {
            metadata.target().starts_with("merkletree")
        }

        fn new_span(&self, _span: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }

        fn record(&self, _span: &tracing::span::Id, _values: &tracing::span::Record<'_>) {}

        fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {}

        fn event(&self, event: &tracing::Event<'_>) {
            let mut fields = BTreeMap::new();
            event.record(&mut CapturedFields(&mut fields));
            self.0.0.lock().expect("captured events lock").push(fields);
        }

        fn enter(&self, _span: &tracing::span::Id) {}

        fn exit(&self, _span: &tracing::span::Id) {}
    }

    fn read_http_request(stream: &mut TcpStream) {
        let mut request = Vec::new();
        let mut buffer = [0_u8; 1024];

        loop {
            let read = stream.read(&mut buffer).expect("read retry request");
            if read == 0 {
                break;
            }
            request.extend_from_slice(&buffer[..read]);
            if request_is_complete(&request) {
                break;
            }
        }

        assert!(request.starts_with(b"POST "));
    }

    fn request_is_complete(request: &[u8]) -> bool {
        let Some(header_end) = request
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .map(|position| position + 4)
        else {
            return false;
        };
        let headers = String::from_utf8_lossy(&request[..header_end]);
        let content_length = headers
            .lines()
            .filter_map(|line| line.split_once(':'))
            .find_map(|(name, value)| {
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().expect("parse content length"))
            })
            .unwrap_or(0);

        request.len() >= header_end + content_length
    }
}
