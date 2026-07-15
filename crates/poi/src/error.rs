use std::fmt;

use alloy::primitives::FixedBytes;
use broadcaster_core::crypto::snark_proof::SnarkProofError;
use serde_json::Value;
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PoiRpcTransportPhase {
    Send,
    ResponseBody,
}

impl fmt::Display for PoiRpcTransportPhase {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Send => formatter.write_str("request send"),
            Self::ResponseBody => formatter.write_str("response body"),
        }
    }
}

#[derive(Debug, Error)]
pub enum PoiError {
    #[error("POI validation failed for listKey={list_key}: {source}")]
    ValidateList {
        list_key: FixedBytes<32>,
        #[source]
        source: Box<Self>,
    },
    #[error("missing required listKey in POI map")]
    MissingListKey,
    #[error("missing POI proof for txidLeafHash={leaf_hex}")]
    MissingProof { leaf_hex: FixedBytes<32> },
    #[error("txidMerkleroot mismatch. expected(dummy)={expected}, got={actual}")]
    TxidMerklerootMismatch {
        expected: FixedBytes<32>,
        actual: FixedBytes<32>,
    },
    #[error("RPC request failed: {source}")]
    RpcRequest {
        #[from]
        source: PoiRpcError,
    },
    #[error("POI node rejected merkle roots")]
    MerkleRootsRejected,
    #[error("invalid SNARK proof")]
    InvalidSnarkProof,
    #[error("SNARK verification failed: {source}")]
    SnarkVerify {
        #[from]
        source: SnarkProofError,
    },
}

#[derive(Error)]
pub enum PoiRpcError {
    #[error("POI RPC POST failed during {phase}")]
    Post {
        phase: PoiRpcTransportPhase,
        #[source]
        source: reqwest::Error,
    },
    #[error("POI RPC HTTP {status}")]
    HttpStatus { status: reqwest::StatusCode },
    #[error("POI RPC JSON decode failed: {0}")]
    JsonDecode(#[source] serde_json::Error),
    #[error("POI RPC response missing result")]
    MissingResult,
    #[error("POI RPC JSON-RPC error {code}")]
    JsonRpc {
        code: i64,
        message: String,
        data: Option<Value>,
    },
    #[error("txid merkleroot not found")]
    TxidMerklerootNotFound,
}

impl PoiRpcError {
    #[must_use]
    pub fn is_timeout(&self) -> bool {
        matches!(self, Self::Post { source, .. } if source.is_timeout())
    }

    #[must_use]
    pub fn status(&self) -> Option<reqwest::StatusCode> {
        match self {
            Self::Post { source, .. } => source.status(),
            Self::HttpStatus { status } => Some(*status),
            _ => None,
        }
    }

    #[must_use]
    pub const fn json_rpc_code(&self) -> Option<i64> {
        match self {
            Self::JsonRpc { code, .. } => Some(*code),
            _ => None,
        }
    }

    #[must_use]
    pub const fn transport_phase(&self) -> Option<PoiRpcTransportPhase> {
        match self {
            Self::Post { phase, .. } => Some(*phase),
            _ => None,
        }
    }
}

impl fmt::Debug for PoiRpcError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}
