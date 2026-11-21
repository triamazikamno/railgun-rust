use std::borrow::Borrow;
use std::fmt::{self, Display};
use std::ops::Deref;
use std::str::FromStr;

use alloy::hex;
use alloy::primitives::Address;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;

const WALLET_CACHE_KEY_DOMAIN: &[u8] = b"railgun-wallet-cache-key-v1";

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct WalletCacheKey(String);

impl WalletCacheKey {
    #[must_use]
    pub fn new(wallet_id: &str, chain_id: u64, contract: Address) -> Self {
        let wallet_id = wallet_id.as_bytes();
        let mut bytes = Vec::with_capacity(
            WALLET_CACHE_KEY_DOMAIN.len() + 8 + wallet_id.len() + 8 + contract.len(),
        );
        bytes.extend_from_slice(WALLET_CACHE_KEY_DOMAIN);
        bytes.extend_from_slice(&(wallet_id.len() as u64).to_be_bytes());
        bytes.extend_from_slice(wallet_id);
        bytes.extend_from_slice(&chain_id.to_be_bytes());
        bytes.extend_from_slice(contract.as_slice());
        Self(hex::encode(bytes))
    }

    #[must_use]
    pub fn from_opaque_id(id: [u8; 16]) -> Self {
        Self(hex::encode(id))
    }

    pub fn from_opaque_bytes(value: &[u8]) -> Result<Self, WalletCacheKeyError> {
        if value.is_empty() {
            return Err(WalletCacheKeyError);
        }
        Ok(Self(hex::encode(value)))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for WalletCacheKey {
    type Err = WalletCacheKeyError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let non_canonical = value.is_empty()
            || !value.len().is_multiple_of(2)
            || value
                .bytes()
                .any(|byte| !matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
            || hex::decode(value).is_err();
        if non_canonical {
            return Err(WalletCacheKeyError);
        }
        Ok(Self(value.to_owned()))
    }
}

impl AsRef<str> for WalletCacheKey {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl Deref for WalletCacheKey {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.as_str()
    }
}

impl From<WalletCacheKey> for String {
    fn from(value: WalletCacheKey) -> Self {
        value.0
    }
}

impl Borrow<str> for WalletCacheKey {
    fn borrow(&self) -> &str {
        self.as_str()
    }
}

impl Display for WalletCacheKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl Serialize for WalletCacheKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for WalletCacheKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
#[error("wallet cache key must be non-empty canonical lowercase hex")]
pub struct WalletCacheKeyError;
