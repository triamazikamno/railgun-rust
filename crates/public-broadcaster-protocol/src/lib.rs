use alloy::primitives::{Address, U256};
use broadcaster_core::crypto::railgun;
use broadcaster_core::serde_helpers;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PayloadError {
    #[error("serialize payload")]
    Serialize(#[from] serde_json::Error),
    #[error("invalid signature length: {len}")]
    InvalidSignatureLen { len: usize },
    #[error("invalid viewing key: {message}")]
    PublicKey { message: String },
    #[error("signature error")]
    Signature(#[from] ed25519_dalek::SignatureError),
    #[error("invalid signature bytes")]
    SignatureBytes(#[from] std::array::TryFromSliceError),
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Payload {
    #[serde(with = "serde_helpers::hex_string")]
    pub data: Vec<u8>,
    #[serde(with = "serde_helpers::hex_string")]
    pub signature: Vec<u8>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "camelCase")]
pub struct Body {
    pub fees: HashMap<Address, U256>,
    pub fee_expiration: u64,
    #[serde(rename = "feesID")]
    pub fees_id: String,
    pub railgun_address: railgun::Address,
    pub available_wallets: u32,
    pub version: String,
    #[serde(with = "serde_helpers::checksum_address")]
    pub relay_adapt: Address,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub relay_adapt_7702: Option<Address>,
    #[serde(rename = "requiredPOIListKeys")]
    pub required_poi_list_keys: Vec<String>,
    pub reliability: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identifier: Option<String>,
}

impl Body {
    pub fn into_signed_payload(
        self,
        viewing_priv_seed_32: [u8; 32],
    ) -> Result<Payload, PayloadError> {
        let data = serde_json::to_string(&self)?.into_bytes();
        let sk = SigningKey::from_bytes(&viewing_priv_seed_32);
        let signature = sk.sign(&data);
        Ok(Payload {
            data,
            signature: signature.to_bytes().into(),
        })
    }
}

impl Payload {
    pub fn decode_and_verify(&self) -> Result<(Body, bool), PayloadError> {
        if self.signature.len() != 64 {
            return Err(PayloadError::InvalidSignatureLen {
                len: self.signature.len(),
            });
        }
        let decoded_data: Body = serde_json::from_slice(self.data.as_ref())?;
        let viewing_pk =
            railgun::PublicKey::try_from(&decoded_data.railgun_address).map_err(|error| {
                PayloadError::PublicKey {
                    message: error.to_string(),
                }
            })?;

        let vk = VerifyingKey::from_bytes(&viewing_pk)?;
        let sig = Signature::from_bytes(self.signature.as_slice().try_into()?);

        Ok((decoded_data, vk.verify(self.data.as_ref(), &sig).is_ok()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signed_payload_roundtrips_and_rejects_tampering() {
        let seed = [7_u8; 32];
        let viewing_public_key = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
        let body = Body {
            fees: HashMap::new(),
            fee_expiration: 1_800_000_000,
            fees_id: "test-fees".to_string(),
            railgun_address: railgun::Address::try_from_parts(
                U256::from(1),
                viewing_public_key,
                None,
            )
            .expect("test Railgun address"),
            available_wallets: 1,
            version: "1.0.0".to_string(),
            relay_adapt: Address::ZERO,
            relay_adapt_7702: None,
            required_poi_list_keys: Vec::new(),
            reliability: 1.0,
            identifier: None,
        };
        let mut payload = body.into_signed_payload(seed).expect("signed payload");

        let (_, verified) = payload.decode_and_verify().expect("decoded payload");
        assert!(verified);

        payload.signature[0] ^= 1;
        let (_, verified) = payload
            .decode_and_verify()
            .expect("decoded tampered payload");
        assert!(!verified);
    }
}
