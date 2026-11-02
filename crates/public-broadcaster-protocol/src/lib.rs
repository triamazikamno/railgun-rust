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
    #[serde(with = "relay_adapt")]
    pub relay_adapt: Option<Address>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub relay_adapt_7702: Option<Address>,
    #[serde(rename = "requiredPOIListKeys")]
    pub required_poi_list_keys: Vec<String>,
    pub reliability: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identifier: Option<String>,
}

/// Broadcasters announce "no relay adapt" as `""` or the zero address, and
/// Alloy's `Address` deserializer rejects `""`. `None` is written as the zero
/// address so builds that still require an address accept our announcements.
mod relay_adapt {
    use super::serde_helpers::checksum_address;
    use alloy::primitives::Address;
    use serde::{Deserialize, Deserializer, Serializer};

    #[allow(clippy::ref_option)] // serde `with` passes `&Option<T>`
    pub(super) fn serialize<S>(address: &Option<Address>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        checksum_address::serialize(&address.unwrap_or_default(), serializer)
    }

    pub(super) fn deserialize<'de, D>(deserializer: D) -> Result<Option<Address>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        if s.is_empty() {
            return Ok(None);
        }
        let address: Address = s.parse().map_err(serde::de::Error::custom)?;
        Ok((!address.is_zero()).then_some(address))
    }
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
        let delegate = Address::repeat_byte(0x22);
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
            version: "8.2.3".to_string(),
            relay_adapt: None,
            relay_adapt_7702: Some(delegate),
            required_poi_list_keys: Vec::new(),
            reliability: 1.0,
            identifier: None,
        };
        let mut payload = body.into_signed_payload(seed).expect("signed payload");
        let wire = std::str::from_utf8(&payload.data).expect("utf-8 payload");
        assert!(wire.contains(r#""relayAdapt":"0x0000000000000000000000000000000000000000""#));

        let (body, verified) = payload.decode_and_verify().expect("decoded payload");
        assert!(verified);
        assert_eq!(body.relay_adapt, None);
        assert_eq!(body.relay_adapt_7702, Some(delegate));

        payload.signature[0] ^= 1;
        let (_, verified) = payload
            .decode_and_verify()
            .expect("decoded tampered payload");
        assert!(!verified);
    }

    #[test]
    fn relay_adapt_decodes_empty_and_zero_as_none() {
        #[derive(Deserialize)]
        struct Wrapper {
            #[serde(with = "super::relay_adapt")]
            relay_adapt: Option<Address>,
        }
        let decode = |value: &str| {
            serde_json::from_str::<Wrapper>(&format!(r#"{{"relay_adapt":"{value}"}}"#))
                .map(|wrapper| wrapper.relay_adapt)
        };

        assert_eq!(decode("").expect("empty"), None);
        assert_eq!(
            decode("0x0000000000000000000000000000000000000000").expect("zero"),
            None
        );
        assert_eq!(
            decode("0x2222222222222222222222222222222222222222").expect("address"),
            Some(Address::repeat_byte(0x22))
        );
        assert!(decode("0x12").is_err());
    }
}
