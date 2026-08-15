use alloy::primitives::{Address, FixedBytes, U256};
use thiserror::Error;

use crate::contracts::railgun::CommitmentCiphertext;
use crate::crypto::aes_gcm::{AesGcmError, decrypt_in_place_16b_iv, split_iv_tag};
use crate::crypto::poseidon::poseidon;
use crate::crypto::railgun::ViewingKeyData;
use crate::crypto::shared_key::shared_symmetric_key;

#[derive(Debug, Error)]
pub enum NoteError {
    #[error("ciphertext too short")]
    CiphertextTooShort,
    #[error("invalid iv/tag length")]
    InvalidIvTag,
    #[error("invalid key")]
    InvalidKey,
    #[error("encrypt failed")]
    EncryptFailed,
    #[error("decrypt failed")]
    DecryptFailed,
    #[error(transparent)]
    AesGcm(#[from] AesGcmError),
    #[error("invalid viewing key")]
    InvalidViewingKey,
}

#[derive(Debug, Clone)]
pub struct Note {
    pub token_hash: U256,
    pub value: U256,
    pub random: [u8; 16],
    pub npk: U256,
}

impl Note {
    #[must_use]
    pub fn new_unshield(to: Address, token_address: Address, value: U256) -> Self {
        let token_hash = U256::from_be_slice(token_address.as_slice());
        let npk = U256::from_be_slice(to.as_slice());
        Self {
            token_hash,
            value,
            random: [0u8; 16],
            npk,
        }
    }

    #[must_use]
    pub fn new_change(
        master_public_key: U256,
        token_address: Address,
        value: U256,
        random: [u8; 16],
    ) -> Self {
        let token_hash = U256::from_be_slice(token_address.as_slice());
        let npk = Self::npk_for(master_public_key, random);
        Self {
            token_hash,
            value,
            random,
            npk,
        }
    }

    #[must_use]
    pub fn commitment(&self) -> U256 {
        poseidon(vec![self.npk, self.token_hash, self.value])
    }

    pub fn decrypt_v2(
        ciphertext: &[FixedBytes<32>; 4],
        memo: &[u8],
        shared_key: &[u8; 32],
        receiver_mpk: U256,
    ) -> Result<Self, NoteError> {
        let (iv, tag) = split_iv_tag(ciphertext[0].0);
        let mut ct = Vec::with_capacity(32 * 3 + memo.len());
        ct.extend_from_slice(&ciphertext[1].0);
        ct.extend_from_slice(&ciphertext[2].0);
        ct.extend_from_slice(&ciphertext[3].0);
        ct.extend_from_slice(memo);

        let mut pt = ct;
        decrypt_in_place_16b_iv(shared_key, &iv, &tag, &mut pt)?;
        if pt.len() < 96 {
            return Err(NoteError::CiphertextTooShort);
        }

        let mut encoded_mpk = [0u8; 32];
        encoded_mpk.copy_from_slice(&pt[..32]);
        let mut token_hash = [0u8; 32];
        token_hash.copy_from_slice(&pt[32..64]);
        let mut random = [0u8; 16];
        random.copy_from_slice(&pt[64..80]);
        let mut value_bytes = [0u8; 16];
        value_bytes.copy_from_slice(&pt[80..96]);

        let token_hash = U256::from_be_bytes(token_hash);
        let value = U256::from_be_slice(&value_bytes);
        let npk = Self::npk_for(receiver_mpk, random);
        Ok(Self {
            token_hash,
            value,
            random,
            npk,
        })
    }

    #[must_use]
    pub fn npk_for(master_public_key: U256, random: [u8; 16]) -> U256 {
        let random_value = U256::from_be_slice(&random);
        poseidon(vec![master_public_key, random_value])
    }
}

/// Decrypt a sender-visible note and require the supplied commitment to match.
///
/// Sender note slots are intentionally best-effort: unavailable keys, malformed
/// ciphertext, authentication failures, and commitment mismatches are all
/// represented as `None`.
#[must_use]
pub fn decrypt_sender_note(
    ciphertext: &CommitmentCiphertext,
    expected_commitment: U256,
    scan_keys: &ViewingKeyData,
) -> Option<Note> {
    if ciphertext.blindedReceiverViewingKey == FixedBytes::ZERO {
        return None;
    }
    let shared_key = shared_symmetric_key(
        &scan_keys.viewing_private_key,
        &ciphertext.blindedReceiverViewingKey.0,
    )
    .ok()?;
    let (iv, tag) = split_iv_tag(ciphertext.ciphertext[0].0);
    let mut plaintext = Vec::with_capacity(96 + ciphertext.memo.len());
    plaintext.extend_from_slice(&ciphertext.ciphertext[1].0);
    plaintext.extend_from_slice(&ciphertext.ciphertext[2].0);
    plaintext.extend_from_slice(&ciphertext.ciphertext[3].0);
    plaintext.extend_from_slice(ciphertext.memo.as_ref());
    decrypt_in_place_16b_iv(&shared_key, &iv, &tag, &mut plaintext).ok()?;
    if plaintext.len() < 96 {
        return None;
    }

    let encoded_mpk = U256::from_be_slice(&plaintext[0..32]);
    let token_hash = U256::from_be_slice(&plaintext[32..64]);
    let mut random = [0u8; 16];
    random.copy_from_slice(&plaintext[64..80]);
    let value = U256::from_be_slice(&plaintext[80..96]);
    for receiver_mpk in [encoded_mpk ^ scan_keys.master_public_key, encoded_mpk] {
        let note = Note {
            token_hash,
            value,
            random,
            npk: Note::npk_for(receiver_mpk, random),
        };
        if note.commitment() == expected_commitment {
            return Some(note);
        }
    }
    None
}

/// Resolve a receiver-visible fee note without exposing decryption failures.
pub(crate) fn decrypt_receiver_fee_note(
    ciphertext: &CommitmentCiphertext,
    expected_commitment: U256,
    broadcaster_viewing: &ViewingKeyData,
) -> Option<Note> {
    if ciphertext.blindedSenderViewingKey == FixedBytes::ZERO {
        return None;
    }
    let shared_key = shared_symmetric_key(
        &broadcaster_viewing.viewing_private_key,
        &ciphertext.blindedSenderViewingKey.0,
    )
    .ok()?;
    let note = Note::decrypt_v2(
        &ciphertext.ciphertext,
        ciphertext.memo.as_ref(),
        &shared_key,
        broadcaster_viewing.master_public_key,
    )
    .ok()?;
    (note.commitment() == expected_commitment).then_some(note)
}

pub fn decrypt_shield_random(
    encrypted_bundle: &[FixedBytes<32>; 3],
    shared_key: &[u8; 32],
) -> Result<[u8; 16], NoteError> {
    let (iv, tag) = split_iv_tag(encrypted_bundle[0].0);
    let mut ct = Vec::with_capacity(32);
    ct.extend_from_slice(&encrypted_bundle[1].0[..16]);

    let mut pt = ct;
    decrypt_in_place_16b_iv(shared_key, &iv, &tag, &mut pt)?;
    if pt.len() < 16 {
        return Err(NoteError::CiphertextTooShort);
    }
    let mut random = [0u8; 16];
    random.copy_from_slice(&pt[..16]);
    Ok(random)
}

pub fn decrypt_legacy_random(
    iv_tag: FixedBytes<32>,
    data: FixedBytes<16>,
    viewing_private_key: &[u8; 32],
) -> Result<[u8; 16], NoteError> {
    let (iv, tag) = split_iv_tag(iv_tag.0);
    let mut pt = data.0.to_vec();
    decrypt_in_place_16b_iv(viewing_private_key, &iv, &tag, &mut pt)?;
    if pt.len() < 16 {
        return Err(NoteError::CiphertextTooShort);
    }
    let mut random = [0u8; 16];
    random.copy_from_slice(&pt[..16]);
    Ok(random)
}

#[cfg(test)]
mod tests {
    use alloy::primitives::{Address, Bytes, FixedBytes, U256};

    use crate::contracts::railgun::CommitmentCiphertext;
    use crate::crypto::aes_gcm::encrypt_in_place_16b_iv;
    use crate::crypto::railgun::{ViewingKeyData, derive_viewing_public_key};
    use crate::crypto::shared_key::shared_symmetric_key;

    use super::{Note, decrypt_receiver_fee_note, decrypt_sender_note};

    fn ciphertext(keys: &ViewingKeyData, note: &Note) -> CommitmentCiphertext {
        let blinded = derive_viewing_public_key(&[11u8; 32]);
        let shared_key = shared_symmetric_key(&keys.viewing_private_key, &blinded).expect("key");
        let mut plaintext = Vec::with_capacity(96);
        plaintext.extend_from_slice(&keys.master_public_key.to_be_bytes::<32>());
        plaintext.extend_from_slice(&note.token_hash.to_be_bytes::<32>());
        plaintext.extend_from_slice(&note.random);
        let value = note.value.to_be_bytes::<32>();
        plaintext.extend_from_slice(&value[16..]);
        let iv_tag = encrypt_in_place_16b_iv(&shared_key, &mut plaintext).expect("encrypt");
        let mut words = [[0u8; 32]; 4];
        words[0].copy_from_slice(&iv_tag);
        words[1].copy_from_slice(&plaintext[..32]);
        words[2].copy_from_slice(&plaintext[32..64]);
        words[3].copy_from_slice(&plaintext[64..96]);
        CommitmentCiphertext {
            ciphertext: words.map(FixedBytes::from),
            blindedSenderViewingKey: FixedBytes::from(blinded),
            blindedReceiverViewingKey: FixedBytes::from(blinded),
            annotationData: Bytes::new(),
            memo: Bytes::new(),
        }
    }

    #[test]
    fn note_resolvers_accept_valid_sender_and_receiver_notes() {
        let keys =
            ViewingKeyData::from_spending_public_key([7u8; 32], [U256::from(3), U256::from(9)]);
        let note = Note::new_change(
            keys.master_public_key,
            Address::ZERO,
            U256::from(42),
            [5u8; 16],
        );
        let ciphertext = ciphertext(&keys, &note);

        assert_eq!(
            decrypt_sender_note(&ciphertext, note.commitment(), &keys)
                .expect("sender note")
                .commitment(),
            note.commitment()
        );
        assert_eq!(
            decrypt_receiver_fee_note(&ciphertext, note.commitment(), &keys)
                .expect("receiver note")
                .commitment(),
            note.commitment()
        );
        assert!(decrypt_sender_note(&ciphertext, U256::from(1), &keys).is_none());
        assert!(decrypt_receiver_fee_note(&ciphertext, U256::from(1), &keys).is_none());

        let mut missing_key = ciphertext.clone();
        missing_key.blindedReceiverViewingKey = FixedBytes::ZERO;
        assert!(decrypt_sender_note(&missing_key, note.commitment(), &keys).is_none());
        let mut malformed = ciphertext;
        malformed.ciphertext[1].0[0] ^= 1;
        assert!(decrypt_sender_note(&malformed, note.commitment(), &keys).is_none());
    }
}
