use alloy::primitives::{Bytes, FixedBytes, U256};

use broadcaster_core::contracts::railgun::CommitmentCiphertext;
use broadcaster_core::crypto::aes_gcm::{AesGcmError, encrypt_in_place_16b_iv};
use broadcaster_core::crypto::railgun::AddressData;
use broadcaster_core::crypto::shared_key::shared_symmetric_key;
pub use broadcaster_core::notes::{
    Note, NoteError, decrypt_legacy_random, decrypt_sender_note, decrypt_shield_random,
};

use crate::keys::note_blinding_keys;

type V2Payload = ([u8; 32], [[u8; 32]; 3], Vec<u8>);
const MEMO_SENDER_RANDOM_NULL: [u8; 15] = [0u8; 15];

#[derive(Debug, Clone)]
pub struct NoteCiphertext {
    pub ciphertext: [FixedBytes<32>; 4],
    pub blinded_sender_viewing_key: FixedBytes<32>,
    pub blinded_receiver_viewing_key: FixedBytes<32>,
    pub annotation_data: Bytes,
    pub memo: Bytes,
}

impl NoteCiphertext {
    pub fn try_from_note(
        note: &Note,
        sender: &AddressData,
        receiver: &AddressData,
        sender_viewing_private_key: &[u8; 32],
    ) -> Result<Self, NoteError> {
        let sender_random = MEMO_SENDER_RANDOM_NULL;
        let (blinded_sender, blinded_receiver) = note_blinding_keys(
            &sender.viewing_public_key,
            &receiver.viewing_public_key,
            note.random,
            sender_random,
        )
        .map_err(|_| NoteError::InvalidViewingKey)?;

        let shared_key = shared_symmetric_key(sender_viewing_private_key, &blinded_receiver)
            .map_err(|_| NoteError::InvalidViewingKey)?;

        let encoded_mpk = if sender_random == MEMO_SENDER_RANDOM_NULL {
            receiver.master_public_key ^ sender.master_public_key
        } else {
            receiver.master_public_key
        };

        let (iv_tag, ct_blocks, memo) = Self::encrypt_v2_payload(
            &shared_key,
            encoded_mpk,
            note.token_hash,
            note.random,
            note.value,
        )?;

        Ok(Self {
            ciphertext: [
                FixedBytes::from(iv_tag),
                FixedBytes::from(ct_blocks[0]),
                FixedBytes::from(ct_blocks[1]),
                FixedBytes::from(ct_blocks[2]),
            ],
            blinded_sender_viewing_key: FixedBytes::from(blinded_sender),
            blinded_receiver_viewing_key: FixedBytes::from(blinded_receiver),
            annotation_data: Bytes::new(),
            memo: Bytes::from(memo),
        })
    }

    fn encrypt_v2_payload(
        shared_key: &[u8; 32],
        encoded_mpk: U256,
        token_hash: U256,
        random: [u8; 16],
        value: U256,
    ) -> Result<V2Payload, NoteError> {
        let mut pt = Vec::with_capacity(96);
        pt.extend_from_slice(&encoded_mpk.to_be_bytes::<32>());
        pt.extend_from_slice(&token_hash.to_be_bytes::<32>());
        pt.extend_from_slice(&random);
        let value_bytes = value.to_be_bytes::<32>();
        pt.extend_from_slice(&value_bytes[16..]);

        let iv_tag = encrypt_in_place_16b_iv(shared_key, &mut pt).map_err(|err| match err {
            AesGcmError::InvalidKey => NoteError::InvalidKey,
            AesGcmError::RandomFailed | AesGcmError::EncryptFailed | AesGcmError::DecryptFailed => {
                NoteError::EncryptFailed
            }
        })?;

        let mut blocks = [[0u8; 32]; 3];
        blocks[0].copy_from_slice(&pt[0..32]);
        blocks[1].copy_from_slice(&pt[32..64]);
        blocks[2].copy_from_slice(&pt[64..96]);
        Ok((iv_tag, blocks, Vec::new()))
    }
}

impl From<NoteCiphertext> for CommitmentCiphertext {
    fn from(value: NoteCiphertext) -> Self {
        Self {
            ciphertext: value.ciphertext,
            blindedSenderViewingKey: value.blinded_sender_viewing_key,
            blindedReceiverViewingKey: value.blinded_receiver_viewing_key,
            annotationData: value.annotation_data,
            memo: value.memo,
        }
    }
}

#[cfg(test)]
mod tests {
    use alloy::primitives::{Address, FixedBytes, U256};

    use super::{Note, NoteCiphertext, decrypt_sender_note};
    use broadcaster_core::contracts::railgun::CommitmentCiphertext;
    use broadcaster_core::crypto::railgun::ViewingKeyData;

    fn sender_fixture() -> (ViewingKeyData, Note, CommitmentCiphertext) {
        let keys =
            ViewingKeyData::from_spending_public_key([7; 32], [U256::from(11), U256::from(12)]);
        let receiver =
            ViewingKeyData::from_spending_public_key([9; 32], [U256::from(13), U256::from(14)]);
        let note = Note::new_change(
            receiver.master_public_key,
            Address::ZERO,
            U256::from(42),
            [3; 16],
        );
        let ciphertext = NoteCiphertext::try_from_note(
            &note,
            &keys.address_data(),
            &receiver.address_data(),
            &keys.viewing_private_key,
        )
        .expect("encrypt sender note")
        .into();
        (keys, note, ciphertext)
    }

    #[test]
    fn sender_note_decoder_validates_expected_commitment() {
        let (keys, note, ciphertext) = sender_fixture();

        let decoded =
            decrypt_sender_note(&ciphertext, note.commitment(), &keys).expect("valid sender note");

        assert_eq!(decoded.commitment(), note.commitment());
        assert!(decrypt_sender_note(&ciphertext, U256::from(1), &keys).is_none());
    }

    #[test]
    fn sender_note_decoder_rejects_missing_key_and_malformed_ciphertext() {
        let (keys, note, mut ciphertext) = sender_fixture();
        ciphertext.blindedReceiverViewingKey = FixedBytes::ZERO;
        assert!(decrypt_sender_note(&ciphertext, note.commitment(), &keys).is_none());

        let (_, note, mut ciphertext) = sender_fixture();
        ciphertext.ciphertext[1].0[0] ^= 0xff;
        assert!(decrypt_sender_note(&ciphertext, note.commitment(), &keys).is_none());
    }
}
