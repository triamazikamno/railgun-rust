use alloy::primitives::{Bytes, FixedBytes, U256};

use broadcaster_core::contracts::railgun::CommitmentCiphertext;
use broadcaster_core::crypto::aes_gcm::{
    AesGcmError, decrypt_in_place_16b_iv, encrypt_in_place_16b_iv, split_iv_tag,
};
use broadcaster_core::crypto::railgun::{AddressData, ViewingKeyData};
use broadcaster_core::crypto::shared_key::shared_symmetric_key;
pub use broadcaster_core::notes::{Note, NoteError, decrypt_legacy_random, decrypt_shield_random};
use ctr::cipher::{KeyIvInit, StreamCipher};

use crate::keys::note_blinding_keys;

type V2Payload = ([u8; 32], [[u8; 32]; 3], Vec<u8>);
const MEMO_SENDER_RANDOM_NULL: [u8; 15] = [0u8; 15];
const ANNOTATION_IV_LEN: usize = 16;

/// Length of the `annotationData` the Railgun engine writes on every V2 output:
/// a 16-byte IV followed by 46 encrypted bytes.
pub const ANNOTATION_DATA_LEN: usize = 62;

/// Output type the Railgun engine records in a note's `annotationData`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum NoteOutputType {
    Transfer = 0,
    BroadcasterFee = 1,
    Change = 2,
}

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
        output_type: NoteOutputType,
    ) -> Result<Self, NoteError> {
        let sender_random: [u8; 15] = rand::random();
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
            annotation_data: Bytes::from(Self::encrypt_annotation_data(
                sender_viewing_private_key,
                rand::random(),
                output_type,
                sender_random,
            )),
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

    /// Encrypts `output_type || sender_random || 15 zero bytes || empty wallet source`
    /// with AES-256-CTR under the sender viewing key and prepends `iv`.
    ///
    /// Matches engine `Memo.createEncryptedNoteAnnotationDataV2` byte for byte,
    /// because the annotation's length and shape are public on chain.
    fn encrypt_annotation_data(
        sender_viewing_private_key: &[u8; 32],
        iv: [u8; ANNOTATION_IV_LEN],
        output_type: NoteOutputType,
        sender_random: [u8; 15],
    ) -> [u8; ANNOTATION_DATA_LEN] {
        let mut data = [0u8; ANNOTATION_DATA_LEN];
        data[..ANNOTATION_IV_LEN].copy_from_slice(&iv);
        data[ANNOTATION_IV_LEN] = output_type as u8;
        data[ANNOTATION_IV_LEN + 1..ANNOTATION_IV_LEN + 16].copy_from_slice(&sender_random);
        ctr::Ctr128BE::<aes::Aes256>::new(sender_viewing_private_key.into(), &iv.into())
            .apply_keystream(&mut data[ANNOTATION_IV_LEN..]);
        data
    }
}

/// Decrypts `annotationData` into its output type byte and sender random.
#[cfg(test)]
pub(crate) fn decrypt_annotation_data(
    sender_viewing_private_key: &[u8; 32],
    annotation_data: &[u8],
) -> (u8, [u8; 15]) {
    let (iv, ciphertext) = annotation_data.split_at(ANNOTATION_IV_LEN);
    let mut plaintext = ciphertext.to_vec();
    ctr::Ctr128BE::<aes::Aes256>::new_from_slices(sender_viewing_private_key, iv)
        .expect("AES-256-CTR key and IV")
        .apply_keystream(&mut plaintext);
    let sender_random: [u8; 15] = plaintext[1..16].try_into().expect("sender random");
    (plaintext[0], sender_random)
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

/// Decrypts an output note with the sender viewing key and validates its commitment.
///
/// `None` means the slot is not sender-decryptable, malformed, or does not match the expected
/// commitment. Callers that retain unavailable slots can represent those cases explicitly.
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

#[cfg(test)]
mod tests {
    use alloy::hex;
    use alloy::primitives::{Address, FixedBytes, U256};

    use broadcaster_core::contracts::railgun::CommitmentCiphertext;
    use broadcaster_core::crypto::railgun::ViewingKeyData;

    use super::{Note, NoteCiphertext, NoteOutputType, decrypt_sender_note};

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
            NoteOutputType::Transfer,
        )
        .expect("encrypt sender note")
        .into();
        (keys, note, ciphertext)
    }

    #[test]
    fn annotation_data_matches_engine_vectors() {
        // Produced by engine `Memo.createEncryptedNoteAnnotationDataV2` with a pinned IV and an
        // empty wallet source.
        let key = [0x11; 32];
        let iv = hex!("0123456789abcdeffedcba9876543210");
        let sender_random = hex!("aabbccdd11223344aabbccdd112233");
        for (output_type, expected) in [
            (
                NoteOutputType::Transfer,
                hex!(
                    "0123456789abcdeffedcba9876543210c6131f918336bcc39d126538b22b6682b2d275818e30c4f2b55c22ef9d8e9c5a6ebb11b6bddc93f8b0df21076a95"
                ),
            ),
            (
                NoteOutputType::BroadcasterFee,
                hex!(
                    "0123456789abcdeffedcba9876543210c7131f918336bcc39d126538b22b6682b2d275818e30c4f2b55c22ef9d8e9c5a6ebb11b6bddc93f8b0df21076a95"
                ),
            ),
            (
                NoteOutputType::Change,
                hex!(
                    "0123456789abcdeffedcba9876543210c4131f918336bcc39d126538b22b6682b2d275818e30c4f2b55c22ef9d8e9c5a6ebb11b6bddc93f8b0df21076a95"
                ),
            ),
        ] {
            assert_eq!(
                NoteCiphertext::encrypt_annotation_data(&key, iv, output_type, sender_random),
                expected,
                "{output_type:?}"
            );
        }
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
