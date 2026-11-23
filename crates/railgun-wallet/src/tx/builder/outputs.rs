//! The notes and ciphertexts each transaction kind creates: the payment or
//! unshield note, the broadcaster fee note and the change note.

use alloy::primitives::{Address, U256};
use broadcaster_core::crypto::railgun::AddressData;

use crate::notes::{Note, NoteCiphertext, NoteOutputType};

use super::super::{BroadcasterFeeOutput, BuildError};
use super::rand_array;

pub(super) struct SendOutputs {
    pub(super) outputs: Vec<Note>,
    pub(super) commitment_ciphertext: Vec<NoteCiphertext>,
    pub(super) broadcaster_fee_note: Option<Note>,
    pub(super) recipient_note: Note,
    pub(super) change_note: Option<Note>,
}

pub(super) struct UnshieldOutputs {
    pub(super) outputs: Vec<Note>,
    pub(super) commitment_ciphertext: Vec<NoteCiphertext>,
    pub(super) broadcaster_fee_note: Option<Note>,
    pub(super) unshield_note: Note,
    pub(super) unshield_output_index: usize,
    pub(super) change_note: Option<Note>,
}

pub(super) struct FeeOnlyOutputs {
    pub(super) outputs: Vec<Note>,
    pub(super) commitment_ciphertext: Vec<NoteCiphertext>,
    pub(super) broadcaster_fee_note: Note,
    pub(super) change_note: Option<Note>,
}

fn push_broadcaster_fee_output(
    outputs: &mut Vec<Note>,
    commitment_ciphertext: &mut Vec<NoteCiphertext>,
    sender: &AddressData,
    broadcaster_fee: Option<BroadcasterFeeOutput>,
    sender_viewing_private_key: &[u8; 32],
) -> Result<Option<Note>, BuildError> {
    let Some(fee) = broadcaster_fee else {
        return Ok(None);
    };
    let note = Note::new_change(
        fee.recipient.master_public_key,
        fee.token_address,
        fee.amount,
        rand_array(),
    );
    let ciphertext = NoteCiphertext::try_from_note(
        &note,
        sender,
        &fee.recipient,
        sender_viewing_private_key,
        NoteOutputType::BroadcasterFee,
    )?;
    outputs.push(note.clone());
    commitment_ciphertext.push(ciphertext);
    Ok(Some(note))
}

pub(super) fn build_fee_only_outputs(
    broadcaster_fee: BroadcasterFeeOutput,
    change: U256,
    sender: &AddressData,
    sender_viewing_private_key: &[u8; 32],
) -> Result<FeeOnlyOutputs, BuildError> {
    let mut outputs = Vec::with_capacity(1 + usize::from(!change.is_zero()));
    let mut commitment_ciphertext = Vec::with_capacity(outputs.capacity());
    let broadcaster_fee_note = push_broadcaster_fee_output(
        &mut outputs,
        &mut commitment_ciphertext,
        sender,
        Some(broadcaster_fee),
        sender_viewing_private_key,
    )?
    .expect("broadcaster fee is provided");

    let change_note = if change.is_zero() {
        None
    } else {
        let note = Note::new_change(
            sender.master_public_key,
            broadcaster_fee.token_address,
            change,
            rand_array(),
        );
        let ciphertext = NoteCiphertext::try_from_note(
            &note,
            sender,
            sender,
            sender_viewing_private_key,
            NoteOutputType::Change,
        )?;
        outputs.push(note.clone());
        commitment_ciphertext.push(ciphertext);
        Some(note)
    };

    Ok(FeeOnlyOutputs {
        outputs,
        commitment_ciphertext,
        broadcaster_fee_note,
        change_note,
    })
}

pub(super) fn build_unshield_outputs(
    token_address: Address,
    unshield_amount: U256,
    unshield_to: Address,
    change: U256,
    receiver: &AddressData,
    broadcaster_fee: Option<BroadcasterFeeOutput>,
    sender_viewing_private_key: &[u8; 32],
) -> Result<UnshieldOutputs, BuildError> {
    let mut outputs = Vec::with_capacity(1 + usize::from(broadcaster_fee.is_some()) + 1);
    let mut commitment_ciphertext = Vec::with_capacity(usize::from(broadcaster_fee.is_some()) + 1);
    let broadcaster_fee_note = push_broadcaster_fee_output(
        &mut outputs,
        &mut commitment_ciphertext,
        receiver,
        broadcaster_fee,
        sender_viewing_private_key,
    )?;

    let change_note = if change.is_zero() {
        None
    } else {
        let note = Note::new_change(
            receiver.master_public_key,
            token_address,
            change,
            rand_array(),
        );
        let ciphertext = NoteCiphertext::try_from_note(
            &note,
            receiver,
            receiver,
            sender_viewing_private_key,
            NoteOutputType::Change,
        )?;
        outputs.push(note.clone());
        commitment_ciphertext.push(ciphertext);
        Some(note)
    };

    let unshield_output_index = outputs.len();
    let unshield_note = Note::new_unshield(unshield_to, token_address, unshield_amount);
    outputs.push(unshield_note.clone());

    Ok(UnshieldOutputs {
        outputs,
        commitment_ciphertext,
        broadcaster_fee_note,
        unshield_note,
        unshield_output_index,
        change_note,
    })
}

pub(super) fn build_send_outputs(
    token_address: Address,
    send_amount: U256,
    change: U256,
    sender: &AddressData,
    recipient: &AddressData,
    broadcaster_fee: Option<BroadcasterFeeOutput>,
    sender_viewing_private_key: &[u8; 32],
    recipient_output_type: NoteOutputType,
) -> Result<SendOutputs, BuildError> {
    let mut outputs = Vec::with_capacity(1 + usize::from(broadcaster_fee.is_some()) + 1);
    let mut commitment_ciphertext = Vec::with_capacity(outputs.capacity());
    let broadcaster_fee_note = push_broadcaster_fee_output(
        &mut outputs,
        &mut commitment_ciphertext,
        sender,
        broadcaster_fee,
        sender_viewing_private_key,
    )?;

    let recipient_note = Note::new_change(
        recipient.master_public_key,
        token_address,
        send_amount,
        rand_array(),
    );
    let recipient_ciphertext = NoteCiphertext::try_from_note(
        &recipient_note,
        sender,
        recipient,
        sender_viewing_private_key,
        recipient_output_type,
    )?;
    outputs.push(recipient_note.clone());
    commitment_ciphertext.push(recipient_ciphertext);

    let change_note = if change.is_zero() {
        None
    } else {
        let note = Note::new_change(
            sender.master_public_key,
            token_address,
            change,
            rand_array(),
        );
        let ciphertext = NoteCiphertext::try_from_note(
            &note,
            sender,
            sender,
            sender_viewing_private_key,
            NoteOutputType::Change,
        )?;
        outputs.push(note.clone());
        commitment_ciphertext.push(ciphertext);
        Some(note)
    };

    Ok(SendOutputs {
        outputs,
        commitment_ciphertext,
        broadcaster_fee_note,
        recipient_note,
        change_note,
    })
}
