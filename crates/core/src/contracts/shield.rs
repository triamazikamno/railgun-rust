use alloy::primitives::{Address, FixedBytes, U256, Uint, keccak256};
use alloy::sol_types::SolCall;

use crate::contracts::railgun::{
    CommitmentPreimage, ShieldCiphertext, ShieldRequest, TokenData, approveCall, shieldCall,
};
use crate::crypto::aes_gcm::{AesGcmError, encrypt_in_place_16b_iv};
use crate::crypto::shared_key::{SharedKeyError, shared_symmetric_key};
use crate::notes::Note;

use ed25519_dalek::SigningKey;
use getrandom::fill;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ShieldError {
    #[error("random generation failed")]
    RandomFailed,
    #[error("shared key derivation failed: {0}")]
    SharedKey(#[from] SharedKeyError),
    #[error("encryption failed: {0}")]
    Encrypt(#[from] AesGcmError),
    #[error("invalid EVM private key")]
    InvalidPrivateKey,
    #[error("ECDSA signing failed")]
    SigningFailed,
}

/// Railgun fee denominator, `BASIS_POINTS` in `RailgunLogic`.
const FEE_BASIS_POINTS: u64 = 10_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum ShieldFeeError {
    #[error("minimum shielded amount must be nonzero")]
    ZeroMinimum,
    #[error("shield fee must be below 10000 basis points")]
    FeeTooHigh,
    #[error("required shield amount exceeds the uint120 note value")]
    Overflow,
}

/// Smallest amount to shield so the note receives at least `min_net` after the
/// shield fee.
///
/// Railgun's inclusive `getFee` leaves `amount - floor(amount * fee_bp / 10000)`
/// in the note, which rises by at most 1 per unit of `amount`. The smallest
/// sufficient amount is therefore
/// `floor((min_net - 1) * 10000 / (10000 - fee_bp)) + 1`.
///
/// A zero `min_net` is rejected: the result is used as the executor's exact
/// transfer guard, and its transfer helper treats 0 as the full balance.
pub fn min_shield_amount(min_net: U256, fee_bp: U256) -> Result<U256, ShieldFeeError> {
    if min_net.is_zero() {
        return Err(ShieldFeeError::ZeroMinimum);
    }
    let basis = U256::from(FEE_BASIS_POINTS);
    if fee_bp >= basis {
        return Err(ShieldFeeError::FeeTooHigh);
    }
    let amount = (min_net - U256::ONE)
        .checked_mul(basis)
        .ok_or(ShieldFeeError::Overflow)?
        / (basis - fee_bp)
        + U256::ONE;
    if amount.bit_len() > 120 {
        return Err(ShieldFeeError::Overflow);
    }
    Ok(amount)
}

/// Build ABI-encoded calldata for `shield(ShieldRequest[])`.
///
/// `shield_private_key` is the 32-byte key derived from `keccak256(evm_sign("RAILGUN_SHIELD"))`.
pub fn build_shield_calldata(
    master_public_key: U256,
    viewing_public_key: &[u8; 32],
    token_address: Address,
    amount: U256,
    shield_private_key: &[u8; 32],
) -> Result<Vec<u8>, ShieldError> {
    let request = build_shield_request(
        master_public_key,
        viewing_public_key,
        TokenData::erc20(token_address),
        Uint::<120, 2>::from(amount),
        shield_private_key,
    )?;
    Ok(shieldCall {
        _shieldRequests: vec![request],
    }
    .abi_encode())
}

/// Build an encrypted shield request for the supplied protocol token and value.
///
/// Callers select the token standards supported by their execution route. Keeping
/// the typed request also lets them track its commitment before transaction handoff.
pub fn build_shield_request(
    master_public_key: U256,
    viewing_public_key: &[u8; 32],
    token: TokenData,
    value: Uint<120, 2>,
    shield_private_key: &[u8; 32],
) -> Result<ShieldRequest, ShieldError> {
    let mut random = [0u8; 16];
    fill(&mut random).map_err(|_| ShieldError::RandomFailed)?;

    let npk = Note::npk_for(master_public_key, random);

    let preimage = CommitmentPreimage {
        npk: FixedBytes::from(npk.to_be_bytes::<32>()),
        token,
        value,
    };

    let ciphertext = encrypt_shield_random(random, shield_private_key, viewing_public_key)?;

    Ok(ShieldRequest {
        preimage,
        ciphertext,
    })
}

/// Build ABI-encoded calldata for ERC-20 `approve(spender, amount)`.
#[must_use]
pub fn build_approve_calldata(spender: Address, amount: U256) -> Vec<u8> {
    approveCall { spender, amount }.abi_encode()
}

/// Derive `shieldPrivateKey` from an EVM private key.
///
/// Signs the fixed message `"RAILGUN_SHIELD"` using EIP-191 personal sign,
/// then returns `keccak256(signature)`.
pub fn derive_shield_private_key(evm_private_key: &[u8; 32]) -> Result<[u8; 32], ShieldError> {
    let msg = b"RAILGUN_SHIELD";

    // EIP-191 personal sign hash: keccak256("\x19Ethereum Signed Message:\n" + len + msg)
    let prefix = format!("\x19Ethereum Signed Message:\n{}", msg.len());
    let mut hash_input = Vec::with_capacity(prefix.len() + msg.len());
    hash_input.extend_from_slice(prefix.as_bytes());
    hash_input.extend_from_slice(msg);
    let msg_hash = keccak256(&hash_input);

    // secp256k1 ECDSA sign
    let signing_key = k256::ecdsa::SigningKey::from_bytes(evm_private_key.into())
        .map_err(|_| ShieldError::InvalidPrivateKey)?;
    let (signature, recovery_id) = signing_key.sign_prehash_recoverable(msg_hash.as_ref());

    // 65-byte signature: r (32) + s (32) + v (1)
    let mut sig_bytes = [0u8; 65];
    sig_bytes[..64].copy_from_slice(&signature.to_bytes());
    sig_bytes[64] = recovery_id.to_byte() + 27;

    Ok(keccak256(sig_bytes).0)
}

fn encrypt_shield_random(
    random: [u8; 16],
    shield_private_key: &[u8; 32],
    viewing_public_key: &[u8; 32],
) -> Result<ShieldCiphertext, ShieldError> {
    // Derive the ed25519 public key from shield_private_key to use as shieldKey
    let shield_public_key = SigningKey::from_bytes(shield_private_key)
        .verifying_key()
        .to_bytes();

    // Compute shared symmetric key via ECDH
    let shared_key = shared_symmetric_key(shield_private_key, viewing_public_key)?;

    // Encrypt the 16-byte random
    let mut buffer = random;
    let iv_tag = encrypt_in_place_16b_iv(&shared_key, &mut buffer)?;

    // Pack into ShieldCiphertext: encryptedBundle[0] = iv||tag, encryptedBundle[1] = encrypted random (padded), encryptedBundle[2] = zeros
    let mut bundle = [FixedBytes::<32>::ZERO; 3];
    bundle[0] = FixedBytes::from(iv_tag);
    let mut padded_ct = [0u8; 32];
    padded_ct[..16].copy_from_slice(&buffer);
    bundle[1] = FixedBytes::from(padded_ct);
    // bundle[2] stays zero

    Ok(ShieldCiphertext {
        encryptedBundle: bundle,
        shieldKey: FixedBytes::from(shield_public_key),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // Note value left by `RailgunLogic.getFee(amount, true, fee_bp)`.
    fn net(amount: U256, fee_bp: u64) -> U256 {
        amount - amount * U256::from(fee_bp) / U256::from(FEE_BASIS_POINTS)
    }

    fn assert_minimal(amount: U256, min_net: U256, fee_bp: u64) {
        assert!(
            net(amount, fee_bp) >= min_net,
            "{amount} nets below {min_net} at {fee_bp} bp"
        );
        assert!(
            net(amount - U256::ONE, fee_bp) < min_net,
            "{amount} is not minimal for {min_net} at {fee_bp} bp"
        );
    }

    #[test]
    fn min_shield_amount_is_the_smallest_amount_meeting_the_net() {
        assert_eq!(
            min_shield_amount(U256::from(9_975), U256::from(25)),
            Ok(U256::from(9_999))
        );
        assert_minimal(U256::from(9_999), U256::from(9_975), 25);
        for fee_bp in [0, 1, 25, 50, 333, 5_000, 9_999] {
            for min_net in 1..=3_000_u64 {
                let min_net = U256::from(min_net);
                let amount = min_shield_amount(min_net, U256::from(fee_bp)).unwrap();
                assert_minimal(amount, min_net, fee_bp);
            }
        }
    }

    #[test]
    fn min_shield_amount_near_the_note_value_limit() {
        let max = (U256::ONE << 120) - U256::ONE;
        assert_eq!(min_shield_amount(max, U256::ZERO), Ok(max));
        assert_eq!(
            min_shield_amount(max, U256::from(25)),
            Err(ShieldFeeError::Overflow)
        );
        let min_net = net(max, 25);
        let amount = min_shield_amount(min_net, U256::from(25)).unwrap();
        assert!(amount <= max);
        assert_minimal(amount, min_net, 25);
    }

    #[test]
    fn min_shield_amount_rejects_unusable_inputs() {
        assert_eq!(
            min_shield_amount(U256::ZERO, U256::from(25)),
            Err(ShieldFeeError::ZeroMinimum)
        );
        assert_eq!(
            min_shield_amount(U256::ONE, U256::from(FEE_BASIS_POINTS)),
            Err(ShieldFeeError::FeeTooHigh)
        );
        assert_eq!(
            min_shield_amount(U256::MAX, U256::ZERO),
            Err(ShieldFeeError::Overflow)
        );
    }
}
