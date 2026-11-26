use alloy::primitives::Address;
use alloy::signers::local::PrivateKeySigner;
use coins_bip32::{ecdsa::SigningKey, xkeys::XPriv};
use railgun_wallet::keys::{KeyError, derive_executor_signer};
use serde::Deserialize;

#[derive(Deserialize)]
struct Fixtures {
    mnemonic: String,
    derivations: Vec<Derivation>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Derivation {
    wallet_index: u32,
    chain_id: u64,
    index: u32,
    passphrase: String,
    address: Address,
}

#[test]
fn executor_derivation_matches_sdk_with_passphrases_and_separate_account_namespace() {
    let fixture: Fixtures =
        serde_json::from_str(include_str!("../../core/tests/fixtures/executor.json"))
            .expect("public SDK fixtures");
    let mnemonic = bip39::Mnemonic::parse(&fixture.mnemonic).expect("public mnemonic");
    for vector in fixture.derivations {
        let seed = mnemonic.to_seed(&vector.passphrase);
        let signer =
            derive_executor_signer(&seed, vector.wallet_index, vector.chain_id, vector.index)
                .expect("executor signer");
        assert_eq!(signer.address(), vector.address);
        let ordinary = XPriv::root_from_seed(&seed, None)
            .and_then(|root| root.derive_path(format!("m/44'/60'/0'/0/{}", vector.index).as_str()))
            .expect("ordinary path");
        let ordinary: &SigningKey = ordinary.as_ref();
        let ordinary = PrivateKeySigner::from_signing_key(ordinary.clone());
        assert_ne!(signer.address(), ordinary.address());
    }
    let seed = mnemonic.to_seed("");
    for (wallet_index, chain_id, index) in [
        (1 << 31, 1, 0),
        (0, 1 << 31, 0),
        (0, 1, 1 << 31),
        (0, u64::MAX, 0),
    ] {
        assert!(matches!(
            derive_executor_signer(&seed, wallet_index, chain_id, index),
            Err(KeyError::InvalidPath)
        ));
    }
}
