use alloy::primitives::Address;
use alloy::signers::local::MnemonicBuilder;
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
        let ordinary = MnemonicBuilder::english()
            .phrase(fixture.mnemonic.as_str())
            .password(vector.passphrase.as_str())
            .index(vector.index)
            .expect("ordinary path")
            .build()
            .expect("ordinary signer");
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
