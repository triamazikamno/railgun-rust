use alloy::primitives::{Bytes, U256};
use broadcaster_core::crypto::railgun::{ShareableViewingKey, ViewingKeyData};

#[test]
fn shareable_viewing_key_preserves_address_for_both_spending_key_signs() {
    // Circomlib's BabyJubJub Base8 point and its negation. Their x-coordinate
    // parity disagrees with the packed sign bit, which denotes the upper half
    // of the field: https://github.com/iden3/circomlibjs/blob/main/src/babyjub.js
    let x = U256::from_str_radix(
        "5299619240641551281634865583518297030282874472190772894086521144482721001553",
        10,
    )
    .expect("Base8 x");
    let y = U256::from_str_radix(
        "16950150798460657717958625567821834550301663161624707787222815936182638968203",
        10,
    )
    .expect("Base8 y");
    let modulus = U256::from_str_radix(
        "21888242871839275222246405745257275088548364400416034343698204186575808495617",
        10,
    )
    .expect("field modulus");
    let viewing_private_key = [42; 32];

    for (sign, spending_x) in [(false, x), (true, modulus - x)] {
        let mut packed = y.to_le_bytes::<32>();
        if sign {
            packed[31] |= 0x80;
        }
        let payload = serde_json::json!({
            "vpriv": alloy::hex::encode(viewing_private_key),
            "spub": alloy::hex::encode(packed),
        });
        let shareable_key = ShareableViewingKey::from(Bytes::from(
            rmp_serde::to_vec_named(&payload).expect("encode shareable key"),
        ));
        let expected =
            ViewingKeyData::from_spending_public_key(viewing_private_key, [spending_x, y]);

        assert_eq!(
            shareable_key.derive_address(None).expect("decoded address"),
            expected.derive_address(None).expect("original address"),
            "packed spending key sign: {sign}",
        );
    }
}
