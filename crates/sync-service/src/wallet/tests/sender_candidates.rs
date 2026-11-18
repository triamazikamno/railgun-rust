use super::*;

/// Seeds a verified TXID artifact bound containing only `txid_transaction`.
async fn seed_single_txid_artifact(
    db: &DbStore,
    cfg: &WalletConfig,
    txid_transaction: IndexedRailgunTransaction,
) {
    let artifact_leaf = txid_transaction.txid_leaf_hash();
    let artifact_root = FixedBytes::from(
        DenseMerkleTree::from_ordered_leaves(vec![artifact_leaf], 1)
            .root()
            .to_be_bytes::<32>(),
    );
    seed_verified_artifact_bound_for_test(
        db,
        TxidPublicCacheKey {
            chain_type: 0,
            chain_id: cfg.chain.chain_id,
            railgun_contract: cfg.chain.contract,
            txid_version: DEFAULT_TXID_VERSION,
        },
        vec![txid_transaction],
        artifact_root,
    )
    .await
    .expect("persist verified sender artifact bound");
}

mod candidate_retirement;
mod public_cache_txid;
mod unshield_submission;
