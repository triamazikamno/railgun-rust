use super::*;
use crate::wallet::DbStore;

pub(in crate::wallet) fn apply_wallet_delta_to_vec(
    cfg: &WalletConfig,
    wallet_utxos: &mut Vec<WalletUtxo>,
    delta: WalletLogDelta,
) -> bool {
    apply_wallet_delta_to_vec_with_outcome(cfg, wallet_utxos, delta).changed
}

pub(in crate::wallet) fn discard_pending_output_poi_contexts_for_spent_outputs(
    db: &DbStore,
    chain_id: u64,
    wallet_id: &str,
    spent_output_commitments: &[FixedBytes<32>],
) -> Result<usize, local_db::DbError> {
    let mut discarded = 0;
    for output_commitment in spent_output_commitments {
        db.delete_pending_output_poi_context(chain_id, wallet_id, output_commitment)?;
        discarded += 1;
    }
    Ok(discarded)
}
