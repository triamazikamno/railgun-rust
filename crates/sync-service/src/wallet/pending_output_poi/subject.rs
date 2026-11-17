//! A pending output's subject: its submit identity, and whether a wallet UTXO
//! or the current wallet state still matches it.

use super::{
    ExpectedWalletOutput, FixedBytes, PendingOutputPoiContextRecord, PendingOutputPoiObservation,
    PendingOutputPoiRole, PendingOutputPoiSubject, UtxoPoiMetadata, WalletConfig,
    WalletPrivateMutationAuthority, WalletUtxo,
};

pub(in crate::wallet) struct PendingOutputPoiSubmitIdentity {
    pub(in crate::wallet) derived_blinded_commitment: FixedBytes<32>,
}

pub(in crate::wallet) fn pending_output_poi_submit_identity(
    record: &PendingOutputPoiContextRecord,
    observation: &PendingOutputPoiObservation,
) -> Option<PendingOutputPoiSubmitIdentity> {
    let output_tree = u32::try_from(observation.output_tree).ok()?;
    record.txid_leaf_hash()?;
    Some(PendingOutputPoiSubmitIdentity {
        derived_blinded_commitment: UtxoPoiMetadata::blinded_commitment_for(
            record.output_commitment,
            record.output_npk,
            output_tree,
            observation.output_position,
        ),
    })
}

pub(in crate::wallet) fn pending_output_poi_context_matches_wallet_utxo(
    cfg: &WalletConfig,
    wallet_utxo: &WalletUtxo,
    record: &PendingOutputPoiContextRecord,
) -> bool {
    if !record_in_wallet_scope(cfg, record)
        || record.output_commitment != wallet_utxo.utxo.poi.commitment
    {
        return false;
    }
    let Some(observation) = record.observation.as_ref() else {
        return false;
    };
    if !observation_matches_wallet_utxo(observation, wallet_utxo) {
        return false;
    }
    pending_output_poi_submit_identity(record, observation).is_some_and(|identity| {
        identity.derived_blinded_commitment == wallet_utxo.utxo.poi.blinded_commitment
    })
}

pub(super) enum PendingOutputPoiSubjectMatch {
    Owned(Box<WalletUtxo>),
    External,
}

impl PendingOutputPoiSubjectMatch {
    pub(super) const fn poi(&self) -> Option<&UtxoPoiMetadata> {
        match self {
            Self::Owned(output) => Some(&output.utxo.poi),
            Self::External => None,
        }
    }
}

pub(super) fn pending_output_poi_subject_matches_snapshot(
    cfg: &WalletConfig,
    snapshot: &[WalletUtxo],
    record: &PendingOutputPoiContextRecord,
    subject: &PendingOutputPoiSubject,
) -> Option<PendingOutputPoiSubjectMatch> {
    if !record_in_wallet_scope(cfg, record) {
        return None;
    }
    let observation = record.observation.as_ref()?;
    let identity = pending_output_poi_submit_identity(record, observation)?;
    match subject {
        PendingOutputPoiSubject::Owned(expected_output) => snapshot
            .iter()
            .find(|output| {
                expected_output.matches(output)
                    && pending_output_poi_context_matches_wallet_utxo(cfg, output, record)
            })
            .cloned()
            .map(Box::new)
            .map(PendingOutputPoiSubjectMatch::Owned),
        PendingOutputPoiSubject::External {
            output_commitment,
            derived_blinded_commitment,
        } => {
            if !has_external_output_role(record) || record.output_commitment != *output_commitment {
                return None;
            }
            if identity.derived_blinded_commitment != *derived_blinded_commitment
                || snapshot_has_unspent_commitment(snapshot, record.output_commitment)
            {
                return None;
            }
            Some(PendingOutputPoiSubjectMatch::External)
        }
    }
}

pub(in crate::wallet) async fn current_pending_output_poi_subject(
    authority: &WalletPrivateMutationAuthority<'_>,
    cfg: &WalletConfig,
    record: &PendingOutputPoiContextRecord,
) -> Option<(PendingOutputPoiSubject, Option<WalletUtxo>)> {
    if authority.revalidate().is_err() {
        return None;
    }
    if !authority_in_wallet_scope(authority, cfg) || !record_in_wallet_scope(cfg, record) {
        return None;
    }
    let observation = record.observation.as_ref()?;
    let identity = pending_output_poi_submit_identity(record, observation)?;
    let snapshot = authority.wallet_utxos().await.ok()?;
    let matching_output = snapshot.iter().find(|output| {
        !output.is_spent() && pending_output_poi_context_matches_wallet_utxo(cfg, output, record)
    });
    let result = if let Some(output) = matching_output {
        (
            PendingOutputPoiSubject::Owned(ExpectedWalletOutput::new(output)),
            Some(output.clone()),
        )
    } else {
        if !has_external_output_role(record)
            || snapshot_has_unspent_commitment(&snapshot, record.output_commitment)
        {
            return None;
        }
        (
            PendingOutputPoiSubject::External {
                output_commitment: record.output_commitment,
                derived_blinded_commitment: identity.derived_blinded_commitment,
            },
            None,
        )
    };
    authority.revalidate().is_ok().then_some(result)
}

/// Whether the record belongs to this wallet on this chain.
fn record_in_wallet_scope(cfg: &WalletConfig, record: &PendingOutputPoiContextRecord) -> bool {
    record.chain_id == cfg.chain.chain_id && record.wallet_id == cfg.cache_key.as_str()
}

/// Whether the authority acts for this wallet on this chain.
fn authority_in_wallet_scope(
    authority: &WalletPrivateMutationAuthority<'_>,
    cfg: &WalletConfig,
) -> bool {
    authority.chain_id() == cfg.chain.chain_id && authority.wallet_id() == &cfg.cache_key
}

/// Whether the observation saw this UTXO's tree position in its transaction.
fn observation_matches_wallet_utxo(
    observation: &PendingOutputPoiObservation,
    wallet_utxo: &WalletUtxo,
) -> bool {
    observation.output_tree == u64::from(wallet_utxo.utxo.tree)
        && observation.output_position == wallet_utxo.utxo.position
        && observation.tx_hash == wallet_utxo.utxo.source.tx_hash
}

/// Whether the output goes to someone else, so its subject can be external.
const fn has_external_output_role(record: &PendingOutputPoiContextRecord) -> bool {
    matches!(
        record.output_role,
        PendingOutputPoiRole::Recipient
            | PendingOutputPoiRole::BroadcasterFee
            | PendingOutputPoiRole::RecoveredOutgoing
    )
}

/// Whether an unspent wallet UTXO carries the commitment.
fn snapshot_has_unspent_commitment(snapshot: &[WalletUtxo], commitment: FixedBytes<32>) -> bool {
    snapshot
        .iter()
        .any(|output| !output.is_spent() && output.utxo.poi.commitment == commitment)
}
