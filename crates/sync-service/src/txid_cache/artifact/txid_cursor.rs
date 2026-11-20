#[allow(clippy::wildcard_imports)]
use super::*;

impl<'a> PublicTxidCursor<'a> {
    pub(super) const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    const fn is_eof(&self) -> bool {
        self.position == self.bytes.len()
    }

    fn read_row(&mut self) -> Result<TxidPublicCacheRow, TxidPublicCacheError> {
        let txid_index = self.read_u64("txid_index")?;
        let id = self.read_string("id")?;
        let block_number = self.read_u64("block_number")?;
        let block_timestamp = self.read_u64("block_timestamp")?;
        let _block_hash = self.read_fixed_bytes("block_hash")?;
        let transaction_hash = self.read_fixed_bytes("transaction_hash")?;
        let _first_log_index = self.read_u64("first_log_index")?;
        let _last_log_index = self.read_u64("last_log_index")?;
        let nullifiers = self.read_u256_vec("nullifiers")?;
        let commitments = self.read_u256_vec("commitments")?;
        let bound_params_hash = U256::from_be_bytes(self.read_fixed_bytes("bound_params_hash")?);
        let has_unshield = self.read_bool("has_unshield")?;
        let utxo_tree_in = self.read_u64("utxo_tree_in")?;
        let utxo_tree_out = self.read_u64("utxo_tree_out")?;
        let utxo_batch_start_position_out = self.read_u64("utxo_batch_start_position_out")?;
        let railgun_txid = compute_railgun_txid_parts(&nullifiers, &commitments, bound_params_hash);
        let output_start_global = u128::from(utxo_tree_out)
            .saturating_mul(u128::from(TREE_LEAF_COUNT))
            .saturating_add(u128::from(utxo_batch_start_position_out));
        let txid_leaf_hash = FixedBytes::from(
            railgun_txid_leaf_hash_with_output_start(
                railgun_txid,
                utxo_tree_in,
                U256::from(output_start_global),
            )
            .to_be_bytes::<32>(),
        );
        Ok(TxidPublicCacheRow {
            txid_index,
            txid_leaf_hash,
            transaction: TxidPublicCacheTransaction {
                id,
                transaction_hash: FixedBytes::from(transaction_hash),
                block_number,
                block_timestamp,
                nullifiers,
                commitments,
                bound_params_hash,
                has_unshield,
                unshield_preimage: None,
                utxo_tree_in,
                utxo_tree_out,
                utxo_batch_start_position_out,
            },
        })
    }

    pub(super) fn read_rows(
        &mut self,
        expected_start: u64,
        expected_end: u64,
        row_count: u64,
    ) -> Result<Vec<TxidPublicCacheRow>, TxidPublicCacheError> {
        let expected_count = expected_end
            .checked_sub(expected_start)
            .and_then(|count| count.checked_add(1))
            .ok_or_else(|| {
                TxidPublicCacheError::MetadataMismatch(
                    "public_txid artifact range overflow".to_string(),
                )
            })?;
        if row_count != expected_count {
            return Err(TxidPublicCacheError::MetadataMismatch(format!(
                "public_txid artifact row count mismatch: expected {expected_count}, got {row_count}"
            )));
        }
        let mut rows = Vec::new();
        let mut expected_index = expected_start;
        for _ in 0..row_count {
            let row = self.read_row()?;
            if row.txid_index != expected_index {
                return Err(TxidPublicCacheError::MetadataMismatch(format!(
                    "public_txid artifact index gap: expected {expected_index}, got {}",
                    row.txid_index
                )));
            }
            expected_index = expected_index.checked_add(1).ok_or_else(|| {
                TxidPublicCacheError::MetadataMismatch("txid index overflow".to_string())
            })?;
            rows.push(row);
        }
        if rows.last().map(|row| row.txid_index) != Some(expected_end) {
            return Err(TxidPublicCacheError::MetadataMismatch(
                "public_txid artifact range end mismatch".to_string(),
            ));
        }
        if !self.is_eof() {
            return Err(TxidPublicCacheError::MetadataMismatch(
                "public_txid artifact has trailing bytes".to_string(),
            ));
        }
        Ok(rows)
    }

    fn read_u8(&mut self, field: &'static str) -> Result<u8, TxidPublicCacheError> {
        Ok(self.read_exact(1, field)?[0])
    }

    fn read_bool(&mut self, field: &'static str) -> Result<bool, TxidPublicCacheError> {
        match self.read_u8(field)? {
            0 => Ok(false),
            1 => Ok(true),
            other => Err(TxidPublicCacheError::MetadataMismatch(format!(
                "invalid bool byte {other} in {field}"
            ))),
        }
    }

    fn read_u16(&mut self, field: &'static str) -> Result<u16, TxidPublicCacheError> {
        let bytes = self.read_exact(2, field)?;
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
    }

    fn read_u32(&mut self, field: &'static str) -> Result<u32, TxidPublicCacheError> {
        let bytes = self.read_exact(4, field)?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn read_u64(&mut self, field: &'static str) -> Result<u64, TxidPublicCacheError> {
        let bytes = self.read_exact(8, field)?;
        Ok(u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }

    fn read_string(&mut self, field: &'static str) -> Result<String, TxidPublicCacheError> {
        let length = self.read_u16(field)? as usize;
        let bytes = self.read_exact(length, field)?;
        std::str::from_utf8(bytes)
            .map(str::to_string)
            .map_err(|err| {
                TxidPublicCacheError::MetadataMismatch(format!("invalid utf8 in {field}: {err}"))
            })
    }

    fn read_fixed_bytes(&mut self, field: &'static str) -> Result<[u8; 32], TxidPublicCacheError> {
        self.read_exact(32, field)?.try_into().map_err(|_| {
            TxidPublicCacheError::MetadataMismatch(format!("invalid fixed bytes in {field}"))
        })
    }

    fn read_u256_vec(&mut self, field: &'static str) -> Result<Vec<U256>, TxidPublicCacheError> {
        let count = self.read_u32(field)? as usize;
        let byte_count = count.checked_mul(32).ok_or_else(|| {
            TxidPublicCacheError::MetadataMismatch(format!(
                "public_txid artifact {field} byte count overflow"
            ))
        })?;
        if self.bytes.len().saturating_sub(self.position) < byte_count {
            return Err(TxidPublicCacheError::MetadataMismatch(format!(
                "public_txid artifact ended while reading {field}"
            )));
        }
        let mut values = Vec::with_capacity(count);
        for _ in 0..count {
            values.push(U256::from_be_bytes(self.read_fixed_bytes(field)?));
        }
        Ok(values)
    }

    fn read_exact(
        &mut self,
        length: usize,
        field: &'static str,
    ) -> Result<&'a [u8], TxidPublicCacheError> {
        let end = self.position.checked_add(length).ok_or_else(|| {
            TxidPublicCacheError::MetadataMismatch(format!(
                "public_txid artifact overflow in {field}"
            ))
        })?;
        let value = self.bytes.get(self.position..end).ok_or_else(|| {
            TxidPublicCacheError::MetadataMismatch(format!(
                "public_txid artifact ended while reading {field}"
            ))
        })?;
        self.position = end;
        Ok(value)
    }
}

pub(super) fn attach_unshield_preimages(
    payload: &[u8],
    rows: &mut [TxidPublicCacheRow],
) -> Result<(), TxidPublicCacheError> {
    let mut cursor = PublicTxidCursor::new(payload);
    let entry_count = cursor.read_u32("unshield_preimage_count")? as usize;
    if entry_count > rows.len() {
        return Err(TxidPublicCacheError::MetadataMismatch(
            "public_txid unshield preimage count exceeds row count".to_string(),
        ));
    }
    let first_index = rows.first().map(|row| row.txid_index).ok_or_else(|| {
        TxidPublicCacheError::MetadataMismatch(
            "public_txid unshield sidecar cannot target an empty chunk".to_string(),
        )
    })?;
    let mut previous_index = None;
    for _ in 0..entry_count {
        let txid_index = cursor.read_u64("unshield_preimage_txid_index")?;
        if previous_index.is_some_and(|previous| txid_index <= previous) {
            return Err(TxidPublicCacheError::MetadataMismatch(
                "public_txid unshield preimage indexes are not strictly increasing".to_string(),
            ));
        }
        previous_index = Some(txid_index);
        let row_offset = txid_index
            .checked_sub(first_index)
            .and_then(|offset| usize::try_from(offset).ok())
            .ok_or_else(|| {
                TxidPublicCacheError::MetadataMismatch(
                    "public_txid unshield preimage index is outside the chunk".to_string(),
                )
            })?;
        let row = rows
            .get_mut(row_offset)
            .filter(|row| row.txid_index == txid_index)
            .ok_or_else(|| {
                TxidPublicCacheError::MetadataMismatch(
                    "public_txid unshield preimage index is outside the chunk".to_string(),
                )
            })?;
        if !row.transaction.has_unshield {
            return Err(TxidPublicCacheError::MetadataMismatch(
                "public_txid unshield preimage targets a non-unshield row".to_string(),
            ));
        }
        let length = cursor.read_u16("unshield_preimage_length")? as usize;
        let encoded = cursor.read_exact(length, "unshield_preimage")?;
        let preimage = CommitmentPreimage::abi_decode(encoded).map_err(|err| {
            TxidPublicCacheError::MetadataMismatch(format!(
                "invalid public_txid unshield preimage: {err}"
            ))
        })?;
        if preimage.abi_encode() != encoded {
            return Err(TxidPublicCacheError::MetadataMismatch(
                "public_txid unshield preimage is not canonically encoded".to_string(),
            ));
        }
        if row.transaction.commitments.last() != Some(&preimage.hash()) {
            return Err(TxidPublicCacheError::MetadataMismatch(
                "public_txid unshield preimage does not match its commitment".to_string(),
            ));
        }
        row.transaction.unshield_preimage = Some(encoded.to_vec());
    }
    if !cursor.is_eof() {
        return Err(TxidPublicCacheError::MetadataMismatch(
            "public_txid unshield sidecar has trailing bytes".to_string(),
        ));
    }
    if rows
        .iter()
        .any(|row| row.transaction.has_unshield && row.transaction.unshield_preimage.is_none())
    {
        return Err(TxidPublicCacheError::MetadataMismatch(
            "public_txid unshield sidecar is missing an unshield row".to_string(),
        ));
    }
    Ok(())
}
