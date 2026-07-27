use std::io::Cursor;
use std::marker::PhantomData;

use poi::cache::POI_EVENTS_PAGE_SIZE;
use serde::de::{self, DeserializeOwned, DeserializeSeed, IgnoredAny, SeqAccess, Visitor};

pub(crate) const POI_RPC_EVENT_PAGE_LIMIT: usize = 8;
pub(crate) const POI_RPC_EVENT_LIMIT: usize =
    POI_RPC_EVENT_PAGE_LIMIT * POI_EVENTS_PAGE_SIZE as usize;
pub(crate) const POI_RPC_LEAF_LIMIT: usize = POI_RPC_EVENT_LIMIT;
pub(crate) const POI_BLOCKED_SHIELD_LIMIT: usize = 16_384;

pub(crate) fn decode_bounded_vec<T>(
    bytes: &[u8],
    limit: usize,
) -> Result<Vec<T>, rmp_serde::decode::Error>
where
    T: DeserializeOwned,
{
    let mut deserializer = rmp_serde::Deserializer::new(Cursor::new(bytes));
    let values = BoundedVecSeed {
        limit,
        marker: PhantomData,
    }
    .deserialize(&mut deserializer)?;
    if deserializer.get_ref().position() != u64::try_from(bytes.len()).unwrap_or(u64::MAX) {
        return Err(rmp_serde::decode::Error::Syntax(
            "trailing bytes after MessagePack value".to_string(),
        ));
    }
    Ok(values)
}

struct BoundedVecSeed<T> {
    limit: usize,
    marker: PhantomData<T>,
}

impl<'de, T> DeserializeSeed<'de> for BoundedVecSeed<T>
where
    T: serde::Deserialize<'de>,
{
    type Value = Vec<T>;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_seq(BoundedVecVisitor {
            limit: self.limit,
            marker: PhantomData,
        })
    }
}

struct BoundedVecVisitor<T> {
    limit: usize,
    marker: PhantomData<T>,
}

impl<'de, T> Visitor<'de> for BoundedVecVisitor<T>
where
    T: serde::Deserialize<'de>,
{
    type Value = Vec<T>;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "a sequence with at most {} entries", self.limit)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        if sequence
            .size_hint()
            .is_some_and(|length| length > self.limit)
        {
            return Err(de::Error::custom(format_args!(
                "sequence entry count exceeds limit {}",
                self.limit
            )));
        }
        let mut values = Vec::with_capacity(sequence.size_hint().unwrap_or(0).min(self.limit));
        while values.len() < self.limit {
            let Some(value) = sequence.next_element()? else {
                return Ok(values);
            };
            values.push(value);
        }
        if sequence.next_element::<IgnoredAny>()?.is_some() {
            return Err(de::Error::custom(format_args!(
                "sequence entry count exceeds limit {}",
                self.limit
            )));
        }
        Ok(values)
    }
}

#[cfg(test)]
mod tests {
    use super::decode_bounded_vec;

    #[test]
    fn bounded_vector_decoder_rejects_declared_count_before_allocation() {
        let encoded = rmp_serde::to_vec_named(&vec![1_u64, 2]).expect("encode vector");

        assert_eq!(
            decode_bounded_vec::<u64>(&encoded, 2).expect("decode bounded vector"),
            vec![1, 2]
        );
        assert!(decode_bounded_vec::<u64>(&encoded, 1).is_err());
    }

    #[test]
    fn bounded_vector_decoder_requires_exact_messagepack_input() {
        let encoded = rmp_serde::to_vec_named(&vec![1_u64, 2]).expect("encode vector");

        for suffix in [&[0xc0_u8][..], &[0xc1_u8][..]] {
            let mut tainted = encoded.clone();
            tainted.extend_from_slice(suffix);
            assert!(decode_bounded_vec::<u64>(&tainted, 2).is_err());
        }
    }
}
