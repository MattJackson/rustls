use alloc::sync::Arc;
use core::num::NonZeroUsize;

use crate::msgs::codec::{Codec, Encoder, LengthPrefixedBuffer, ListLength};
use crate::output_storage::{OutputStorage, OutputStorageLimits, OutputStoragePlan};

fn plan(records: usize, ciphertext: usize, serialization: usize) -> OutputStoragePlan {
    OutputStoragePlan::new(OutputStorageLimits {
        pending_records: NonZeroUsize::new(records).unwrap(),
        ciphertext_bytes: NonZeroUsize::new(ciphertext).unwrap(),
        serialization_bytes: NonZeroUsize::new(serialization).unwrap(),
    })
    .unwrap()
}

#[test]
fn quote_rejects_layout_overflow_before_allocating() {
    assert!(OutputStoragePlan::new(OutputStorageLimits {
        pending_records: NonZeroUsize::new(usize::MAX).unwrap(),
        ciphertext_bytes: NonZeroUsize::new(1).unwrap(),
        serialization_bytes: NonZeroUsize::new(1).unwrap(),
    }).is_err());
}

#[test]
fn partial_record_retains_full_capacity_and_slot() {
    let storage = OutputStorage::new(plan(1, 32, 32));
    let mut chunk = storage.record(32).unwrap();
    chunk.extend_from_slice(&[7; 32]);
    chunk.truncate(1);
    assert!(storage.record(1).is_err());
    drop(chunk);
    assert!(storage.record(32).is_ok());
}

#[test]
fn serialization_alias_keeps_backing_reserved_until_final_drop() {
    let storage = OutputStorage::new(plan(2, 64, 16));
    let owner = Arc::new(storage.serialization(16).unwrap());
    let alias = owner.clone();
    drop(owner);
    assert!(storage.serialization(1).is_err());
    drop(alias);
    assert!(storage.serialization(16).is_ok());
}

#[test]
fn replacement_must_fund_old_and_new_backing_together() {
    let storage = OutputStorage::new(plan(2, 64, 24));
    let old = storage.serialization(16).unwrap();
    assert!(storage.serialization(16).is_err());
    drop(old);
    assert!(storage.serialization(24).is_ok());
}

#[test]
fn counting_and_bounded_sink_share_wire_recipe() {
    fn recipe(out: &mut dyn Encoder) {
        7u8.encode(out);
        let nested = LengthPrefixedBuffer::new(ListLength::U16, out);
        0x1234u16.encode(nested.buf);
        nested.buf.extend_from_slice(b"payload");
    }
    let mut count = crate::msgs::codec::CountingEncoder::default();
    recipe(&mut count);
    let size = count.finish().unwrap();
    let storage = OutputStorage::new(plan(2, 64, size));
    let mut bounded = storage.serialization(size).unwrap();
    recipe(&mut bounded);
    bounded.finish_encoding(size).unwrap();
    assert_eq!(bounded.as_ref(), b"\x07\x00\x09\x12\x34payload");
}

#[test]
fn bounded_sink_never_grows_on_overrun_or_bad_backpatch() {
    let storage = OutputStorage::new(plan(2, 64, 8));
    let mut bounded = storage.serialization(8).unwrap();
    bounded.extend_from_slice(&[0; 9]);
    assert!(bounded.finish_encoding(9).is_err());
    assert_eq!(bounded.requested_capacity(), 8);
    let mut count = crate::msgs::codec::CountingEncoder::default();
    count.overwrite(1, &[1]);
    assert!(count.finish().is_err());
}
