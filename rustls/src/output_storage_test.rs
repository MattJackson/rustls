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
    assert!(
        OutputStoragePlan::new(OutputStorageLimits {
            pending_records: NonZeroUsize::new(usize::MAX).unwrap(),
            ciphertext_bytes: NonZeroUsize::new(1).unwrap(),
            serialization_bytes: NonZeroUsize::new(1).unwrap(),
        })
        .is_err()
    );
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

#[test]
fn counting_refuses_truncated_protocol_lengths_before_allocating_output() {
    use crate::msgs::base::{MaybeEmpty, PayloadU8, PayloadU16};

    let mut count = crate::msgs::codec::CountingEncoder::default();
    PayloadU8::<MaybeEmpty>::new(alloc::vec![0; 256]).encode(&mut count);
    assert!(count.finish().is_err());
    let mut count = crate::msgs::codec::CountingEncoder::default();
    PayloadU16::<MaybeEmpty>::new(alloc::vec![0; 65536]).encode(&mut count);
    assert!(count.finish().is_err());
    let mut count = crate::msgs::codec::CountingEncoder::default();
    crate::msgs::codec::u24(0x0100_0000).encode(&mut count);
    assert!(count.finish().is_err());
}

#[test]
fn ticket_extend_overflow_is_sticky_and_never_publishes_success() {
    let account = OutputStorage::new(plan(1, 1, 8));
    let storage = crate::TicketStorage::new(&account);
    let mut ticket = storage.allocate(8).unwrap();
    ticket.extend(&[1; 9]);
    assert!(matches!(ticket.check_len(9), Err(crate::OutputStorageError::Integrity)));
    assert_eq!(ticket.requested_capacity(), 8);
    assert_eq!(account.error(), Some(crate::OutputStorageError::Integrity));
    assert_eq!(account.allocation_attempts(), 1);
    assert!(storage.allocate(1).is_err());
    assert_eq!(account.allocation_attempts(), 1);
}

#[test]
fn client_ticket_payload_alias_keeps_one_funded_backing() {
    let account = OutputStorage::new(plan(1, 1, 8));
    let ticket = crate::TicketStorage::new(&account).copy(b"identity").unwrap();
    let payload = crate::msgs::message::EncodedPayload::ticket(ticket);
    let alias = payload.clone();
    drop(payload);
    assert!(account.serialization(1).is_err());
    assert_eq!(alias.bytes(), b"identity");
    assert_eq!(account.allocation_attempts(), 1);
    drop(alias);
    assert!(account.serialization(8).is_ok());
}

#[test]
fn denied_ticket_copy_never_attempts_backing_allocation() {
    let account = OutputStorage::new(plan(1, 1, 8));
    let held = account.serialization(8).unwrap();
    let before = account.allocation_attempts();
    assert!(crate::TicketStorage::new(&account).copy(b"x").is_err());
    assert_eq!(account.allocation_attempts(), before);
    drop(held);
    assert!(account.serialization(8).is_ok());
}
