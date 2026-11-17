//! Optional buffered-output provenance. No ciphertext or key material is retained here.

use alloc::collections::VecDeque;
use core::fmt;
use core::ops::Range;

/// Finite metadata capacity for a buffered connection's pending application records.
#[derive(Clone, Copy, Debug)]
pub struct WriteTrackingLimits {
    /// Maximum simultaneously pending application-record descriptors. Must be nonzero.
    pub max_pending_records: usize,
}

/// Monotone output frontiers, relative to enabling tracking after the handshake.
///
/// `written_plaintext` observes successful writes to the writer supplied to `write_tls`.
/// It proves socket progress only when that writer is itself an unbuffered socket carrier.
/// It never proves receipt or authentication by the peer.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WriteProgress {
    /// Application bytes accepted and encrypted, including a valid prefix before a fault.
    pub accepted_plaintext: u64,
    /// Application bytes whose corresponding ciphertext has been successfully written.
    pub written_plaintext: u64,
    /// Application bytes whose entire records, including authentication tags, were written.
    /// Successful flushing of the supplied writer is a separate caller obligation.
    pub complete_records_plaintext: u64,
    /// A permanent local failure. No subsequent application acceptance or drain is allowed.
    pub fault: Option<WriteTrackingFault>,
}

/// A permanent failure of a tracked buffered connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WriteTrackingFault {
    /// A finite capacity or checked offset was exhausted.
    Limit,
    /// Mapping, sequence, or raw-writer invariants were violated.
    Integrity,
    /// The supplied writer returned zero for a nonempty ciphertext offer.
    WriteZero,
    /// The crypto provider could not encrypt a record.
    Encryption,
    /// The active provider does not supply positional plaintext provenance.
    Unsupported,
    /// The supplied writer failed (excluding retryable interruption or WouldBlock).
    Io,
}

impl fmt::Display for WriteTrackingFault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TLS write tracking failed: {self:?}")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for WriteTrackingFault {}

impl WriteTrackingFault {
    #[cfg(feature = "std")]
    pub(crate) fn io_error(self) -> std::io::Error {
        let kind = match self {
            Self::WriteZero => std::io::ErrorKind::WriteZero,
            Self::Unsupported => std::io::ErrorKind::Unsupported,
            Self::Io => std::io::ErrorKind::Other,
            _ => std::io::ErrorKind::InvalidData,
        };
        std::io::Error::new(kind, self)
    }
}

/// Why tracking could not be enabled before application output.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WriteTrackingError {
    /// Tracking was already enabled or application output has already been accepted.
    AlreadyStarted,
    /// The connection has not finished its handshake, or uses an incompatible mode.
    IncompatibleState,
    /// The finite metadata allocation or finite output-buffer requirement could not be met.
    Capacity,
}

impl fmt::Display for WriteTrackingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "cannot enable TLS write tracking: {self:?}")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for WriteTrackingError {}

struct Record {
    logical: Range<u64>,
    ciphertext: Range<u64>,
    end: u64,
}

pub(crate) fn descriptor_layout(
    records: usize,
) -> Result<usize, crate::output_storage::OutputStorageError> {
    alloc::alloc::Layout::array::<Record>(records)
        .map(|layout| layout.size())
        .map_err(|_| crate::output_storage::OutputStorageError::Limit)
}

pub(crate) struct WriteTracker {
    records: VecDeque<Record>,
    capacity: usize,
    queued: u64,
    consumed: u64,
    progress: WriteProgress,
}

impl WriteTracker {
    pub(crate) fn reset_baseline(&mut self, pending: usize) -> Result<(), WriteTrackingError> {
        if !self.records.is_empty() {
            return Err(WriteTrackingError::AlreadyStarted);
        }
        self.queued = u64::try_from(pending).map_err(|_| WriteTrackingError::Capacity)?;
        self.consumed = 0;
        self.progress = WriteProgress::default();
        Ok(())
    }
    pub(crate) fn new(
        limits: WriteTrackingLimits,
        pending: usize,
    ) -> Result<Self, WriteTrackingError> {
        if limits.max_pending_records == 0 {
            return Err(WriteTrackingError::Capacity);
        }
        let mut records = VecDeque::new();
        records
            .try_reserve_exact(limits.max_pending_records)
            .map_err(|_| WriteTrackingError::Capacity)?;
        Ok(Self {
            records,
            capacity: limits.max_pending_records,
            queued: u64::try_from(pending).map_err(|_| WriteTrackingError::Capacity)?,
            consumed: 0,
            progress: WriteProgress::default(),
        })
    }

    pub(crate) fn progress(&self) -> WriteProgress {
        self.progress
    }

    pub(crate) fn fault(&mut self, fault: WriteTrackingFault) {
        self.progress.fault.get_or_insert(fault);
    }

    pub(crate) fn has_capacity(&self) -> bool {
        self.records.len() < self.capacity
    }

    /// Commit descriptor and byte offsets before the already-encoded record is appended.
    pub(crate) fn enqueue(
        &mut self,
        encoded_len: usize,
        application: Option<Range<usize>>,
    ) -> Result<(), WriteTrackingFault> {
        if self.consumed > self.queued
            || self
                .records
                .back()
                .is_some_and(|record| {
                    record.logical.end != self.progress.accepted_plaintext
                        || record.ciphertext.end > record.end
                        || record.end > self.queued
                })
        {
            return Err(WriteTrackingFault::Integrity);
        }
        let encoded_len = u64::try_from(encoded_len).map_err(|_| WriteTrackingFault::Limit)?;
        let end = self
            .queued
            .checked_add(encoded_len)
            .ok_or(WriteTrackingFault::Limit)?;
        if let Some(range) = application {
            let range_start = u64::try_from(range.start).map_err(|_| WriteTrackingFault::Limit)?;
            let range_end = u64::try_from(range.end).map_err(|_| WriteTrackingFault::Limit)?;
            if !self.has_capacity() || range_start > range_end || range_end > encoded_len {
                return Err(WriteTrackingFault::Integrity);
            }
            let len = u64::try_from(range.len()).map_err(|_| WriteTrackingFault::Limit)?;
            let logical_start = self.progress.accepted_plaintext;
            let logical_end = logical_start
                .checked_add(len)
                .ok_or(WriteTrackingFault::Limit)?;
            let start = self
                .queued
                .checked_add(range_start)
                .ok_or(WriteTrackingFault::Limit)?;
            let stop = start
                .checked_add(len)
                .ok_or(WriteTrackingFault::Limit)?;
            self.records.push_back(Record {
                logical: logical_start..logical_end,
                ciphertext: start..stop,
                end,
            });
            self.progress.accepted_plaintext = logical_end;
        }
        self.queued = end;
        Ok(())
    }

    #[cfg(feature = "std")]
    pub(crate) fn consume(&mut self, count: usize) -> Result<(), WriteTrackingFault> {
        let count = u64::try_from(count).map_err(|_| WriteTrackingFault::Limit)?;
        let end = self
            .consumed
            .checked_add(count)
            .ok_or(WriteTrackingFault::Limit)?;
        if end > self.queued {
            return Err(WriteTrackingFault::Integrity);
        }
        self.consumed = end;
        while let Some(record) = self.records.front() {
            let written = end
                .saturating_sub(record.ciphertext.start)
                .min(record.ciphertext.end - record.ciphertext.start);
            self.progress.written_plaintext = self
                .progress
                .written_plaintext
                .max(record.logical.start + written);
            if end < record.end {
                break;
            }
            self.progress.complete_records_plaintext = record.logical.end;
            self.records.pop_front();
        }
        Ok(())
    }
}
