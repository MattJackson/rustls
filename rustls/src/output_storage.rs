//! Requested-layout bounds for buffered TLS output, installed before the handshake.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::alloc::Layout;
use core::fmt;
use core::num::NonZeroUsize;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicU8, AtomicUsize, Ordering};

use crate::msgs::codec::Encoder;

/// Finite ceilings for all outgoing wire records and serialized handshake staging.
#[derive(Clone, Copy, Debug)]
pub struct OutputStorageLimits {
    /// Queued, pending-KeyUpdate and in-construction records together.
    pub pending_records: NonZeroUsize,
    /// Requested ciphertext allocation bytes, including consumed prefixes.
    pub ciphertext_bytes: NonZeroUsize,
    /// Requested serialized-output allocation bytes, including overlapping replacements.
    pub serialization_bytes: NonZeroUsize,
}

/// A validated dependency-owned quote. The caller must fund it before construction.
#[derive(Clone, Copy, Debug)]
pub struct OutputStoragePlan {
    limits: OutputStorageLimits,
    requested: usize,
}

impl OutputStoragePlan {
    /// Compute the actual private descriptor layouts with checked arithmetic.
    pub fn new(limits: OutputStorageLimits) -> Result<Self, OutputStorageError> {
        let n = limits.pending_records.get();
        let descriptors = crate::write_tracking::descriptor_layout(n)?;
        let chunks = Layout::array::<OutputBuffer>(n)
            .map_err(|_| OutputStorageError::Limit)?
            .size();
        let requested = descriptors
            .checked_add(chunks)
            .and_then(|n| n.checked_add(limits.ciphertext_bytes.get()))
            .and_then(|n| n.checked_add(limits.serialization_bytes.get()))
            .ok_or(OutputStorageError::Limit)?;
        // Individual byte allocations must also be representable by the allocator.
        Layout::array::<u8>(limits.ciphertext_bytes.get())
            .map_err(|_| OutputStorageError::Limit)?;
        Layout::array::<u8>(limits.serialization_bytes.get())
            .map_err(|_| OutputStorageError::Limit)?;
        Ok(Self { limits, requested })
    }

    /// Total prepaid requested backing, excluding allocator overhead and fixed control owners.
    pub fn requested_bytes(&self) -> usize {
        self.requested
    }

    /// The immutable limits used to compute this quote.
    pub fn limits(&self) -> OutputStorageLimits {
        self.limits
    }
}

/// An unsupported outgoing feature in the bounded profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutputStorageFeature {
    /// Allocator-owning certificate compressors have no bounded output contract.
    CertificateCompression,
    /// Shared compression caches can outlive connection funding.
    CertificateCompressionCache,
    /// ECH HPKE output has no bounded allocation contract, including GREASE.
    Ech,
}

/// Failure to satisfy the requested output-storage contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutputStorageError {
    /// A configured capacity, allocator request or checked layout was exhausted.
    Limit,
    /// The encoder or provider violated its preflight contract.
    Integrity,
    /// The configuration enables an unsupported outgoing path.
    UnsupportedConfiguration(OutputStorageFeature),
    /// The active provider cannot construct output within a preallocated buffer.
    UnsupportedProvider,
}

impl fmt::Display for OutputStorageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TLS output storage: {self:?}")
    }
}
#[cfg(feature = "std")]
impl std::error::Error for OutputStorageError {}

impl From<OutputStorageError> for crate::Error {
    fn from(error: OutputStorageError) -> Self {
        Self::OutputStorage(error)
    }
}

pub(crate) fn validate_compression(
    compressors: &[&'static dyn crate::compress::CertCompressor],
    cache: &crate::compress::CompressionCache,
) -> Result<(), OutputStorageError> {
    if !compressors.is_empty() {
        return Err(OutputStorageError::UnsupportedConfiguration(
            OutputStorageFeature::CertificateCompression,
        ));
    }
    if !matches!(cache, crate::compress::CompressionCache::Disabled) {
        return Err(OutputStorageError::UnsupportedConfiguration(
            OutputStorageFeature::CertificateCompressionCache,
        ));
    }
    Ok(())
}

#[derive(Debug)]
struct State {
    plan: OutputStoragePlan,
    records: AtomicUsize,
    ciphertext: AtomicUsize,
    serialization: AtomicUsize,
    fault: AtomicU8,
}

#[derive(Clone, Debug)]
pub(crate) struct OutputStorage(Arc<State>);

impl OutputStorage {
    pub(crate) fn new(plan: OutputStoragePlan) -> Self {
        Self(Arc::new(State {
            plan,
            records: AtomicUsize::new(0),
            ciphertext: AtomicUsize::new(0),
            serialization: AtomicUsize::new(0),
            fault: AtomicU8::new(0),
        }))
    }

    pub(crate) fn plan(&self) -> OutputStoragePlan {
        self.0.plan
    }

    pub(crate) fn fault(&self, error: OutputStorageError) {
        let code = match error {
            OutputStorageError::Limit => 1,
            OutputStorageError::Integrity => 2,
            OutputStorageError::UnsupportedProvider => 3,
            OutputStorageError::UnsupportedConfiguration(
                OutputStorageFeature::CertificateCompression,
            ) => 4,
            OutputStorageError::UnsupportedConfiguration(
                OutputStorageFeature::CertificateCompressionCache,
            ) => 5,
            OutputStorageError::UnsupportedConfiguration(OutputStorageFeature::Ech) => 6,
        };
        let _ = self
            .0
            .fault
            .compare_exchange(0, code, Ordering::AcqRel, Ordering::Acquire);
    }

    pub(crate) fn error(&self) -> Option<OutputStorageError> {
        match self.0.fault.load(Ordering::Acquire) {
            0 => None,
            1 => Some(OutputStorageError::Limit),
            2 => Some(OutputStorageError::Integrity),
            3 => Some(OutputStorageError::UnsupportedProvider),
            4 => Some(OutputStorageError::UnsupportedConfiguration(
                OutputStorageFeature::CertificateCompression,
            )),
            5 => Some(OutputStorageError::UnsupportedConfiguration(
                OutputStorageFeature::CertificateCompressionCache,
            )),
            6 => Some(OutputStorageError::UnsupportedConfiguration(
                OutputStorageFeature::Ech,
            )),
            _ => Some(OutputStorageError::Integrity),
        }
    }

    pub(crate) fn encode(
        &self,
        recipe: impl Fn(&mut dyn Encoder),
    ) -> Result<OutputBuffer, OutputStorageError> {
        if let Some(error) = self.error() {
            return Err(error);
        }
        let mut count = crate::msgs::codec::CountingEncoder::default();
        recipe(&mut count);
        let len = count.finish()?;
        let mut buffer = self.serialization(len)?;
        recipe(&mut buffer);
        buffer.finish_encoding(len)?;
        Ok(buffer)
    }

    pub(crate) fn record(&self, bytes: usize) -> Result<OutputBuffer, OutputStorageError> {
        reserve(&self.0.records, 1, self.0.plan.limits.pending_records.get())?;
        if let Err(error) = reserve(
            &self.0.ciphertext,
            bytes,
            self.0
                .plan
                .limits
                .ciphertext_bytes
                .get(),
        ) {
            self.0
                .records
                .fetch_sub(1, Ordering::AcqRel);
            return Err(error);
        }
        OutputBuffer::allocate(Reservation {
            state: self.0.clone(),
            bytes,
            record: true,
        })
    }

    pub(crate) fn serialization(&self, bytes: usize) -> Result<OutputBuffer, OutputStorageError> {
        reserve(
            &self.0.serialization,
            bytes,
            self.0
                .plan
                .limits
                .serialization_bytes
                .get(),
        )?;
        OutputBuffer::allocate(Reservation {
            state: self.0.clone(),
            bytes,
            record: false,
        })
    }
}

fn reserve(counter: &AtomicUsize, bytes: usize, limit: usize) -> Result<(), OutputStorageError> {
    counter
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |old| {
            old.checked_add(bytes)
                .filter(|&next| next <= limit)
        })
        .map(|_| ())
        .map_err(|_| OutputStorageError::Limit)
}

#[derive(Debug)]
pub(crate) struct Reservation {
    state: Arc<State>,
    bytes: usize,
    record: bool,
}
impl Drop for Reservation {
    fn drop(&mut self) {
        if self.record {
            self.state
                .ciphertext
                .fetch_sub(self.bytes, Ordering::AcqRel);
            self.state
                .records
                .fetch_sub(1, Ordering::AcqRel);
        } else {
            self.state
                .serialization
                .fetch_sub(self.bytes, Ordering::AcqRel);
        }
    }
}

/// Backing drops before its reservation. No growable Vec is exposed in bounded mode.
#[derive(Debug)]
pub(crate) struct OutputBuffer {
    bytes: Vec<u8>,
    reservation: Option<Reservation>,
    error: Option<OutputStorageError>,
}

impl OutputBuffer {
    pub(crate) fn as_slice(&self) -> &[u8] {
        &self.bytes
    }

    pub(crate) fn into_parts(self) -> (Vec<u8>, Option<Reservation>) {
        (self.bytes, self.reservation)
    }

    pub(crate) fn from_parts(bytes: Vec<u8>, reservation: Option<Reservation>) -> Self {
        Self {
            bytes,
            reservation,
            error: None,
        }
    }
    fn allocate(reservation: Reservation) -> Result<Self, OutputStorageError> {
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(reservation.bytes)
            .map_err(|_| OutputStorageError::Limit)?;
        Ok(Self {
            bytes,
            reservation: Some(reservation),
            error: None,
        })
    }

    pub(crate) fn requested_capacity(&self) -> usize {
        self.reservation
            .as_ref()
            .map_or(self.bytes.capacity(), |r| r.bytes)
    }

    pub(crate) fn finish_encoding(&self, expected: usize) -> Result<(), OutputStorageError> {
        if let Some(error) = self.error {
            return Err(error);
        }
        if self.bytes.len() != expected {
            return Err(OutputStorageError::Integrity);
        }
        Ok(())
    }

    pub(crate) fn truncate(&mut self, len: usize) {
        self.bytes.truncate(len);
    }

    pub(crate) fn discard_prefix(&mut self, prefix: usize) {
        self.bytes.copy_within(prefix.., 0);
        self.bytes
            .truncate(self.bytes.len() - prefix);
    }
}

impl From<Vec<u8>> for OutputBuffer {
    fn from(bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            reservation: None,
            error: None,
        }
    }
}
impl Deref for OutputBuffer {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.bytes
    }
}
impl DerefMut for OutputBuffer {
    fn deref_mut(&mut self) -> &mut [u8] {
        &mut self.bytes
    }
}
impl AsRef<[u8]> for OutputBuffer {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl Encoder for OutputBuffer {
    fn len(&self) -> usize {
        self.bytes.len()
    }
    fn extend_from_slice(&mut self, input: &[u8]) {
        if self.error.is_some() {
            return;
        }
        if self.reservation.is_some()
            && self
                .bytes
                .len()
                .checked_add(input.len())
                .map_or(true, |len| len > self.requested_capacity())
        {
            self.error = Some(OutputStorageError::Integrity);
            return;
        }
        self.bytes.extend_from_slice(input);
    }
    fn overwrite(&mut self, offset: usize, input: &[u8]) {
        match offset
            .checked_add(input.len())
            .and_then(|end| self.bytes.get_mut(offset..end))
        {
            Some(out) => out.copy_from_slice(input),
            None => self.fail(),
        }
    }
    fn fail(&mut self) {
        self.error
            .get_or_insert(OutputStorageError::Integrity);
    }
}
