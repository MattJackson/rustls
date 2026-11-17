//! Provider capability for outgoing ticket bytes within the existing connection H account.

use core::fmt;
use zeroize::Zeroize;

use crate::OutputStorageError;
use crate::msgs::codec::Encoder;
use crate::output_storage::{OutputBuffer, OutputStorage};

/// Borrowed authority to allocate ticket output/scratch from the connection's prepaid H budget.
///
/// Providers must use this for every separate output/scratch backing in a bounded operation.
/// Neither this capability nor resulting buffers may escape into a shared provider/cache.
pub struct TicketStorage<'a> {
    storage: &'a OutputStorage,
}

impl<'a> TicketStorage<'a> {
    pub(crate) fn new(storage: &'a OutputStorage) -> Self {
        Self { storage }
    }

    /// Reserve the full requested backing before allocating. Length starts at zero.
    pub fn allocate(&self, requested_bytes: usize) -> Result<TicketBuffer, OutputStorageError> {
        if let Some(error) = self.storage.error() {
            return Err(error);
        }
        self.storage
            .serialization(requested_bytes)
            .map(TicketBuffer)
            .map_err(|error| self.fail(error))
    }

    /// Retain a separately funded copy of bytes emitted in a ticket/reoffer.
    pub fn copy(&self, bytes: &[u8]) -> Result<TicketBuffer, OutputStorageError> {
        let mut out = self.allocate(bytes.len())?;
        out.extend_from_slice(bytes)?;
        Ok(out)
    }

    pub(crate) fn encode(
        &self,
        recipe: impl Fn(&mut dyn Encoder),
    ) -> Result<TicketBuffer, OutputStorageError> {
        self.storage
            .encode(recipe)
            .map(TicketBuffer)
            .map_err(|error| self.fail(error))
    }

    pub(crate) fn fail(&self, error: OutputStorageError) -> OutputStorageError {
        self.storage.fault(error);
        error
    }
}

/// Move-only ticket backing. All initialized bytes are wiped before backing and funding retire.
///
/// Mutable slices cannot grow it. The infallible backend `Extend` adapter latches overflow;
/// providers must call [`Self::check_len`] after such an operation, including on backend error.
pub struct TicketBuffer(OutputBuffer);

impl TicketBuffer {
    /// Append within the original requested allocation, without implicit growth.
    pub fn extend_from_slice(&mut self, bytes: &[u8]) -> Result<(), OutputStorageError> {
        let expected = self
            .0
            .len()
            .checked_add(bytes.len())
            .ok_or_else(|| {
                self.0
                    .latch_error(OutputStorageError::Integrity);
                OutputStorageError::Integrity
            })?;
        self.0.extend_from_slice(bytes);
        self.check_len(expected)
    }

    /// Check the exact encoded length and any latched infallible-adapter error before publication.
    pub fn check_len(&self, expected: usize) -> Result<(), OutputStorageError> {
        self.0
            .finish_encoding(expected)
            .map_err(|error| {
                self.0.latch_error(error);
                error
            })
    }

    /// Full requested capacity, unchanged by a shorter current length.
    pub fn requested_capacity(&self) -> usize {
        self.0.requested_capacity()
    }
}

impl AsRef<[u8]> for TicketBuffer {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}
impl AsMut<[u8]> for TicketBuffer {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}
impl<'a> Extend<&'a u8> for TicketBuffer {
    fn extend<T: IntoIterator<Item = &'a u8>>(&mut self, iter: T) {
        for byte in iter {
            self.0.push(*byte);
        }
    }
}
impl Drop for TicketBuffer {
    fn drop(&mut self) {
        self.as_mut().zeroize();
    }
}
impl fmt::Debug for TicketBuffer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TicketBuffer")
            .field("len", &self.as_ref().len())
            .finish_non_exhaustive()
    }
}
