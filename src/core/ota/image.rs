//! Firmware image source for the OTA send half.
//!
//! The gateway host implements this over its artifact store (file on disk,
//! Forgejo release download, ROM section, ...). The engine reads strictly
//! within `[0, len)` and never buffers more than one chunk.

use crate::core::ota::error::OtaError;

/// Random-access view of the firmware image being distributed.
pub trait OtaImageSource {
    /// Total image length in bytes (must match the signed manifest).
    fn len(&self) -> u32;

    /// Always `false` for a real artifact; provided for the
    /// `len_without_is_empty` convention. An empty image cannot pass the
    /// BEGIN geometry gate anyway.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Reads exactly `out.len()` bytes at `offset` into `out`.
    ///
    /// Implementations must fail with [`OtaError::Storage`] on short reads
    /// or I/O faults rather than returning partial data.
    fn read_at(&self, offset: u32, out: &mut [u8]) -> Result<(), OtaError>;
}
