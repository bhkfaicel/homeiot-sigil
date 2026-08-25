//! Host-implemented storage sink for staged OTA image data.
//!
//! The receive engine sequences all erase/write operations and guarantees
//! the alignment contract documented on [`OtaStorage`]; implementations stay
//! dumb byte-movers over their hardware (SAMD21 NVMCTRL rows in firmware,
//! RAM in tests). All offsets are RELATIVE to the host's staging window
//! base; engines never see absolute addresses.

use crate::core::ota::error::OtaError;

/// Byte sink backing the OTA staging window.
///
/// # Alignment contract
///
/// `erase_range` offsets and lengths are always multiples of
/// [`Self::erase_granularity`] (the engine aligns every call). `write`
/// targets are always inside a range previously erased for THIS transfer,
/// so implementations may assume erased (all-`0xFF`) cells behind `data`.
///
/// # Erase-once contract
///
/// The engine erases each granularity block at most ONCE per transfer
/// session (bitmap bookkeeping), so consecutive chunk writes into the same
/// block arrive WITHOUT a new erase. Implementations must therefore not tie
/// any invariant to "every write is preceded by an immediate erase".
///
/// # Bounds
///
/// The receive engine tracks at most [`MAX_STAGING_BLOCKS`](crate::core::ota::receiver::MAX_STAGING_BLOCKS)
/// blocks per session; transfers whose image would span more are rejected
/// at BEGIN. Keep the reported granularity coarse enough (e.g. 256 B rows)
/// for the intended window size.
pub trait OtaStorage {
    /// Hardware erase granularity in bytes (e.g. 256 for SAMD21 NVM rows).
    fn erase_granularity(&self) -> u32;

    /// Erases `[offset, offset + len)` inside the staging window.
    ///
    /// Both arguments are granularity-aligned by the engine. Implementations
    /// must reject out-of-window ranges with [`OtaError::Storage`] rather
    /// than panicking.
    fn erase_range(&mut self, offset: u32, len: u32) -> Result<(), OtaError>;

    /// Writes `data` at `offset`. The covering range was erased beforehand
    /// by the engine for the current transfer session.
    fn write(&mut self, offset: u32, data: &[u8]) -> Result<(), OtaError>;

    /// Reads back `buf.len()` bytes at `offset` (verification hooks and
    /// tests; not used on the hot chunk path).
    fn read(&mut self, offset: u32, buf: &mut [u8]) -> Result<(), OtaError>;
}
