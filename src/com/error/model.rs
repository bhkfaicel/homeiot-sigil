use lora::error::model::LoRaError;

#[derive(Debug, PartialEq, Clone)]
pub enum ComError<SpiErr> {
    /// A timeout occurred while waiting for a transmission to complete.
    Timeout,

    /// An SPI bus error occurred.
    ///
    /// This wraps the underlying SPI error type provided by the user.
    Spi(SpiErr),

    /// The detected module version is not supported.
    ///
    /// Contains the raw version value read from the `REG_VERSION` register.
    UnsupportedModule(u8),

    /// A CRC error was detected in the received payload.
    CrcError,

    /// No valid packet was received.
    ///
    /// This typically means the IRQ flags did not indicate `RX_DONE`.
    NoPacket,

    /// The provided buffer was too small to hold the received packet.
    ///
    /// - `required`: Number of bytes required to store the full payload.
    /// - `available`: Size of the provided buffer.
    BufferTooSmall {
        required: usize,
        available: usize,
    },

    /// The message to send exceeds the maximum allowed LoRa payload length.
    ///
    /// - `length`: Actual length of the message.
    /// - `max`: Maximum allowed length (typically 200 bytes).
    MessageTooLong {
        length: usize,
        max: usize,
    },

    /// Compression failed.
    ///
    /// This typically means the buffer size is too small.
    CompressionFailed,
    /// Decompression failed.
    ///
    /// This typically means the buffer size is too small.
    DeCompressionFailed,
    /// Deserialize failed.
    DeserializeFailed,
    /// Wrong destination.
    ///
    /// This typically means the message is not for this receiver.
    WrongDistination,

    /// Init handshake verification failed (sensor or gateway public key/signature invalid).
    VerificationFailed,

    Custom(&'static str),
    Canceled,
}

impl<SpiErr> From<LoRaError<SpiErr>> for ComError<SpiErr> {
    fn from(error: LoRaError<SpiErr>) -> Self {
        match error {
            LoRaError::Timeout => ComError::Timeout,
            LoRaError::Spi(e) => ComError::Spi(e),
            LoRaError::UnsupportedModule(v) => ComError::UnsupportedModule(v),
            LoRaError::CrcError => ComError::CrcError,
            LoRaError::NoPacket => ComError::NoPacket,
            LoRaError::BufferTooSmall {
                required,
                available,
            } => ComError::BufferTooSmall {
                required,
                available,
            },
            LoRaError::MessageTooLong { length, max } => ComError::MessageTooLong { length, max },
            LoRaError::CompressionFailed => ComError::CompressionFailed,
            LoRaError::DeCompressionFailed => ComError::DeCompressionFailed,
            LoRaError::Canceled => ComError::Canceled,
        }
    }
}
