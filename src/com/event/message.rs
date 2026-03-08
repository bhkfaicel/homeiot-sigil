use bincode::{Decode, Encode};

/// Time unit for vibration count time windows
#[derive(Encode, Decode, Debug, Clone, Copy, PartialEq)]
pub enum TimeUnit {
    /// Seconds
    Seconds = 0,
    /// Minutes
    Minutes = 1,
    /// Hours
    Hours = 2,
}

/// Defines the possible event types.
#[derive(Encode, Decode, Debug, Clone, Copy, PartialEq)]
pub enum EventType {
    IsOpen,
    VibrationCount,
}

/// Represents a strongly-typed event with fixed-size payloads.
#[derive(Encode, Decode, Debug, Clone, Copy, PartialEq)]
pub enum Event {
    /// (1=open, 0=closed)
    IsOpen { value: u8 },

    /// Vibration count in a time window
    /// - `count`: Number of vibrations detected
    /// - `time_window`: Duration of the time window
    /// - `unit`: Time unit (Seconds, Minutes, or Hours)
    VibrationCount {
        count: u16,
        time_window: u16,
        unit: TimeUnit,
        is_open: u8,
    },
}

impl Event {
    /// Creates a new "IsOpen" event (bool → 0/1)
    pub const fn is_open(is_open: bool) -> Self {
        Self::IsOpen {
            value: is_open as u8,
        }
    }

    /// Creates a new "VibrationCount" event with count, time window, and unit
    ///
    /// This event type is used to report the number of vibrations detected
    /// within a specific time window.
    ///
    /// # Arguments
    /// - `count`: Number of vibrations detected in the time window
    /// - `time_window`: Duration of the time window
    /// - `unit`: Time unit (TimeUnit::Seconds, TimeUnit::Minutes, or TimeUnit::Hours)
    ///
    /// # Examples
    /// ```
    /// use sigil::com::event::message::{Event, TimeUnit};
    ///
    /// // 5 vibrations detected in a 5-second window
    /// let event = Event::vibration_count(5, 5, TimeUnit::Seconds, true);
    ///
    /// // 10 vibrations detected in a 1-minute window
    /// let event = Event::vibration_count(10, 1, TimeUnit::Minutes, true);
    ///
    /// // 3 vibrations detected in a 2-hour window
    /// let event = Event::vibration_count(3, 2, TimeUnit::Hours, true);
    /// ```
    ///
    /// # Usage in Firmware
    ///
    /// To implement vibration counting in your firmware, you can use a periodic
    /// task that counts vibrations and sends the count at regular intervals:
    ///
    /// ```ignore
    /// use sigil::com::event::message::{Event, TimeUnit};
    /// use core::sync::atomic::{AtomicU16, Ordering};
    ///
    /// // In your interrupt handler, increment a counter
    /// static VIBRATION_COUNT: AtomicU16 = AtomicU16::new(0);
    ///
    /// // In a periodic task (e.g., every 5 seconds):
    /// let count = VIBRATION_COUNT.swap(0, Ordering::Relaxed);
    /// if count > 0 {
    ///     let event = Event::vibration_count(count, 5, TimeUnit::Seconds, true);
    ///     // Send event via your communication layer
    ///     // send_sensor_event::spawn(event).ok();
    /// }
    /// ```
    pub const fn vibration_count(
        count: u16,
        time_window: u16,
        unit: TimeUnit,
        is_open: bool,
    ) -> Self {
        Self::VibrationCount {
            count,
            time_window,
            unit,
            is_open: is_open as u8,
        }
    }
    /// Returns the associated event type.
    pub const fn event_type(&self) -> EventType {
        match self {
            Self::IsOpen { .. } => EventType::IsOpen,
            Self::VibrationCount { .. } => EventType::VibrationCount,
        }
    }
}
