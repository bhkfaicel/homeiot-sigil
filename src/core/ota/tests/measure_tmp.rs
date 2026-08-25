extern crate std;

use std::println;

#[test]
fn measure() {
    println!("OtaSender      = {}", size_of::<crate::core::ota::OtaSender>());
    println!("OtaReceiver    = {}", size_of::<crate::core::ota::OtaReceiver>());
    println!("BeginFrame     = {}", size_of::<crate::core::ota::BeginFrame>());
    println!("TrailerRecord  = {}", size_of::<crate::core::ota::trailer::TrailerRecord>());
}
