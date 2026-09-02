#![doc = include_str!("../README.md")]
#![doc(html_logo_url = "https://raw.githubusercontent.com/al8n/viewstamp/main/art/logo_72x72.png")]

mod bridge;
mod driver;
mod stream_driver;

pub use driver::CompioQuicDriver;
#[cfg(any(test, vsrr_internal_testkit))]
pub use driver::InboundLoss;
pub use stream_driver::CompioStreamDriver;
pub use viewstamp_driver::{
  BlockLane, Clock, Command, DriverConfig, DriverError, Handle, Reply, SHUTDOWN_DRAIN_DEADLINE,
  ShutdownReport, StorageQuiescence,
};
