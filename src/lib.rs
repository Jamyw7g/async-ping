pub mod error;
pub mod packet;
pub mod ping;

#[allow(dead_code)]
mod socket;
#[allow(dead_code)]
#[cfg(unix)]
#[path = "sys/unix.rs"]
mod sys;

pub use error::Result;
