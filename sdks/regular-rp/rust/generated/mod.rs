//! Generated Rust code from CSIL specification

//! ## Additional dependencies for the consuming crate
//!
//! time = { version = "0.3.47", features = ["formatting", "parsing"] }
//!
pub mod types;
pub use types::*;

#[path = "codec.gen.rs"]
pub mod codec;
pub use codec::*;

pub mod client;
pub use client::*;

pub mod client_async;
pub use client_async::*;
