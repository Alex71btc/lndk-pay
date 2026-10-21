#![allow(clippy::large_enum_variant)]
#![allow(clippy::doc_lazy_continuation)]
/// This is part of public interface so it's re-exported.
pub extern crate tonic;

mod client;
mod error;
mod protos;
mod tls;
pub use client::*;
pub use error::*;
pub use protos::*;
