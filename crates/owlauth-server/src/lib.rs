#![forbid(unsafe_code)]

//! `OwlAuth` server composition, persistence, and isolated HTTP planes.

mod adapters;
mod composition;
pub mod config;
mod http;
mod web_assets;

pub use composition::{ServerError, run};
