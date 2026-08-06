#![forbid(unsafe_code)]

//! `OwlAuth` server composition, persistence, and isolated HTTP planes.

mod adapters;
mod application;
mod composition;
pub mod config;
mod domain;
mod http;
mod providers;
mod web_assets;

pub use composition::{SchemaFailure, ServerError, run, run_with_providers};
pub use providers::{ActiveProvider, ProviderCompositionError, ProviderRegistrations};
