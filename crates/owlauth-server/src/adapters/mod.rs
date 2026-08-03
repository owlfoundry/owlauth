pub(crate) mod migrations;
#[cfg(test)]
mod migrations_checksum_tests;
pub(crate) mod oidc;
pub(crate) mod postgres;
pub(crate) mod redis_admission;
pub(crate) mod runtime_security;
#[allow(
    dead_code,
    reason = "SMTP transport is composed with the Runtime mail worker"
)]
pub(crate) mod smtp;
pub(crate) mod software_store;
pub(crate) mod system;
