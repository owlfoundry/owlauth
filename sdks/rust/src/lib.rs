#![forbid(unsafe_code)]

//! Async, storage-free Project Auth protocol client for `OwlAuth` Runtime.

/// Effective package version compiled into this crate.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

mod client;
mod error;
mod models;
mod transport;

pub use client::{CancellationToken, Client, ClientConfig, Clock, EntropySource, OperationOptions};
pub use error::{Error, ErrorCategory, LocalAction, RetryPolicy};
pub use models::{
    AccessToken, BrowserLogoutPreparation, CredentialPair, CredentialPairRecord, CurrentUser,
    JwksDocument, LoginStart, PendingLogin, PendingLoginRecord, PublicConfiguration, PublicJwk,
    PublicProvider, RefreshToken, UserProjection, ValidatedCallback,
};
pub use transport::{
    HttpMethod, HttpRequest, HttpResponse, Transport, TransportFailure, TransportFailureKind,
};

pub(crate) use models::{
    CompletionResponse, CredentialPairWire, HandoffGuard, HandoffRequest, LoginStartRequest,
    LoginStartResponse, RefreshRequest, RuntimeErrorWire,
};
