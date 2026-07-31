use std::{fmt, sync::Arc, time::Duration};

use async_trait::async_trait;
use reqwest::{Method, redirect::Policy};

use crate::Error;

/// HTTP method used by the narrow Runtime transport.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HttpMethod {
    Get,
    Post,
}

/// Bounded request passed to an injected transport. Debug output redacts body and headers.
#[derive(Clone)]
pub struct HttpRequest {
    pub method: HttpMethod,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<Vec<u8>>,
    pub max_response_bytes: usize,
}

impl fmt::Debug for HttpRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HttpRequest")
            .field("method", &self.method)
            .field("url", &self.url)
            .field("headers", &"[REDACTED]")
            .field("body", &self.body.as_ref().map(std::vec::Vec::len))
            .field("max_response_bytes", &self.max_response_bytes)
            .finish()
    }
}

/// Bounded response returned by a transport.
#[derive(Clone, Eq, PartialEq)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl fmt::Debug for HttpResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HttpResponse")
            .field("status", &self.status)
            .field("headers", &"[ALLOWLISTED]")
            .field(
                "body",
                &format_args!("[REDACTED; {} bytes]", self.body.len()),
            )
            .finish()
    }
}

/// Stable transport failure kind.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransportFailureKind {
    Transport,
    Timeout,
    Cancelled,
    ResponseTooLarge,
}

/// Transport failure with explicit dispatch knowledge for one-use operations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransportFailure {
    pub kind: TransportFailureKind,
    pub dispatched: bool,
}

impl TransportFailure {
    #[must_use]
    pub const fn new(kind: TransportFailureKind, dispatched: bool) -> Self {
        Self { kind, dispatched }
    }
}

/// Injectable async transport. Implementations must not follow redirects.
#[async_trait]
pub trait Transport: Send + Sync {
    /// Sends one bounded request without following redirects.
    ///
    /// # Errors
    /// Returns a failure that states whether dispatch may have occurred.
    async fn send(
        &self,
        request: HttpRequest,
        deadline: Duration,
    ) -> Result<HttpResponse, TransportFailure>;
}

#[derive(Clone)]
pub(crate) struct ReqwestTransport {
    client: reqwest::Client,
}

impl ReqwestTransport {
    pub(crate) fn new() -> Result<Self, Error> {
        let client = reqwest::Client::builder()
            .redirect(Policy::none())
            .connect_timeout(Duration::from_secs(10))
            .build()
            .map_err(|_| {
                crate::error::configuration(
                    "transport_configuration",
                    "HTTP transport could not be configured.",
                )
            })?;
        Ok(Self { client })
    }
}

#[async_trait]
impl Transport for ReqwestTransport {
    async fn send(
        &self,
        request: HttpRequest,
        deadline: Duration,
    ) -> Result<HttpResponse, TransportFailure> {
        let operation = async {
            let method = match request.method {
                HttpMethod::Get => Method::GET,
                HttpMethod::Post => Method::POST,
            };
            let maximum = request.max_response_bytes;
            let mut builder = self.client.request(method, &request.url);
            for (name, value) in &request.headers {
                builder = builder.header(name, value);
            }
            if let Some(body) = request.body {
                builder = builder.body(body);
            }
            let mut response = builder.send().await.map_err(|error| {
                TransportFailure::new(
                    if error.is_timeout() {
                        TransportFailureKind::Timeout
                    } else {
                        TransportFailureKind::Transport
                    },
                    !error.is_connect(),
                )
            })?;
            let status = response.status().as_u16();
            let headers = response
                .headers()
                .iter()
                .filter_map(|(name, value)| {
                    let name = name.as_str();
                    if matches!(name, "content-type" | "retry-after" | "x-request-id") {
                        value
                            .to_str()
                            .ok()
                            .map(|value| (name.to_owned(), value.chars().take(256).collect()))
                    } else {
                        None
                    }
                })
                .collect();
            let mut body = Vec::new();
            loop {
                let chunk = response
                    .chunk()
                    .await
                    .map_err(|_| TransportFailure::new(TransportFailureKind::Transport, true))?;
                let Some(chunk) = chunk else { break };
                if body.len().saturating_add(chunk.len()) > maximum {
                    return Err(TransportFailure::new(
                        TransportFailureKind::ResponseTooLarge,
                        true,
                    ));
                }
                body.extend_from_slice(&chunk);
            }
            Ok(HttpResponse {
                status,
                headers,
                body,
            })
        };
        tokio::time::timeout(deadline, operation)
            .await
            .map_err(|_| TransportFailure::new(TransportFailureKind::Timeout, true))?
    }
}

pub(crate) fn default_transport() -> Result<Arc<dyn Transport>, Error> {
    Ok(Arc::new(ReqwestTransport::new()?))
}
