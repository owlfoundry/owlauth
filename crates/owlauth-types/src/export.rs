use std::{fmt, str::FromStr};

/// Public HTTP plane whose `OpenAPI` document should be exported.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OpenApiPlane {
    /// Project Auth Runtime API.
    Runtime,
    /// Deployment Control API.
    Control,
}

impl fmt::Display for OpenApiPlane {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Runtime => "runtime",
            Self::Control => "control",
        })
    }
}

impl FromStr for OpenApiPlane {
    type Err = ParseOpenApiPlaneError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "runtime" => Ok(Self::Runtime),
            "control" => Ok(Self::Control),
            _ => Err(ParseOpenApiPlaneError),
        }
    }
}

/// Error returned for an unsupported `OpenAPI` plane name.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ParseOpenApiPlaneError;

impl fmt::Display for ParseOpenApiPlaneError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("plane must be `runtime` or `control`")
    }
}

impl std::error::Error for ParseOpenApiPlaneError {}

/// Generates one complete plane-specific `OpenAPI` document as stable pretty JSON.
///
/// # Errors
///
/// Returns a serialization error if the generated document cannot be encoded.
pub fn to_pretty_json(plane: OpenApiPlane) -> Result<String, serde_json::Error> {
    match plane {
        OpenApiPlane::Runtime => {
            let mut document = serde_json::to_value(crate::runtime::openapi())?;
            require_runtime_retry_after_headers(&mut document);
            serde_json::to_string_pretty(&document)
        }
        OpenApiPlane::Control => crate::control::openapi().to_pretty_json(),
    }
}

fn require_runtime_retry_after_headers(document: &mut serde_json::Value) {
    // utoipa 5.5 models response Header Objects without the OpenAPI `required` field.
    // Preserve the typed Rust declarations, then add that standard field at the one
    // serialization boundary consumed by checked generated clients.
    let Some(paths) = document
        .get_mut("paths")
        .and_then(serde_json::Value::as_object_mut)
    else {
        return;
    };
    for path in paths.values_mut() {
        let Some(operations) = path.as_object_mut() else {
            continue;
        };
        for operation in operations.values_mut() {
            let Some(retry_after) = operation
                .get_mut("responses")
                .and_then(|responses| responses.get_mut("429"))
                .and_then(|response| response.get_mut("headers"))
                .and_then(|headers| headers.get_mut("Retry-After"))
                .and_then(serde_json::Value::as_object_mut)
            else {
                continue;
            };
            retry_after.insert("required".to_owned(), serde_json::Value::Bool(true));
        }
    }
}
