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
        OpenApiPlane::Runtime => crate::runtime::openapi().to_pretty_json(),
        OpenApiPlane::Control => crate::control::openapi().to_pretty_json(),
    }
}
