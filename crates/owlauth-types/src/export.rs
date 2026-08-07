use std::{fmt, str::FromStr};

/// Public HTTP plane whose `OpenAPI` document should be exported.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OpenApiPlane {
    /// Project Auth Runtime API.
    Runtime,
    /// Project-scoped customer backend Server API.
    Server,
    /// Deployment Control API.
    Control,
}

impl fmt::Display for OpenApiPlane {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Runtime => "runtime",
            Self::Server => "server",
            Self::Control => "control",
        })
    }
}

impl FromStr for OpenApiPlane {
    type Err = ParseOpenApiPlaneError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "runtime" => Ok(Self::Runtime),
            "server" => Ok(Self::Server),
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
        formatter.write_str("plane must be `runtime`, `server`, or `control`")
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
            require_contract_headers(&mut document);
            serde_json::to_string_pretty(&document)
        }
        OpenApiPlane::Server => {
            let mut document = serde_json::to_value(crate::server::openapi())?;
            require_contract_headers(&mut document);
            require_server_literal_discriminator(&mut document);
            serde_json::to_string_pretty(&document)
        }
        OpenApiPlane::Control => crate::control::openapi().to_pretty_json(),
    }
}

fn require_contract_headers(document: &mut serde_json::Value) {
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
            for (status, header) in [("429", "Retry-After"), ("401", "WWW-Authenticate")] {
                let Some(value) = operation
                    .get_mut("responses")
                    .and_then(|responses| responses.get_mut(status))
                    .and_then(|response| response.get_mut("headers"))
                    .and_then(|headers| headers.get_mut(header))
                    .and_then(serde_json::Value::as_object_mut)
                else {
                    continue;
                };
                value.insert("required".to_owned(), serde_json::Value::Bool(true));
            }
        }
    }
}

fn require_server_literal_discriminator(document: &mut serde_json::Value) {
    for (schema, expected) in [
        ("InactiveProjectToken", false),
        ("ActiveProjectToken", true),
    ] {
        let Some(active) = document
            .get_mut("components")
            .and_then(|components| components.get_mut("schemas"))
            .and_then(|schemas| schemas.get_mut(schema))
            .and_then(|schema| schema.get_mut("properties"))
            .and_then(|properties| properties.get_mut("active"))
            .and_then(serde_json::Value::as_object_mut)
        else {
            continue;
        };
        active.insert("const".to_owned(), serde_json::Value::Bool(expected));
    }
}
