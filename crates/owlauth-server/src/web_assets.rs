use std::{fmt::Write as _, sync::LazyLock};

use axum::{
    body::Body,
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use rust_embed::Embed;
use serde::Deserialize;

pub(crate) const RUNTIME_BOOTSTRAP_META_NAME: &str = "owlauth-runtime-bootstrap";
const OWLAUTH_FAVICON_PATH: &str = "assets/owlauth-favicon.svg";
const OWLAUTH_FAVICON: &str = r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64"><rect width="64" height="64" rx="14" fill="#101211"/><path fill="#f7f7f5" d="M13 14.5 24.3 20A21.7 21.7 0 0 1 32 18.6c2.7 0 5.3.5 7.7 1.4L51 14.5v17.3C51 44.1 42.5 52 32 52s-19-7.9-19-20.2V14.5Z"/><circle cx="23.5" cy="31" r="7.5" fill="#101211"/><circle cx="40.5" cy="31" r="7.5" fill="#101211"/><circle cx="23.5" cy="31" r="2.5" fill="#f7f7f5"/><circle cx="40.5" cy="31" r="2.5" fill="#f7f7f5"/><path fill="#101211" d="m32 35 4.5 5.5h-9L32 35Z"/></svg>"##;

#[derive(Embed)]
#[folder = "web/dist/runtime"]
#[exclude = ".vite/*"]
struct RuntimeAssets;

#[derive(Embed)]
#[folder = "web/dist/control"]
#[exclude = ".vite/*"]
struct ControlAssets;

#[derive(Clone, Copy, Debug)]
pub(crate) enum WebPlane {
    Runtime,
    Control,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ServerManifest {
    entry: String,
    scripts: Vec<String>,
    stylesheets: Vec<String>,
    files: Vec<AssetFile>,
}

#[derive(Deserialize)]
struct AssetFile {
    path: String,
    mime: String,
    bytes: usize,
    sha256: String,
}

static RUNTIME_MANIFEST: LazyLock<ServerManifest> = LazyLock::new(|| {
    parse_manifest::<RuntimeAssets>().expect("validated Runtime server manifest should parse")
});
static CONTROL_MANIFEST: LazyLock<ServerManifest> = LazyLock::new(|| {
    parse_manifest::<ControlAssets>().expect("validated Control server manifest should parse")
});

fn parse_manifest<E: Embed>() -> Result<ServerManifest, serde_json::Error> {
    let bytes = E::get("server-manifest.json")
        .expect("build validation requires a server manifest")
        .data;
    serde_json::from_slice(&bytes)
}

fn manifest(plane: WebPlane) -> &'static ServerManifest {
    match plane {
        WebPlane::Runtime => &RUNTIME_MANIFEST,
        WebPlane::Control => &CONTROL_MANIFEST,
    }
}

pub(crate) fn shell(plane: WebPlane, base_path: &str) -> Response {
    shell_with_context(plane, base_path, &[])
}

pub(crate) fn shell_with_context(
    plane: WebPlane,
    base_path: &str,
    context: &[(&str, &str)],
) -> Response {
    let manifest = manifest(plane);
    let application_path = match plane {
        WebPlane::Runtime => "auth/",
        WebPlane::Control => "console/",
    };
    let configured_base_name = match plane {
        WebPlane::Runtime => "owlauth-runtime-base",
        WebPlane::Control => "owlauth-control-base",
    };
    let title = match plane {
        WebPlane::Runtime => "OwlAuth Hosted Authentication",
        WebPlane::Control => "OwlAuth Management Console",
    };
    let prefix = format!("{base_path}{application_path}");

    let mut head = String::new();
    for stylesheet in &manifest.stylesheets {
        write!(
            head,
            "<link rel=\"stylesheet\" href=\"{}\">",
            html_escape(&format!("{prefix}{stylesheet}"))
        )
        .expect("writing to a String cannot fail");
    }
    for preload in manifest
        .scripts
        .iter()
        .filter(|script| *script != &manifest.entry)
    {
        write!(
            head,
            "<link rel=\"modulepreload\" href=\"{}\">",
            html_escape(&format!("{prefix}{preload}"))
        )
        .expect("writing to a String cannot fail");
    }

    for (name, value) in context {
        write!(
            head,
            "<meta name=\"{}\" content=\"{}\">",
            html_escape(name),
            html_escape(value)
        )
        .expect("writing to a String cannot fail");
    }
    let document = format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><meta name=\"{configured_base_name}\" content=\"{}\"><link rel=\"icon\" type=\"image/svg+xml\" href=\"{}\"><title>{title}</title>{head}</head><body><div id=\"owlauth-root\"></div><script type=\"module\" src=\"{}\"></script></body></html>",
        html_escape(base_path),
        html_escape(&format!("{prefix}{OWLAUTH_FAVICON_PATH}")),
        html_escape(&format!("{prefix}{}", manifest.entry)),
    );
    let mut response = Response::new(Body::from(document));
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    response
}

pub(crate) fn asset(plane: WebPlane, requested_path: &str) -> Response {
    if requested_path == OWLAUTH_FAVICON_PATH {
        let mut response = Response::new(Body::from(OWLAUTH_FAVICON));
        let headers = response.headers_mut();
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("image/svg+xml"),
        );
        headers.insert(
            header::CONTENT_LENGTH,
            HeaderValue::from_str(&OWLAUTH_FAVICON.len().to_string())
                .expect("favicon length should be a header value"),
        );
        headers.insert(
            header::CACHE_CONTROL,
            HeaderValue::from_static("public, max-age=31536000, immutable"),
        );
        return response;
    }

    let manifest = manifest(plane);
    let Some(file) = manifest
        .files
        .iter()
        .find(|file| file.path == requested_path)
    else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let bytes = match plane {
        WebPlane::Runtime => RuntimeAssets::get(&file.path),
        WebPlane::Control => ControlAssets::get(&file.path),
    };
    let Some(bytes) = bytes else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    if bytes.data.len() != file.bytes || sha256_hex(&bytes.data) != file.sha256 {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    let mut response = Response::new(Body::from(bytes.data.into_owned()));
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_str(&file.mime).expect("validated MIME should be a header value"),
    );
    headers.insert(
        header::CONTENT_LENGTH,
        HeaderValue::from_str(&file.bytes.to_string())
            .expect("asset length should be a header value"),
    );
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=31536000, immutable"),
    );
    response
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest as _, Sha256};
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(64);
    for byte in digest {
        write!(output, "{byte:02x}").expect("writing to a String cannot fail");
    }
    output
}

fn html_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('"', "&quot;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_plane_manifests_are_distinct() {
        assert!(RUNTIME_MANIFEST.entry.contains("runtime-"));
        assert!(CONTROL_MANIFEST.entry.contains("control-"));
    }

    #[tokio::test]
    async fn contextual_runtime_meta_is_non_executable_and_attribute_escaped() {
        let hostile = r#"{\"display_name\":\"\\\"><script>alert(1)</script>&\"}"#;
        let response = shell_with_context(
            WebPlane::Runtime,
            "/runtime/",
            &[(RUNTIME_BOOTSTRAP_META_NAME, hostile)],
        );
        let document = String::from_utf8(
            axum::body::to_bytes(response.into_body(), 1_000_000)
                .await
                .expect("contextual shell should be bounded")
                .to_vec(),
        )
        .expect("shell should be UTF-8");
        assert!(!document.contains("<script>alert(1)</script>"));
        assert!(document.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
        assert!(document.contains("&quot;"));
        assert!(document.contains("&amp;"));
        assert!(document.contains("<meta name=\"owlauth-runtime-bootstrap\""));
        assert!(!document.contains("owlauth-auth-bootstrap"));
        assert!(document.contains("<link rel=\"icon\" type=\"image/svg+xml\""));
        assert!(document.contains("href=\"/runtime/auth/assets/owlauth-favicon.svg\""));
        assert!(!document.contains("data:image"));
    }

    #[tokio::test]
    async fn favicon_is_a_same_origin_immutable_svg_on_both_planes() {
        for plane in [WebPlane::Runtime, WebPlane::Control] {
            let response = asset(plane, OWLAUTH_FAVICON_PATH);
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(response.headers()[header::CONTENT_TYPE], "image/svg+xml");
            assert_eq!(
                response.headers()[header::CACHE_CONTROL],
                "public, max-age=31536000, immutable"
            );
            let body = axum::body::to_bytes(response.into_body(), 4096)
                .await
                .expect("favicon should be bounded");
            assert_eq!(body.as_ref(), OWLAUTH_FAVICON.as_bytes());
        }
    }
}
