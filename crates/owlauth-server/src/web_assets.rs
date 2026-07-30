use std::{collections::BTreeMap, fmt::Write as _, sync::LazyLock};

use axum::{
    body::Body,
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use rust_embed::Embed;
use serde::Deserialize;

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
    asset_set_sha256: String,
    files: Vec<AssetFile>,
}

#[derive(Deserialize)]
struct AssetFile {
    path: String,
    mime: String,
    representations: Representations,
}

#[derive(Deserialize)]
struct Representations {
    identity: Representation,
    gzip: Option<Representation>,
    brotli: Option<Representation>,
}

#[derive(Deserialize)]
struct Representation {
    path: String,
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

    let document = format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><meta name=\"{configured_base_name}\" content=\"{}\"><title>{title}</title>{head}</head><body><div id=\"owlauth-root\"></div><script type=\"module\" src=\"{}\"></script></body></html>",
        html_escape(base_path),
        html_escape(&format!("{prefix}{}", manifest.entry)),
    );
    let mut response = Response::new(Body::from(document));
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    response.headers_mut().insert(
        header::ETAG,
        HeaderValue::from_str(&format!("\"assets-{}\"", manifest.asset_set_sha256))
            .expect("asset-set ETag should be a header value"),
    );
    response
}

pub(crate) fn asset(plane: WebPlane, requested_path: &str, headers: &HeaderMap) -> Response {
    let manifest = manifest(plane);
    let Some(file) = manifest
        .files
        .iter()
        .find(|file| file.path == requested_path)
    else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let Some((encoding, representation)) = select_representation(&file.representations, headers)
    else {
        return StatusCode::NOT_ACCEPTABLE.into_response();
    };
    let etag = format!("\"sha256-{}\"", representation.sha256);
    if headers
        .get_all(header::IF_NONE_MATCH)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .map(str::trim)
        .any(|candidate| candidate == etag || candidate == "*")
    {
        let mut response = StatusCode::NOT_MODIFIED.into_response();
        set_asset_headers(&mut response, file, encoding, representation, &etag);
        return response;
    }

    let bytes = match plane {
        WebPlane::Runtime => RuntimeAssets::get(&representation.path),
        WebPlane::Control => ControlAssets::get(&representation.path),
    };
    let Some(bytes) = bytes else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    let mut response = Response::new(Body::from(bytes.data.into_owned()));
    set_asset_headers(&mut response, file, encoding, representation, &etag);
    response
}

fn set_asset_headers(
    response: &mut Response,
    file: &AssetFile,
    encoding: Option<&'static str>,
    representation: &Representation,
    etag: &str,
) {
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_str(&file.mime).expect("validated MIME should be a header value"),
    );
    headers.insert(
        header::CONTENT_LENGTH,
        HeaderValue::from_str(&representation.bytes.to_string())
            .expect("asset length should be a header value"),
    );
    headers.insert(
        header::ETAG,
        HeaderValue::from_str(etag).expect("digest ETag should be a header value"),
    );
    headers.insert(header::VARY, HeaderValue::from_static("Accept-Encoding"));
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=31536000, immutable"),
    );
    if let Some(encoding) = encoding {
        headers.insert(header::CONTENT_ENCODING, HeaderValue::from_static(encoding));
    }
}

fn select_representation<'a>(
    representations: &'a Representations,
    headers: &HeaderMap,
) -> Option<(Option<&'static str>, &'a Representation)> {
    let quality = encoding_qualities(headers);
    let brotli_quality = quality
        .get("br")
        .copied()
        .or_else(|| quality.get("*").copied())
        .unwrap_or(0);
    let gzip_quality = quality
        .get("gzip")
        .copied()
        .or_else(|| quality.get("*").copied())
        .unwrap_or(0);
    let identity_quality = quality
        .get("identity")
        .copied()
        .or_else(|| quality.get("*").copied())
        .unwrap_or(1_000);

    if brotli_quality > 0
        && brotli_quality >= gzip_quality
        && brotli_quality >= identity_quality
        && let Some(representation) = &representations.brotli
    {
        return Some((Some("br"), representation));
    }
    if gzip_quality > 0
        && gzip_quality >= identity_quality
        && let Some(representation) = &representations.gzip
    {
        return Some((Some("gzip"), representation));
    }
    (identity_quality > 0).then_some((None, &representations.identity))
}

fn encoding_qualities(headers: &HeaderMap) -> BTreeMap<String, u16> {
    let mut qualities = BTreeMap::new();
    for value in headers
        .get_all(header::ACCEPT_ENCODING)
        .iter()
        .filter_map(|value| value.to_str().ok())
    {
        for item in value.split(',') {
            let mut parts = item.trim().split(';');
            let encoding = parts.next().unwrap_or_default().trim().to_ascii_lowercase();
            if encoding.is_empty() {
                continue;
            }
            let mut quality = 1_000;
            for parameter in parts {
                let Some(value) = parameter.trim().strip_prefix("q=") else {
                    continue;
                };
                quality = parse_quality(value).unwrap_or(0);
            }
            qualities.insert(encoding, quality);
        }
    }
    qualities
}

fn parse_quality(value: &str) -> Option<u16> {
    if value == "1" {
        return Some(1_000);
    }
    if value == "0" {
        return Some(0);
    }
    let fraction = value.strip_prefix("0.")?;
    if fraction.is_empty()
        || fraction.len() > 3
        || !fraction.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    let number = fraction.parse::<u16>().ok()?;
    Some(number * 10_u16.pow(u32::try_from(3 - fraction.len()).ok()?))
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
    fn quality_values_are_bounded() {
        assert_eq!(parse_quality("1"), Some(1_000));
        assert_eq!(parse_quality("0.5"), Some(500));
        assert_eq!(parse_quality("0.125"), Some(125));
        assert_eq!(parse_quality("1.1"), None);
        assert_eq!(parse_quality("0.0000"), None);
    }

    #[test]
    fn embedded_plane_manifests_are_distinct() {
        assert_ne!(
            RUNTIME_MANIFEST.asset_set_sha256,
            CONTROL_MANIFEST.asset_set_sha256
        );
        assert!(RUNTIME_MANIFEST.entry.contains("runtime-"));
        assert!(CONTROL_MANIFEST.entry.contains("control-"));
    }
}
