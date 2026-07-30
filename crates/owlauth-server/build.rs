use std::{
    collections::BTreeSet,
    env,
    error::Error,
    fs,
    path::{Path, PathBuf},
};

use serde::Deserialize;
use sha2::{Digest, Sha256};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ServerManifest {
    schema_version: u32,
    plane: String,
    entry: String,
    scripts: Vec<String>,
    stylesheets: Vec<String>,
    asset_set_sha256: String,
    files: Vec<AssetFile>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AssetFile {
    path: String,
    mime: String,
    bytes: usize,
    sha256: String,
    representations: Representations,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Representations {
    identity: Representation,
    gzip: Option<Representation>,
    brotli: Option<Representation>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Representation {
    path: String,
    bytes: usize,
    sha256: String,
}

fn main() {
    if let Err(error) = validate() {
        panic!(
            "prepared hosted-web assets are missing or stale: {error}. Run `pnpm --filter @owlauth/server-web build`."
        );
    }
}

fn validate() -> Result<(), Box<dyn Error>> {
    let crate_root = PathBuf::from(env::var("CARGO_MANIFEST_DIR")?);
    for plane in ["runtime", "control"] {
        let root = crate_root.join("web/dist").join(plane);
        println!("cargo:rerun-if-changed={}", root.display());
        validate_plane(&root, plane)?;
    }
    Ok(())
}

fn validate_plane(root: &Path, expected_plane: &str) -> Result<(), Box<dyn Error>> {
    let manifest_path = root.join("server-manifest.json");
    println!("cargo:rerun-if-changed={}", manifest_path.display());
    let manifest: ServerManifest = serde_json::from_slice(&fs::read(&manifest_path)?)?;
    if manifest.schema_version != 1 || manifest.plane != expected_plane {
        return Err(format!("invalid {expected_plane} server manifest identity").into());
    }

    let mut allowed = BTreeSet::from([
        ".vite/manifest.json".to_owned(),
        "server-manifest.json".to_owned(),
    ]);
    let mut identity_paths = BTreeSet::new();
    let mut set_digest = Sha256::new();
    for file in &manifest.files {
        validate_relative_path(&file.path)?;
        if !file.path.starts_with(&format!("assets/{expected_plane}-"))
            || file.mime.is_empty()
            || !identity_paths.insert(file.path.clone())
        {
            return Err(format!("invalid {expected_plane} asset entry").into());
        }
        if file.representations.identity.path != file.path
            || file.representations.identity.bytes != file.bytes
            || file.representations.identity.sha256 != file.sha256
        {
            return Err(format!("inconsistent {expected_plane} identity metadata").into());
        }

        verify_representation(root, &file.representations.identity, &mut allowed)?;
        if let Some(representation) = &file.representations.gzip {
            if representation.path != format!("{}.gz", file.path) {
                return Err(format!("invalid {expected_plane} gzip path").into());
            }
            verify_representation(root, representation, &mut allowed)?;
        }
        if let Some(representation) = &file.representations.brotli {
            if representation.path != format!("{}.br", file.path) {
                return Err(format!("invalid {expected_plane} Brotli path").into());
            }
            verify_representation(root, representation, &mut allowed)?;
        }

        set_digest.update(file.path.as_bytes());
        set_digest.update(b"\0");
        set_digest.update(file.sha256.as_bytes());
        set_digest.update(b"\n");
    }

    if !identity_paths.contains(&manifest.entry)
        || manifest.scripts.first() != Some(&manifest.entry)
        || manifest
            .scripts
            .iter()
            .chain(&manifest.stylesheets)
            .any(|path| !identity_paths.contains(path))
    {
        return Err(format!("invalid {expected_plane} shell closure").into());
    }
    let finalized_set_digest = set_digest.finalize();
    let calculated_set_digest = hexadecimal(finalized_set_digest.as_ref());
    if calculated_set_digest != manifest.asset_set_sha256 {
        return Err(format!("invalid {expected_plane} asset-set digest").into());
    }

    let actual = list_files(root, root)?;
    if actual != allowed {
        return Err(format!("unexpected or missing files in {expected_plane} asset tree").into());
    }
    Ok(())
}

fn verify_representation(
    root: &Path,
    representation: &Representation,
    allowed: &mut BTreeSet<String>,
) -> Result<(), Box<dyn Error>> {
    validate_relative_path(&representation.path)?;
    if !allowed.insert(representation.path.clone()) {
        return Err("duplicate asset representation".into());
    }
    let path = root.join(&representation.path);
    println!("cargo:rerun-if-changed={}", path.display());
    let bytes = fs::read(path)?;
    let digest = Sha256::digest(&bytes);
    if bytes.len() != representation.bytes || hexadecimal(digest.as_ref()) != representation.sha256
    {
        return Err("asset representation digest mismatch".into());
    }
    Ok(())
}

fn validate_relative_path(path: &str) -> Result<(), Box<dyn Error>> {
    if path.is_empty()
        || path.starts_with('/')
        || path.contains('\\')
        || path.contains('%')
        || path.contains('?')
        || path.contains('#')
        || path
            .split('/')
            .any(|segment| segment.is_empty() || matches!(segment, "." | ".."))
    {
        return Err("non-canonical asset path".into());
    }
    Ok(())
}

fn list_files(root: &Path, directory: &Path) -> Result<BTreeSet<String>, Box<dyn Error>> {
    let mut files = BTreeSet::new();
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let kind = entry.file_type()?;
        if kind.is_symlink() {
            return Err("asset tree contains a symbolic link".into());
        }
        if kind.is_dir() {
            files.extend(list_files(root, &entry.path())?);
        } else if kind.is_file() {
            files.insert(
                entry
                    .path()
                    .strip_prefix(root)?
                    .to_string_lossy()
                    .replace('\\', "/"),
            );
        } else {
            return Err("asset tree contains an unsupported entry".into());
        }
    }
    Ok(files)
}

fn hexadecimal(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    output
}
