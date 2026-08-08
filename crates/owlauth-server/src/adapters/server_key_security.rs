use std::{collections::BTreeMap, sync::Arc};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::application::{
    ApplicationError, IssuedServerCredential, OneTimeServerCredential,
    SERVER_KEY_CREDENTIAL_PREFIX, SERVER_KEY_PUBLIC_ID_BYTES, SERVER_KEY_SECRET_BYTES,
    ServerKeyIssuer, ServerKeyVerifier, server_key_display_prefix,
};

const SERVER_KEY_DIGEST_DOMAIN: &[u8] = b"owlauth-project-server-key-digest-v1\0";
type HmacSha256 = Hmac<Sha256>;

pub(crate) struct ServerKeyDigestMaterial(Zeroizing<[u8; 32]>);

impl ServerKeyDigestMaterial {
    pub(crate) fn new(value: [u8; 32]) -> Self {
        Self(Zeroizing::new(value))
    }
}

struct SoftwareServerKeyRingInner {
    deployment_context: Arc<str>,
    active_version: i32,
    keys: BTreeMap<i32, ServerKeyDigestMaterial>,
}

#[derive(Clone)]
pub(crate) struct SoftwareServerKeyIssuer {
    inner: Arc<SoftwareServerKeyRingInner>,
}

#[derive(Clone)]
pub(crate) struct SoftwareServerKeyVerifier {
    inner: Arc<SoftwareServerKeyRingInner>,
}

pub(crate) struct SoftwareServerKeyRing {
    inner: Arc<SoftwareServerKeyRingInner>,
}

impl SoftwareServerKeyRing {
    pub(crate) fn new(
        deployment_context: String,
        active_version: i32,
        active: ServerKeyDigestMaterial,
        retained: BTreeMap<i32, ServerKeyDigestMaterial>,
    ) -> Result<Self, ApplicationError> {
        if deployment_context.is_empty()
            || deployment_context.len() > 128
            || active_version <= 0
            || retained.keys().any(|version| *version <= 0)
            || retained.contains_key(&active_version)
            || retained.len() >= 32
        {
            return Err(ApplicationError::InvalidInput);
        }
        let mut keys = retained;
        keys.insert(active_version, active);
        Ok(Self {
            inner: Arc::new(SoftwareServerKeyRingInner {
                deployment_context: Arc::from(deployment_context),
                active_version,
                keys,
            }),
        })
    }

    pub(crate) fn issuer(&self) -> SoftwareServerKeyIssuer {
        SoftwareServerKeyIssuer {
            inner: Arc::clone(&self.inner),
        }
    }

    pub(crate) fn verifier(&self) -> SoftwareServerKeyVerifier {
        SoftwareServerKeyVerifier {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl SoftwareServerKeyRingInner {
    fn digest(
        &self,
        project_id: Uuid,
        key_id: Uuid,
        public_key_id: &str,
        secret: &[u8; SERVER_KEY_SECRET_BYTES],
        digest_key_version: i32,
    ) -> Result<[u8; 32], ApplicationError> {
        server_key_display_prefix(public_key_id)?;
        let key = self
            .keys
            .get(&digest_key_version)
            .ok_or(ApplicationError::Integrity)?;
        let mut mac = <HmacSha256 as Mac>::new_from_slice(key.0.as_ref())
            .map_err(|_| ApplicationError::Integrity)?;
        mac.update(SERVER_KEY_DIGEST_DOMAIN);
        update_framed(&mut mac, self.deployment_context.as_bytes())?;
        update_framed(&mut mac, &digest_key_version.to_be_bytes())?;
        update_framed(&mut mac, SERVER_KEY_CREDENTIAL_PREFIX.as_bytes())?;
        update_framed(&mut mac, project_id.as_bytes())?;
        update_framed(&mut mac, key_id.as_bytes())?;
        update_framed(&mut mac, public_key_id.as_bytes())?;
        update_framed(&mut mac, secret)?;
        Ok(mac.finalize().into_bytes().into())
    }
}

impl ServerKeyIssuer for SoftwareServerKeyIssuer {
    fn active_version(&self) -> i32 {
        self.inner.active_version
    }

    fn issue(
        &self,
        project_id: Uuid,
        key_id: Uuid,
    ) -> Result<IssuedServerCredential, ApplicationError> {
        let mut public_id_bytes = Zeroizing::new([0_u8; SERVER_KEY_PUBLIC_ID_BYTES]);
        let mut secret = Zeroizing::new([0_u8; SERVER_KEY_SECRET_BYTES]);
        getrandom::fill(public_id_bytes.as_mut()).map_err(|_| ApplicationError::ExternalStore)?;
        getrandom::fill(secret.as_mut()).map_err(|_| ApplicationError::ExternalStore)?;
        let public_key_id = URL_SAFE_NO_PAD.encode(public_id_bytes.as_slice());
        let encoded_secret = Zeroizing::new(URL_SAFE_NO_PAD.encode(secret.as_slice()));
        let display_prefix = server_key_display_prefix(&public_key_id)?;
        let credential = OneTimeServerCredential::new(Zeroizing::new(format!(
            "{display_prefix}.{}",
            encoded_secret.as_str()
        )))?;
        let digest = self.inner.digest(
            project_id,
            key_id,
            &public_key_id,
            &secret,
            self.inner.active_version,
        )?;
        Ok(IssuedServerCredential {
            public_key_id,
            display_prefix,
            digest_key_version: self.inner.active_version,
            digest,
            credential,
        })
    }
}

impl ServerKeyVerifier for SoftwareServerKeyVerifier {
    fn digest_candidate(
        &self,
        project_id: Uuid,
        key_id: Uuid,
        public_key_id: &str,
        secret: &[u8; SERVER_KEY_SECRET_BYTES],
        digest_key_version: i32,
    ) -> Result<[u8; 32], ApplicationError> {
        self.inner.digest(
            project_id,
            key_id,
            public_key_id,
            secret,
            digest_key_version,
        )
    }
}

fn update_framed(mac: &mut HmacSha256, value: &[u8]) -> Result<(), ApplicationError> {
    let length = u32::try_from(value.len()).map_err(|_| ApplicationError::InvalidInput)?;
    mac.update(&length.to_be_bytes());
    mac.update(value);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::application::ParsedServerCredential;

    fn ring() -> SoftwareServerKeyRing {
        SoftwareServerKeyRing::new(
            "deployment-1".to_owned(),
            2,
            ServerKeyDigestMaterial::new([2_u8; 32]),
            BTreeMap::from([(1, ServerKeyDigestMaterial::new([1_u8; 32]))]),
        )
        .expect("valid ring")
    }

    #[test]
    fn issuer_and_verifier_share_the_exact_purpose_bound_digest() {
        let project_id = Uuid::new_v4();
        let key_id = Uuid::new_v4();
        let ring = ring();
        let issued = ring
            .issuer()
            .issue(project_id, key_id)
            .expect("issue credential");
        let parsed = ParsedServerCredential::parse(issued.credential.expose())
            .expect("parse issued credential");
        let verified = ring
            .verifier()
            .digest_candidate(
                project_id,
                key_id,
                parsed.public_key_id(),
                parsed.secret(),
                issued.digest_key_version,
            )
            .expect("digest candidate");
        assert_eq!(verified, issued.digest);
        assert_ne!(
            ring.verifier()
                .digest_candidate(
                    Uuid::new_v4(),
                    key_id,
                    parsed.public_key_id(),
                    parsed.secret(),
                    issued.digest_key_version,
                )
                .expect("other Project digest"),
            issued.digest
        );
        assert_ne!(
            ring.verifier()
                .digest_candidate(
                    project_id,
                    Uuid::new_v4(),
                    parsed.public_key_id(),
                    parsed.secret(),
                    issued.digest_key_version,
                )
                .expect("other key digest"),
            issued.digest
        );
    }

    #[test]
    fn verifier_rejects_unavailable_versions_and_reports_only_versions() {
        let ring = ring();
        assert_eq!(
            ring.verifier().digest_candidate(
                Uuid::new_v4(),
                Uuid::new_v4(),
                &URL_SAFE_NO_PAD.encode([1_u8; SERVER_KEY_PUBLIC_ID_BYTES]),
                &[2_u8; SERVER_KEY_SECRET_BYTES],
                3,
            ),
            Err(ApplicationError::Integrity)
        );
    }
}
