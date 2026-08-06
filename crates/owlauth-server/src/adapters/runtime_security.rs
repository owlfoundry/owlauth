use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

#[cfg(test)]
use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use ed25519_dalek::{Signature, VerifyingKey};
use hmac::{Hmac, Mac};
use serde_json::{Map, Value};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::application::{
    ApplicationError, CandidateEvidenceMaterial, IdentityMutationCandidateEvidenceContext,
    IdentityMutationCandidateKind, IdentityMutationCandidateVerifier,
    IdentityMutationDurableEmailProtector, IdentityMutationProofMaterialProtector,
    IdentityMutationTargetIssuer, IdentityMutationTargetVerifier, ManagedCredentialContext,
    ManagedCredentialProtector, ManagedReauthorizationTargetIssuer,
    ManagedReauthorizationTargetVerifier, OpaquePurpose, ProtectedPurpose, ProtectedValue,
    RuntimeProtector, VersionedDigest,
};
#[cfg(test)]
use crate::application::{ProviderSecretResolver, RuntimeSigner};

#[cfg(test)]
use super::software_store::EncryptedFileStore;

const DIGEST_DOMAIN: &[u8] = b"owlauth-runtime-digest-v1\0";
const DERIVATION_DOMAIN: &[u8] = b"owlauth-runtime-derived-opaque-v1\0";
const PROTECTION_DOMAIN: &[u8] = b"owlauth-runtime-protection-v1\0";
const MANAGED_CREDENTIAL_DOMAIN: &[u8] = b"owlauth-managed-credential-aead-v1\0";
const PROJECTION_EMAIL_PROTECTION_DOMAIN: &[u8] = b"owlauth-projection-email-aead-v1\0";
const NONCE_BYTES: usize = 24;
const TAG_BYTES: usize = 16;
const SIGNING_ALGORITHM: &str = "EdDSA";

type HmacSha256 = Hmac<Sha256>;

/// Independent roots for keyed digests and authenticated encryption at one key version.
///
/// This type intentionally has no `Debug` implementation: both fields are secret key material.
pub(crate) struct RuntimeKeyMaterial {
    digest_key: Zeroizing<[u8; 32]>,
    protection_key: Zeroizing<[u8; 32]>,
}

impl RuntimeKeyMaterial {
    pub(crate) fn new(digest_key: [u8; 32], protection_key: [u8; 32]) -> Self {
        Self {
            digest_key: Zeroizing::new(digest_key),
            protection_key: Zeroizing::new(protection_key),
        }
    }
}

/// In-process Runtime cryptography backed by explicitly supplied active and retained keys.
///
/// The active version is used for new values. Retained versions are accepted only for
/// deterministic derivation and decryption of already-persisted values.
#[derive(Clone)]
pub(crate) struct SoftwareRuntimeProtector {
    deployment_context: Arc<str>,
    active_version: i32,
    keys: Arc<BTreeMap<i32, RuntimeKeyMaterial>>,
}

impl SoftwareRuntimeProtector {
    pub(crate) fn new(
        deployment_context: String,
        active_version: i32,
        active: RuntimeKeyMaterial,
        retained: BTreeMap<i32, RuntimeKeyMaterial>,
    ) -> Result<Self, ApplicationError> {
        if deployment_context.is_empty()
            || deployment_context.len() > 128
            || active_version <= 0
            || retained.keys().any(|version| *version <= 0)
            || retained.contains_key(&active_version)
        {
            return Err(ApplicationError::InvalidInput);
        }

        let mut keys = retained;
        keys.insert(active_version, active);
        Ok(Self {
            deployment_context: Arc::from(deployment_context),
            active_version,
            keys: Arc::new(keys),
        })
    }

    fn key(&self, version: i32) -> Result<&RuntimeKeyMaterial, ApplicationError> {
        self.keys.get(&version).ok_or(ApplicationError::Integrity)
    }

    fn keyed_output(
        &self,
        domain: &[u8],
        version: i32,
        purpose: &str,
        context: &[u8],
        value: &[u8],
    ) -> Result<[u8; 32], ApplicationError> {
        let key = self.key(version)?;
        let mut mac = <HmacSha256 as Mac>::new_from_slice(key.digest_key.as_ref())
            .map_err(|_| ApplicationError::Integrity)?;
        mac.update(domain);
        update_framed(&mut mac, self.deployment_context.as_bytes())?;
        update_framed(&mut mac, &version.to_be_bytes())?;
        update_framed(&mut mac, purpose.as_bytes())?;
        update_framed(&mut mac, context)?;
        update_framed(&mut mac, value)?;
        Ok(mac.finalize().into_bytes().into())
    }

    fn associated_data(
        &self,
        version: i32,
        purpose: ProtectedPurpose,
        context: &[u8],
    ) -> Result<Vec<u8>, ApplicationError> {
        let mut associated_data = Vec::with_capacity(
            PROTECTION_DOMAIN.len()
                + self.deployment_context.len()
                + purpose.as_str().len()
                + context.len()
                + 48,
        );
        associated_data.extend_from_slice(PROTECTION_DOMAIN);
        append_framed(&mut associated_data, self.deployment_context.as_bytes())?;
        append_framed(&mut associated_data, &version.to_be_bytes())?;
        append_framed(&mut associated_data, purpose.as_str().as_bytes())?;
        append_framed(&mut associated_data, context)?;
        Ok(associated_data)
    }
}

impl RuntimeProtector for SoftwareRuntimeProtector {
    fn active_version(&self) -> i32 {
        self.active_version
    }

    fn readable_key_versions(&self) -> BTreeSet<i32> {
        self.keys.keys().copied().collect()
    }

    fn random_opaque(&self, bytes: usize) -> Result<Zeroizing<String>, ApplicationError> {
        if bytes == 0 {
            return Err(ApplicationError::InvalidInput);
        }
        let mut random = Zeroizing::new(vec![0_u8; bytes]);
        getrandom::fill(random.as_mut()).map_err(|_| ApplicationError::ExternalStore)?;
        Ok(Zeroizing::new(URL_SAFE_NO_PAD.encode(random.as_slice())))
    }

    fn digest(
        &self,
        purpose: OpaquePurpose,
        context: &[u8],
        value: &[u8],
    ) -> Result<VersionedDigest, ApplicationError> {
        self.digest_at(purpose, context, value, self.active_version)
    }

    fn digest_at(
        &self,
        purpose: OpaquePurpose,
        context: &[u8],
        value: &[u8],
        key_version: i32,
    ) -> Result<VersionedDigest, ApplicationError> {
        Ok(VersionedDigest {
            value: self.keyed_output(
                DIGEST_DOMAIN,
                key_version,
                purpose.as_str(),
                context,
                value,
            )?,
            key_version,
        })
    }

    fn derive_opaque(
        &self,
        purpose: OpaquePurpose,
        context: &[u8],
        key_version: Option<i32>,
    ) -> Result<Zeroizing<String>, ApplicationError> {
        let version = key_version.unwrap_or(self.active_version);
        let derived = Zeroizing::new(self.keyed_output(
            DERIVATION_DOMAIN,
            version,
            purpose.as_str(),
            context,
            &[],
        )?);
        Ok(Zeroizing::new(URL_SAFE_NO_PAD.encode(derived.as_slice())))
    }

    fn protect(
        &self,
        purpose: ProtectedPurpose,
        context: &[u8],
        value: &[u8],
    ) -> Result<ProtectedValue, ApplicationError> {
        let key = self.key(self.active_version)?;
        let cipher = XChaCha20Poly1305::new_from_slice(key.protection_key.as_ref())
            .map_err(|_| ApplicationError::Integrity)?;
        let mut nonce = [0_u8; NONCE_BYTES];
        getrandom::fill(&mut nonce).map_err(|_| ApplicationError::ExternalStore)?;
        let associated_data = self.associated_data(self.active_version, purpose, context)?;
        let nonce_value = XNonce::from(nonce);
        let encrypted = cipher
            .encrypt(
                &nonce_value,
                Payload {
                    msg: value,
                    aad: &associated_data,
                },
            )
            .map_err(|_| ApplicationError::Integrity)?;
        let mut ciphertext = Vec::with_capacity(NONCE_BYTES + encrypted.len());
        ciphertext.extend_from_slice(&nonce);
        ciphertext.extend_from_slice(&encrypted);
        nonce.fill(0);
        Ok(ProtectedValue {
            ciphertext,
            key_version: self.active_version,
        })
    }

    fn unprotect(
        &self,
        purpose: ProtectedPurpose,
        context: &[u8],
        value: &ProtectedValue,
    ) -> Result<Zeroizing<Vec<u8>>, ApplicationError> {
        if value.ciphertext.len() < NONCE_BYTES + TAG_BYTES {
            return Err(ApplicationError::Integrity);
        }
        let key = self.key(value.key_version)?;
        let cipher = XChaCha20Poly1305::new_from_slice(key.protection_key.as_ref())
            .map_err(|_| ApplicationError::Integrity)?;
        let (nonce, ciphertext) = value.ciphertext.split_at(NONCE_BYTES);
        let nonce: [u8; NONCE_BYTES] = nonce.try_into().map_err(|_| ApplicationError::Integrity)?;
        let nonce_value = XNonce::from(nonce);
        let associated_data = self.associated_data(value.key_version, purpose, context)?;
        let plaintext = cipher
            .decrypt(
                &nonce_value,
                Payload {
                    msg: ciphertext,
                    aad: &associated_data,
                },
            )
            .map_err(|_| ApplicationError::Integrity)?;
        Ok(Zeroizing::new(plaintext))
    }
}

/// Routes short-lived Runtime material and durable email identity material through physically
/// independent active/retained rings. Purpose labels remain defense in depth; they are not used
/// as a substitute for independent retention authority.
#[derive(Clone)]
pub(crate) struct SplitRuntimeProtector {
    short_term: SoftwareRuntimeProtector,
    email_identity: Option<SoftwareRuntimeProtector>,
    projection_email: Option<SoftwareProjectionVerifiedEmailProtector>,
}

impl SplitRuntimeProtector {
    #[cfg(test)]
    pub(crate) fn new(
        short_term: SoftwareRuntimeProtector,
        email_identity: Option<SoftwareRuntimeProtector>,
    ) -> Self {
        Self {
            short_term,
            email_identity,
            projection_email: None,
        }
    }

    pub(crate) fn new_with_projection_email(
        short_term: SoftwareRuntimeProtector,
        email_identity: Option<SoftwareRuntimeProtector>,
        projection_email: SoftwareProjectionVerifiedEmailProtector,
    ) -> Self {
        Self {
            short_term,
            email_identity,
            projection_email: Some(projection_email),
        }
    }

    fn opaque_ring(
        &self,
        purpose: OpaquePurpose,
    ) -> Result<&SoftwareRuntimeProtector, ApplicationError> {
        match purpose {
            OpaquePurpose::EmailIdentityLookup => self
                .email_identity
                .as_ref()
                .ok_or(ApplicationError::Disabled),
            OpaquePurpose::Interaction
            | OpaquePurpose::BrowserBinding
            | OpaquePurpose::InteractionCsrf
            | OpaquePurpose::UpstreamState
            | OpaquePurpose::OidcNonce
            | OpaquePurpose::HandoffTicket
            | OpaquePurpose::BrowserSession
            | OpaquePurpose::RefreshToken
            | OpaquePurpose::BrowserLogout
            | OpaquePurpose::EmailOtpProof
            | OpaquePurpose::EmailMagicProof
            | OpaquePurpose::EmailMagicTransferContext
            | OpaquePurpose::EmailMagicTransferCsrf
            | OpaquePurpose::ManagedReauthorization
            | OpaquePurpose::ManagedReauthorizationBrowser
            | OpaquePurpose::ManagedReauthorizationCsrf
            | OpaquePurpose::ManagedReauthorizationState
            | OpaquePurpose::ManagedReauthorizationNonce
            | OpaquePurpose::IdentityMutationIntent
            | OpaquePurpose::IdentityMutationBrowser
            | OpaquePurpose::IdentityMutationCsrf
            | OpaquePurpose::IdentityMutationMagicTransferContext
            | OpaquePurpose::IdentityMutationMagicTransferCsrf
            | OpaquePurpose::IdentityMutationProviderState
            | OpaquePurpose::IdentityMutationNonce
            | OpaquePurpose::IdentityMutationCandidateEvidenceDigest
            | OpaquePurpose::IdentityMutationReceipt => Ok(&self.short_term),
        }
    }

    fn protected_ring(
        &self,
        purpose: ProtectedPurpose,
    ) -> Result<&SoftwareRuntimeProtector, ApplicationError> {
        match purpose {
            ProtectedPurpose::EmailIdentityAddress => self
                .email_identity
                .as_ref()
                .ok_or(ApplicationError::Disabled),
            ProtectedPurpose::ApplicationProjectionVerifiedEmail => Err(ApplicationError::Disabled),
            ProtectedPurpose::ApplicationState
            | ProtectedPurpose::ProviderPkce
            | ProtectedPurpose::EmailChallengeAddress
            | ProtectedPurpose::EmailOutboxEnvelope
            | ProtectedPurpose::EmailOutboxBody
            | ProtectedPurpose::ManagedProviderCredential
            | ProtectedPurpose::ManagedReauthorizationPkce
            | ProtectedPurpose::ManagedReauthorizationCreateResult
            | ProtectedPurpose::IdentityMutationProviderPkce
            | ProtectedPurpose::IdentityMutationCallbackContinuation
            | ProtectedPurpose::IdentityMutationCandidateEvidence
            | ProtectedPurpose::IdentityMutationCreateResult => Ok(&self.short_term),
        }
    }
}

impl RuntimeProtector for SplitRuntimeProtector {
    fn active_version(&self) -> i32 {
        self.short_term.active_version()
    }

    fn email_identity_active_version(&self) -> i32 {
        self.email_identity
            .as_ref()
            .map_or(0, SoftwareRuntimeProtector::active_version)
    }

    fn random_opaque(&self, bytes: usize) -> Result<Zeroizing<String>, ApplicationError> {
        self.short_term.random_opaque(bytes)
    }

    fn digest(
        &self,
        purpose: OpaquePurpose,
        context: &[u8],
        value: &[u8],
    ) -> Result<VersionedDigest, ApplicationError> {
        self.opaque_ring(purpose)?.digest(purpose, context, value)
    }

    fn digest_at(
        &self,
        purpose: OpaquePurpose,
        context: &[u8],
        value: &[u8],
        key_version: i32,
    ) -> Result<VersionedDigest, ApplicationError> {
        self.opaque_ring(purpose)?
            .digest_at(purpose, context, value, key_version)
    }

    fn derive_opaque(
        &self,
        purpose: OpaquePurpose,
        context: &[u8],
        key_version: Option<i32>,
    ) -> Result<Zeroizing<String>, ApplicationError> {
        self.opaque_ring(purpose)?
            .derive_opaque(purpose, context, key_version)
    }

    fn protect(
        &self,
        purpose: ProtectedPurpose,
        context: &[u8],
        value: &[u8],
    ) -> Result<ProtectedValue, ApplicationError> {
        if purpose == ProtectedPurpose::ApplicationProjectionVerifiedEmail {
            return self
                .projection_email
                .as_ref()
                .ok_or(ApplicationError::Disabled)?
                .protect_context(context, value);
        }
        self.protected_ring(purpose)?
            .protect(purpose, context, value)
    }

    fn unprotect(
        &self,
        purpose: ProtectedPurpose,
        context: &[u8],
        value: &ProtectedValue,
    ) -> Result<Zeroizing<Vec<u8>>, ApplicationError> {
        if purpose == ProtectedPurpose::ApplicationProjectionVerifiedEmail {
            return self
                .projection_email
                .as_ref()
                .ok_or(ApplicationError::Disabled)?
                .unprotect_context(context, value);
        }
        self.protected_ring(purpose)?
            .unprotect(purpose, context, value)
    }

    fn readable_key_versions(&self) -> BTreeSet<i32> {
        RuntimeProtector::readable_key_versions(&self.short_term)
    }

    fn projection_email_write_version(&self) -> i32 {
        self.projection_email
            .as_ref()
            .map_or(0, SoftwareProjectionVerifiedEmailProtector::active_version)
    }

    fn projection_email_readable_versions(&self) -> BTreeSet<i32> {
        self.projection_email.as_ref().map_or_else(
            BTreeSet::new,
            SoftwareProjectionVerifiedEmailProtector::readable_versions,
        )
    }
}

struct DurableEmailReadKeyRing(SoftwareRuntimeProtector);

#[derive(Clone, Default)]
pub(crate) struct UnavailableDurableEmailAddressReader;

impl crate::application::DurableEmailAddressReader for UnavailableDurableEmailAddressReader {
    fn read_durable_address(
        &self,
        _project_id: uuid::Uuid,
        _identity_id: uuid::Uuid,
        _value: &ProtectedValue,
    ) -> Result<Zeroizing<String>, ApplicationError> {
        Err(ApplicationError::Disabled)
    }
}

#[derive(Clone)]
pub(crate) struct SoftwareDurableEmailAddressReader(Arc<DurableEmailReadKeyRing>);

impl SoftwareDurableEmailAddressReader {
    pub(crate) fn new(
        deployment_context: String,
        active_version: i32,
        active: RuntimeKeyMaterial,
        retained: BTreeMap<i32, RuntimeKeyMaterial>,
    ) -> Result<Self, ApplicationError> {
        SoftwareRuntimeProtector::new(deployment_context, active_version, active, retained)
            .map(DurableEmailReadKeyRing)
            .map(Arc::new)
            .map(Self)
    }
}

impl crate::application::DurableEmailAddressReader for SoftwareDurableEmailAddressReader {
    fn read_durable_address(
        &self,
        project_id: uuid::Uuid,
        identity_id: uuid::Uuid,
        value: &ProtectedValue,
    ) -> Result<Zeroizing<String>, ApplicationError> {
        let mut context = Vec::with_capacity(58);
        context.extend_from_slice(b"owlauth-email-identity-v1\0");
        context.extend_from_slice(project_id.as_bytes());
        context.extend_from_slice(identity_id.as_bytes());
        let plaintext =
            self.0
                .0
                .unprotect(ProtectedPurpose::EmailIdentityAddress, &context, value)?;
        let text =
            std::str::from_utf8(plaintext.as_slice()).map_err(|_| ApplicationError::Integrity)?;
        let canonical = crate::domain::CanonicalEmail::parse_v1(text)
            .map_err(|_| ApplicationError::Integrity)?;
        Ok(Zeroizing::new(canonical.expose().to_owned()))
    }
}

struct ProjectionVerifiedEmailKeyRing {
    deployment_context: Arc<str>,
    active_version: i32,
    keys: BTreeMap<i32, Zeroizing<[u8; 32]>>,
}

#[derive(Clone)]
pub(crate) struct SoftwareProjectionVerifiedEmailProtector(Arc<ProjectionVerifiedEmailKeyRing>);

impl SoftwareProjectionVerifiedEmailProtector {
    pub(crate) fn new(
        deployment_context: String,
        active_version: i32,
        active_key: [u8; 32],
        retained: BTreeMap<i32, [u8; 32]>,
    ) -> Result<Self, ApplicationError> {
        if deployment_context.is_empty()
            || deployment_context.len() > 128
            || active_version <= 0
            || retained.keys().any(|version| *version <= 0)
            || retained.contains_key(&active_version)
        {
            return Err(ApplicationError::InvalidInput);
        }
        let mut keys = retained
            .into_iter()
            .map(|(version, key)| (version, Zeroizing::new(key)))
            .collect::<BTreeMap<_, _>>();
        keys.insert(active_version, Zeroizing::new(active_key));
        Ok(Self(Arc::new(ProjectionVerifiedEmailKeyRing {
            deployment_context: Arc::from(deployment_context),
            active_version,
            keys,
        })))
    }

    fn active_version(&self) -> i32 {
        self.0.active_version
    }

    fn readable_versions(&self) -> BTreeSet<i32> {
        self.0.keys.keys().copied().collect()
    }

    fn context(
        project_id: uuid::Uuid,
        application_id: uuid::Uuid,
        user_id: uuid::Uuid,
        projection_revision: i64,
    ) -> Result<Vec<u8>, ApplicationError> {
        if projection_revision <= 0 {
            return Err(ApplicationError::Integrity);
        }
        let mut context = Vec::with_capacity(112);
        context.extend_from_slice(b"owlauth-application-projection-email-v1\0");
        context.extend_from_slice(project_id.as_bytes());
        context.extend_from_slice(application_id.as_bytes());
        context.extend_from_slice(user_id.as_bytes());
        context.extend_from_slice(&projection_revision.to_be_bytes());
        context.extend_from_slice(crate::domain::USER_PROJECTION_SCHEMA_V1.as_bytes());
        Ok(context)
    }

    fn associated_data(
        &self,
        key_version: i32,
        context: &[u8],
    ) -> Result<Vec<u8>, ApplicationError> {
        let purpose = ProtectedPurpose::ApplicationProjectionVerifiedEmail;
        let mut associated_data = Vec::with_capacity(
            PROJECTION_EMAIL_PROTECTION_DOMAIN.len()
                + self.0.deployment_context.len()
                + purpose.as_str().len()
                + context.len()
                + 48,
        );
        associated_data.extend_from_slice(PROJECTION_EMAIL_PROTECTION_DOMAIN);
        append_framed(&mut associated_data, self.0.deployment_context.as_bytes())?;
        append_framed(&mut associated_data, &key_version.to_be_bytes())?;
        append_framed(&mut associated_data, purpose.as_str().as_bytes())?;
        append_framed(&mut associated_data, context)?;
        Ok(associated_data)
    }

    fn protect_context(
        &self,
        context: &[u8],
        value: &[u8],
    ) -> Result<ProtectedValue, ApplicationError> {
        let key = self
            .0
            .keys
            .get(&self.0.active_version)
            .ok_or(ApplicationError::Integrity)?;
        let cipher = XChaCha20Poly1305::new_from_slice(key.as_ref())
            .map_err(|_| ApplicationError::Integrity)?;
        let mut nonce = [0_u8; NONCE_BYTES];
        getrandom::fill(&mut nonce).map_err(|_| ApplicationError::ExternalStore)?;
        let associated_data = self.associated_data(self.0.active_version, context)?;
        let nonce_value = XNonce::from(nonce);
        let encrypted = cipher
            .encrypt(
                &nonce_value,
                Payload {
                    msg: value,
                    aad: &associated_data,
                },
            )
            .map_err(|_| ApplicationError::Integrity)?;
        let mut ciphertext = Vec::with_capacity(NONCE_BYTES + encrypted.len());
        ciphertext.extend_from_slice(&nonce);
        ciphertext.extend_from_slice(&encrypted);
        nonce.fill(0);
        Ok(ProtectedValue {
            ciphertext,
            key_version: self.0.active_version,
        })
    }

    fn unprotect_context(
        &self,
        context: &[u8],
        value: &ProtectedValue,
    ) -> Result<Zeroizing<Vec<u8>>, ApplicationError> {
        if value.ciphertext.len() < NONCE_BYTES + TAG_BYTES {
            return Err(ApplicationError::Integrity);
        }
        let key = self
            .0
            .keys
            .get(&value.key_version)
            .ok_or(ApplicationError::Integrity)?;
        let cipher = XChaCha20Poly1305::new_from_slice(key.as_ref())
            .map_err(|_| ApplicationError::Integrity)?;
        let (nonce, ciphertext) = value.ciphertext.split_at(NONCE_BYTES);
        let nonce: [u8; NONCE_BYTES] = nonce.try_into().map_err(|_| ApplicationError::Integrity)?;
        let nonce_value = XNonce::from(nonce);
        let associated_data = self.associated_data(value.key_version, context)?;
        cipher
            .decrypt(
                &nonce_value,
                Payload {
                    msg: ciphertext,
                    aad: &associated_data,
                },
            )
            .map(Zeroizing::new)
            .map_err(|_| ApplicationError::Integrity)
    }
}

impl crate::application::ProjectionVerifiedEmailProtector
    for SoftwareProjectionVerifiedEmailProtector
{
    fn write_version(&self) -> i32 {
        self.active_version()
    }

    fn readable_versions(&self) -> BTreeSet<i32> {
        self.readable_versions()
    }

    fn protect_verified_email(
        &self,
        project_id: uuid::Uuid,
        application_id: uuid::Uuid,
        user_id: uuid::Uuid,
        projection_revision: i64,
        email: &[u8],
    ) -> Result<ProtectedValue, ApplicationError> {
        self.protect_context(
            &Self::context(project_id, application_id, user_id, projection_revision)?,
            email,
        )
    }

    fn unprotect_verified_email(
        &self,
        project_id: uuid::Uuid,
        application_id: uuid::Uuid,
        user_id: uuid::Uuid,
        projection_revision: i64,
        value: &ProtectedValue,
    ) -> Result<Zeroizing<String>, ApplicationError> {
        let plaintext = self.unprotect_context(
            &Self::context(project_id, application_id, user_id, projection_revision)?,
            value,
        )?;
        let text =
            std::str::from_utf8(plaintext.as_slice()).map_err(|_| ApplicationError::Integrity)?;
        let canonical = crate::domain::CanonicalEmail::parse_v1(text)
            .map_err(|_| ApplicationError::Integrity)?;
        Ok(Zeroizing::new(canonical.expose().to_owned()))
    }
}

/// Private purpose-limited target key ring shared only behind role-specific facades.
/// The facades have private fields and no conversion API, so composition can never recover this
/// primitive or broaden a Runtime verifier into a Control issuer/replay capability.
struct ManagedReauthorizationTargetKeyRing(SoftwareRuntimeProtector);

impl ManagedReauthorizationTargetKeyRing {
    fn new(
        deployment_context: &str,
        active_version: i32,
        active: RuntimeKeyMaterial,
        retained: BTreeMap<i32, RuntimeKeyMaterial>,
    ) -> Result<Self, ApplicationError> {
        SoftwareRuntimeProtector::new(
            format!("managed-reauthorization-target:{deployment_context}"),
            active_version,
            active,
            retained,
        )
        .map(Self)
    }

    fn digest_handle_at(
        &self,
        interaction_id: uuid::Uuid,
        value: &[u8],
        key_version: i32,
    ) -> Result<VersionedDigest, ApplicationError> {
        self.0.digest_at(
            OpaquePurpose::ManagedReauthorization,
            interaction_id.as_bytes(),
            value,
            key_version,
        )
    }
}

#[derive(Clone)]
pub(crate) struct SoftwareManagedReauthorizationTargetIssuer(
    Arc<ManagedReauthorizationTargetKeyRing>,
);

impl SoftwareManagedReauthorizationTargetIssuer {
    pub(crate) fn new(
        deployment_context: &str,
        active_version: i32,
        active: RuntimeKeyMaterial,
        retained: BTreeMap<i32, RuntimeKeyMaterial>,
    ) -> Result<Self, ApplicationError> {
        ManagedReauthorizationTargetKeyRing::new(
            deployment_context,
            active_version,
            active,
            retained,
        )
        .map(Arc::new)
        .map(Self)
    }
}

impl ManagedReauthorizationTargetIssuer for SoftwareManagedReauthorizationTargetIssuer {
    fn random_handle(&self, bytes: usize) -> Result<Zeroizing<String>, ApplicationError> {
        self.0.0.random_opaque(bytes)
    }

    fn digest_handle(
        &self,
        interaction_id: uuid::Uuid,
        value: &[u8],
    ) -> Result<VersionedDigest, ApplicationError> {
        self.0.0.digest(
            OpaquePurpose::ManagedReauthorization,
            interaction_id.as_bytes(),
            value,
        )
    }

    fn protect_create_result(
        &self,
        interaction_id: uuid::Uuid,
        value: &[u8],
    ) -> Result<ProtectedValue, ApplicationError> {
        self.0.0.protect(
            ProtectedPurpose::ManagedReauthorizationCreateResult,
            interaction_id.as_bytes(),
            value,
        )
    }

    fn replay_create_result(
        &self,
        interaction_id: uuid::Uuid,
        value: &ProtectedValue,
    ) -> Result<Zeroizing<Vec<u8>>, ApplicationError> {
        self.0.0.unprotect(
            ProtectedPurpose::ManagedReauthorizationCreateResult,
            interaction_id.as_bytes(),
            value,
        )
    }
}

#[derive(Clone)]
pub(crate) struct SoftwareManagedReauthorizationTargetVerifier(
    Arc<ManagedReauthorizationTargetKeyRing>,
);

impl SoftwareManagedReauthorizationTargetVerifier {
    pub(crate) fn new(
        deployment_context: &str,
        active_version: i32,
        active: RuntimeKeyMaterial,
        retained: BTreeMap<i32, RuntimeKeyMaterial>,
    ) -> Result<Self, ApplicationError> {
        ManagedReauthorizationTargetKeyRing::new(
            deployment_context,
            active_version,
            active,
            retained,
        )
        .map(Arc::new)
        .map(Self)
    }
}

impl ManagedReauthorizationTargetVerifier for SoftwareManagedReauthorizationTargetVerifier {
    fn readable_key_versions(&self) -> BTreeSet<i32> {
        RuntimeProtector::readable_key_versions(&self.0.0)
    }

    fn digest_handle_at(
        &self,
        interaction_id: uuid::Uuid,
        value: &[u8],
        key_version: i32,
    ) -> Result<VersionedDigest, ApplicationError> {
        self.0.digest_handle_at(interaction_id, value, key_version)
    }
}

/// Private identity-mutation target ring exposed only through plane-specific capabilities.
/// It may reuse configured root bytes with other short-lived target rings, but its deployment
/// context and purpose labels provide independent cryptographic domains.
struct IdentityMutationTargetKeyRing(SoftwareRuntimeProtector);

#[allow(
    dead_code,
    reason = "identity mutation target composition follows its PostgreSQL repository"
)]
impl IdentityMutationTargetKeyRing {
    fn new(
        deployment_context: &str,
        active_version: i32,
        active: RuntimeKeyMaterial,
        retained: BTreeMap<i32, RuntimeKeyMaterial>,
    ) -> Result<Self, ApplicationError> {
        SoftwareRuntimeProtector::new(
            format!("identity-mutation-target:{deployment_context}"),
            active_version,
            active,
            retained,
        )
        .map(Self)
    }

    fn digest_handle_at(
        &self,
        intent_id: uuid::Uuid,
        value: &[u8],
        key_version: i32,
    ) -> Result<VersionedDigest, ApplicationError> {
        self.0.digest_at(
            OpaquePurpose::IdentityMutationIntent,
            intent_id.as_bytes(),
            value,
            key_version,
        )
    }
}

#[derive(Clone)]
pub(crate) struct SoftwareIdentityMutationTargetIssuer(Arc<IdentityMutationTargetKeyRing>);

#[allow(
    dead_code,
    reason = "identity mutation Control composition follows its PostgreSQL repository"
)]
impl SoftwareIdentityMutationTargetIssuer {
    pub(crate) fn new(
        deployment_context: &str,
        active_version: i32,
        active: RuntimeKeyMaterial,
        retained: BTreeMap<i32, RuntimeKeyMaterial>,
    ) -> Result<Self, ApplicationError> {
        IdentityMutationTargetKeyRing::new(deployment_context, active_version, active, retained)
            .map(Arc::new)
            .map(Self)
    }
}

impl IdentityMutationTargetIssuer for SoftwareIdentityMutationTargetIssuer {
    fn random_handle(&self, bytes: usize) -> Result<Zeroizing<String>, ApplicationError> {
        self.0.0.random_opaque(bytes)
    }

    fn digest_handle(
        &self,
        intent_id: uuid::Uuid,
        value: &[u8],
    ) -> Result<VersionedDigest, ApplicationError> {
        self.0.0.digest(
            OpaquePurpose::IdentityMutationIntent,
            intent_id.as_bytes(),
            value,
        )
    }

    fn protect_create_result(
        &self,
        intent_id: uuid::Uuid,
        value: &[u8],
    ) -> Result<ProtectedValue, ApplicationError> {
        self.0.0.protect(
            ProtectedPurpose::IdentityMutationCreateResult,
            intent_id.as_bytes(),
            value,
        )
    }

    fn replay_create_result(
        &self,
        intent_id: uuid::Uuid,
        value: &ProtectedValue,
    ) -> Result<Zeroizing<Vec<u8>>, ApplicationError> {
        self.0.0.unprotect(
            ProtectedPurpose::IdentityMutationCreateResult,
            intent_id.as_bytes(),
            value,
        )
    }
}

#[derive(Clone)]
pub(crate) struct SoftwareIdentityMutationTargetVerifier(Arc<IdentityMutationTargetKeyRing>);

#[allow(
    dead_code,
    reason = "identity mutation Runtime composition follows its PostgreSQL repository"
)]
impl SoftwareIdentityMutationTargetVerifier {
    pub(crate) fn new(
        deployment_context: &str,
        active_version: i32,
        active: RuntimeKeyMaterial,
        retained: BTreeMap<i32, RuntimeKeyMaterial>,
    ) -> Result<Self, ApplicationError> {
        IdentityMutationTargetKeyRing::new(deployment_context, active_version, active, retained)
            .map(Arc::new)
            .map(Self)
    }
}

impl IdentityMutationTargetVerifier for SoftwareIdentityMutationTargetVerifier {
    #[cfg(test)]
    fn readable_key_versions(&self) -> BTreeSet<i32> {
        RuntimeProtector::readable_key_versions(&self.0.0)
    }

    fn digest_handle_at(
        &self,
        intent_id: uuid::Uuid,
        value: &[u8],
        key_version: i32,
    ) -> Result<VersionedDigest, ApplicationError> {
        self.0.digest_handle_at(intent_id, value, key_version)
    }
}

/// Private, dedicated candidate-evidence ring. It is constructed directly from the reviewed
/// `OWLAUTH_IDENTITY_MUTATION_EVIDENCE_*` material and is never interchangeable with the generic
/// Runtime protector. Plane-specific facades deliberately expose disjoint producer/verifier
/// capabilities.
struct IdentityMutationEvidenceKeyRing(SoftwareRuntimeProtector);

impl IdentityMutationEvidenceKeyRing {
    fn new(
        deployment_context: &str,
        active_version: i32,
        active: RuntimeKeyMaterial,
        retained: BTreeMap<i32, RuntimeKeyMaterial>,
    ) -> Result<Self, ApplicationError> {
        SoftwareRuntimeProtector::new(
            format!("identity-mutation-evidence-v1:{deployment_context}"),
            active_version,
            active,
            retained,
        )
        .map(Self)
    }
}

#[derive(Clone)]
pub(crate) struct SoftwareIdentityMutationProofMaterialProtector(
    Arc<IdentityMutationEvidenceKeyRing>,
);

impl SoftwareIdentityMutationProofMaterialProtector {
    pub(crate) fn new(
        deployment_context: &str,
        active_version: i32,
        active: RuntimeKeyMaterial,
        retained: BTreeMap<i32, RuntimeKeyMaterial>,
    ) -> Result<Self, ApplicationError> {
        IdentityMutationEvidenceKeyRing::new(deployment_context, active_version, active, retained)
            .map(Arc::new)
            .map(Self)
    }
}

impl IdentityMutationProofMaterialProtector for SoftwareIdentityMutationProofMaterialProtector {
    fn protect_candidate(
        &self,
        context: IdentityMutationCandidateEvidenceContext,
        plaintext: &[u8],
    ) -> Result<CandidateEvidenceMaterial, ApplicationError> {
        let cryptographic_context = identity_mutation_candidate_context(&context);
        Ok(CandidateEvidenceMaterial {
            ciphertext: self.0.0.protect(
                ProtectedPurpose::IdentityMutationCandidateEvidence,
                &cryptographic_context,
                plaintext,
            )?,
            digest: self.0.0.digest(
                OpaquePurpose::IdentityMutationCandidateEvidenceDigest,
                &cryptographic_context,
                plaintext,
            )?,
            context,
        })
    }

    fn issue_receipt_digest(
        &self,
        intent_id: uuid::Uuid,
        proof_slot_id: uuid::Uuid,
    ) -> Result<VersionedDigest, ApplicationError> {
        let secret = self.0.0.random_opaque(32)?;
        self.0.0.digest(
            OpaquePurpose::IdentityMutationReceipt,
            &identity_mutation_slot_context(intent_id, proof_slot_id),
            secret.as_bytes(),
        )
    }
}

/// Control-only view of candidate evidence cryptography. The capability cannot issue evidence or
/// receipts, so composition cannot accidentally promote a final-confirmation reader into a proof
/// producer.
#[derive(Clone)]
pub(crate) struct SoftwareIdentityMutationCandidateVerifier(Arc<IdentityMutationEvidenceKeyRing>);

impl SoftwareIdentityMutationCandidateVerifier {
    pub(crate) fn new(
        deployment_context: &str,
        active_version: i32,
        active: RuntimeKeyMaterial,
        retained: BTreeMap<i32, RuntimeKeyMaterial>,
    ) -> Result<Self, ApplicationError> {
        IdentityMutationEvidenceKeyRing::new(deployment_context, active_version, active, retained)
            .map(Arc::new)
            .map(Self)
    }
}

impl IdentityMutationCandidateVerifier for SoftwareIdentityMutationCandidateVerifier {
    fn unprotect_candidate(
        &self,
        context: &IdentityMutationCandidateEvidenceContext,
        ciphertext: &ProtectedValue,
    ) -> Result<Zeroizing<Vec<u8>>, ApplicationError> {
        self.0.0.unprotect(
            ProtectedPurpose::IdentityMutationCandidateEvidence,
            &identity_mutation_candidate_context(context),
            ciphertext,
        )
    }

    fn digest_candidate_at(
        &self,
        context: &IdentityMutationCandidateEvidenceContext,
        plaintext: &[u8],
        key_version: i32,
    ) -> Result<VersionedDigest, ApplicationError> {
        self.0.0.digest_at(
            OpaquePurpose::IdentityMutationCandidateEvidenceDigest,
            &identity_mutation_candidate_context(context),
            plaintext,
            key_version,
        )
    }
}

/// Runtime-only view of the durable email-identity ring used when an email candidate becomes a
/// real identity during final confirmation.
#[derive(Clone)]
pub(crate) struct SoftwareIdentityMutationDurableEmailProtector {
    protector: Arc<dyn RuntimeProtector>,
}

#[allow(
    dead_code,
    reason = "identity mutation Runtime composition follows its PostgreSQL repository"
)]
impl SoftwareIdentityMutationDurableEmailProtector {
    pub(crate) fn new(protector: Arc<dyn RuntimeProtector>) -> Self {
        Self { protector }
    }
}

impl IdentityMutationDurableEmailProtector for SoftwareIdentityMutationDurableEmailProtector {
    fn protect_durable_address(
        &self,
        project_id: uuid::Uuid,
        identity_id: uuid::Uuid,
        normalized_address: &[u8],
    ) -> Result<ProtectedValue, ApplicationError> {
        self.protector.protect(
            ProtectedPurpose::EmailIdentityAddress,
            &email_identity_context(project_id, identity_id),
            normalized_address,
        )
    }
}

fn identity_mutation_slot_context(intent_id: uuid::Uuid, proof_slot_id: uuid::Uuid) -> [u8; 32] {
    let mut context = [0_u8; 32];
    context[..16].copy_from_slice(intent_id.as_bytes());
    context[16..].copy_from_slice(proof_slot_id.as_bytes());
    context
}

fn identity_mutation_candidate_context(
    context: &IdentityMutationCandidateEvidenceContext,
) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(112);
    encoded.extend_from_slice(b"owlauth-identity-mutation-candidate-v1\0");
    encoded.extend_from_slice(context.project_id.as_bytes());
    encoded.extend_from_slice(context.intent_id.as_bytes());
    encoded.extend_from_slice(context.proof_slot_id.as_bytes());
    encoded.extend_from_slice(context.evidence_id.as_bytes());
    encoded.extend_from_slice(&context.evidence_revision.to_be_bytes());
    encoded.push(match context.candidate_kind {
        IdentityMutationCandidateKind::Provider => 1,
        IdentityMutationCandidateKind::Email => 2,
    });
    encoded
}

fn email_identity_context(project_id: uuid::Uuid, identity_id: uuid::Uuid) -> Vec<u8> {
    let mut context = Vec::with_capacity(58);
    context.extend_from_slice(b"owlauth-email-identity-v1\0");
    context.extend_from_slice(project_id.as_bytes());
    context.extend_from_slice(identity_id.as_bytes());
    context
}

/// Dedicated long-lived managed-credential AEAD material. It intentionally cannot provide
/// Runtime digest, derivation, or short-term protection capabilities.
pub(crate) struct ManagedCredentialKeyMaterial(Zeroizing<[u8; 32]>);

impl ManagedCredentialKeyMaterial {
    pub(crate) fn new(key: [u8; 32]) -> Self {
        Self(Zeroizing::new(key))
    }
}

#[derive(Clone)]
pub(crate) struct SoftwareManagedCredentialProtector {
    deployment_context: Arc<str>,
    active_version: i32,
    keys: Arc<BTreeMap<i32, ManagedCredentialKeyMaterial>>,
}

impl SoftwareManagedCredentialProtector {
    pub(crate) fn new(
        deployment_context: String,
        active_version: i32,
        active: ManagedCredentialKeyMaterial,
        retained: BTreeMap<i32, ManagedCredentialKeyMaterial>,
    ) -> Result<Self, ApplicationError> {
        if deployment_context.is_empty()
            || deployment_context.len() > 128
            || active_version <= 0
            || retained.keys().any(|version| *version <= 0)
            || retained.contains_key(&active_version)
        {
            return Err(ApplicationError::InvalidInput);
        }
        let mut keys = retained;
        keys.insert(active_version, active);
        Ok(Self {
            deployment_context: Arc::from(deployment_context),
            active_version,
            keys: Arc::new(keys),
        })
    }

    fn associated_data(
        &self,
        version: i32,
        context: &ManagedCredentialContext,
    ) -> Result<Vec<u8>, ApplicationError> {
        let encoded = context.encode();
        let mut aad = Vec::with_capacity(
            MANAGED_CREDENTIAL_DOMAIN.len() + self.deployment_context.len() + encoded.len() + 32,
        );
        aad.extend_from_slice(MANAGED_CREDENTIAL_DOMAIN);
        append_framed(&mut aad, self.deployment_context.as_bytes())?;
        append_framed(&mut aad, &version.to_be_bytes())?;
        append_framed(
            &mut aad,
            ProtectedPurpose::ManagedProviderCredential
                .as_str()
                .as_bytes(),
        )?;
        append_framed(&mut aad, &encoded)?;
        Ok(aad)
    }
}

impl ManagedCredentialProtector for SoftwareManagedCredentialProtector {
    fn protect_credential(
        &self,
        context: &ManagedCredentialContext,
        credential: &[u8],
    ) -> Result<ProtectedValue, ApplicationError> {
        if credential.is_empty() || credential.len() > 8192 {
            return Err(ApplicationError::InvalidInput);
        }
        let key = self
            .keys
            .get(&self.active_version)
            .ok_or(ApplicationError::Integrity)?;
        let cipher = XChaCha20Poly1305::new_from_slice(key.0.as_ref())
            .map_err(|_| ApplicationError::Integrity)?;
        let mut nonce = [0_u8; NONCE_BYTES];
        getrandom::fill(&mut nonce).map_err(|_| ApplicationError::ExternalStore)?;
        let nonce_value = XNonce::from(nonce);
        let aad = self.associated_data(self.active_version, context)?;
        let encrypted = cipher
            .encrypt(
                &nonce_value,
                Payload {
                    msg: credential,
                    aad: &aad,
                },
            )
            .map_err(|_| ApplicationError::Integrity)?;
        let mut ciphertext = Vec::with_capacity(NONCE_BYTES + encrypted.len());
        ciphertext.extend_from_slice(&nonce);
        ciphertext.extend_from_slice(&encrypted);
        nonce.fill(0);
        Ok(ProtectedValue {
            ciphertext,
            key_version: self.active_version,
        })
    }

    fn unprotect_credential(
        &self,
        context: &ManagedCredentialContext,
        value: &ProtectedValue,
    ) -> Result<Zeroizing<Vec<u8>>, ApplicationError> {
        if value.ciphertext.len() < NONCE_BYTES + TAG_BYTES {
            return Err(ApplicationError::Integrity);
        }
        let key = self
            .keys
            .get(&value.key_version)
            .ok_or(ApplicationError::Integrity)?;
        let cipher = XChaCha20Poly1305::new_from_slice(key.0.as_ref())
            .map_err(|_| ApplicationError::Integrity)?;
        let (nonce, ciphertext) = value.ciphertext.split_at(NONCE_BYTES);
        let nonce: [u8; NONCE_BYTES] = nonce.try_into().map_err(|_| ApplicationError::Integrity)?;
        let nonce_value = XNonce::from(nonce);
        let aad = self.associated_data(value.key_version, context)?;
        cipher
            .decrypt(
                &nonce_value,
                Payload {
                    msg: ciphertext,
                    aad: &aad,
                },
            )
            .map(Zeroizing::new)
            .map_err(|_| ApplicationError::Integrity)
    }

    fn readable_key_versions(&self) -> BTreeSet<i32> {
        self.keys.keys().copied().collect()
    }

    fn active_key_version(&self) -> i32 {
        self.active_version
    }
}

// Retained for focused unit and repository fixtures that intentionally exercise both traits on one
// object. Production composition never supplies this short-term protector as managed custody.
impl ManagedCredentialProtector for SoftwareRuntimeProtector {
    fn protect_credential(
        &self,
        context: &ManagedCredentialContext,
        credential: &[u8],
    ) -> Result<ProtectedValue, ApplicationError> {
        if credential.is_empty() || credential.len() > 8192 {
            return Err(ApplicationError::InvalidInput);
        }
        RuntimeProtector::protect(
            self,
            ProtectedPurpose::ManagedProviderCredential,
            &context.encode(),
            credential,
        )
    }

    fn unprotect_credential(
        &self,
        context: &ManagedCredentialContext,
        value: &ProtectedValue,
    ) -> Result<Zeroizing<Vec<u8>>, ApplicationError> {
        RuntimeProtector::unprotect(
            self,
            ProtectedPurpose::ManagedProviderCredential,
            &context.encode(),
            value,
        )
    }

    fn readable_key_versions(&self) -> BTreeSet<i32> {
        self.keys.keys().copied().collect()
    }

    fn active_key_version(&self) -> i32 {
        self.active_version
    }
}

/// A signer capability over an encrypted file store. It cannot read or return signing seeds.
#[cfg(test)]
#[derive(Clone)]
pub(crate) struct EncryptedFileRuntimeSigner {
    store: EncryptedFileStore,
}

#[cfg(test)]
impl EncryptedFileRuntimeSigner {
    pub(crate) fn new(store: EncryptedFileStore) -> Self {
        Self { store }
    }
}

#[cfg(test)]
#[async_trait]
impl RuntimeSigner for EncryptedFileRuntimeSigner {
    async fn sign(
        &self,
        signer_ref: &str,
        signing_input: &[u8],
    ) -> Result<Vec<u8>, ApplicationError> {
        self.store
            .sign_ed25519(signer_ref, signing_input)
            .await
            .map_err(authoritative_reference_error)
    }

    fn verify(
        &self,
        public_jwk: &Value,
        signing_input: &[u8],
        signature: &[u8],
    ) -> Result<(), ApplicationError> {
        verify_ed25519(public_jwk, signing_input, signature)
    }
}

/// A resolver capability over an encrypted file store. References are used exactly as supplied.
#[cfg(test)]
#[derive(Clone)]
pub(crate) struct EncryptedFileProviderSecretResolver {
    store: EncryptedFileStore,
}

#[cfg(test)]
impl EncryptedFileProviderSecretResolver {
    pub(crate) fn new(store: EncryptedFileStore) -> Self {
        Self { store }
    }
}

#[cfg(test)]
#[async_trait]
impl ProviderSecretResolver for EncryptedFileProviderSecretResolver {
    async fn resolve(&self, secret_ref: &str) -> Result<Zeroizing<String>, ApplicationError> {
        self.store
            .read_utf8_secret(secret_ref)
            .await
            .map_err(authoritative_reference_error)
    }
}

#[cfg(test)]
#[async_trait]
impl crate::application::WebhookSecretResolver for EncryptedFileProviderSecretResolver {
    async fn resolve(&self, reference: &str) -> Result<Zeroizing<Vec<u8>>, ApplicationError> {
        let value = self
            .store
            .read_utf8_secret(reference)
            .await
            .map_err(authoritative_reference_error)?;
        Ok(Zeroizing::new(value.as_bytes().to_vec()))
    }

    async fn erase(&self, reference: &str) -> Result<(), ApplicationError> {
        self.store
            .erase(reference.to_owned())
            .await
            .map_err(|_| ApplicationError::ExternalStore)
    }
}

#[cfg(test)]
#[async_trait]
impl crate::application::SmtpCredentialResolver for EncryptedFileProviderSecretResolver {
    async fn resolve(&self, reference: &str) -> Result<Zeroizing<Vec<u8>>, ApplicationError> {
        let value = self
            .store
            .read_utf8_secret(reference)
            .await
            .map_err(authoritative_reference_error)?;
        Ok(Zeroizing::new(value.as_bytes().to_vec()))
    }

    async fn resolve_checked(
        &self,
        reference: &str,
        expected_fingerprint: &[u8; 32],
    ) -> Result<Zeroizing<Vec<u8>>, ApplicationError> {
        let value = crate::application::SmtpCredentialResolver::resolve(self, reference).await?;
        if self.store.request_fingerprint(value.as_slice()) != *expected_fingerprint {
            return Err(ApplicationError::Disabled);
        }
        Ok(value)
    }

    async fn erase(&self, reference: &str) -> Result<(), ApplicationError> {
        self.store
            .erase(reference.to_owned())
            .await
            .map_err(|_| ApplicationError::ExternalStore)
    }
}

pub(crate) fn verify_ed25519(
    public_jwk: &Value,
    signing_input: &[u8],
    signature: &[u8],
) -> Result<(), ApplicationError> {
    let jwk = public_jwk.as_object().ok_or(ApplicationError::Integrity)?;
    validate_public_ed25519_jwk(jwk)?;
    let encoded_key = jwk
        .get("x")
        .and_then(Value::as_str)
        .ok_or(ApplicationError::Integrity)?;
    let decoded_key = URL_SAFE_NO_PAD
        .decode(encoded_key)
        .map_err(|_| ApplicationError::Integrity)?;
    if URL_SAFE_NO_PAD.encode(&decoded_key) != encoded_key {
        return Err(ApplicationError::Integrity);
    }
    let key_bytes: [u8; 32] = decoded_key
        .try_into()
        .map_err(|_| ApplicationError::Integrity)?;
    let verifying_key =
        VerifyingKey::from_bytes(&key_bytes).map_err(|_| ApplicationError::Integrity)?;
    let signature = Signature::from_slice(signature).map_err(|_| ApplicationError::InvalidInput)?;
    verifying_key
        .verify_strict(signing_input, &signature)
        .map_err(|_| ApplicationError::InvalidTransition)
}

fn validate_public_ed25519_jwk(jwk: &Map<String, Value>) -> Result<(), ApplicationError> {
    const ALLOWED_FIELDS: [&str; 6] = ["alg", "crv", "kid", "kty", "use", "x"];
    let fields_are_known = jwk
        .keys()
        .all(|field| ALLOWED_FIELDS.contains(&field.as_str()));
    if !fields_are_known
        || jwk.get("kty").and_then(Value::as_str) != Some("OKP")
        || jwk.get("crv").and_then(Value::as_str) != Some("Ed25519")
        || jwk.get("alg").and_then(Value::as_str) != Some(SIGNING_ALGORITHM)
        || jwk.get("use").and_then(Value::as_str) != Some("sig")
        || !jwk.get("x").is_some_and(Value::is_string)
        || jwk
            .get("kid")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
    {
        return Err(ApplicationError::Integrity);
    }
    Ok(())
}

#[cfg(test)]
fn authoritative_reference_error(error: ApplicationError) -> ApplicationError {
    if error == ApplicationError::InvalidInput {
        ApplicationError::Integrity
    } else {
        error
    }
}

fn update_framed(mac: &mut HmacSha256, value: &[u8]) -> Result<(), ApplicationError> {
    let length = u64::try_from(value.len()).map_err(|_| ApplicationError::InvalidInput)?;
    mac.update(&length.to_be_bytes());
    mac.update(value);
    Ok(())
}

fn append_framed(output: &mut Vec<u8>, value: &[u8]) -> Result<(), ApplicationError> {
    let length = u64::try_from(value.len()).map_err(|_| ApplicationError::InvalidInput)?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value);
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, fs, path::PathBuf};

    use ed25519_dalek::SigningKey;
    use serde_json::json;
    use uuid::Uuid;

    use super::*;

    fn material(digest: u8, protection: u8) -> RuntimeKeyMaterial {
        RuntimeKeyMaterial::new([digest; 32], [protection; 32])
    }

    fn protector() -> SoftwareRuntimeProtector {
        SoftwareRuntimeProtector::new(
            "deployment".to_owned(),
            2,
            material(2, 12),
            BTreeMap::from([(1, material(1, 11))]),
        )
        .unwrap()
    }

    fn temporary_root(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!("owlauth-{label}-{}", Uuid::new_v4()))
    }

    #[test]
    fn managed_reauthorization_target_roles_rotate_without_cross_role_authority() {
        let interaction_id = Uuid::new_v4();
        let old_issuer = SoftwareManagedReauthorizationTargetIssuer::new(
            "deployment",
            1,
            material(21, 31),
            BTreeMap::new(),
        )
        .expect("old target issuer");
        let digest = old_issuer
            .digest_handle(interaction_id, b"opaque-target")
            .expect("target digest");
        let protected = old_issuer
            .protect_create_result(interaction_id, b"https://runtime.example/target")
            .expect("protected target");

        let rotated_verifier = SoftwareManagedReauthorizationTargetVerifier::new(
            "deployment",
            2,
            material(22, 32),
            BTreeMap::from([(1, material(21, 31))]),
        )
        .expect("rotated target verifier");
        assert_eq!(
            rotated_verifier
                .digest_handle_at(interaction_id, b"opaque-target", 1)
                .expect("retained target digest"),
            digest
        );
        assert_eq!(
            rotated_verifier.readable_key_versions(),
            BTreeSet::from([1, 2])
        );

        let rotated_issuer = SoftwareManagedReauthorizationTargetIssuer::new(
            "deployment",
            2,
            material(22, 32),
            BTreeMap::from([(1, material(21, 31))]),
        )
        .expect("rotated target issuer");
        assert_eq!(
            rotated_issuer
                .replay_create_result(interaction_id, &protected)
                .expect("retained replay decrypt")
                .as_slice(),
            b"https://runtime.example/target"
        );

        let without_old = SoftwareManagedReauthorizationTargetVerifier::new(
            "deployment",
            2,
            material(22, 32),
            BTreeMap::new(),
        )
        .expect("target verifier without retained key");
        assert_eq!(
            without_old
                .digest_handle_at(interaction_id, b"opaque-target", 1)
                .expect_err("missing retained digest fails closed"),
            ApplicationError::Integrity
        );

        let runtime = protector();
        assert_eq!(
            runtime
                .unprotect(
                    ProtectedPurpose::ManagedReauthorizationCreateResult,
                    interaction_id.as_bytes(),
                    &protected,
                )
                .expect_err("generic Runtime roots cannot decrypt the dedicated target"),
            ApplicationError::Integrity
        );
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one custody test keeps target, evidence, context, and receipt non-interchangeability together"
    )]
    fn identity_mutation_target_and_proof_material_are_role_and_context_bound() {
        let intent_id = Uuid::new_v4();
        let slot_id = Uuid::new_v4();
        let issuer = SoftwareIdentityMutationTargetIssuer::new(
            "deployment",
            1,
            material(41, 51),
            BTreeMap::new(),
        )
        .expect("identity mutation target issuer");
        let digest = issuer
            .digest_handle(intent_id, b"opaque-target")
            .expect("identity mutation target digest");
        let protected = issuer
            .protect_create_result(intent_id, b"https://runtime.example/identity-target")
            .expect("protected identity mutation target");
        let verifier = SoftwareIdentityMutationTargetVerifier::new(
            "deployment",
            2,
            material(42, 52),
            BTreeMap::from([(1, material(41, 51))]),
        )
        .expect("identity mutation target verifier");
        assert_eq!(
            verifier
                .digest_handle_at(intent_id, b"opaque-target", 1)
                .expect("retained target digest"),
            digest
        );
        assert_eq!(verifier.readable_key_versions(), BTreeSet::from([1, 2]));

        let managed = SoftwareManagedReauthorizationTargetVerifier::new(
            "deployment",
            1,
            material(41, 51),
            BTreeMap::new(),
        )
        .expect("managed target verifier");
        assert_ne!(
            managed
                .digest_handle_at(intent_id, b"opaque-target", 1)
                .expect("managed target digest"),
            digest,
            "shared root bytes must remain separated by target domain"
        );
        assert_eq!(
            protector()
                .unprotect(
                    ProtectedPurpose::IdentityMutationCreateResult,
                    intent_id.as_bytes(),
                    &protected,
                )
                .expect_err("generic Runtime roots cannot replay Control target"),
            ApplicationError::Integrity
        );

        let proof = SoftwareIdentityMutationProofMaterialProtector::new(
            "deployment",
            2,
            material(31, 32),
            BTreeMap::from([(1, material(29, 30))]),
        )
        .expect("evidence producer");
        let verifier = SoftwareIdentityMutationCandidateVerifier::new(
            "deployment",
            2,
            material(31, 32),
            BTreeMap::from([(1, material(29, 30))]),
        )
        .expect("evidence verifier");
        let evidence_context = IdentityMutationCandidateEvidenceContext {
            project_id: Uuid::new_v4(),
            intent_id,
            proof_slot_id: slot_id,
            evidence_id: Uuid::new_v4(),
            evidence_revision: 1,
            candidate_kind: IdentityMutationCandidateKind::Provider,
        };
        let candidate = proof
            .protect_candidate(evidence_context.clone(), b"candidate-evidence")
            .expect("candidate protection");
        assert_eq!(candidate.context, evidence_context);
        let plaintext = verifier
            .unprotect_candidate(&candidate.context, &candidate.ciphertext)
            .expect("candidate decrypt");
        assert_eq!(plaintext.as_slice(), b"candidate-evidence");
        assert_eq!(
            candidate.digest,
            verifier
                .digest_candidate_at(
                    &candidate.context,
                    plaintext.as_slice(),
                    candidate.digest.key_version,
                )
                .expect("candidate digest")
        );
        let mut wrong_context = candidate.context.clone();
        wrong_context.evidence_id = Uuid::new_v4();
        assert_eq!(
            verifier
                .unprotect_candidate(&wrong_context, &candidate.ciphertext)
                .expect_err("candidate cannot move between evidence envelopes"),
            ApplicationError::Integrity
        );
        assert_ne!(
            proof
                .issue_receipt_digest(intent_id, slot_id)
                .expect("first receipt"),
            proof
                .issue_receipt_digest(intent_id, slot_id)
                .expect("second receipt"),
            "receipt anchors require fresh discarded entropy"
        );
    }

    #[test]
    fn identity_mutation_evidence_rotates_cross_plane_without_generic_interchangeability() {
        let context = IdentityMutationCandidateEvidenceContext {
            project_id: Uuid::new_v4(),
            intent_id: Uuid::new_v4(),
            proof_slot_id: Uuid::new_v4(),
            evidence_id: Uuid::new_v4(),
            evidence_revision: 1,
            candidate_kind: IdentityMutationCandidateKind::Email,
        };
        let old = SoftwareIdentityMutationProofMaterialProtector::new(
            "deployment",
            1,
            material(41, 42),
            BTreeMap::new(),
        )
        .expect("old producer");
        let evidence = old
            .protect_candidate(context.clone(), b"versioned-candidate")
            .expect("old evidence");
        let rotated = SoftwareIdentityMutationCandidateVerifier::new(
            "deployment",
            2,
            material(43, 44),
            BTreeMap::from([(1, material(41, 42))]),
        )
        .expect("rotated verifier");
        assert_eq!(
            rotated
                .unprotect_candidate(&context, &evidence.ciphertext)
                .expect("retained evidence decrypt")
                .as_slice(),
            b"versioned-candidate"
        );
        assert_eq!(
            rotated
                .digest_candidate_at(&context, b"versioned-candidate", 1)
                .expect("retained evidence digest"),
            evidence.digest
        );
        let wrong = SoftwareIdentityMutationCandidateVerifier::new(
            "deployment",
            1,
            material(45, 46),
            BTreeMap::new(),
        )
        .expect("wrong verifier");
        assert_eq!(
            wrong
                .unprotect_candidate(&context, &evidence.ciphertext)
                .expect_err("unrelated evidence roots fail closed"),
            ApplicationError::Integrity
        );
        let generic = protector();
        assert_eq!(
            generic
                .unprotect(
                    ProtectedPurpose::IdentityMutationCandidateEvidence,
                    &identity_mutation_candidate_context(&context),
                    &evidence.ciphertext,
                )
                .expect_err("generic Runtime roots cannot read evidence"),
            ApplicationError::Integrity
        );
    }

    #[test]
    fn digests_and_derivations_separate_purpose_context_and_version() {
        let protector = protector();
        assert_eq!(protector.active_version(), 2);
        let digest = protector
            .digest(OpaquePurpose::Interaction, b"project-a", b"opaque")
            .unwrap();
        assert_eq!(digest.key_version, 2);
        let old = SoftwareRuntimeProtector::new(
            "deployment".to_owned(),
            1,
            material(1, 11),
            BTreeMap::new(),
        )
        .unwrap();
        assert_eq!(
            protector
                .digest_at(OpaquePurpose::Interaction, b"project-a", b"opaque", 1)
                .unwrap(),
            old.digest(OpaquePurpose::Interaction, b"project-a", b"opaque")
                .unwrap()
        );
        assert_eq!(
            protector.digest_at(OpaquePurpose::Interaction, b"project-a", b"opaque", 99),
            Err(ApplicationError::Integrity)
        );
        let version_one_same_root = SoftwareRuntimeProtector::new(
            "deployment".to_owned(),
            1,
            material(2, 12),
            BTreeMap::new(),
        )
        .unwrap();
        assert_ne!(
            digest.value,
            version_one_same_root
                .digest(OpaquePurpose::Interaction, b"project-a", b"opaque")
                .unwrap()
                .value
        );
        assert_ne!(
            digest.value,
            protector
                .digest(OpaquePurpose::BrowserBinding, b"project-a", b"opaque")
                .unwrap()
                .value
        );
        assert_ne!(
            digest.value,
            protector
                .digest(OpaquePurpose::Interaction, b"project-b", b"opaque")
                .unwrap()
                .value
        );

        let first = protector
            .derive_opaque(OpaquePurpose::InteractionCsrf, b"transaction", Some(1))
            .unwrap();
        assert_eq!(
            first,
            protector
                .derive_opaque(OpaquePurpose::InteractionCsrf, b"transaction", Some(1))
                .unwrap()
        );
        assert_ne!(
            first,
            protector
                .derive_opaque(OpaquePurpose::InteractionCsrf, b"transaction", Some(2))
                .unwrap()
        );
        assert_ne!(
            first,
            protector
                .derive_opaque(OpaquePurpose::OidcNonce, b"transaction", Some(1))
                .unwrap()
        );
        assert_ne!(
            first,
            protector
                .derive_opaque(OpaquePurpose::InteractionCsrf, b"other", Some(1))
                .unwrap()
        );
        assert_eq!(
            protector.derive_opaque(OpaquePurpose::InteractionCsrf, b"transaction", Some(99)),
            Err(ApplicationError::Integrity)
        );
    }

    #[test]
    fn split_rings_rotate_and_retire_independently() {
        let short = SoftwareRuntimeProtector::new(
            "deployment".to_owned(),
            7,
            material(7, 17),
            BTreeMap::new(),
        )
        .unwrap();
        let durable_old = SoftwareRuntimeProtector::new(
            "deployment".to_owned(),
            3,
            material(33, 43),
            BTreeMap::new(),
        )
        .unwrap();
        let durable_value = durable_old
            .protect(
                ProtectedPurpose::EmailIdentityAddress,
                b"identity",
                b"person@example.com",
            )
            .unwrap();
        let split = SplitRuntimeProtector::new(
            short,
            Some(
                SoftwareRuntimeProtector::new(
                    "deployment".to_owned(),
                    4,
                    material(34, 44),
                    BTreeMap::from([(3, material(33, 43))]),
                )
                .unwrap(),
            ),
        );
        assert_eq!(split.active_version(), 7);
        assert_eq!(split.email_identity_active_version(), 4);
        assert_eq!(
            split
                .digest(OpaquePurpose::Interaction, b"login", b"value")
                .unwrap()
                .key_version,
            7
        );
        assert_eq!(
            split
                .digest(OpaquePurpose::EmailIdentityLookup, b"project", b"email")
                .unwrap()
                .key_version,
            4
        );
        assert_eq!(
            split
                .unprotect(
                    ProtectedPurpose::EmailIdentityAddress,
                    b"identity",
                    &durable_value,
                )
                .unwrap()
                .as_slice(),
            b"person@example.com"
        );
        assert_eq!(
            split.unprotect(
                ProtectedPurpose::EmailChallengeAddress,
                b"identity",
                &durable_value,
            ),
            Err(ApplicationError::Integrity)
        );
    }

    #[test]
    fn protection_is_context_bound_and_retained_versions_decrypt() {
        let old = SoftwareRuntimeProtector::new(
            "deployment".to_owned(),
            1,
            material(1, 11),
            BTreeMap::new(),
        )
        .unwrap();
        let old_value = old
            .protect(
                ProtectedPurpose::ApplicationState,
                b"application-a",
                b"state",
            )
            .unwrap();
        let rotated = SoftwareRuntimeProtector::new(
            "deployment".to_owned(),
            2,
            material(1, 11),
            BTreeMap::from([(1, material(1, 11))]),
        )
        .unwrap();
        assert_eq!(
            &*rotated
                .unprotect(
                    ProtectedPurpose::ApplicationState,
                    b"application-a",
                    &old_value
                )
                .unwrap(),
            b"state"
        );
        assert_eq!(
            rotated.unprotect(ProtectedPurpose::ProviderPkce, b"application-a", &old_value),
            Err(ApplicationError::Integrity)
        );
        assert_eq!(
            rotated.unprotect(
                ProtectedPurpose::ApplicationState,
                b"application-b",
                &old_value
            ),
            Err(ApplicationError::Integrity)
        );

        let mut wrong_version = old_value.clone();
        wrong_version.key_version = 2;
        assert_eq!(
            rotated.unprotect(
                ProtectedPurpose::ApplicationState,
                b"application-a",
                &wrong_version
            ),
            Err(ApplicationError::Integrity)
        );
    }

    #[test]
    fn managed_credential_ring_rotates_independently_and_preserves_context_binding() {
        let context = ManagedCredentialContext {
            project_id: Uuid::from_u128(1),
            provider_configuration_id: Uuid::from_u128(2),
            linked_identity_id: Uuid::from_u128(3),
            connection_id: Uuid::from_u128(4),
            connection_generation: 5,
            credential_generation: 6,
        };
        let old = SoftwareManagedCredentialProtector::new(
            "deployment".to_owned(),
            1,
            ManagedCredentialKeyMaterial::new([21; 32]),
            BTreeMap::new(),
        )
        .unwrap();
        let protected = old
            .protect_credential(&context, b"renewable-secret")
            .unwrap();
        let rotated = SoftwareManagedCredentialProtector::new(
            "deployment".to_owned(),
            2,
            ManagedCredentialKeyMaterial::new([22; 32]),
            BTreeMap::from([(1, ManagedCredentialKeyMaterial::new([21; 32]))]),
        )
        .unwrap();
        assert_eq!(rotated.active_key_version(), 2);
        assert_eq!(rotated.readable_key_versions(), BTreeSet::from([1, 2]));
        assert_eq!(
            rotated
                .unprotect_credential(&context, &protected)
                .unwrap()
                .as_slice(),
            b"renewable-secret"
        );
        let missing = SoftwareManagedCredentialProtector::new(
            "deployment".to_owned(),
            2,
            ManagedCredentialKeyMaterial::new([22; 32]),
            BTreeMap::new(),
        )
        .unwrap();
        assert_eq!(
            missing.unprotect_credential(&context, &protected),
            Err(ApplicationError::Integrity)
        );
        let mut wrong_context = context.clone();
        wrong_context.connection_generation += 1;
        assert_eq!(
            rotated.unprotect_credential(&wrong_context, &protected),
            Err(ApplicationError::Integrity)
        );
        assert_eq!(
            ManagedCredentialProtector::unprotect_credential(&protector(), &context, &protected),
            Err(ApplicationError::Integrity),
            "short-term Runtime custody cannot decrypt the dedicated managed ring"
        );
    }

    #[test]
    fn narrow_email_capabilities_fix_purpose_context_and_ring_custody() {
        let project_id = Uuid::from_u128(11);
        let identity_id = Uuid::from_u128(12);
        let source_ring = SoftwareRuntimeProtector::new(
            "deployment".to_owned(),
            1,
            material(31, 32),
            BTreeMap::new(),
        )
        .unwrap();
        let mut source_context = Vec::new();
        source_context.extend_from_slice(b"owlauth-email-identity-v1\0");
        source_context.extend_from_slice(project_id.as_bytes());
        source_context.extend_from_slice(identity_id.as_bytes());
        let durable = source_ring
            .protect(
                ProtectedPurpose::EmailIdentityAddress,
                &source_context,
                b"person@example.com",
            )
            .unwrap();
        let reader = SoftwareDurableEmailAddressReader::new(
            "deployment".to_owned(),
            1,
            material(31, 32),
            BTreeMap::new(),
        )
        .unwrap();
        assert_eq!(
            crate::application::DurableEmailAddressReader::read_durable_address(
                &reader,
                project_id,
                identity_id,
                &durable,
            )
            .unwrap()
            .as_str(),
            "person@example.com"
        );
        assert_eq!(
            crate::application::DurableEmailAddressReader::read_durable_address(
                &reader,
                project_id,
                Uuid::from_u128(13),
                &durable,
            ),
            Err(ApplicationError::Integrity)
        );

        let projection = SoftwareProjectionVerifiedEmailProtector::new(
            "deployment".to_owned(),
            7,
            [42; 32],
            BTreeMap::new(),
        )
        .unwrap();
        let application_id = Uuid::from_u128(21);
        let user_id = Uuid::from_u128(22);
        let protected =
            crate::application::ProjectionVerifiedEmailProtector::protect_verified_email(
                &projection,
                project_id,
                application_id,
                user_id,
                3,
                b"person@example.com",
            )
            .unwrap();
        assert_eq!(protected.key_version, 7);
        assert_eq!(
            crate::application::ProjectionVerifiedEmailProtector::unprotect_verified_email(
                &projection,
                project_id,
                application_id,
                user_id,
                3,
                &protected,
            )
            .unwrap()
            .as_str(),
            "person@example.com"
        );
        assert_eq!(
            crate::application::ProjectionVerifiedEmailProtector::unprotect_verified_email(
                &projection,
                project_id,
                Uuid::from_u128(23),
                user_id,
                3,
                &protected,
            ),
            Err(ApplicationError::Integrity)
        );
        assert_eq!(
            source_ring.unprotect(
                ProtectedPurpose::ApplicationProjectionVerifiedEmail,
                b"irrelevant",
                &protected,
            ),
            Err(ApplicationError::Integrity),
            "durable source custody cannot decrypt the projection ring"
        );
    }

    #[test]
    fn ciphertext_tampering_is_rejected() {
        let protector = protector();
        let mut protected = protector
            .protect(ProtectedPurpose::ProviderPkce, b"provider", b"verifier")
            .unwrap();
        let last = protected.ciphertext.last_mut().unwrap();
        *last ^= 1;
        assert_eq!(
            protector.unprotect(ProtectedPurpose::ProviderPkce, b"provider", &protected),
            Err(ApplicationError::Integrity)
        );
    }

    #[test]
    fn random_opaque_is_unpadded_base64url() {
        let protector = protector();
        let first = protector.random_opaque(32).unwrap();
        let second = protector.random_opaque(32).unwrap();
        assert_ne!(first, second);
        assert!(!first.contains('='));
        assert_eq!(URL_SAFE_NO_PAD.decode(first.as_bytes()).unwrap().len(), 32);
    }

    #[tokio::test]
    async fn signer_signs_and_strictly_verifies_without_exporting_seed() {
        let root = temporary_root("runtime-signer");
        let store = EncryptedFileStore::new(root.clone(), [31; 32]).unwrap();
        let alias = "signer_opaque_reference".to_owned();
        let seed = [7_u8; 32];
        store
            .put_if_absent(alias.clone(), Zeroizing::new(seed.to_vec()))
            .await
            .unwrap();
        let signer = EncryptedFileRuntimeSigner::new(store);
        let input = b"header.payload";
        let signature = signer.sign(&alias, input).await.unwrap();
        let public = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
        let jwk = json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "alg": "EdDSA",
            "use": "sig",
            "kid": "key-1",
            "x": URL_SAFE_NO_PAD.encode(public),
        });
        signer.verify(&jwk, input, &signature).unwrap();

        let wrong_public = SigningKey::from_bytes(&[8; 32]).verifying_key().to_bytes();
        let wrong_jwk = json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "alg": "EdDSA",
            "use": "sig",
            "kid": "key-2",
            "x": URL_SAFE_NO_PAD.encode(wrong_public),
        });
        assert_eq!(
            signer.verify(&wrong_jwk, input, &signature),
            Err(ApplicationError::InvalidTransition)
        );
        let private_jwk = json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "alg": "EdDSA",
            "use": "sig",
            "x": URL_SAFE_NO_PAD.encode(public),
            "d": URL_SAFE_NO_PAD.encode(seed),
        });
        assert_eq!(
            signer.verify(&private_jwk, input, &signature),
            Err(ApplicationError::Integrity)
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn provider_secret_resolver_reads_the_exact_reference() {
        let root = temporary_root("runtime-secret");
        let store = EncryptedFileStore::new(root.clone(), [41; 32]).unwrap();
        let alias = "provider_secret_reference".to_owned();
        store
            .put_if_absent(
                alias.clone(),
                Zeroizing::new(b"exact-provider-secret".to_vec()),
            )
            .await
            .unwrap();
        let resolver = EncryptedFileProviderSecretResolver::new(store);
        assert_eq!(
            &*resolver.resolve(&alias).await.unwrap(),
            "exact-provider-secret"
        );
        assert_eq!(
            resolver.resolve("provider_secret_other").await,
            Err(ApplicationError::Integrity)
        );
        fs::remove_dir_all(root).unwrap();
    }
}
