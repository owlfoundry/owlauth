use std::fmt;

use crate::{ProviderFormatVersion, ProviderId, ValueError};

const CONTEXT_DOMAIN: &[u8] = b"owlauth-key-provider-context\0";

macro_rules! context_identifier {
    ($name:ident, $max_len:expr) => {
        #[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(String);

        impl $name {
            pub const MAX_LEN: usize = $max_len;

            /// Creates a bounded ASCII context identifier.
            ///
            /// # Errors
            ///
            /// Returns [`ValueError`] for an empty, oversized, or malformed value.
            pub fn new(value: impl Into<String>) -> Result<Self, ValueError> {
                let value = value.into();
                if value.is_empty() {
                    return Err(ValueError::Empty);
                }
                if value.len() > Self::MAX_LEN {
                    return Err(ValueError::TooLong);
                }
                if !value.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-')
                }) {
                    return Err(ValueError::InvalidCharacter);
                }
                Ok(Self(value))
            }

            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_tuple(stringify!($name))
                    .field(&self.0)
                    .finish()
            }
        }
    };
}

context_identifier!(DeploymentId, 128);
context_identifier!(ProjectId, 128);
context_identifier!(MaterialId, 128);
context_identifier!(OwnerId, 128);

fn validate_label(value: String, max_len: usize) -> Result<String, ValueError> {
    if value.is_empty() {
        return Err(ValueError::Empty);
    }
    if value.len() > max_len {
        return Err(ValueError::TooLong);
    }
    if !value.bytes().all(|byte| {
        byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
    }) {
        return Err(ValueError::InvalidCharacter);
    }
    Ok(value)
}

macro_rules! context_label {
    ($name:ident) => {
        #[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(String);

        impl $name {
            pub const MAX_LEN: usize = 64;

            /// Creates a lowercase bounded semantic context label.
            ///
            /// # Errors
            ///
            /// Returns [`ValueError`] for an empty, oversized, or malformed value.
            pub fn new(value: impl Into<String>) -> Result<Self, ValueError> {
                validate_label(value.into(), Self::MAX_LEN).map(Self)
            }

            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_tuple(stringify!($name))
                    .field(&self.0)
                    .finish()
            }
        }
    };
}

context_label!(OwnerKind);
context_label!(FieldPurpose);

/// Supported canonical context encoding layouts.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum ContextVersion {
    V1,
}

impl ContextVersion {
    #[must_use]
    pub const fn get(self) -> u16 {
        match self {
            Self::V1 => 1,
        }
    }
}

impl TryFrom<u16> for ContextVersion {
    type Error = ValueError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::V1),
            _ => Err(ValueError::InvalidValue),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Scope {
    Deployment,
    Project(ProjectId),
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum MaterialKind {
    SigningKey,
    ConfigurationSecret,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProtectionContextParts {
    pub version: ContextVersion,
    pub deployment_id: DeploymentId,
    pub scope: Scope,
    pub material_id: MaterialId,
    pub material_kind: MaterialKind,
    pub owner_kind: OwnerKind,
    pub owner_id: OwnerId,
    pub generation: u64,
    pub field_purpose: FieldPurpose,
    pub provider_id: ProviderId,
    pub provider_format_version: ProviderFormatVersion,
}

impl ProtectionContextParts {
    /// Validates the complete typed context before canonical encoding.
    ///
    /// # Errors
    ///
    /// Returns [`ValueError::InvalidValue`] when generation is zero.
    pub fn validate(&self) -> Result<(), ValueError> {
        if self.generation == 0 {
            return Err(ValueError::InvalidValue);
        }
        Ok(())
    }
}

/// Exact versioned canonical context authenticated by provider material.
#[derive(Clone, Eq, PartialEq)]
pub struct ProtectionContext {
    parts: ProtectionContextParts,
    canonical: Vec<u8>,
}

impl ProtectionContext {
    pub const MAX_CANONICAL_LEN: usize = 2_048;

    /// Creates and canonically encodes typed context.
    ///
    /// # Errors
    ///
    /// Returns [`ValueError`] when a semantic or encoded bound is invalid.
    pub fn new(parts: ProtectionContextParts) -> Result<Self, ValueError> {
        parts.validate()?;
        let canonical = match parts.version {
            ContextVersion::V1 => encode_v1(&parts)?,
        };
        if canonical.len() > Self::MAX_CANONICAL_LEN {
            return Err(ValueError::TooLong);
        }
        Ok(Self { parts, canonical })
    }

    #[must_use]
    pub const fn parts(&self) -> &ProtectionContextParts {
        &self.parts
    }

    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical
    }
}

impl fmt::Debug for ProtectionContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProtectionContext")
            .field("version", &self.parts.version)
            .field("material_kind", &self.parts.material_kind)
            .field("canonical_length", &self.canonical.len())
            .finish_non_exhaustive()
    }
}

fn encode_v1(parts: &ProtectionContextParts) -> Result<Vec<u8>, ValueError> {
    let mut output = Vec::with_capacity(256);
    output.extend_from_slice(CONTEXT_DOMAIN);
    output.extend_from_slice(&parts.version.get().to_be_bytes());
    push_field(&mut output, 1, parts.deployment_id.as_str().as_bytes())?;
    match &parts.scope {
        Scope::Deployment => push_field(&mut output, 2, &[0])?,
        Scope::Project(project_id) => {
            push_field(&mut output, 2, &[1])?;
            push_field(&mut output, 3, project_id.as_str().as_bytes())?;
        }
    }
    push_field(&mut output, 4, parts.material_id.as_str().as_bytes())?;
    push_field(
        &mut output,
        5,
        &[match parts.material_kind {
            MaterialKind::SigningKey => 1,
            MaterialKind::ConfigurationSecret => 2,
        }],
    )?;
    push_field(&mut output, 6, parts.owner_kind.as_str().as_bytes())?;
    push_field(&mut output, 7, parts.owner_id.as_str().as_bytes())?;
    push_field(&mut output, 8, &parts.generation.to_be_bytes())?;
    push_field(&mut output, 9, parts.field_purpose.as_str().as_bytes())?;
    push_field(&mut output, 10, parts.provider_id.as_str().as_bytes())?;
    push_field(
        &mut output,
        11,
        &parts.provider_format_version.get().to_be_bytes(),
    )?;
    Ok(output)
}

fn push_field(output: &mut Vec<u8>, tag: u8, value: &[u8]) -> Result<(), ValueError> {
    let length = u32::try_from(value.len()).map_err(|_| ValueError::TooLong)?;
    output.push(tag);
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn context(scope: Scope) -> ProtectionContext {
        ProtectionContext::new(ProtectionContextParts {
            version: ContextVersion::V1,
            deployment_id: DeploymentId::new("instance-1").unwrap(),
            scope,
            material_id: MaterialId::new("018f-material").unwrap(),
            material_kind: MaterialKind::ConfigurationSecret,
            owner_kind: OwnerKind::new("provider.client").unwrap(),
            owner_id: OwnerId::new("018f-owner").unwrap(),
            generation: 7,
            field_purpose: FieldPurpose::new("client-secret").unwrap(),
            provider_id: ProviderId::new("software").unwrap(),
            provider_format_version: ProviderFormatVersion::new(1).unwrap(),
        })
        .unwrap()
    }

    #[test]
    fn canonical_context_is_stable_and_length_delimited() {
        let context = context(Scope::Project(ProjectId::new("018f-project").unwrap()));
        assert_eq!(
            context.canonical_bytes(),
            b"owlauth-key-provider-context\0\0\x01\x01\0\0\0\x0ainstance-1\x02\0\0\0\x01\x01\x03\0\0\0\x0c018f-project\x04\0\0\0\x0d018f-material\x05\0\0\0\x01\x02\x06\0\0\0\x0fprovider.client\x07\0\0\0\x0a018f-owner\x08\0\0\0\x08\0\0\0\0\0\0\0\x07\x09\0\0\0\x0dclient-secret\x0a\0\0\0\x08software\x0b\0\0\0\x02\0\x01"
        );
    }

    #[test]
    fn unknown_context_versions_fail_closed() {
        assert_eq!(
            ContextVersion::try_from(2).unwrap_err(),
            ValueError::InvalidValue
        );
    }

    #[test]
    fn scope_and_generation_change_context_bytes() {
        let project = context(Scope::Project(ProjectId::new("018f-project").unwrap()));
        let deployment = context(Scope::Deployment);
        assert_ne!(project.canonical_bytes(), deployment.canonical_bytes());

        let mut parts = project.parts().clone();
        parts.generation += 1;
        let successor = ProtectionContext::new(parts).unwrap();
        assert_ne!(project.canonical_bytes(), successor.canonical_bytes());
    }

    #[test]
    fn semantic_labels_are_not_interchangeable() {
        let owner = OwnerKind::new("provider").unwrap();
        let purpose = FieldPurpose::new("client-secret").unwrap();
        assert_eq!(owner.as_str(), "provider");
        assert_eq!(purpose.as_str(), "client-secret");
    }

    #[test]
    fn zero_generation_is_rejected() {
        let mut parts = context(Scope::Deployment).parts().clone();
        parts.generation = 0;
        assert_eq!(
            ProtectionContext::new(parts).unwrap_err(),
            ValueError::InvalidValue
        );
    }
}
