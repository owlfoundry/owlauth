use time::OffsetDateTime;

use super::DomainError;

pub(crate) const MAX_MANAGED_SCOPES: usize = 16;
pub(crate) const MAX_PROFILE_BODY_BYTES: usize = 64 * 1024;
pub(crate) const MAX_PROVIDER_LATENCY_SECONDS: u64 = 15;

/// Adapter-owned profile capability. It is deliberately separate from login support: only an
/// adapter returning `Some` can ever receive or retain a renewable credential. Scope input is
/// not accepted from an Application, browser, or Control command.
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "the immutable adapter protocol snapshot keeps independent reviewed properties explicit"
)]
pub(crate) struct ManagedProfileCapability {
    pub adapter_key: &'static str,
    pub adapter_revision: i64,
    pub exact_scopes: &'static [&'static str],
    pub provider_pkce_required: bool,
    pub oidc_nonce_required: bool,
    pub credential_rotates: bool,
    pub read_retry_safe: bool,
    pub renewal_replay: RenewalReplay,
    pub supports_revocation: bool,
    pub profile_schema: &'static str,
    pub maximum_body_bytes: usize,
    pub maximum_latency_seconds: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RenewalReplay {
    Never,
    StableAttemptId,
}

impl ManagedProfileCapability {
    pub(crate) fn validate(&self) -> Result<(), DomainError> {
        if self.adapter_key.is_empty()
            || self.adapter_revision <= 0
            || self.profile_schema != "owlauth.provider-profile.v1"
            || !self.oidc_nonce_required
            || self.exact_scopes.is_empty()
            || self.exact_scopes.len() > MAX_MANAGED_SCOPES
            || self.maximum_body_bytes == 0
            || self.maximum_body_bytes > MAX_PROFILE_BODY_BYTES
            || self.maximum_latency_seconds == 0
            || self.maximum_latency_seconds > MAX_PROVIDER_LATENCY_SECONDS
            || self.exact_scopes.iter().any(|scope| {
                scope.is_empty() || scope.len() > 128 || scope.contains(char::is_whitespace)
            })
        {
            return Err(DomainError::InvalidTransition);
        }
        let mut sorted = self.exact_scopes.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        if sorted.len() != self.exact_scopes.len() {
            return Err(DomainError::InvalidTransition);
        }
        Ok(())
    }

    pub(crate) fn scopes_match(&self, returned: &[String]) -> bool {
        let mut expected = self.exact_scopes.to_vec();
        expected.sort_unstable();
        let mut actual: Vec<&str> = returned.iter().map(String::as_str).collect();
        actual.sort_unstable();
        let actual_count = actual.len();
        actual.dedup();
        actual.len() == actual_count && actual == expected
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ManagedConnectionState {
    Active,
    ReauthRequired,
    Revoked,
    Disconnected,
}

impl ManagedConnectionState {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::ReauthRequired => "reauth_required",
            Self::Revoked => "revoked",
            Self::Disconnected => "disconnected",
        }
    }

    pub(crate) fn parse(value: &str) -> Result<Self, DomainError> {
        match value {
            "active" => Ok(Self::Active),
            "reauth_required" => Ok(Self::ReauthRequired),
            "revoked" => Ok(Self::Revoked),
            "disconnected" => Ok(Self::Disconnected),
            _ => Err(DomainError::InvalidTransition),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ManagedConnectionEvent {
    ReplaceCredential,
    RequireReauthorization,
    ConfirmProviderRevocation,
    Disconnect,
    Reauthorize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ManagedConnectionLifecycle {
    pub state: ManagedConnectionState,
    pub revision: i64,
    pub generation: i64,
    pub credential_generation: i64,
    pub updated_at: OffsetDateTime,
}

impl ManagedConnectionLifecycle {
    pub(crate) fn transition(
        &mut self,
        event: ManagedConnectionEvent,
        expected_revision: i64,
        expected_generation: i64,
        now: OffsetDateTime,
    ) -> Result<(), DomainError> {
        if expected_revision != self.revision
            || expected_generation != self.generation
            || now < self.updated_at
        {
            return Err(DomainError::InvalidTransition);
        }
        let next = match (self.state, event) {
            (ManagedConnectionState::Active, ManagedConnectionEvent::ReplaceCredential) => {
                ManagedConnectionState::Active
            }
            (ManagedConnectionState::Active, ManagedConnectionEvent::RequireReauthorization) => {
                ManagedConnectionState::ReauthRequired
            }
            (ManagedConnectionState::Active, ManagedConnectionEvent::ConfirmProviderRevocation) => {
                ManagedConnectionState::Revoked
            }
            (
                ManagedConnectionState::Active
                | ManagedConnectionState::ReauthRequired
                | ManagedConnectionState::Revoked,
                ManagedConnectionEvent::Disconnect,
            ) => ManagedConnectionState::Disconnected,
            (
                ManagedConnectionState::ReauthRequired
                | ManagedConnectionState::Revoked
                | ManagedConnectionState::Disconnected,
                ManagedConnectionEvent::Reauthorize,
            ) => ManagedConnectionState::Active,
            _ => return Err(DomainError::InvalidTransition),
        };
        self.revision = self
            .revision
            .checked_add(1)
            .ok_or(DomainError::InvalidTransition)?;
        if matches!(
            event,
            ManagedConnectionEvent::ReplaceCredential
                | ManagedConnectionEvent::Reauthorize
                | ManagedConnectionEvent::RequireReauthorization
                | ManagedConnectionEvent::ConfirmProviderRevocation
                | ManagedConnectionEvent::Disconnect
        ) {
            self.generation = self
                .generation
                .checked_add(1)
                .ok_or(DomainError::InvalidTransition)?;
        }
        if matches!(
            event,
            ManagedConnectionEvent::ReplaceCredential | ManagedConnectionEvent::Reauthorize
        ) {
            self.credential_generation = self
                .credential_generation
                .checked_add(1)
                .ok_or(DomainError::InvalidTransition)?;
        }
        self.state = next;
        self.updated_at = now;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    fn lifecycle(state: ManagedConnectionState) -> ManagedConnectionLifecycle {
        ManagedConnectionLifecycle {
            state,
            revision: 7,
            generation: 3,
            credential_generation: 3,
            updated_at: datetime!(2026-08-01 00:00 UTC),
        }
    }

    #[test]
    fn transition_matrix_is_explicit_and_generation_fenced() {
        for event in [
            ManagedConnectionEvent::ReplaceCredential,
            ManagedConnectionEvent::RequireReauthorization,
            ManagedConnectionEvent::ConfirmProviderRevocation,
            ManagedConnectionEvent::Disconnect,
        ] {
            let mut value = lifecycle(ManagedConnectionState::Active);
            value
                .transition(event, 7, 3, datetime!(2026-08-01 00:01 UTC))
                .unwrap();
            assert_eq!(value.revision, 8);
            assert_eq!(value.generation, 4);
            assert_eq!(
                value.credential_generation,
                if matches!(event, ManagedConnectionEvent::ReplaceCredential) {
                    4
                } else {
                    3
                }
            );
        }
        let mut stale = lifecycle(ManagedConnectionState::Active);
        assert_eq!(
            stale.transition(
                ManagedConnectionEvent::Disconnect,
                6,
                3,
                datetime!(2026-08-01 00:01 UTC)
            ),
            Err(DomainError::InvalidTransition)
        );
        let mut disconnected = lifecycle(ManagedConnectionState::Disconnected);
        assert!(
            disconnected
                .transition(
                    ManagedConnectionEvent::Reauthorize,
                    7,
                    3,
                    datetime!(2026-08-01 00:01 UTC)
                )
                .is_ok()
        );
        assert_eq!(
            disconnected.transition(
                ManagedConnectionEvent::Reauthorize,
                8,
                4,
                datetime!(2026-08-01 00:02 UTC)
            ),
            Err(DomainError::InvalidTransition)
        );
    }

    #[test]
    fn capability_requires_fixed_unique_least_scopes_and_bounds() {
        let capability = ManagedProfileCapability {
            adapter_key: "controlled_oidc_profile_v1",
            adapter_revision: 1,
            exact_scopes: &["openid", "offline_access", "profile"],
            provider_pkce_required: true,
            oidc_nonce_required: true,
            credential_rotates: true,
            read_retry_safe: true,
            renewal_replay: RenewalReplay::Never,
            supports_revocation: true,
            profile_schema: "owlauth.provider-profile.v1",
            maximum_body_bytes: 16 * 1024,
            maximum_latency_seconds: 10,
        };
        capability.validate().unwrap();
        assert!(capability.scopes_match(&[
            "profile".to_owned(),
            "openid".to_owned(),
            "offline_access".to_owned()
        ]));
        assert!(!capability.scopes_match(&[
            "profile".to_owned(),
            "openid".to_owned(),
            "offline_access".to_owned(),
            "mail.read".to_owned()
        ]));
    }
}
