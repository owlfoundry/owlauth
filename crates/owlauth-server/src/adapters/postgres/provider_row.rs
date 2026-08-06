use serde_json::Value;

use crate::{
    application::ApplicationError,
    domain::{ProviderEgressMode, ProviderEgressPolicy, ProviderKind},
};

/// Decodes the closed provider kind and validates its issuer invariant.
pub(super) fn effective_provider_kind(
    stored_kind: &str,
    issuer: &str,
) -> Result<ProviderKind, ApplicationError> {
    let kind = ProviderKind::parse(stored_kind).map_err(|_| ApplicationError::Integrity)?;
    if !kind.issuer_matches(issuer) {
        return Err(ApplicationError::Integrity);
    }
    Ok(kind)
}

/// Decodes the identical Custom OIDC policy value shape used by operation-specific row mappers.
///
/// Revision matching, stale terminalization, and named-provider policy absence remain local to
/// each owning adapter because those state machines intentionally assign different semantics.
pub(super) fn decode_provider_egress_policy(
    mode: &str,
    exact_origins: Value,
) -> Result<ProviderEgressPolicy, ApplicationError> {
    let mode = ProviderEgressMode::parse(mode).map_err(|_| ApplicationError::Integrity)?;
    let exact_origins = serde_json::from_value::<Vec<String>>(exact_origins)
        .map_err(|_| ApplicationError::Integrity)?;
    let policy = ProviderEgressPolicy::new(mode, exact_origins.clone(), true)
        .map_err(|_| ApplicationError::Integrity)?;
    let canonical_origins = policy
        .exact_origins()
        .map(crate::domain::ProviderOrigin::as_str)
        .collect::<Vec<_>>();
    if canonical_origins != exact_origins {
        return Err(ApplicationError::Integrity);
    }
    Ok(policy)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{GITHUB_ISSUER, GOOGLE_ISSUER};

    #[test]
    fn live_provider_rows_require_a_closed_kind_and_matching_issuer() {
        assert_eq!(
            effective_provider_kind("google", GOOGLE_ISSUER),
            Ok(ProviderKind::Google)
        );
        assert_eq!(
            effective_provider_kind("google", GITHUB_ISSUER),
            Err(ApplicationError::Integrity)
        );
        assert_eq!(
            effective_provider_kind("saml", "https://issuer.example"),
            Err(ApplicationError::Integrity)
        );
    }

    #[test]
    fn custom_oidc_policy_values_are_strict_and_canonical() {
        let policy = decode_provider_egress_policy(
            "exact_origins",
            serde_json::json!(["https://issuer.example"]),
        )
        .expect("valid policy");
        assert_eq!(policy.mode(), ProviderEgressMode::ExactOrigins);
        assert_eq!(
            policy
                .exact_origins()
                .map(crate::domain::ProviderOrigin::as_str)
                .collect::<Vec<_>>(),
            ["https://issuer.example"]
        );
        assert_eq!(
            decode_provider_egress_policy("unknown", serde_json::json!([])),
            Err(ApplicationError::Integrity)
        );
        assert_eq!(
            decode_provider_egress_policy("exact_origins", serde_json::json!({})),
            Err(ApplicationError::Integrity)
        );
        assert_eq!(
            decode_provider_egress_policy(
                "exact_origins",
                serde_json::json!(["https://issuer.example/path"]),
            ),
            Err(ApplicationError::Integrity)
        );
        assert_eq!(
            decode_provider_egress_policy(
                "exact_origins",
                serde_json::json!(["https://issuer.example", "https://issuer.example"]),
            ),
            Err(ApplicationError::Integrity)
        );
        assert_eq!(
            decode_provider_egress_policy(
                "exact_origins",
                serde_json::json!(["https://z.example", "https://a.example"]),
            ),
            Err(ApplicationError::Integrity)
        );
    }
}
