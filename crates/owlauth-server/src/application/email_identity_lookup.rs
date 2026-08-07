use uuid::Uuid;

use super::{ApplicationError, VersionedDigest};

/// Narrow capability for exact canonical email lookup. Implementations expose only versioned
/// lookup candidates; they cannot encrypt, decrypt, or access arbitrary protection contexts.
pub(crate) trait EmailIdentityLookupDigester: Send + Sync {
    fn digest_candidates(
        &self,
        project_id: Uuid,
        canonical_email: &str,
    ) -> Result<Vec<VersionedDigest>, ApplicationError>;
}
