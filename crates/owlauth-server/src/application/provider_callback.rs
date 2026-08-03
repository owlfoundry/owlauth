use async_trait::async_trait;
use uuid::Uuid;

use super::ApplicationError;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProviderCallbackOwner {
    Login {
        transaction_id: Uuid,
    },
    IdentityMutation {
        intent_id: Uuid,
        proof_slot_id: Uuid,
    },
    ManagedReauthorization {
        interaction_id: Uuid,
    },
}

#[async_trait]
pub(crate) trait ProviderCallbackOwnerResolver: Send + Sync {
    async fn resolve(
        &self,
        state_id: Uuid,
        project_public_id: &str,
        provider_key: &str,
    ) -> Result<ProviderCallbackOwner, ApplicationError>;
}
