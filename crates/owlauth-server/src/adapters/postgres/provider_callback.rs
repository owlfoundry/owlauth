use async_trait::async_trait;
use sea_orm::{ConnectionTrait, DatabaseConnection, DbBackend, Statement, TryGetable};
use uuid::Uuid;

use crate::application::{ApplicationError, ProviderCallbackOwner, ProviderCallbackOwnerResolver};

#[derive(Clone, Debug)]
pub(crate) struct PostgresProviderCallbackOwnerResolver {
    database: DatabaseConnection,
}

impl PostgresProviderCallbackOwnerResolver {
    pub(crate) const fn new(database: DatabaseConnection) -> Self {
        Self { database }
    }
}

#[async_trait]
impl ProviderCallbackOwnerResolver for PostgresProviderCallbackOwnerResolver {
    async fn resolve(
        &self,
        state_id: Uuid,
        project_public_id: &str,
        provider_key: &str,
    ) -> Result<ProviderCallbackOwner, ApplicationError> {
        let row = self
            .database
            .query_one_raw(Statement::from_sql_and_values(
                DbBackend::Postgres,
                "SELECT owner.owner_kind, owner.login_transaction_id,
                        owner.identity_mutation_intent_id,
                        owner.identity_mutation_proof_slot_id,
                        owner.managed_reauthorization_interaction_id
                   FROM provider_callback_owners AS owner
                   JOIN projects AS project ON project.id=owner.project_id
                   JOIN provider_configurations AS provider
                     ON provider.project_id=owner.project_id
                    AND provider.id=owner.provider_configuration_id
                  WHERE owner.state_id=$1
                    AND project.public_id=$2
                    AND provider.provider_key=$3",
                [
                    state_id.into(),
                    project_public_id.to_owned().into(),
                    provider_key.to_owned().into(),
                ],
            ))
            .await
            .map_err(|_| ApplicationError::Persistence)?
            .ok_or(ApplicationError::NotFound)?;
        let owner_kind =
            String::try_get(&row, "", "owner_kind").map_err(|_| ApplicationError::Integrity)?;
        match owner_kind.as_str() {
            "login" => Ok(ProviderCallbackOwner::Login {
                transaction_id: Uuid::try_get(&row, "", "login_transaction_id")
                    .map_err(|_| ApplicationError::Integrity)?,
            }),
            "identity_mutation" => Ok(ProviderCallbackOwner::IdentityMutation {
                intent_id: Uuid::try_get(&row, "", "identity_mutation_intent_id")
                    .map_err(|_| ApplicationError::Integrity)?,
                proof_slot_id: Uuid::try_get(&row, "", "identity_mutation_proof_slot_id")
                    .map_err(|_| ApplicationError::Integrity)?,
            }),
            "managed_reauthorization" => Ok(ProviderCallbackOwner::ManagedReauthorization {
                interaction_id: Uuid::try_get(&row, "", "managed_reauthorization_interaction_id")
                    .map_err(|_| ApplicationError::Integrity)?,
            }),
            _ => Err(ApplicationError::Integrity),
        }
    }
}
