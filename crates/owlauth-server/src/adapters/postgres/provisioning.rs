use std::{collections::BTreeSet, sync::Arc, time::Duration};

use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use owlauth_key_provider::{
    MaterialKind, OpaqueHandle, ProviderErrorClass, ProviderFormatVersion, ProviderId,
    RetryClassification, SigningAlgorithm, SigningPublicKey,
};
use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ColumnTrait, ConnectionTrait, DatabaseConnection,
    DatabaseTransaction, DbBackend, DbErr, EntityTrait, FromQueryResult, IntoActiveModel,
    QueryFilter, QueryOrder, QuerySelect, RuntimeErr, Statement, TransactionTrait,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use time::OffsetDateTime;
use url::Url;
use uuid::Uuid;

use crate::{
    adapters::{
        postgres::{
            custody::{
                MaterialOwnerKind, MaterialPurpose, ProtectedMaterialRepository,
                finalize_pending_material,
            },
            entity::{
                application, application_origin, application_provider_assignment,
                application_publishable_key, application_redirect, audit_event,
                control_idempotency_record, key_provisioning_operation, key_state_event, project,
                project_key_ring, project_policy, project_provider_egress_policy,
                project_signing_key, protected_material, provider_configuration,
                provider_secret_operation, runtime_publication_lease, webhook_endpoint,
            },
        },
        system::{Sha256RequestDigester, SystemClock},
    },
    application::{
        ApplicationConfiguration, ApplicationError, ApplicationProvisioningPort, ApplicationRecord,
        Clock, CreateApplication, CreateProject, PrepareProvider, PreparedProvider,
        PreparedSecretMaterial, PreparedSigningKey, PreparedSigningMaterial, ProjectPolicyRecord,
        ProjectProvisioningPort, ProjectRecord, ProviderProvisioningPort, ProviderRecord,
        ProviderRecovery, ProvisionedProtectedSigningMaterial, ProvisioningOperationState,
        ReplaceApplicationConfiguration, RequestDigester, SealedProtectedMaterial,
        SigningKeyMaintenanceItem, SigningKeyProvisioningPort, SigningKeyRecord,
        SigningProviderAction, SigningProviderCall, SigningProviderLease, UpdateApplication,
        UpdateProject, UpdateProjectPolicy,
    },
    domain::{
        ApplicationStatus, ApplicationType, BrowserOrigin, MAX_ACCESS_TOKEN_LIFETIME_SECONDS,
        MAX_WEBHOOK_ENDPOINTS_PER_APPLICATION, ProjectStatus, ProviderStatus, RedirectUri,
        SigningKeyState,
    },
};

const LIST_LIMIT: u64 = 100;
const CONFIGURATION_VALUE_LIMIT: usize = 50;
const PROJECT_CAPACITY_LOCK: &str = "owlauth:deployment-project-capacity:v1";
const SIGNING_PURPOSE: &str = "application_tokens";
const SIGNING_ALGORITHM: &str = "EdDSA";

mod project_application;
mod provider_secret;
mod shared;
mod signing;

pub(super) use shared::*;

#[derive(Clone)]
pub(crate) struct PostgresProvisioningAdapter {
    database: DatabaseConnection,
    clock: Arc<dyn Clock>,
    digester: Arc<dyn RequestDigester>,
    runtime_base: Arc<Url>,
    required_runtime_process_ids: Arc<BTreeSet<String>>,
    propagation_delay: Duration,
    verification_retention: Duration,
    custody: ProvisioningCustody,
}

#[derive(Clone)]
struct ProvisioningCustody {
    materials: ProtectedMaterialRepository,
    signing: CustodySelection,
    secrets: CustodySelection,
}

#[derive(Clone)]
struct CustodySelection {
    provider_id: ProviderId,
    provider_format_version: ProviderFormatVersion,
}

impl PostgresProvisioningAdapter {
    #[allow(
        clippy::too_many_arguments,
        reason = "composition passes distinct Runtime timing and signing/secret custody selections explicitly"
    )]
    pub(crate) fn new_protected(
        database: DatabaseConnection,
        runtime_base: Url,
        required_runtime_process_ids: Vec<String>,
        propagation_delay: Duration,
        verification_retention: Duration,
        deployment_id: &str,
        signing_provider_id: ProviderId,
        signing_provider_format_version: ProviderFormatVersion,
        secret_provider_id: ProviderId,
        secret_provider_format_version: ProviderFormatVersion,
    ) -> Result<Self, ApplicationError> {
        let custody = ProvisioningCustody {
            materials: ProtectedMaterialRepository::new(database.clone(), deployment_id)?,
            signing: CustodySelection {
                provider_id: signing_provider_id,
                provider_format_version: signing_provider_format_version,
            },
            secrets: CustodySelection {
                provider_id: secret_provider_id,
                provider_format_version: secret_provider_format_version,
            },
        };
        Ok(Self {
            database,
            clock: Arc::new(SystemClock),
            digester: Arc::new(Sha256RequestDigester),
            runtime_base: Arc::new(runtime_base),
            required_runtime_process_ids: Arc::new(
                required_runtime_process_ids.into_iter().collect(),
            ),
            propagation_delay,
            verification_retention,
            custody,
        })
    }

    #[cfg(test)]
    pub(crate) fn new(
        database: DatabaseConnection,
        runtime_base: Url,
        required_runtime_process_ids: Vec<String>,
        propagation_delay: Duration,
        verification_retention: Duration,
    ) -> Self {
        let provider_id = ProviderId::new("software").expect("test provider ID is valid");
        let provider_format_version =
            ProviderFormatVersion::new(1).expect("test provider format is valid");
        Self::new_protected(
            database,
            runtime_base,
            required_runtime_process_ids,
            propagation_delay,
            verification_retention,
            "test-deployment",
            provider_id.clone(),
            provider_format_version,
            provider_id,
            provider_format_version,
        )
        .expect("test provisioning custody is valid")
    }

    #[cfg(test)]
    pub(crate) fn with_custody(
        self,
        deployment_id: &str,
        provider_id: ProviderId,
        provider_format_version: ProviderFormatVersion,
    ) -> Result<Self, ApplicationError> {
        self.with_provider_custody(
            deployment_id,
            provider_id.clone(),
            provider_format_version,
            provider_id,
            provider_format_version,
        )
    }

    #[cfg(test)]
    pub(crate) fn with_provider_custody(
        mut self,
        deployment_id: &str,
        signing_provider_id: ProviderId,
        signing_provider_format_version: ProviderFormatVersion,
        secret_provider_id: ProviderId,
        secret_provider_format_version: ProviderFormatVersion,
    ) -> Result<Self, ApplicationError> {
        self.custody = ProvisioningCustody {
            materials: ProtectedMaterialRepository::new(self.database.clone(), deployment_id)?,
            signing: CustodySelection {
                provider_id: signing_provider_id,
                provider_format_version: signing_provider_format_version,
            },
            secrets: CustodySelection {
                provider_id: secret_provider_id,
                provider_format_version: secret_provider_format_version,
            },
        };
        Ok(self)
    }

    fn custody(&self) -> &ProvisioningCustody {
        &self.custody
    }
}
