pub(crate) mod project {
    use sea_orm::entity::prelude::*;

    #[derive(Clone, Debug, Eq, PartialEq, DeriveEntityModel)]
    #[sea_orm(table_name = "projects")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: Uuid,
        pub public_id: String,
        pub belongs_to: Option<String>,
        pub display_name: String,
        pub status: String,
        pub metadata_revision: i64,
        pub security_revision: i64,
        pub created_at: TimeDateTimeWithTimeZone,
        pub updated_at: TimeDateTimeWithTimeZone,
    }

    #[derive(Clone, Copy, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

pub(crate) mod application {
    use sea_orm::entity::prelude::*;

    #[derive(Clone, Debug, Eq, PartialEq, DeriveEntityModel)]
    #[sea_orm(table_name = "applications")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: Uuid,
        pub project_id: Uuid,
        pub public_id: String,
        pub display_name: String,
        pub application_type: String,
        pub status: String,
        pub revision: i64,
        pub metadata_revision: i64,
        pub security_revision: i64,
        pub projection_revision: i64,
        pub created_at: TimeDateTimeWithTimeZone,
        pub updated_at: TimeDateTimeWithTimeZone,
    }

    #[derive(Clone, Copy, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

pub(crate) mod application_redirect {
    use sea_orm::entity::prelude::*;

    #[derive(Clone, Debug, Eq, PartialEq, DeriveEntityModel)]
    #[sea_orm(table_name = "application_redirects")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub project_id: Uuid,
        #[sea_orm(primary_key, auto_increment = false)]
        pub application_id: Uuid,
        #[sea_orm(primary_key, auto_increment = false)]
        pub redirect_uri: String,
        pub redirect_type: String,
    }

    #[derive(Clone, Copy, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

pub(crate) mod application_origin {
    use sea_orm::entity::prelude::*;

    #[derive(Clone, Debug, Eq, PartialEq, DeriveEntityModel)]
    #[sea_orm(table_name = "application_origins")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub project_id: Uuid,
        #[sea_orm(primary_key, auto_increment = false)]
        pub application_id: Uuid,
        #[sea_orm(primary_key, auto_increment = false)]
        pub origin: String,
    }

    #[derive(Clone, Copy, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

pub(crate) mod application_publishable_key {
    use sea_orm::entity::prelude::*;

    #[derive(Clone, Debug, Eq, PartialEq, DeriveEntityModel)]
    #[sea_orm(table_name = "application_publishable_keys")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: Uuid,
        pub project_id: Uuid,
        pub application_id: Uuid,
        pub public_id: String,
        pub status: String,
        pub revision: i64,
    }

    #[derive(Clone, Copy, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

pub(crate) mod project_key_ring {
    use sea_orm::entity::prelude::*;

    #[derive(Clone, Debug, Eq, PartialEq, DeriveEntityModel)]
    #[sea_orm(table_name = "project_key_rings")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: Uuid,
        pub project_id: Uuid,
        pub issuer: String,
        pub purpose: String,
        pub algorithm: String,
        pub revision: i64,
        pub signing_epoch: i64,
    }

    #[derive(Clone, Copy, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

pub(crate) mod project_signing_key {
    use sea_orm::entity::prelude::*;

    #[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
    #[sea_orm(table_name = "project_signing_keys")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: Uuid,
        pub project_id: Uuid,
        pub ring_id: Uuid,
        pub kid: String,
        pub public_jwk: Json,
        pub signer_ref: String,
        pub state: String,
        pub ring_revision: i64,
        pub provisioned_at: Option<TimeDateTimeWithTimeZone>,
        pub published_at: Option<TimeDateTimeWithTimeZone>,
        pub activated_at: Option<TimeDateTimeWithTimeZone>,
        pub sign_not_before: Option<TimeDateTimeWithTimeZone>,
        pub retiring_at: Option<TimeDateTimeWithTimeZone>,
        pub verify_not_after: Option<TimeDateTimeWithTimeZone>,
        pub retired_at: Option<TimeDateTimeWithTimeZone>,
        pub revoked_at: Option<TimeDateTimeWithTimeZone>,
        pub created_at: TimeDateTimeWithTimeZone,
        pub updated_at: TimeDateTimeWithTimeZone,
    }

    #[derive(Clone, Copy, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

pub(crate) mod project_policy {
    use sea_orm::entity::prelude::*;

    #[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
    #[sea_orm(table_name = "project_policies")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub project_id: Uuid,
        pub claims_revision: i64,
        pub session_revision: i64,
        pub projection_revision: i64,
        pub claims_policy: Json,
        pub session_policy: Json,
    }

    #[derive(Clone, Copy, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

pub(crate) mod key_state_event {
    use sea_orm::entity::prelude::*;

    #[derive(Clone, Debug, Eq, PartialEq, DeriveEntityModel)]
    #[sea_orm(table_name = "key_state_events")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: Uuid,
        pub project_id: Uuid,
        pub ring_id: Uuid,
        pub signing_key_id: Uuid,
        pub ring_revision: i64,
        pub from_state: String,
        pub to_state: String,
        pub actor_kind: String,
        pub occurred_at: TimeDateTimeWithTimeZone,
    }

    #[derive(Clone, Copy, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

pub(crate) mod key_provisioning_operation {
    use sea_orm::entity::prelude::*;

    #[derive(Clone, Debug, Eq, PartialEq, DeriveEntityModel)]
    #[sea_orm(table_name = "key_provisioning_operations")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: Uuid,
        pub project_id: Uuid,
        pub ring_id: Uuid,
        pub key_id: Uuid,
        pub operation_alias: String,
        pub request_digest: Vec<u8>,
        pub state: String,
        pub attempt_count: i32,
        pub expected_project_revision: i64,
        pub expected_ring_revision: i64,
        pub last_attempt_at: Option<TimeDateTimeWithTimeZone>,
        pub completed_at: Option<TimeDateTimeWithTimeZone>,
    }

    #[derive(Clone, Copy, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

pub(crate) mod provider_configuration {
    use sea_orm::entity::prelude::*;

    #[derive(Clone, Debug, Eq, PartialEq, DeriveEntityModel)]
    #[sea_orm(table_name = "provider_configurations")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: Uuid,
        pub project_id: Uuid,
        pub provider_key: String,
        pub kind: String,
        pub display_name: String,
        pub issuer: String,
        pub client_id: String,
        pub callback_url: String,
        pub secret_ref: Option<String>,
        pub status: String,
        pub revision: i64,
    }

    #[derive(Clone, Copy, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

pub(crate) mod provider_secret_operation {
    use sea_orm::entity::prelude::*;

    #[derive(Clone, Debug, Eq, PartialEq, DeriveEntityModel)]
    #[sea_orm(table_name = "provider_secret_operations")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: Uuid,
        pub project_id: Uuid,
        pub provider_id: Uuid,
        pub operation_alias: String,
        pub request_digest: Vec<u8>,
        pub state: String,
        pub attempt_count: i32,
        pub expected_project_revision: i64,
        pub expected_provider_revision: i64,
        pub last_attempt_at: Option<TimeDateTimeWithTimeZone>,
        pub completed_at: Option<TimeDateTimeWithTimeZone>,
    }

    #[derive(Clone, Copy, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

pub(crate) mod application_provider_assignment {
    use sea_orm::entity::prelude::*;

    #[derive(Clone, Debug, Eq, PartialEq, DeriveEntityModel)]
    #[sea_orm(table_name = "application_provider_assignments")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub project_id: Uuid,
        #[sea_orm(primary_key, auto_increment = false)]
        pub application_id: Uuid,
        #[sea_orm(primary_key, auto_increment = false)]
        pub provider_id: Uuid,
        pub status: String,
        pub security_revision: i64,
    }

    #[derive(Clone, Copy, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

pub(crate) mod runtime_publication_lease {
    use sea_orm::entity::prelude::*;

    #[derive(Clone, Debug, Eq, PartialEq, DeriveEntityModel)]
    #[sea_orm(table_name = "runtime_publication_leases")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub project_id: Uuid,
        #[sea_orm(primary_key, auto_increment = false)]
        pub ring_id: Uuid,
        #[sea_orm(primary_key, auto_increment = false)]
        pub process_id: String,
        pub loaded_revision: i64,
        pub first_observed_at: TimeDateTimeWithTimeZone,
        pub last_observed_at: TimeDateTimeWithTimeZone,
        pub expires_at: TimeDateTimeWithTimeZone,
    }

    #[derive(Clone, Copy, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

pub(crate) mod audit_event {
    use sea_orm::entity::prelude::*;

    #[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
    #[sea_orm(table_name = "audit_events")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: Uuid,
        pub project_id: Option<Uuid>,
        pub actor_kind: String,
        pub action: String,
        pub target_kind: String,
        pub target_id: Option<Uuid>,
        pub outcome: String,
        pub correlation_id: Uuid,
        pub safe_context: Json,
    }

    #[derive(Clone, Copy, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

pub(crate) mod control_idempotency_record {
    use sea_orm::entity::prelude::*;

    #[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
    #[sea_orm(table_name = "control_idempotency_records")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub idempotency_key: String,
        pub project_id: Option<Uuid>,
        pub request_digest: Vec<u8>,
        pub state: String,
        pub result_resource_id: Option<Uuid>,
        pub response: Option<Json>,
        pub operation_kind: String,
        pub request_scope: String,
        pub expires_at: Option<TimeDateTimeWithTimeZone>,
        pub completed_at: Option<TimeDateTimeWithTimeZone>,
    }

    #[derive(Clone, Copy, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

#[allow(
    dead_code,
    reason = "Block B repositories follow the schema/entity slice"
)]
pub(crate) mod project_user {
    use sea_orm::entity::prelude::*;

    #[derive(Clone, Debug, Eq, PartialEq, DeriveEntityModel)]
    #[sea_orm(table_name = "project_users")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: Uuid,
        pub project_id: Uuid,
        pub public_id: String,
        pub status: String,
        pub user_revision: i64,
        pub security_revision: i64,
        pub primary_profile_identity_id: Option<Uuid>,
        pub base_profile_digest: Vec<u8>,
        pub display_name: Option<String>,
        pub picture_url: Option<String>,
        pub created_at: TimeDateTimeWithTimeZone,
        pub updated_at: TimeDateTimeWithTimeZone,
    }

    #[derive(Clone, Copy, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

#[allow(
    dead_code,
    reason = "Block B repositories follow the schema/entity slice"
)]
pub(crate) mod linked_identity {
    use sea_orm::entity::prelude::*;

    #[derive(Clone, Debug, Eq, PartialEq, DeriveEntityModel)]
    #[sea_orm(table_name = "linked_identities")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: Uuid,
        pub project_id: Uuid,
        pub user_id: Uuid,
        pub created_via_provider_configuration_id: Uuid,
        pub issuer: String,
        pub subject: String,
        pub status: String,
        pub identity_revision: i64,
        pub display_name: Option<String>,
        pub picture_url: Option<String>,
        pub observed_at: TimeDateTimeWithTimeZone,
        pub created_at: TimeDateTimeWithTimeZone,
        pub updated_at: TimeDateTimeWithTimeZone,
    }

    #[derive(Clone, Copy, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

#[allow(
    dead_code,
    reason = "Block B repositories follow the schema/entity slice"
)]
pub(crate) mod login_transaction {
    use sea_orm::entity::prelude::*;

    #[derive(Clone, Debug, Eq, PartialEq, DeriveEntityModel)]
    #[sea_orm(table_name = "login_transactions")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: Uuid,
        pub project_id: Uuid,
        pub application_id: Uuid,
        pub interaction_digest: Vec<u8>,
        pub interaction_digest_key_version: i32,
        pub status: String,
        pub transaction_revision: i64,
        pub redirect_uri: String,
        pub application_pkce_challenge: String,
        pub application_state_ciphertext: Vec<u8>,
        pub application_state_key_version: i32,
        pub presentation_hint: Option<String>,
        pub browser_binding_digest: Option<Vec<u8>>,
        pub browser_binding_digest_key_version: Option<i32>,
        pub csrf_digest: Option<Vec<u8>>,
        pub csrf_digest_key_version: Option<i32>,
        pub selected_method: Option<String>,
        pub provider_configuration_id: Option<Uuid>,
        pub user_id: Option<Uuid>,
        pub callback_url: Option<String>,
        pub upstream_state_digest: Option<Vec<u8>>,
        pub upstream_state_digest_key_version: Option<i32>,
        pub oidc_nonce_digest: Option<Vec<u8>>,
        pub oidc_nonce_digest_key_version: Option<i32>,
        pub provider_pkce_ciphertext: Option<Vec<u8>>,
        pub provider_pkce_key_version: Option<i32>,
        pub project_metadata_revision: i64,
        pub project_security_revision: i64,
        pub application_security_revision: i64,
        pub provider_revision: Option<i64>,
        pub assignment_security_revision: Option<i64>,
        pub claims_revision: i64,
        pub session_revision: i64,
        pub authenticated_at: Option<TimeDateTimeWithTimeZone>,
        pub expires_at: TimeDateTimeWithTimeZone,
        pub terminal_at: Option<TimeDateTimeWithTimeZone>,
        pub created_at: TimeDateTimeWithTimeZone,
        pub updated_at: TimeDateTimeWithTimeZone,
    }

    #[derive(Clone, Copy, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

#[allow(
    dead_code,
    reason = "Block B repositories follow the schema/entity slice"
)]
pub(crate) mod login_transaction_method {
    use sea_orm::entity::prelude::*;

    #[derive(Clone, Debug, Eq, PartialEq, DeriveEntityModel)]
    #[sea_orm(table_name = "login_transaction_methods")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub project_id: Uuid,
        #[sea_orm(primary_key, auto_increment = false)]
        pub transaction_id: Uuid,
        #[sea_orm(primary_key, auto_increment = false)]
        pub method_key: String,
        pub method_kind: String,
        pub provider_configuration_id: Option<Uuid>,
        pub display_name: String,
        pub provider_revision: Option<i64>,
        pub assignment_security_revision: Option<i64>,
        pub created_at: TimeDateTimeWithTimeZone,
    }

    #[derive(Clone, Copy, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

#[allow(
    dead_code,
    reason = "Block B repositories follow the schema/entity slice"
)]
pub(crate) mod project_browser_session {
    use sea_orm::entity::prelude::*;

    #[derive(Clone, Debug, Eq, PartialEq, DeriveEntityModel)]
    #[sea_orm(table_name = "project_browser_sessions")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: Uuid,
        pub project_id: Uuid,
        pub user_id: Uuid,
        pub credential_digest: Vec<u8>,
        pub credential_digest_key_version: i32,
        pub status: String,
        pub session_revision: i64,
        pub project_security_revision: i64,
        pub user_security_revision: i64,
        pub policy_session_revision: i64,
        pub authenticated_at: TimeDateTimeWithTimeZone,
        pub last_activity_at: TimeDateTimeWithTimeZone,
        pub idle_expires_at: TimeDateTimeWithTimeZone,
        pub absolute_expires_at: TimeDateTimeWithTimeZone,
        pub terminated_at: Option<TimeDateTimeWithTimeZone>,
        pub created_at: TimeDateTimeWithTimeZone,
        pub updated_at: TimeDateTimeWithTimeZone,
    }

    #[derive(Clone, Copy, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

#[allow(
    dead_code,
    reason = "Block B repositories follow the schema/entity slice"
)]
pub(crate) mod handoff_ticket {
    use sea_orm::entity::prelude::*;

    #[derive(Clone, Debug, Eq, PartialEq, DeriveEntityModel)]
    #[sea_orm(table_name = "handoff_tickets")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: Uuid,
        pub project_id: Uuid,
        pub login_transaction_id: Uuid,
        pub application_id: Uuid,
        pub user_id: Uuid,
        pub browser_session_id: Uuid,
        pub provider_configuration_id: Option<Uuid>,
        pub ticket_digest: Vec<u8>,
        pub ticket_digest_key_version: i32,
        pub status: String,
        pub redirect_uri: String,
        pub application_pkce_challenge: String,
        pub authentication_method: String,
        pub authenticated_at: TimeDateTimeWithTimeZone,
        pub project_security_revision: i64,
        pub application_security_revision: i64,
        pub user_security_revision: i64,
        pub provider_revision: Option<i64>,
        pub assignment_security_revision: Option<i64>,
        pub claims_revision: i64,
        pub policy_session_revision: i64,
        pub issued_at: TimeDateTimeWithTimeZone,
        pub expires_at: TimeDateTimeWithTimeZone,
        pub consumed_at: Option<TimeDateTimeWithTimeZone>,
        pub created_at: TimeDateTimeWithTimeZone,
    }

    #[derive(Clone, Copy, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

#[allow(
    dead_code,
    reason = "Block B repositories follow the schema/entity slice"
)]
pub(crate) mod application_user_binding {
    use sea_orm::entity::prelude::*;

    #[derive(Clone, Debug, Eq, PartialEq, DeriveEntityModel)]
    #[sea_orm(table_name = "application_user_bindings")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: Uuid,
        pub project_id: Uuid,
        pub application_id: Uuid,
        pub user_id: Uuid,
        pub status: String,
        pub binding_revision: i64,
        pub created_at: TimeDateTimeWithTimeZone,
        pub updated_at: TimeDateTimeWithTimeZone,
    }

    #[derive(Clone, Copy, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

#[allow(
    dead_code,
    reason = "Block B repositories follow the schema/entity slice"
)]
pub(crate) mod application_user_projection {
    use sea_orm::entity::prelude::*;

    #[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
    #[sea_orm(table_name = "application_user_projections")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: Uuid,
        pub project_id: Uuid,
        pub binding_id: Uuid,
        pub application_id: Uuid,
        pub user_id: Uuid,
        pub schema_name: String,
        pub projection_revision: i64,
        pub source_user_revision: i64,
        pub project_policy_revision: i64,
        pub application_policy_revision: i64,
        pub canonical_digest: Vec<u8>,
        pub document: Json,
        pub created_at: TimeDateTimeWithTimeZone,
        pub updated_at: TimeDateTimeWithTimeZone,
    }

    #[derive(Clone, Copy, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

#[allow(
    dead_code,
    reason = "Block B repositories follow the schema/entity slice"
)]
pub(crate) mod application_session {
    use sea_orm::entity::prelude::*;

    #[derive(Clone, Debug, Eq, PartialEq, DeriveEntityModel)]
    #[sea_orm(table_name = "application_sessions")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: Uuid,
        pub project_id: Uuid,
        pub application_id: Uuid,
        pub user_id: Uuid,
        pub binding_id: Uuid,
        pub browser_session_id: Option<Uuid>,
        pub status: String,
        pub session_revision: i64,
        pub project_security_revision: i64,
        pub application_security_revision: i64,
        pub user_security_revision: i64,
        pub claims_revision: i64,
        pub policy_session_revision: i64,
        pub authenticated_at: TimeDateTimeWithTimeZone,
        pub absolute_expires_at: TimeDateTimeWithTimeZone,
        pub revoked_at: Option<TimeDateTimeWithTimeZone>,
        pub created_at: TimeDateTimeWithTimeZone,
        pub updated_at: TimeDateTimeWithTimeZone,
    }

    #[derive(Clone, Copy, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

#[allow(
    dead_code,
    reason = "Block B repositories follow the schema/entity slice"
)]
pub(crate) mod refresh_family {
    use sea_orm::entity::prelude::*;

    #[derive(Clone, Debug, Eq, PartialEq, DeriveEntityModel)]
    #[sea_orm(table_name = "refresh_families")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: Uuid,
        pub project_id: Uuid,
        pub application_id: Uuid,
        pub user_id: Uuid,
        pub application_session_id: Uuid,
        pub status: String,
        pub family_revision: i64,
        pub current_generation: i64,
        pub allowed_clock_skew_seconds: i32,
        pub absolute_expires_at: TimeDateTimeWithTimeZone,
        pub revoked_at: Option<TimeDateTimeWithTimeZone>,
        pub revocation_reason: Option<String>,
        pub created_at: TimeDateTimeWithTimeZone,
        pub updated_at: TimeDateTimeWithTimeZone,
    }

    #[derive(Clone, Copy, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

#[allow(
    dead_code,
    reason = "Block B repositories follow the schema/entity slice"
)]
pub(crate) mod refresh_token_generation {
    use sea_orm::entity::prelude::*;

    #[derive(Clone, Debug, Eq, PartialEq, DeriveEntityModel)]
    #[sea_orm(table_name = "refresh_token_generations")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: Uuid,
        pub project_id: Uuid,
        pub family_id: Uuid,
        pub application_id: Uuid,
        pub user_id: Uuid,
        pub generation: i64,
        pub token_digest: Vec<u8>,
        pub token_digest_key_version: i32,
        pub status: String,
        pub consumed_at: Option<TimeDateTimeWithTimeZone>,
        pub replay_detected_at: Option<TimeDateTimeWithTimeZone>,
        pub retain_until: TimeDateTimeWithTimeZone,
        pub created_at: TimeDateTimeWithTimeZone,
    }

    #[derive(Clone, Copy, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

#[allow(
    dead_code,
    reason = "Block B repositories follow the schema/entity slice"
)]
pub(crate) mod project_browser_logout_interaction {
    use sea_orm::entity::prelude::*;

    #[derive(Clone, Debug, Eq, PartialEq, DeriveEntityModel)]
    #[sea_orm(table_name = "project_browser_logout_interactions")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: Uuid,
        pub project_id: Uuid,
        pub application_id: Uuid,
        pub user_id: Uuid,
        pub application_session_id: Uuid,
        pub browser_session_id: Uuid,
        pub preparation_digest: Vec<u8>,
        pub preparation_digest_key_version: i32,
        pub status: String,
        pub interaction_revision: i64,
        pub csrf_digest: Option<Vec<u8>>,
        pub csrf_digest_key_version: Option<i32>,
        pub application_session_revision: i64,
        pub browser_session_revision: i64,
        pub expires_at: TimeDateTimeWithTimeZone,
        pub csrf_bound_at: Option<TimeDateTimeWithTimeZone>,
        pub consumed_at: Option<TimeDateTimeWithTimeZone>,
        pub created_at: TimeDateTimeWithTimeZone,
        pub updated_at: TimeDateTimeWithTimeZone,
    }

    #[derive(Clone, Copy, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}
