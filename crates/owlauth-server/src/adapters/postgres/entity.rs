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
