pub(crate) mod project {
    use sea_orm::entity::prelude::*;

    #[derive(Clone, Debug, Eq, PartialEq, DeriveEntityModel)]
    #[sea_orm(table_name = "projects")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: Uuid,
        pub public_id: String,
        pub belongs_to: Option<String>,
        pub status: String,
        pub metadata_revision: i64,
        pub security_revision: i64,
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
        pub completed_at: Option<TimeDateTimeWithTimeZone>,
    }

    #[derive(Clone, Copy, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}
