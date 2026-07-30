-- Authoritative Project, Application, Control idempotency, and audit core.

CREATE TABLE projects (
    id UUID PRIMARY KEY,
    public_id TEXT NOT NULL UNIQUE,
    belongs_to TEXT,
    status TEXT NOT NULL CHECK (status IN ('active', 'disabled')),
    metadata_revision BIGINT NOT NULL CHECK (metadata_revision > 0),
    security_revision BIGINT NOT NULL CHECK (security_revision > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    UNIQUE (id, metadata_revision)
);

CREATE INDEX projects_belongs_to_idx ON projects (belongs_to) WHERE belongs_to IS NOT NULL;

CREATE TABLE applications (
    id UUID PRIMARY KEY,
    project_id UUID NOT NULL REFERENCES projects (id),
    public_id TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('active', 'disabled')),
    revision BIGINT NOT NULL CHECK (revision > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    UNIQUE (project_id, id),
    UNIQUE (project_id, public_id)
);

CREATE TABLE control_idempotency_records (
    idempotency_key TEXT PRIMARY KEY,
    project_id UUID REFERENCES projects (id),
    request_digest BYTEA NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('pending', 'completed')),
    result_resource_id UUID,
    response JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    completed_at TIMESTAMPTZ,
    CHECK (
        (state = 'pending' AND completed_at IS NULL AND response IS NULL)
        OR (state = 'completed' AND completed_at IS NOT NULL AND response IS NOT NULL)
    )
);

CREATE TABLE audit_events (
    id UUID PRIMARY KEY,
    project_id UUID REFERENCES projects (id),
    actor_kind TEXT NOT NULL,
    action TEXT NOT NULL,
    target_kind TEXT NOT NULL,
    target_id UUID,
    outcome TEXT NOT NULL,
    correlation_id UUID NOT NULL,
    safe_context JSONB NOT NULL DEFAULT '{}'::jsonb,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp()
);

CREATE INDEX audit_events_project_time_idx
    ON audit_events (project_id, occurred_at DESC, id);
