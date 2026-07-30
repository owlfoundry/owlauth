-- Control provisioning and Runtime login-readiness authority.
-- This migration is additive to the retained Project/Application foundation.

ALTER TABLE projects
    ADD COLUMN display_name TEXT NOT NULL DEFAULT 'Untitled project',
    ADD CONSTRAINT projects_display_name_length CHECK (char_length(display_name) BETWEEN 1 AND 128),
    ADD CONSTRAINT projects_public_id_length CHECK (char_length(public_id) BETWEEN 8 AND 96),
    ADD CONSTRAINT projects_belongs_to_length CHECK (belongs_to IS NULL OR char_length(belongs_to) BETWEEN 1 AND 256),
    ADD CONSTRAINT projects_id_revision_unique UNIQUE (id, metadata_revision, security_revision);

ALTER TABLE applications
    ADD COLUMN display_name TEXT NOT NULL DEFAULT 'Untitled application',
    ADD COLUMN application_type TEXT NOT NULL DEFAULT 'web',
    ADD COLUMN metadata_revision BIGINT NOT NULL DEFAULT 1,
    ADD COLUMN security_revision BIGINT NOT NULL DEFAULT 1,
    ADD CONSTRAINT applications_display_name_length CHECK (char_length(display_name) BETWEEN 1 AND 128),
    ADD CONSTRAINT applications_public_id_length CHECK (char_length(public_id) BETWEEN 8 AND 96),
    ADD CONSTRAINT applications_type_check CHECK (application_type IN ('web', 'native')),
    ADD CONSTRAINT applications_metadata_revision_check CHECK (metadata_revision > 0),
    ADD CONSTRAINT applications_security_revision_check CHECK (security_revision > 0),
    ADD CONSTRAINT applications_project_id_id_unique UNIQUE (project_id, id),
    ADD CONSTRAINT applications_project_id_id_security_unique UNIQUE (project_id, id, security_revision);

CREATE TABLE application_redirects (
    project_id UUID NOT NULL,
    application_id UUID NOT NULL,
    redirect_uri TEXT NOT NULL,
    redirect_type TEXT NOT NULL CHECK (redirect_type IN ('web', 'loopback', 'custom_scheme')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (project_id, application_id, redirect_uri),
    FOREIGN KEY (project_id, application_id)
        REFERENCES applications (project_id, id) ON DELETE CASCADE,
    CHECK (char_length(redirect_uri) BETWEEN 8 AND 2048)
);

CREATE TABLE application_origins (
    project_id UUID NOT NULL,
    application_id UUID NOT NULL,
    origin TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (project_id, application_id, origin),
    FOREIGN KEY (project_id, application_id)
        REFERENCES applications (project_id, id) ON DELETE CASCADE,
    CHECK (char_length(origin) BETWEEN 8 AND 512)
);

CREATE TABLE application_publishable_keys (
    id UUID PRIMARY KEY,
    project_id UUID NOT NULL,
    application_id UUID NOT NULL,
    public_id TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('active', 'disabled')),
    revision BIGINT NOT NULL CHECK (revision > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    FOREIGN KEY (project_id, application_id)
        REFERENCES applications (project_id, id) ON DELETE CASCADE,
    UNIQUE (project_id, public_id),
    UNIQUE (project_id, application_id, id)
);

ALTER TABLE control_idempotency_records
    ADD COLUMN operation_kind TEXT NOT NULL DEFAULT 'project.create',
    ADD COLUMN request_scope TEXT NOT NULL DEFAULT 'deployment',
    ADD COLUMN expires_at TIMESTAMPTZ,
    ADD CONSTRAINT control_idempotency_key_length CHECK (char_length(idempotency_key) BETWEEN 8 AND 128),
    ADD CONSTRAINT control_idempotency_operation_length CHECK (char_length(operation_kind) BETWEEN 3 AND 96),
    ADD CONSTRAINT control_idempotency_scope_length CHECK (char_length(request_scope) BETWEEN 1 AND 128),
    ADD CONSTRAINT control_idempotency_digest_length CHECK (octet_length(request_digest) = 32),
    ADD CONSTRAINT control_idempotency_expiry_check CHECK (expires_at IS NULL OR expires_at > created_at);

CREATE INDEX control_idempotency_expiry_idx
    ON control_idempotency_records (expires_at)
    WHERE expires_at IS NOT NULL;

CREATE TABLE project_key_rings (
    id UUID PRIMARY KEY,
    project_id UUID NOT NULL REFERENCES projects (id) ON DELETE CASCADE,
    issuer TEXT NOT NULL,
    purpose TEXT NOT NULL CHECK (purpose IN ('application_tokens')),
    algorithm TEXT NOT NULL CHECK (algorithm IN ('EdDSA')),
    revision BIGINT NOT NULL CHECK (revision > 0),
    signing_epoch BIGINT NOT NULL CHECK (signing_epoch > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    UNIQUE (project_id, issuer, purpose, algorithm),
    UNIQUE (project_id, id),
    CHECK (char_length(issuer) BETWEEN 8 AND 2048)
);

CREATE TABLE project_signing_keys (
    id UUID PRIMARY KEY,
    project_id UUID NOT NULL,
    ring_id UUID NOT NULL,
    kid TEXT NOT NULL,
    public_jwk JSONB NOT NULL,
    signer_ref TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN (
        'provisioning', 'published', 'active', 'retiring', 'retired', 'revoked', 'abandoned'
    )),
    ring_revision BIGINT NOT NULL CHECK (ring_revision > 0),
    provisioned_at TIMESTAMPTZ,
    published_at TIMESTAMPTZ,
    activated_at TIMESTAMPTZ,
    retiring_at TIMESTAMPTZ,
    retired_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    FOREIGN KEY (project_id, ring_id)
        REFERENCES project_key_rings (project_id, id) ON DELETE CASCADE,
    UNIQUE (project_id, kid),
    UNIQUE (project_id, ring_id, id),
    CHECK (char_length(kid) BETWEEN 8 AND 128),
    CHECK (char_length(signer_ref) BETWEEN 8 AND 256),
    CHECK (jsonb_typeof(public_jwk) = 'object')
);

CREATE UNIQUE INDEX project_signing_keys_one_active_idx
    ON project_signing_keys (project_id, ring_id)
    WHERE state = 'active';

CREATE TABLE key_provisioning_operations (
    id UUID PRIMARY KEY,
    project_id UUID NOT NULL,
    ring_id UUID NOT NULL,
    key_id UUID NOT NULL,
    operation_alias TEXT NOT NULL,
    request_digest BYTEA NOT NULL CHECK (octet_length(request_digest) = 32),
    state TEXT NOT NULL CHECK (state IN ('prepared', 'stored', 'completed', 'failed', 'abandoned')),
    attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    expected_project_revision BIGINT NOT NULL CHECK (expected_project_revision > 0),
    expected_ring_revision BIGINT NOT NULL CHECK (expected_ring_revision > 0),
    last_attempt_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    FOREIGN KEY (project_id, ring_id, key_id)
        REFERENCES project_signing_keys (project_id, ring_id, id) ON DELETE CASCADE,
    UNIQUE (project_id, operation_alias),
    UNIQUE (project_id, key_id),
    CHECK (char_length(operation_alias) BETWEEN 8 AND 128),
    CHECK ((state = 'completed' AND completed_at IS NOT NULL) OR state <> 'completed')
);

CREATE TABLE runtime_publication_leases (
    project_id UUID NOT NULL,
    ring_id UUID NOT NULL,
    process_id TEXT NOT NULL,
    loaded_revision BIGINT NOT NULL CHECK (loaded_revision > 0),
    first_observed_at TIMESTAMPTZ NOT NULL,
    last_observed_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (project_id, ring_id, process_id),
    FOREIGN KEY (project_id, ring_id)
        REFERENCES project_key_rings (project_id, id) ON DELETE CASCADE,
    CHECK (char_length(process_id) BETWEEN 1 AND 128),
    CHECK (last_observed_at >= first_observed_at),
    CHECK (expires_at > last_observed_at)
);

CREATE INDEX runtime_publication_leases_expiry_idx
    ON runtime_publication_leases (project_id, ring_id, expires_at);

CREATE TABLE provider_configurations (
    id UUID PRIMARY KEY,
    project_id UUID NOT NULL REFERENCES projects (id) ON DELETE CASCADE,
    provider_key TEXT NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('oidc')),
    display_name TEXT NOT NULL,
    issuer TEXT NOT NULL,
    client_id TEXT NOT NULL,
    callback_url TEXT NOT NULL,
    secret_ref TEXT,
    status TEXT NOT NULL CHECK (status IN ('provisioning', 'active', 'disabled')),
    revision BIGINT NOT NULL CHECK (revision > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    UNIQUE (project_id, provider_key),
    UNIQUE (project_id, id),
    CHECK (char_length(provider_key) BETWEEN 1 AND 64),
    CHECK (provider_key ~ '^[a-z][a-z0-9_-]*$'),
    CHECK (char_length(display_name) BETWEEN 1 AND 128),
    CHECK (char_length(issuer) BETWEEN 8 AND 2048),
    CHECK (char_length(client_id) BETWEEN 1 AND 512),
    CHECK (char_length(callback_url) BETWEEN 8 AND 2048),
    CHECK (secret_ref IS NULL OR char_length(secret_ref) BETWEEN 8 AND 256),
    CHECK ((status = 'provisioning' AND secret_ref IS NULL) OR (status <> 'provisioning' AND secret_ref IS NOT NULL))
);

CREATE TABLE provider_secret_operations (
    id UUID PRIMARY KEY,
    project_id UUID NOT NULL,
    provider_id UUID NOT NULL,
    operation_alias TEXT NOT NULL,
    request_digest BYTEA NOT NULL CHECK (octet_length(request_digest) = 32),
    state TEXT NOT NULL CHECK (state IN ('prepared', 'stored', 'completed', 'failed', 'abandoned')),
    attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    expected_project_revision BIGINT NOT NULL CHECK (expected_project_revision > 0),
    expected_provider_revision BIGINT NOT NULL CHECK (expected_provider_revision > 0),
    last_attempt_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    FOREIGN KEY (project_id, provider_id)
        REFERENCES provider_configurations (project_id, id) ON DELETE CASCADE,
    UNIQUE (project_id, operation_alias),
    UNIQUE (project_id, provider_id),
    CHECK (char_length(operation_alias) BETWEEN 8 AND 128),
    CHECK ((state = 'completed' AND completed_at IS NOT NULL) OR state <> 'completed')
);

CREATE TABLE application_provider_assignments (
    project_id UUID NOT NULL,
    application_id UUID NOT NULL,
    provider_id UUID NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('active', 'disabled')),
    security_revision BIGINT NOT NULL CHECK (security_revision > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (project_id, application_id, provider_id),
    FOREIGN KEY (project_id, application_id)
        REFERENCES applications (project_id, id) ON DELETE CASCADE,
    FOREIGN KEY (project_id, provider_id)
        REFERENCES provider_configurations (project_id, id) ON DELETE CASCADE
);

CREATE INDEX applications_project_status_idx ON applications (project_id, status, created_at, id);
CREATE INDEX signing_keys_project_ring_state_idx
    ON project_signing_keys (project_id, ring_id, state, created_at, id);
CREATE INDEX providers_project_status_idx
    ON provider_configurations (project_id, status, created_at, id);
CREATE INDEX assignments_application_status_idx
    ON application_provider_assignments (project_id, application_id, status);
