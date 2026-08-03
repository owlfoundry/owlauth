-- OwlAuth initial PostgreSQL schema.
-- This repository has not published a server release; the complete pre-release schema is kept as one baseline migration.

-- -----------------------------------------------------------------------------
-- Integrated from pre-release schema slice: 20260729000000_project_application_core.sql
-- -----------------------------------------------------------------------------

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

CREATE TABLE mcp_confirmation_capabilities (
    id UUID PRIMARY KEY,
    capability_digest BYTEA NOT NULL UNIQUE CHECK (octet_length(capability_digest) = 32),
    actor_kind TEXT NOT NULL CHECK (actor_kind = 'deployment_operator'),
    audience TEXT NOT NULL CHECK (audience = 'control_mcp'),
    instance_id TEXT NOT NULL CHECK (char_length(instance_id) BETWEEN 1 AND 128),
    control_endpoint TEXT NOT NULL CHECK (char_length(control_endpoint) BETWEEN 1 AND 2048),
    tool_name TEXT NOT NULL CHECK (char_length(tool_name) BETWEEN 1 AND 128),
    command_digest BYTEA NOT NULL CHECK (octet_length(command_digest) = 32),
    project_id UUID REFERENCES projects (id),
    project_metadata_revision BIGINT,
    application_id UUID,
    target_revision BIGINT NOT NULL CHECK (target_revision > 0),
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    CHECK (
        (project_id IS NULL AND project_metadata_revision IS NULL)
        OR (project_id IS NOT NULL AND project_metadata_revision > 0)
    ),
    CHECK (application_id IS NULL OR project_id IS NOT NULL),
    FOREIGN KEY (project_id, application_id) REFERENCES applications (project_id, id),
    CHECK (expires_at > created_at AND expires_at <= created_at + INTERVAL '5 minutes'),
    CHECK (consumed_at IS NULL OR consumed_at >= created_at)
);

CREATE INDEX mcp_confirmation_capabilities_cleanup_idx
    ON mcp_confirmation_capabilities (expires_at, id);

-- -----------------------------------------------------------------------------
-- Integrated from pre-release schema slice: 20260730000000_control_provisioning_readiness.sql
-- -----------------------------------------------------------------------------

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

-- -----------------------------------------------------------------------------
-- Integrated from pre-release schema slice: 20260730010000_policy_signing_safety.sql
-- -----------------------------------------------------------------------------

-- Add durable Project policy and signing-lifecycle safety state.

ALTER TABLE project_signing_keys
    ADD COLUMN sign_not_before TIMESTAMPTZ,
    ADD COLUMN verify_not_after TIMESTAMPTZ;

UPDATE project_signing_keys
SET sign_not_before = COALESCE(activated_at, published_at, provisioned_at, created_at)
WHERE state IN ('active', 'retiring', 'retired');

UPDATE project_signing_keys
SET verify_not_after = CASE
    WHEN state = 'retiring' THEN transaction_timestamp() + INTERVAL '20 minutes'
    ELSE GREATEST(
        COALESCE(retired_at, updated_at, created_at),
        sign_not_before + INTERVAL '1 microsecond'
    )
END
WHERE state IN ('retiring', 'retired');

ALTER TABLE project_signing_keys
    ADD CONSTRAINT project_signing_keys_sign_window_check CHECK (
        verify_not_after IS NULL
        OR sign_not_before IS NULL
        OR verify_not_after > sign_not_before
    ),
    ADD CONSTRAINT project_signing_keys_active_sign_time_check CHECK (
        state NOT IN ('active', 'retiring', 'retired')
        OR sign_not_before IS NOT NULL
    ),
    ADD CONSTRAINT project_signing_keys_retirement_cutoff_check CHECK (
        state NOT IN ('retiring', 'retired')
        OR verify_not_after IS NOT NULL
    );

CREATE TABLE project_policies (
    project_id UUID PRIMARY KEY REFERENCES projects (id) ON DELETE CASCADE,
    claims_revision BIGINT NOT NULL DEFAULT 1 CHECK (claims_revision > 0),
    session_revision BIGINT NOT NULL DEFAULT 1 CHECK (session_revision > 0),
    claims_policy JSONB NOT NULL DEFAULT '{"access_token_lifetime_seconds":900}'::JSONB,
    session_policy JSONB NOT NULL DEFAULT '{"browser_session_reuse":false}'::JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    CHECK (jsonb_typeof(claims_policy) = 'object'),
    CHECK (jsonb_typeof(session_policy) = 'object'),
    CHECK (octet_length(claims_policy::TEXT) <= 8192),
    CHECK (octet_length(session_policy::TEXT) <= 8192),
    CHECK (
        claims_policy - 'access_token_lifetime_seconds' = '{}'::JSONB
        AND jsonb_typeof(claims_policy -> 'access_token_lifetime_seconds') = 'number'
        AND claims_policy -> 'access_token_lifetime_seconds'
            = to_jsonb((claims_policy ->> 'access_token_lifetime_seconds')::INTEGER)
        AND (claims_policy ->> 'access_token_lifetime_seconds')::INTEGER BETWEEN 60 AND 3600
    ),
    CHECK (
        session_policy - 'browser_session_reuse' = '{}'::JSONB
        AND jsonb_typeof(session_policy -> 'browser_session_reuse') = 'boolean'
    )
);

INSERT INTO project_policies (project_id)
SELECT id
FROM projects;

CREATE TABLE key_state_events (
    id UUID PRIMARY KEY,
    project_id UUID NOT NULL,
    ring_id UUID NOT NULL,
    signing_key_id UUID NOT NULL,
    ring_revision BIGINT NOT NULL CHECK (ring_revision > 0),
    from_state TEXT NOT NULL CHECK (from_state IN (
        'provisioning', 'published', 'active', 'retiring', 'retired', 'revoked', 'abandoned'
    )),
    to_state TEXT NOT NULL CHECK (to_state IN (
        'published', 'active', 'retiring', 'retired', 'revoked', 'abandoned'
    )),
    actor_kind TEXT NOT NULL CHECK (actor_kind IN ('deployment_operator', 'system')),
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    FOREIGN KEY (project_id, ring_id, signing_key_id)
        REFERENCES project_signing_keys (project_id, ring_id, id),
    UNIQUE (project_id, signing_key_id, ring_revision, to_state)
);

CREATE INDEX key_state_events_key_revision_idx
    ON key_state_events (project_id, signing_key_id, ring_revision);

-- -----------------------------------------------------------------------------
-- Integrated from pre-release schema slice: 20260730020000_federated_auth_foundation.sql
-- -----------------------------------------------------------------------------

-- Federated Project Auth identity, transaction, session, and one-use credential authority.

-- Browser-session reuse age becomes an explicit session-revision-owned Project policy.
DO $$
DECLARE
    session_policy_constraint TEXT;
BEGIN
    SELECT constraint_row.conname
    INTO STRICT session_policy_constraint
    FROM pg_constraint AS constraint_row
    JOIN pg_class AS table_row ON table_row.oid = constraint_row.conrelid
    JOIN pg_namespace AS namespace_row ON namespace_row.oid = table_row.relnamespace
    WHERE namespace_row.nspname = current_schema()
      AND table_row.relname = 'project_policies'
      AND constraint_row.contype = 'c'
      AND pg_get_constraintdef(constraint_row.oid) LIKE '%browser_session_reuse%';

    EXECUTE format(
        'ALTER TABLE project_policies DROP CONSTRAINT %I',
        session_policy_constraint
    );
END
$$;

UPDATE project_policies
SET session_policy = session_policy || '{"browser_session_reuse_max_age_seconds":28800}'::JSONB;

ALTER TABLE project_policies
    ADD CONSTRAINT project_policies_session_shape_check CHECK (
        session_policy - ARRAY['browser_session_reuse', 'browser_session_reuse_max_age_seconds']
            = '{}'::JSONB
        AND jsonb_typeof(session_policy -> 'browser_session_reuse') = 'boolean'
        AND jsonb_typeof(session_policy -> 'browser_session_reuse_max_age_seconds') = 'number'
        AND session_policy -> 'browser_session_reuse_max_age_seconds'
            = to_jsonb((session_policy ->> 'browser_session_reuse_max_age_seconds')::INTEGER)
        AND (session_policy ->> 'browser_session_reuse_max_age_seconds')::INTEGER
            BETWEEN 0 AND 86400
    );

ALTER TABLE project_policies
    ALTER COLUMN session_policy
        SET DEFAULT '{"browser_session_reuse":false,"browser_session_reuse_max_age_seconds":28800}'::JSONB,
    ADD COLUMN projection_revision BIGINT NOT NULL DEFAULT 1
        CHECK (projection_revision > 0);

ALTER TABLE applications
    ADD COLUMN projection_revision BIGINT NOT NULL DEFAULT 1
        CHECK (projection_revision > 0);

CREATE TABLE project_users (
    id UUID PRIMARY KEY,
    project_id UUID NOT NULL REFERENCES projects (id) ON DELETE CASCADE,
    public_id TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('active', 'disabled')),
    user_revision BIGINT NOT NULL DEFAULT 1 CHECK (user_revision > 0),
    security_revision BIGINT NOT NULL DEFAULT 1 CHECK (security_revision > 0),
    primary_profile_identity_id UUID,
    base_profile_digest BYTEA NOT NULL CHECK (octet_length(base_profile_digest) = 32),
    display_name TEXT,
    picture_url TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    UNIQUE (project_id, id),
    UNIQUE (project_id, public_id),
    UNIQUE (project_id, id, user_revision),
    UNIQUE (project_id, id, security_revision),
    CHECK (char_length(public_id) BETWEEN 8 AND 96),
    CHECK (display_name IS NULL OR char_length(display_name) BETWEEN 1 AND 128),
    CHECK (picture_url IS NULL OR char_length(picture_url) BETWEEN 8 AND 2048)
);

CREATE TABLE linked_identities (
    id UUID PRIMARY KEY,
    project_id UUID NOT NULL,
    user_id UUID NOT NULL,
    created_via_provider_configuration_id UUID NOT NULL,
    issuer TEXT NOT NULL,
    subject TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('active', 'disabled')),
    identity_revision BIGINT NOT NULL DEFAULT 1 CHECK (identity_revision > 0),
    display_name TEXT,
    picture_url TEXT,
    observed_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    FOREIGN KEY (project_id, user_id)
        REFERENCES project_users (project_id, id) ON DELETE CASCADE,
    FOREIGN KEY (project_id, created_via_provider_configuration_id)
        REFERENCES provider_configurations (project_id, id),
    UNIQUE (project_id, id),
    UNIQUE (project_id, id, user_id),
    UNIQUE (project_id, issuer, subject),
    CHECK (char_length(issuer) BETWEEN 8 AND 2048),
    CHECK (char_length(subject) BETWEEN 1 AND 512),
    CHECK (display_name IS NULL OR char_length(display_name) BETWEEN 1 AND 128),
    CHECK (picture_url IS NULL OR char_length(picture_url) BETWEEN 8 AND 2048)
);

ALTER TABLE project_users
    ADD CONSTRAINT project_users_primary_profile_identity_fk
    FOREIGN KEY (project_id, primary_profile_identity_id, id)
        REFERENCES linked_identities (project_id, id, user_id);

CREATE TABLE login_transactions (
    id UUID PRIMARY KEY,
    project_id UUID NOT NULL,
    application_id UUID NOT NULL,
    interaction_digest BYTEA NOT NULL CHECK (octet_length(interaction_digest) = 32),
    interaction_digest_key_version INTEGER NOT NULL CHECK (interaction_digest_key_version > 0),
    status TEXT NOT NULL CHECK (status IN (
        'awaiting_browser_binding', 'awaiting_method_selection', 'email_address_entry',
        'email_challenge_pending', 'provider_authorization_started',
        'provider_exchange_in_progress', 'provider_exchange_failed', 'authenticated',
        'handoff_issued', 'completed', 'expired', 'cancelled'
    )),
    transaction_revision BIGINT NOT NULL DEFAULT 1 CHECK (transaction_revision > 0),
    redirect_uri TEXT NOT NULL,
    application_pkce_challenge TEXT NOT NULL,
    application_state_ciphertext BYTEA NOT NULL,
    application_state_key_version INTEGER NOT NULL CHECK (application_state_key_version > 0),
    presentation_hint TEXT,
    browser_binding_digest BYTEA,
    browser_binding_digest_key_version INTEGER,
    csrf_digest BYTEA,
    csrf_digest_key_version INTEGER,
    selected_method TEXT CHECK (selected_method IN ('provider', 'email')),
    provider_configuration_id UUID,
    user_id UUID,
    callback_url TEXT,
    upstream_state_digest BYTEA,
    upstream_state_digest_key_version INTEGER,
    oidc_nonce_digest BYTEA,
    oidc_nonce_digest_key_version INTEGER,
    provider_pkce_ciphertext BYTEA,
    provider_pkce_key_version INTEGER,
    project_metadata_revision BIGINT NOT NULL CHECK (project_metadata_revision > 0),
    project_security_revision BIGINT NOT NULL CHECK (project_security_revision > 0),
    application_security_revision BIGINT NOT NULL CHECK (application_security_revision > 0),
    provider_revision BIGINT,
    assignment_security_revision BIGINT,
    claims_revision BIGINT NOT NULL CHECK (claims_revision > 0),
    session_revision BIGINT NOT NULL CHECK (session_revision > 0),
    authenticated_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ NOT NULL,
    terminal_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    FOREIGN KEY (project_id, application_id)
        REFERENCES applications (project_id, id) ON DELETE CASCADE,
    FOREIGN KEY (project_id, provider_configuration_id)
        REFERENCES provider_configurations (project_id, id),
    FOREIGN KEY (project_id, user_id)
        REFERENCES project_users (project_id, id),
    UNIQUE (project_id, id),
    UNIQUE (interaction_digest_key_version, interaction_digest),
    CHECK (char_length(redirect_uri) BETWEEN 8 AND 2048),
    CHECK (char_length(application_pkce_challenge) = 43),
    CHECK (octet_length(application_state_ciphertext) BETWEEN 17 AND 4096),
    CHECK (presentation_hint IS NULL OR char_length(presentation_hint) BETWEEN 1 AND 64),
    CHECK (expires_at = created_at + INTERVAL '10 minutes'),
    CHECK (
        (browser_binding_digest IS NULL AND browser_binding_digest_key_version IS NULL
            AND csrf_digest IS NULL AND csrf_digest_key_version IS NULL)
        OR (browser_binding_digest IS NOT NULL
            AND octet_length(browser_binding_digest) = 32
            AND browser_binding_digest_key_version IS NOT NULL
            AND browser_binding_digest_key_version > 0
            AND csrf_digest IS NOT NULL
            AND octet_length(csrf_digest) = 32
            AND csrf_digest_key_version IS NOT NULL
            AND csrf_digest_key_version > 0)
    ),
    CHECK (
        (status = 'awaiting_browser_binding'
            AND browser_binding_digest IS NULL AND selected_method IS NULL
            AND provider_configuration_id IS NULL AND user_id IS NULL)
        OR (status <> 'awaiting_browser_binding' AND browser_binding_digest IS NOT NULL)
    ),
    CHECK (
        (selected_method IS NULL AND provider_configuration_id IS NULL)
        OR selected_method = 'email'
        OR (selected_method = 'provider' AND provider_configuration_id IS NOT NULL)
    ),
    CHECK (
        provider_configuration_id IS NULL
        OR (callback_url IS NOT NULL AND char_length(callback_url) BETWEEN 8 AND 2048
            AND upstream_state_digest IS NOT NULL
            AND octet_length(upstream_state_digest) = 32
            AND upstream_state_digest_key_version IS NOT NULL
            AND upstream_state_digest_key_version > 0
            AND oidc_nonce_digest IS NOT NULL
            AND octet_length(oidc_nonce_digest) = 32
            AND oidc_nonce_digest_key_version IS NOT NULL
            AND oidc_nonce_digest_key_version > 0
            AND provider_pkce_ciphertext IS NOT NULL
            AND octet_length(provider_pkce_ciphertext) BETWEEN 17 AND 4096
            AND provider_pkce_key_version IS NOT NULL
            AND provider_pkce_key_version > 0
            AND provider_revision IS NOT NULL AND provider_revision > 0
            AND assignment_security_revision IS NOT NULL
            AND assignment_security_revision > 0)
    ),
    CHECK (
        status NOT IN ('provider_authorization_started', 'provider_exchange_in_progress',
            'provider_exchange_failed')
        OR (selected_method = 'provider' AND provider_configuration_id IS NOT NULL)
    ),
    CHECK (
        status NOT IN ('email_address_entry', 'email_challenge_pending')
        OR selected_method = 'email'
    ),
    CHECK (
        status NOT IN ('authenticated', 'handoff_issued', 'completed')
        OR (user_id IS NOT NULL AND authenticated_at IS NOT NULL)
    ),
    CHECK (
        (status IN ('provider_exchange_failed', 'completed', 'expired', 'cancelled'))
            = (terminal_at IS NOT NULL)
    )
);

CREATE TABLE login_transaction_methods (
    project_id UUID NOT NULL,
    transaction_id UUID NOT NULL,
    method_key TEXT NOT NULL,
    method_kind TEXT NOT NULL CHECK (method_kind IN ('provider', 'email')),
    provider_configuration_id UUID,
    display_name TEXT NOT NULL,
    provider_revision BIGINT,
    assignment_security_revision BIGINT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (project_id, transaction_id, method_key),
    FOREIGN KEY (project_id, transaction_id)
        REFERENCES login_transactions (project_id, id) ON DELETE CASCADE,
    FOREIGN KEY (project_id, provider_configuration_id)
        REFERENCES provider_configurations (project_id, id),
    CHECK (char_length(method_key) BETWEEN 1 AND 96),
    CHECK (char_length(display_name) BETWEEN 1 AND 128),
    CHECK (
        (method_kind = 'provider' AND provider_configuration_id IS NOT NULL
            AND provider_revision IS NOT NULL AND provider_revision > 0
            AND assignment_security_revision IS NOT NULL
            AND assignment_security_revision > 0)
        OR (method_kind = 'email' AND provider_configuration_id IS NULL
            AND provider_revision IS NULL AND assignment_security_revision IS NULL)
    )
);

CREATE TABLE project_browser_sessions (
    id UUID PRIMARY KEY,
    project_id UUID NOT NULL,
    user_id UUID NOT NULL,
    credential_digest BYTEA NOT NULL CHECK (octet_length(credential_digest) = 32),
    credential_digest_key_version INTEGER NOT NULL CHECK (credential_digest_key_version > 0),
    status TEXT NOT NULL CHECK (status IN ('active', 'terminated', 'expired')),
    session_revision BIGINT NOT NULL DEFAULT 1 CHECK (session_revision > 0),
    project_security_revision BIGINT NOT NULL CHECK (project_security_revision > 0),
    user_security_revision BIGINT NOT NULL CHECK (user_security_revision > 0),
    policy_session_revision BIGINT NOT NULL CHECK (policy_session_revision > 0),
    authenticated_at TIMESTAMPTZ NOT NULL,
    last_activity_at TIMESTAMPTZ NOT NULL,
    idle_expires_at TIMESTAMPTZ NOT NULL,
    absolute_expires_at TIMESTAMPTZ NOT NULL,
    terminated_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    FOREIGN KEY (project_id, user_id)
        REFERENCES project_users (project_id, id) ON DELETE CASCADE,
    UNIQUE (project_id, id),
    UNIQUE (project_id, id, user_id),
    UNIQUE (credential_digest_key_version, credential_digest),
    CHECK (last_activity_at >= authenticated_at),
    CHECK (absolute_expires_at = authenticated_at + INTERVAL '24 hours'),
    CHECK (
        idle_expires_at
            = LEAST(last_activity_at + INTERVAL '8 hours', absolute_expires_at)
    ),
    CHECK ((status = 'terminated') = (terminated_at IS NOT NULL))
);

CREATE INDEX login_transactions_expiry_idx
    ON login_transactions (status, expires_at, id);
CREATE INDEX login_transactions_provider_callback_idx
    ON login_transactions (project_id, provider_configuration_id, status, expires_at)
    WHERE provider_configuration_id IS NOT NULL;
CREATE UNIQUE INDEX login_transactions_upstream_state_unique_idx
    ON login_transactions (upstream_state_digest_key_version, upstream_state_digest)
    WHERE upstream_state_digest IS NOT NULL;
CREATE INDEX project_users_project_status_idx
    ON project_users (project_id, status, created_at, id);
CREATE INDEX linked_identities_user_idx
    ON linked_identities (project_id, user_id, status);
CREATE INDEX browser_sessions_user_status_idx
    ON project_browser_sessions (project_id, user_id, status, absolute_expires_at);

CREATE TABLE handoff_tickets (
    id UUID PRIMARY KEY,
    project_id UUID NOT NULL,
    login_transaction_id UUID NOT NULL,
    application_id UUID NOT NULL,
    user_id UUID NOT NULL,
    browser_session_id UUID NOT NULL,
    provider_configuration_id UUID,
    ticket_digest BYTEA NOT NULL CHECK (octet_length(ticket_digest) = 32),
    ticket_digest_key_version INTEGER NOT NULL CHECK (ticket_digest_key_version > 0),
    status TEXT NOT NULL CHECK (status IN ('issued', 'consumed', 'expired')),
    redirect_uri TEXT NOT NULL,
    application_pkce_challenge TEXT NOT NULL,
    authentication_method TEXT NOT NULL CHECK (authentication_method IN ('provider', 'email', 'session_reuse')),
    authenticated_at TIMESTAMPTZ NOT NULL,
    project_security_revision BIGINT NOT NULL CHECK (project_security_revision > 0),
    application_security_revision BIGINT NOT NULL CHECK (application_security_revision > 0),
    user_security_revision BIGINT NOT NULL CHECK (user_security_revision > 0),
    provider_revision BIGINT,
    assignment_security_revision BIGINT,
    claims_revision BIGINT NOT NULL CHECK (claims_revision > 0),
    policy_session_revision BIGINT NOT NULL CHECK (policy_session_revision > 0),
    issued_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    FOREIGN KEY (project_id, login_transaction_id)
        REFERENCES login_transactions (project_id, id) ON DELETE CASCADE,
    FOREIGN KEY (project_id, application_id)
        REFERENCES applications (project_id, id),
    FOREIGN KEY (project_id, user_id)
        REFERENCES project_users (project_id, id),
    FOREIGN KEY (project_id, browser_session_id, user_id)
        REFERENCES project_browser_sessions (project_id, id, user_id),
    FOREIGN KEY (project_id, provider_configuration_id)
        REFERENCES provider_configurations (project_id, id),
    UNIQUE (project_id, id),
    UNIQUE (project_id, login_transaction_id),
    UNIQUE (ticket_digest_key_version, ticket_digest),
    CHECK (char_length(redirect_uri) BETWEEN 8 AND 2048),
    CHECK (char_length(application_pkce_challenge) = 43),
    CHECK (expires_at > issued_at),
    CHECK (expires_at <= issued_at + INTERVAL '60 seconds'),
    CHECK (
        (authentication_method = 'provider' AND provider_configuration_id IS NOT NULL
            AND provider_revision IS NOT NULL AND provider_revision > 0
            AND assignment_security_revision IS NOT NULL
            AND assignment_security_revision > 0)
        OR (authentication_method <> 'provider' AND provider_configuration_id IS NULL
            AND provider_revision IS NULL AND assignment_security_revision IS NULL)
    ),
    CHECK ((status = 'consumed') = (consumed_at IS NOT NULL))
);

CREATE TABLE application_user_bindings (
    id UUID PRIMARY KEY,
    project_id UUID NOT NULL,
    application_id UUID NOT NULL,
    user_id UUID NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('active', 'disabled')),
    binding_revision BIGINT NOT NULL DEFAULT 1 CHECK (binding_revision > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    FOREIGN KEY (project_id, application_id)
        REFERENCES applications (project_id, id) ON DELETE CASCADE,
    FOREIGN KEY (project_id, user_id)
        REFERENCES project_users (project_id, id) ON DELETE CASCADE,
    UNIQUE (project_id, id),
    UNIQUE (project_id, id, application_id),
    UNIQUE (project_id, id, application_id, user_id),
    UNIQUE (project_id, application_id, user_id)
);

CREATE TABLE application_user_projections (
    id UUID PRIMARY KEY,
    project_id UUID NOT NULL,
    binding_id UUID NOT NULL,
    application_id UUID NOT NULL,
    user_id UUID NOT NULL,
    schema_name TEXT NOT NULL CHECK (schema_name = 'owlauth.user.v1'),
    projection_revision BIGINT NOT NULL DEFAULT 1 CHECK (projection_revision > 0),
    source_user_revision BIGINT NOT NULL CHECK (source_user_revision > 0),
    project_policy_revision BIGINT NOT NULL CHECK (project_policy_revision > 0),
    application_policy_revision BIGINT NOT NULL CHECK (application_policy_revision > 0),
    canonical_digest BYTEA NOT NULL CHECK (octet_length(canonical_digest) = 32),
    document JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    FOREIGN KEY (project_id, binding_id, application_id, user_id)
        REFERENCES application_user_bindings (project_id, id, application_id, user_id)
        ON DELETE CASCADE,
    UNIQUE (project_id, id),
    UNIQUE (project_id, binding_id),
    CHECK (jsonb_typeof(document) = 'object'),
    CHECK (octet_length(document::TEXT) <= 16384)
);

CREATE TABLE application_sessions (
    id UUID PRIMARY KEY,
    project_id UUID NOT NULL,
    application_id UUID NOT NULL,
    user_id UUID NOT NULL,
    binding_id UUID NOT NULL,
    browser_session_id UUID,
    status TEXT NOT NULL CHECK (status IN ('active', 'revoked', 'expired')),
    session_revision BIGINT NOT NULL DEFAULT 1 CHECK (session_revision > 0),
    project_security_revision BIGINT NOT NULL CHECK (project_security_revision > 0),
    application_security_revision BIGINT NOT NULL CHECK (application_security_revision > 0),
    user_security_revision BIGINT NOT NULL CHECK (user_security_revision > 0),
    claims_revision BIGINT NOT NULL CHECK (claims_revision > 0),
    policy_session_revision BIGINT NOT NULL CHECK (policy_session_revision > 0),
    authenticated_at TIMESTAMPTZ NOT NULL,
    absolute_expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    FOREIGN KEY (project_id, binding_id, application_id, user_id)
        REFERENCES application_user_bindings (project_id, id, application_id, user_id),
    FOREIGN KEY (project_id, browser_session_id, user_id)
        REFERENCES project_browser_sessions (project_id, id, user_id),
    UNIQUE (project_id, id),
    UNIQUE (project_id, id, application_id, user_id),
    CHECK (absolute_expires_at = created_at + INTERVAL '30 days'),
    CHECK ((status = 'revoked') = (revoked_at IS NOT NULL))
);

CREATE TABLE refresh_families (
    id UUID PRIMARY KEY,
    project_id UUID NOT NULL,
    application_id UUID NOT NULL,
    user_id UUID NOT NULL,
    application_session_id UUID NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('active', 'revoked', 'expired')),
    family_revision BIGINT NOT NULL DEFAULT 1 CHECK (family_revision > 0),
    current_generation BIGINT NOT NULL DEFAULT 1 CHECK (current_generation > 0),
    allowed_clock_skew_seconds INTEGER NOT NULL
        CHECK (allowed_clock_skew_seconds BETWEEN 0 AND 300),
    absolute_expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    revocation_reason TEXT CHECK (revocation_reason IN ('logout', 'replay', 'control', 'owner_invalidated')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    FOREIGN KEY (project_id, application_session_id, application_id, user_id)
        REFERENCES application_sessions (project_id, id, application_id, user_id)
        ON DELETE CASCADE,
    UNIQUE (project_id, id),
    UNIQUE (project_id, id, application_id, user_id),
    UNIQUE (project_id, application_session_id),
    CHECK (absolute_expires_at = created_at + INTERVAL '30 days'),
    CHECK (
        (status = 'revoked' AND revoked_at IS NOT NULL AND revocation_reason IS NOT NULL)
        OR (status <> 'revoked' AND revoked_at IS NULL AND revocation_reason IS NULL)
    )
);

CREATE TABLE refresh_token_generations (
    id UUID PRIMARY KEY,
    project_id UUID NOT NULL,
    family_id UUID NOT NULL,
    application_id UUID NOT NULL,
    user_id UUID NOT NULL,
    generation BIGINT NOT NULL CHECK (generation > 0),
    token_digest BYTEA NOT NULL CHECK (octet_length(token_digest) = 32),
    token_digest_key_version INTEGER NOT NULL CHECK (token_digest_key_version > 0),
    status TEXT NOT NULL CHECK (status IN ('current', 'consumed')),
    consumed_at TIMESTAMPTZ,
    replay_detected_at TIMESTAMPTZ,
    retain_until TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    FOREIGN KEY (project_id, family_id, application_id, user_id)
        REFERENCES refresh_families (project_id, id, application_id, user_id)
        ON DELETE CASCADE,
    UNIQUE (project_id, id),
    UNIQUE (project_id, family_id, generation),
    UNIQUE (token_digest_key_version, token_digest),
    CHECK (retain_until > created_at),
    CHECK ((status = 'consumed') = (consumed_at IS NOT NULL)),
    CHECK (replay_detected_at IS NULL OR consumed_at IS NOT NULL)
);

CREATE UNIQUE INDEX refresh_generations_one_current_idx
    ON refresh_token_generations (project_id, family_id)
    WHERE status = 'current';

CREATE TABLE project_browser_logout_interactions (
    id UUID PRIMARY KEY,
    project_id UUID NOT NULL,
    application_id UUID NOT NULL,
    user_id UUID NOT NULL,
    application_session_id UUID NOT NULL,
    browser_session_id UUID NOT NULL,
    preparation_digest BYTEA NOT NULL CHECK (octet_length(preparation_digest) = 32),
    preparation_digest_key_version INTEGER NOT NULL CHECK (preparation_digest_key_version > 0),
    status TEXT NOT NULL CHECK (status IN ('prepared', 'csrf_bound', 'consumed', 'expired')),
    interaction_revision BIGINT NOT NULL DEFAULT 1 CHECK (interaction_revision > 0),
    csrf_digest BYTEA,
    csrf_digest_key_version INTEGER,
    application_session_revision BIGINT NOT NULL CHECK (application_session_revision > 0),
    browser_session_revision BIGINT NOT NULL CHECK (browser_session_revision > 0),
    expires_at TIMESTAMPTZ NOT NULL,
    csrf_bound_at TIMESTAMPTZ,
    consumed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    FOREIGN KEY (project_id, application_session_id, application_id, user_id)
        REFERENCES application_sessions (project_id, id, application_id, user_id),
    FOREIGN KEY (project_id, browser_session_id, user_id)
        REFERENCES project_browser_sessions (project_id, id, user_id),
    UNIQUE (project_id, id),
    UNIQUE (preparation_digest_key_version, preparation_digest),
    CHECK (expires_at > created_at),
    CHECK (expires_at <= created_at + INTERVAL '60 seconds'),
    CHECK (
        (status IN ('prepared', 'expired') AND csrf_digest IS NULL
            AND csrf_digest_key_version IS NULL AND csrf_bound_at IS NULL)
        OR (status IN ('csrf_bound', 'consumed', 'expired') AND csrf_digest IS NOT NULL
            AND octet_length(csrf_digest) = 32
            AND csrf_digest_key_version IS NOT NULL
            AND csrf_digest_key_version > 0 AND csrf_bound_at IS NOT NULL)
    ),
    CHECK ((status = 'consumed') = (consumed_at IS NOT NULL))
);

CREATE INDEX handoff_tickets_expiry_idx
    ON handoff_tickets (status, expires_at, id);
CREATE INDEX application_bindings_user_idx
    ON application_user_bindings (project_id, user_id, status, application_id);
CREATE INDEX application_sessions_user_status_idx
    ON application_sessions (project_id, user_id, status, absolute_expires_at);
CREATE INDEX refresh_families_session_status_idx
    ON refresh_families (project_id, application_session_id, status);
CREATE INDEX refresh_generations_retention_idx
    ON refresh_token_generations (retain_until, id);
CREATE INDEX browser_logout_expiry_idx
    ON project_browser_logout_interactions (status, expires_at, id);

-- -----------------------------------------------------------------------------
-- Integrated from pre-release schema slice: 20260730030000_block_a_data_hardening.sql
-- -----------------------------------------------------------------------------

-- Additive Block A data-integrity hardening.

-- Preserve the conservative retirement cutoff correction without rewriting the
-- already-applied signing-safety migration.
UPDATE project_signing_keys
SET verify_not_after = GREATEST(
    verify_not_after,
    transaction_timestamp() + INTERVAL '49 hours'
)
WHERE state = 'retiring';

CREATE FUNCTION reject_audit_event_mutation()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION '% is append-only', TG_TABLE_NAME
        USING ERRCODE = '23514';
END
$$;

CREATE TRIGGER audit_events_append_only
BEFORE UPDATE OR DELETE ON audit_events
FOR EACH ROW
EXECUTE FUNCTION reject_audit_event_mutation();

CREATE TRIGGER key_state_events_append_only
BEFORE UPDATE OR DELETE ON key_state_events
FOR EACH ROW
EXECUTE FUNCTION reject_audit_event_mutation();

CREATE FUNCTION reject_immutable_column_change()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    column_name TEXT;
BEGIN
    FOREACH column_name IN ARRAY TG_ARGV
    LOOP
        IF to_jsonb(OLD) -> column_name IS DISTINCT FROM to_jsonb(NEW) -> column_name THEN
            RAISE EXCEPTION 'immutable column %.% cannot change', TG_TABLE_NAME, column_name
                USING ERRCODE = '23514';
        END IF;
    END LOOP;
    RETURN NEW;
END
$$;

CREATE TRIGGER projects_stable_public_identity
BEFORE UPDATE ON projects
FOR EACH ROW
EXECUTE FUNCTION reject_immutable_column_change('public_id');

CREATE TRIGGER applications_stable_public_identity
BEFORE UPDATE ON applications
FOR EACH ROW
EXECUTE FUNCTION reject_immutable_column_change('project_id', 'public_id');

CREATE TRIGGER publishable_keys_stable_public_identity
BEFORE UPDATE ON application_publishable_keys
FOR EACH ROW
EXECUTE FUNCTION reject_immutable_column_change('project_id', 'application_id', 'public_id');

CREATE TRIGGER key_rings_stable_public_identity
BEFORE UPDATE ON project_key_rings
FOR EACH ROW
EXECUTE FUNCTION reject_immutable_column_change('project_id', 'issuer', 'purpose', 'algorithm');

CREATE TRIGGER signing_keys_stable_public_identity
BEFORE UPDATE ON project_signing_keys
FOR EACH ROW
EXECUTE FUNCTION reject_immutable_column_change('project_id', 'ring_id', 'kid', 'signer_ref');

CREATE FUNCTION reject_published_jwk_change()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF OLD.public_jwk <> '{}'::JSONB
       AND OLD.public_jwk IS DISTINCT FROM NEW.public_jwk THEN
        RAISE EXCEPTION 'published public JWK cannot change'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER signing_keys_public_jwk_write_once
BEFORE UPDATE ON project_signing_keys
FOR EACH ROW
EXECUTE FUNCTION reject_published_jwk_change();

CREATE TRIGGER providers_stable_callback_identity
BEFORE UPDATE ON provider_configurations
FOR EACH ROW
EXECUTE FUNCTION reject_immutable_column_change(
    'project_id',
    'provider_key',
    'kind',
    'issuer',
    'client_id',
    'callback_url'
);

ALTER TABLE projects
    ADD CONSTRAINT projects_public_id_shape_check
        CHECK (public_id ~ '^[A-Za-z0-9_-]+$');

ALTER TABLE applications
    ADD CONSTRAINT applications_public_id_shape_check
        CHECK (public_id ~ '^[A-Za-z0-9_-]+$');

ALTER TABLE application_publishable_keys
    ADD CONSTRAINT application_publishable_keys_public_id_shape_check
        CHECK (public_id ~ '^[A-Za-z0-9_-]+$');

ALTER TABLE project_signing_keys
    ADD CONSTRAINT project_signing_keys_kid_shape_check
        CHECK (kid ~ '^[A-Za-z0-9_-]+$');

ALTER TABLE project_signing_keys
    ADD CONSTRAINT project_signing_keys_public_jwk_shape_check CHECK (
        (
            state IN ('provisioning', 'abandoned')
            AND public_jwk = '{}'::JSONB
        )
        OR (
            jsonb_typeof(public_jwk) = 'object'
            AND public_jwk - ARRAY['kty', 'crv', 'alg', 'use', 'kid', 'x'] = '{}'::JSONB
            AND public_jwk ?& ARRAY['kty', 'crv', 'alg', 'use', 'kid', 'x']
            AND public_jwk ->> 'kty' = 'OKP'
            AND public_jwk ->> 'crv' = 'Ed25519'
            AND public_jwk ->> 'alg' = 'EdDSA'
            AND public_jwk ->> 'use' = 'sig'
            AND public_jwk ->> 'kid' = kid
            AND jsonb_typeof(public_jwk -> 'x') = 'string'
            AND public_jwk ->> 'x' ~ '^[A-Za-z0-9_-]{43}$'
            AND octet_length(
                decode(translate(public_jwk ->> 'x', '-_', '+/') || '=', 'base64')
            ) = 32
            AND octet_length(public_jwk::TEXT) <= 512
        )
    );

-- -----------------------------------------------------------------------------
-- Integrated from pre-release schema slice: 20260730040000_runtime_incarnation_fencing.sql
-- -----------------------------------------------------------------------------

-- Additive Runtime process-incarnation fencing for Runtime-authored work.
--
-- The exact-history predecessor must be drained before this bridge runs. Existing publication
-- leases are expiring observations rather than durable authorization, so clearing them is safer
-- than assigning a synthetic incarnation that a replacement Runtime could mistake for current.

CREATE TABLE runtime_process_incarnations (
    process_id TEXT PRIMARY KEY CHECK (process_id ~ '^[a-zA-Z0-9._:-]{1,128}$'),
    process_incarnation UUID NOT NULL,
    started_at TIMESTAMPTZ NOT NULL,
    UNIQUE (process_id, process_incarnation)
);

ALTER TABLE runtime_publication_leases
    ADD COLUMN process_incarnation UUID;

TRUNCATE TABLE runtime_publication_leases;

ALTER TABLE runtime_publication_leases
    ALTER COLUMN process_incarnation SET NOT NULL;

-- -----------------------------------------------------------------------------
-- Integrated from pre-release schema slice: 20260801000000_identity_projection_foundation.sql
-- -----------------------------------------------------------------------------

-- Bounded identity-source provenance, local field ownership, proof receipts, and merge history.

ALTER TABLE project_users
    ADD COLUMN primary_source_kind TEXT NOT NULL DEFAULT 'provider',
    ADD COLUMN local_display_name_set BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN local_display_name TEXT,
    ADD COLUMN local_picture_url_set BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN local_picture_url TEXT,
    ADD COLUMN local_locale_set BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN local_locale TEXT,
    ADD COLUMN locale TEXT,
    ADD CONSTRAINT project_users_local_profile_shape_check CHECK (
        (local_display_name_set OR local_display_name IS NULL)
        AND (local_picture_url_set OR local_picture_url IS NULL)
        AND (local_locale_set OR local_locale IS NULL)
        AND (local_display_name IS NULL OR char_length(local_display_name) BETWEEN 1 AND 128)
        AND (local_picture_url IS NULL OR char_length(local_picture_url) BETWEEN 8 AND 2048)
        AND (local_locale IS NULL OR char_length(local_locale) BETWEEN 2 AND 35)
        AND (locale IS NULL OR char_length(locale) BETWEEN 2 AND 35)
    ) NOT VALID,
    ADD CONSTRAINT project_users_primary_source_kind_check CHECK (
        primary_source_kind IN ('provider', 'email')
    ) NOT VALID,
    ADD CONSTRAINT project_users_primary_source_shape_check CHECK (
        primary_source_kind = 'provider'
        OR (primary_source_kind = 'email' AND primary_profile_identity_id IS NULL)
    ) NOT VALID;

-- Compatibility defaults remain through the N/N-1 overlap. A later contract migration may
-- remove them only after every supported writer supplies the fields explicitly.

ALTER TABLE linked_identities
    ADD COLUMN source_kind TEXT NOT NULL DEFAULT 'provider',
    ADD COLUMN source_schema TEXT NOT NULL DEFAULT 'owlauth.provider-profile.v1',
    ADD COLUMN source_profile_digest BYTEA,
    ADD COLUMN locale TEXT,
    ADD CONSTRAINT linked_identities_source_kind_check CHECK (
        source_kind = 'provider'
    ) NOT VALID,
    ADD CONSTRAINT linked_identities_source_schema_check CHECK (
        source_schema = 'owlauth.provider-profile.v1'
    ) NOT VALID,
    ADD CONSTRAINT linked_identities_source_profile_shape_check CHECK (
        octet_length(source_profile_digest) = 32
        AND (locale IS NULL OR char_length(locale) BETWEEN 2 AND 35)
    ) NOT VALID;

CREATE FUNCTION owlauth_provider_source_profile_digest(
    profile_display_name TEXT,
    profile_picture_url TEXT,
    profile_locale TEXT
) RETURNS BYTEA
LANGUAGE SQL
IMMUTABLE
PARALLEL SAFE
RETURN sha256(convert_to(
    '{"display_name":' || COALESCE(to_json(profile_display_name)::TEXT, 'null')
        || CASE WHEN profile_locale IS NULL THEN ''
            ELSE ',"locale":' || to_json(profile_locale)::TEXT END
        || ',"picture_url":' || COALESCE(to_json(profile_picture_url)::TEXT, 'null')
        || '}',
    'UTF8'
));

CREATE FUNCTION owlauth_fill_provider_source_profile_digest()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.source_profile_digest IS NULL
        OR (TG_OP = 'UPDATE'
            AND (NEW.display_name, NEW.picture_url, NEW.locale)
                IS DISTINCT FROM (OLD.display_name, OLD.picture_url, OLD.locale)
            AND NEW.source_profile_digest IS NOT DISTINCT FROM OLD.source_profile_digest)
    THEN
        NEW.source_profile_digest := owlauth_provider_source_profile_digest(
            NEW.display_name,
            NEW.picture_url,
            NEW.locale
        );
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER linked_identities_source_profile_digest_fill
BEFORE INSERT OR UPDATE OF display_name, picture_url, locale, source_profile_digest
ON linked_identities
FOR EACH ROW
EXECUTE FUNCTION owlauth_fill_provider_source_profile_digest();

-- Existing rows remain nullable during the expand phase. New and N-1 writes are filled by
-- the trigger; current N reads repair legacy rows without semantic revision churn. A later
-- contract migration may add NOT NULL only after bounded inventory/backfill proves closure.

CREATE TABLE identity_proof_receipts (
    id UUID PRIMARY KEY,
    project_id UUID NOT NULL,
    user_id UUID NOT NULL,
    provider_identity_id UUID NOT NULL,
    identity_kind TEXT NOT NULL CHECK (identity_kind = 'provider'),
    purpose TEXT NOT NULL CHECK (purpose IN ('link', 'unlink', 'merge')),
    browser_session_id UUID NOT NULL,
    receipt_digest BYTEA NOT NULL CHECK (octet_length(receipt_digest) = 32),
    receipt_digest_key_version INTEGER NOT NULL CHECK (receipt_digest_key_version > 0),
    user_revision BIGINT NOT NULL CHECK (user_revision > 0),
    identity_revision BIGINT NOT NULL CHECK (identity_revision > 0),
    status TEXT NOT NULL CHECK (status IN ('issued', 'consumed', 'expired')),
    issued_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    FOREIGN KEY (project_id, user_id)
        REFERENCES project_users (project_id, id) ON DELETE CASCADE,
    FOREIGN KEY (project_id, provider_identity_id, user_id)
        REFERENCES linked_identities (project_id, id, user_id) ON DELETE CASCADE,
    FOREIGN KEY (project_id, browser_session_id, user_id)
        REFERENCES project_browser_sessions (project_id, id, user_id) ON DELETE CASCADE,
    UNIQUE (project_id, id),
    UNIQUE (receipt_digest_key_version, receipt_digest),
    CHECK (expires_at > issued_at AND expires_at <= issued_at + INTERVAL '5 minutes'),
    CHECK ((status = 'consumed') = (consumed_at IS NOT NULL))
);

CREATE INDEX identity_proof_receipts_lookup_idx
    ON identity_proof_receipts
        (project_id, user_id, purpose, status, expires_at, id);

CREATE TABLE project_user_merge_tombstones (
    project_id UUID NOT NULL,
    loser_user_id UUID NOT NULL,
    winner_user_id UUID NOT NULL,
    loser_user_revision BIGINT NOT NULL CHECK (loser_user_revision > 0),
    winner_user_revision BIGINT NOT NULL CHECK (winner_user_revision > 0),
    primary_source_kind TEXT NOT NULL CHECK (primary_source_kind IN ('provider', 'email')),
    primary_provider_identity_id UUID,
    sessions_disposition TEXT NOT NULL CHECK (sessions_disposition = 'loser_revoked'),
    bindings_disposition TEXT NOT NULL CHECK (bindings_disposition = 'winner_preferred'),
    merged_at TIMESTAMPTZ NOT NULL,
    correlation_id UUID NOT NULL,
    PRIMARY KEY (project_id, loser_user_id),
    FOREIGN KEY (project_id, loser_user_id)
        REFERENCES project_users (project_id, id),
    FOREIGN KEY (project_id, winner_user_id)
        REFERENCES project_users (project_id, id),
    FOREIGN KEY (project_id, primary_provider_identity_id, winner_user_id)
        REFERENCES linked_identities (project_id, id, user_id),
    CHECK (loser_user_id <> winner_user_id),
    CHECK (
        (primary_source_kind = 'provider' AND primary_provider_identity_id IS NOT NULL)
        OR (primary_source_kind = 'email' AND primary_provider_identity_id IS NULL)
    )
);

CREATE INDEX project_user_merge_winner_idx
    ON project_user_merge_tombstones (project_id, winner_user_id, merged_at);

ALTER TABLE application_user_projections
    ADD COLUMN source_base_profile_digest BYTEA;

CREATE FUNCTION owlauth_fill_projection_source_base_digest()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    current_base_profile_digest BYTEA;
BEGIN
    IF NEW.source_base_profile_digest IS NULL
        OR (TG_OP = 'UPDATE'
            AND NEW.source_user_revision IS DISTINCT FROM OLD.source_user_revision
            AND NEW.source_base_profile_digest
                IS NOT DISTINCT FROM OLD.source_base_profile_digest)
    THEN
        SELECT project_user.base_profile_digest
        INTO STRICT current_base_profile_digest
        FROM project_users AS project_user
        WHERE project_user.project_id = NEW.project_id
          AND project_user.id = NEW.user_id;
        NEW.source_base_profile_digest := current_base_profile_digest;
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER application_user_projections_source_base_digest_fill
BEFORE INSERT OR UPDATE OF source_user_revision, source_base_profile_digest
ON application_user_projections
FOR EACH ROW
EXECUTE FUNCTION owlauth_fill_projection_source_base_digest();

-- As above, legacy projections are repaired lazily and by later bounded inventory/backfill;
-- startup migration does not scan or rewrite the user directory under one global deadline.
ALTER TABLE application_user_projections
    ADD CONSTRAINT application_user_projections_source_digest_check
        CHECK (octet_length(source_base_profile_digest) = 32) NOT VALID;

-- The existing application_bindings_user_idx covers the bounded fan-out predicate. Do not
-- build a redundant ordinary index during startup; any future index change must use the
-- reviewed online migration path.

-- -----------------------------------------------------------------------------
-- Integrated from pre-release schema slice: 20260801010000_passwordless_email.sql
-- -----------------------------------------------------------------------------

-- First-party passwordless email, SMTP generation pinning, and durable mail delivery.
-- Sensitive address/message columns below always contain application-layer AEAD ciphertext.

CREATE TABLE project_email_policies (
    project_id UUID PRIMARY KEY REFERENCES projects (id) ON DELETE CASCADE,
    status TEXT NOT NULL CHECK (status IN ('enabled', 'disabled')),
    policy_revision BIGINT NOT NULL DEFAULT 1 CHECK (policy_revision > 0),
    security_revision BIGINT NOT NULL DEFAULT 1 CHECK (security_revision > 0),
    canonicalization_version INTEGER NOT NULL DEFAULT 1 CHECK (canonicalization_version = 1),
    otp_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    magic_link_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    otp_digits SMALLINT NOT NULL DEFAULT 6 CHECK (otp_digits BETWEEN 6 AND 10),
    otp_validity_seconds INTEGER NOT NULL DEFAULT 600 CHECK (otp_validity_seconds BETWEEN 30 AND 600),
    otp_max_attempts SMALLINT NOT NULL DEFAULT 5 CHECK (otp_max_attempts BETWEEN 1 AND 5),
    resend_after_seconds INTEGER NOT NULL DEFAULT 30 CHECK (resend_after_seconds BETWEEN 30 AND 600),
    max_generations SMALLINT NOT NULL DEFAULT 5 CHECK (max_generations BETWEEN 1 AND 5),
    magic_validity_seconds INTEGER NOT NULL DEFAULT 600 CHECK (magic_validity_seconds BETWEEN 30 AND 600),
    signup_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    transferred_magic_link_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    allow_deployment_default BOOLEAN NOT NULL DEFAULT FALSE,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    CHECK (otp_enabled OR magic_link_enabled)
);

-- Every Project has an explicit disabled-by-default policy. The trigger preserves that
-- invariant for Projects provisioned after this migration without making generic project
-- creation know about a particular authentication method.
INSERT INTO project_email_policies (project_id, status)
SELECT id, 'disabled' FROM projects
ON CONFLICT (project_id) DO NOTHING;

CREATE FUNCTION owlauth_initialize_project_email_policy()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    INSERT INTO project_email_policies (project_id, status) VALUES (NEW.id, 'disabled');
    RETURN NEW;
END
$$;

CREATE TRIGGER projects_initialize_email_policy
AFTER INSERT ON projects
FOR EACH ROW
EXECUTE FUNCTION owlauth_initialize_project_email_policy();

CREATE TABLE application_email_assignments (
    project_id UUID NOT NULL,
    application_id UUID NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('active', 'disabled')),
    security_revision BIGINT NOT NULL DEFAULT 1 CHECK (security_revision > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (project_id, application_id),
    FOREIGN KEY (project_id, application_id)
        REFERENCES applications (project_id, id) ON DELETE CASCADE
);

CREATE TABLE project_smtp_configurations (
    id UUID PRIMARY KEY,
    project_id UUID NOT NULL REFERENCES projects (id) ON DELETE CASCADE,
    status TEXT NOT NULL CHECK (status IN ('pending', 'active', 'retained', 'disabled', 'compromised', 'retired')),
    generation INTEGER NOT NULL CHECK (generation > 0),
    revision BIGINT NOT NULL DEFAULT 1 CHECK (revision > 0),
    security_eligibility_revision BIGINT NOT NULL DEFAULT 1 CHECK (security_eligibility_revision > 0),
    host TEXT NOT NULL CHECK (char_length(host) BETWEEN 1 AND 253),
    port INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
    tls_mode TEXT NOT NULL CHECK (tls_mode IN ('implicit_tls', 'starttls_required', 'development_loopback_plaintext')),
    sender_address TEXT NOT NULL CHECK (char_length(sender_address) BETWEEN 3 AND 254),
    sender_name TEXT CHECK (sender_name IS NULL OR char_length(sender_name) BETWEEN 1 AND 128),
    reply_to TEXT CHECK (reply_to IS NULL OR char_length(reply_to) BETWEEN 3 AND 254),
    credential_ref TEXT NOT NULL CHECK (char_length(credential_ref) BETWEEN 1 AND 512),
    safe_fingerprint BYTEA NOT NULL CHECK (octet_length(safe_fingerprint) = 32),
    retained_until TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    UNIQUE (project_id, id),
    UNIQUE (project_id, generation),
    CHECK ((status = 'retained') = (retained_until IS NOT NULL)),
    CHECK (tls_mode <> 'development_loopback_plaintext' OR host IN ('127.0.0.1', '::1', 'localhost'))
);
CREATE UNIQUE INDEX project_smtp_one_active_idx
    ON project_smtp_configurations (project_id) WHERE status = 'active';

-- The database-side half of the external SMTP credential write. The stable operation alias
-- and normalized request digest let the same request converge after timeout or process loss;
-- no credential bytes are ever stored here.
CREATE TABLE project_smtp_secret_operations (
    project_id UUID NOT NULL REFERENCES projects (id) ON DELETE CASCADE,
    operation_alias TEXT NOT NULL CHECK (char_length(operation_alias) BETWEEN 8 AND 128),
    configuration_id UUID NOT NULL,
    request_digest BYTEA NOT NULL CHECK (octet_length(request_digest) = 32),
    credential_ref TEXT NOT NULL CHECK (char_length(credential_ref) BETWEEN 1 AND 512),
    state TEXT NOT NULL CHECK (state IN ('prepared', 'provisioning', 'completed')),
    provisioning_token UUID,
    created_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    completed_at TIMESTAMPTZ,
    PRIMARY KEY (project_id, operation_alias),
    FOREIGN KEY (project_id, configuration_id)
        REFERENCES project_smtp_configurations (project_id, id) ON DELETE CASCADE,
    CHECK ((state = 'completed') = (completed_at IS NOT NULL)),
    CHECK ((state = 'provisioning') = (provisioning_token IS NOT NULL))
);

-- SMTP Control tests are external side effects. The durable operation fence makes an
-- Idempotency-Key converge, fixes Message-ID, and refuses to resend after an uncertain response.
CREATE TABLE project_smtp_test_operations (
    id UUID NOT NULL UNIQUE,
    project_id UUID NOT NULL REFERENCES projects (id) ON DELETE CASCADE,
    idempotency_key TEXT NOT NULL CHECK (char_length(idempotency_key) BETWEEN 8 AND 128),
    configuration_id UUID NOT NULL,
    configuration_generation INTEGER NOT NULL CHECK (configuration_generation > 0),
    configuration_revision BIGINT NOT NULL CHECK (configuration_revision > 0),
    configuration_security_eligibility_revision BIGINT NOT NULL CHECK (configuration_security_eligibility_revision > 0),
    host TEXT NOT NULL CHECK (char_length(host) BETWEEN 1 AND 253),
    port INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
    tls_mode TEXT NOT NULL CHECK (tls_mode IN ('implicit_tls','starttls_required')),
    sender_address TEXT NOT NULL CHECK (char_length(sender_address) BETWEEN 3 AND 254),
    credential_ref TEXT NOT NULL CHECK (char_length(credential_ref) BETWEEN 1 AND 512),
    request_digest BYTEA NOT NULL CHECK (octet_length(request_digest) = 32),
    message_id TEXT NOT NULL CHECK (char_length(message_id) BETWEEN 16 AND 255),
    recipient_ref TEXT NOT NULL CHECK (char_length(recipient_ref) BETWEEN 1 AND 512),
    provisioning_token UUID,
    recipient_erased_at TIMESTAMPTZ,
    cleanup_lease_owner TEXT,
    cleanup_lease_expires_at TIMESTAMPTZ,
    state TEXT NOT NULL CHECK (state IN ('preparing', 'pending', 'submitting', 'delivered', 'failed', 'ambiguous')),
    safe_outcome TEXT CHECK (safe_outcome IS NULL OR safe_outcome IN ('delivered', 'transient', 'permanent', 'ambiguous', 'policy_denied')),
    lease_owner TEXT,
    lease_expires_at TIMESTAMPTZ,
    attempts SMALLINT NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 1),
    correlation_id UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    expires_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp() + INTERVAL '10 minutes',
    completed_at TIMESTAMPTZ,
    PRIMARY KEY (project_id, idempotency_key),
    FOREIGN KEY (project_id, configuration_id)
        REFERENCES project_smtp_configurations (project_id, id) ON DELETE CASCADE,
    UNIQUE (message_id),
    CHECK (expires_at = created_at + INTERVAL '10 minutes'),
    CHECK ((state IN ('preparing', 'pending', 'submitting')) = (completed_at IS NULL)),
    CHECK ((state IN ('preparing', 'pending', 'submitting')) = (safe_outcome IS NULL)),
    CHECK ((state = 'preparing') = (provisioning_token IS NOT NULL)),
    CHECK ((state = 'submitting') = (lease_owner IS NOT NULL AND lease_expires_at IS NOT NULL)),
    CHECK ((cleanup_lease_owner IS NULL) = (cleanup_lease_expires_at IS NULL)),
    CHECK (recipient_erased_at IS NULL OR state IN ('delivered','failed','ambiguous'))
);
CREATE INDEX project_smtp_test_claim_idx ON project_smtp_test_operations (created_at, project_id)
    WHERE state = 'pending';

-- SMTP-test recipients use the same durable live/reserved/erased lifecycle as SMTP
-- credentials. Database claim/finalize uses guarded CAS; the external store's permanent alias
-- tombstone orders cleanup against even a delayed writer after all PostgreSQL locks are gone.
CREATE TABLE smtp_test_recipient_reference_reservations (
    recipient_ref TEXT PRIMARY KEY CHECK (char_length(recipient_ref) BETWEEN 1 AND 512),
    state TEXT NOT NULL CHECK (state IN ('live','reserved','erased')),
    operation_id UUID NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    erased_at TIMESTAMPTZ,
    CHECK ((state = 'erased') = (erased_at IS NOT NULL))
);

CREATE TABLE deployment_smtp_generations (
    generation INTEGER PRIMARY KEY CHECK (generation > 0),
    status TEXT NOT NULL CHECK (status IN ('reconciled', 'active', 'retained', 'disabled', 'compromised', 'retired')),
    revision BIGINT NOT NULL DEFAULT 1 CHECK (revision > 0),
    security_eligibility_revision BIGINT NOT NULL DEFAULT 1 CHECK (security_eligibility_revision > 0),
    host TEXT NOT NULL CHECK (char_length(host) BETWEEN 1 AND 253),
    port INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
    tls_mode TEXT NOT NULL CHECK (tls_mode IN ('implicit_tls', 'starttls_required')),
    sender_address TEXT NOT NULL CHECK (char_length(sender_address) BETWEEN 3 AND 254),
    credential_ref TEXT NOT NULL CHECK (char_length(credential_ref) BETWEEN 1 AND 512),
    safe_fingerprint BYTEA NOT NULL CHECK (octet_length(safe_fingerprint) = 32),
    explicitly_allowed_private_ips JSONB NOT NULL DEFAULT '[]'::jsonb
        CHECK (jsonb_typeof(explicitly_allowed_private_ips) = 'array'
            AND jsonb_array_length(explicitly_allowed_private_ips) <= 16),
    retained_until TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    CHECK ((status = 'retained') = (retained_until IS NOT NULL))
);
CREATE UNIQUE INDEX deployment_smtp_one_active_idx
    ON deployment_smtp_generations ((TRUE)) WHERE status = 'active';

-- Runtime readiness is scoped to the exact immutable Project SMTP generation and configured
-- Runtime process. Control can write credentials but cannot manufacture this proof. A process
-- incarnation and bounded lease prevent evidence from an earlier startup authorizing activation.
CREATE TABLE project_smtp_runtime_readiness (
    project_id UUID NOT NULL,
    configuration_id UUID NOT NULL,
    generation INTEGER NOT NULL CHECK (generation > 0),
    process_id TEXT NOT NULL CHECK (process_id ~ '^[a-zA-Z0-9._:-]{1,128}$'),
    process_incarnation UUID NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('ready','unavailable')),
    checked_at TIMESTAMPTZ NOT NULL,
    lease_expires_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (project_id, configuration_id, generation, process_id),
    FOREIGN KEY (project_id, configuration_id)
        REFERENCES project_smtp_configurations (project_id, id) ON DELETE CASCADE,
    CHECK (lease_expires_at > checked_at)
);
CREATE INDEX project_smtp_runtime_readiness_state_idx
    ON project_smtp_runtime_readiness (state, lease_expires_at, checked_at);

-- Bounded operational status for durable email PII reconciliation. An unavailable state is not
-- global server unavailability: protected email operations fail closed while unrelated Runtime
-- and Control capabilities continue serving. Operators must restore the named key material;
-- this state never permits destructive recovery or re-derivation.
CREATE TABLE email_protection_runtime_readiness (
    process_id TEXT PRIMARY KEY CHECK (process_id ~ '^[a-zA-Z0-9._:-]{1,128}$'),
    process_incarnation UUID NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('ready','unavailable')),
    failure_class TEXT CHECK (failure_class IS NULL OR failure_class IN ('key_unavailable','integrity','persistence')),
    checked_at TIMESTAMPTZ NOT NULL,
    lease_expires_at TIMESTAMPTZ NOT NULL,
    CHECK (lease_expires_at > checked_at),
    CHECK ((state='ready') = (failure_class IS NULL))
);

CREATE TABLE smtp_credential_cleanup_operations (
    id UUID PRIMARY KEY,
    scope TEXT NOT NULL CHECK (scope IN ('project','deployment_default')),
    project_id UUID REFERENCES projects (id) ON DELETE CASCADE,
    generation INTEGER NOT NULL CHECK (generation > 0),
    credential_ref TEXT NOT NULL CHECK (char_length(credential_ref) BETWEEN 1 AND 512),
    state TEXT NOT NULL CHECK (state IN ('pending','leased','erased')),
    lease_owner TEXT,
    lease_expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    erased_at TIMESTAMPTZ,
    UNIQUE NULLS NOT DISTINCT (scope,project_id,generation),
    CHECK ((scope = 'project') = (project_id IS NOT NULL)),
    CHECK ((state = 'leased') = (lease_owner IS NOT NULL AND lease_expires_at IS NOT NULL)),
    CHECK ((state = 'erased') = (erased_at IS NOT NULL))
);

-- A credential reference has one database-wide lifecycle authority shared by Project and
-- deployment-default SMTP. Per-reference locks serialize each short database phase, while durable
-- claim/CAS plus the external store's permanent alias tombstone order lock-free external writes
-- against cleanup. Reserved prevents reuse and erased remains the database-side tombstone.
CREATE TABLE smtp_credential_reference_reservations (
    credential_ref TEXT PRIMARY KEY CHECK (char_length(credential_ref) BETWEEN 1 AND 512),
    state TEXT NOT NULL CHECK (state IN ('live','reserved','erased')),
    cleanup_id UUID REFERENCES smtp_credential_cleanup_operations (id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    erased_at TIMESTAMPTZ,
    CHECK ((state = 'reserved') = (cleanup_id IS NOT NULL)),
    CHECK ((state = 'erased') = (erased_at IS NOT NULL))
);

CREATE TABLE login_email_method_snapshots (
    project_id UUID NOT NULL,
    transaction_id UUID NOT NULL,
    application_id UUID NOT NULL,
    method_policy_revision BIGINT NOT NULL CHECK (method_policy_revision > 0),
    method_security_revision BIGINT NOT NULL CHECK (method_security_revision > 0),
    assignment_security_revision BIGINT NOT NULL CHECK (assignment_security_revision > 0),
    otp_enabled BOOLEAN NOT NULL,
    magic_link_enabled BOOLEAN NOT NULL,
    otp_digits SMALLINT NOT NULL CHECK (otp_digits BETWEEN 6 AND 10),
    otp_validity_seconds INTEGER NOT NULL CHECK (otp_validity_seconds BETWEEN 30 AND 600),
    otp_max_attempts SMALLINT NOT NULL CHECK (otp_max_attempts BETWEEN 1 AND 5),
    resend_after_seconds INTEGER NOT NULL CHECK (resend_after_seconds BETWEEN 30 AND 600),
    max_generations SMALLINT NOT NULL CHECK (max_generations BETWEEN 1 AND 5),
    magic_validity_seconds INTEGER NOT NULL CHECK (magic_validity_seconds BETWEEN 30 AND 600),
    signup_enabled BOOLEAN NOT NULL,
    transferred_magic_link_enabled BOOLEAN NOT NULL,
    smtp_selection_kind TEXT NOT NULL CHECK (smtp_selection_kind IN ('project', 'deployment_default')),
    smtp_configuration_id UUID,
    smtp_generation INTEGER NOT NULL CHECK (smtp_generation > 0),
    smtp_security_eligibility_revision BIGINT NOT NULL CHECK (smtp_security_eligibility_revision > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (project_id, transaction_id),
    FOREIGN KEY (project_id, transaction_id)
        REFERENCES login_transactions (project_id, id) ON DELETE CASCADE,
    FOREIGN KEY (project_id, application_id)
        REFERENCES applications (project_id, id),
    FOREIGN KEY (project_id, smtp_configuration_id)
        REFERENCES project_smtp_configurations (project_id, id),
    CHECK (otp_enabled OR magic_link_enabled),
    CHECK ((smtp_selection_kind = 'project') = (smtp_configuration_id IS NOT NULL))
);

CREATE TABLE email_identities (
    id UUID PRIMARY KEY,
    project_id UUID NOT NULL,
    user_id UUID NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('active', 'disabled')),
    identity_revision BIGINT NOT NULL DEFAULT 1 CHECK (identity_revision > 0),
    canonicalization_version INTEGER NOT NULL CHECK (canonicalization_version > 0),
    address_ciphertext BYTEA NOT NULL CHECK (octet_length(address_ciphertext) BETWEEN 41 AND 2048),
    address_key_version INTEGER NOT NULL CHECK (address_key_version > 0),
    verified_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    FOREIGN KEY (project_id, user_id)
        REFERENCES project_users (project_id, id) ON DELETE CASCADE,
    UNIQUE (project_id, id),
    UNIQUE (project_id, id, user_id)
);

CREATE TABLE email_identity_alias_authority (
    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    revision BIGINT NOT NULL CHECK (revision > 0),
    write_version INTEGER NOT NULL CHECK (write_version > 0),
    target_version INTEGER NOT NULL CHECK (target_version >= write_version),
    retirement_version INTEGER CHECK (retirement_version IS NULL OR retirement_version = write_version),
    overlap_verified_revision BIGINT CHECK (overlap_verified_revision IS NULL OR overlap_verified_revision > 0),
    accepted_versions JSONB NOT NULL CHECK (
        jsonb_typeof(accepted_versions) = 'array'
        AND jsonb_array_length(accepted_versions) BETWEEN 1 AND 16
    ),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    CHECK (overlap_verified_revision IS NULL OR overlap_verified_revision <= revision)
);

CREATE TABLE email_identity_alias_authority_events (
    id BIGSERIAL PRIMARY KEY,
    authority_revision BIGINT NOT NULL CHECK (authority_revision > 0),
    action TEXT NOT NULL CHECK (action IN ('initialized', 'staged', 'cutover', 'rollback', 'overlap_verified', 'retirement_authorized', 'aliases_retired')),
    from_write_version INTEGER,
    to_write_version INTEGER NOT NULL CHECK (to_write_version > 0),
    affected_rows BIGINT NOT NULL DEFAULT 0 CHECK (affected_rows >= 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp()
);

CREATE TABLE email_identity_alias_runtime_observations (
    process_id TEXT PRIMARY KEY CHECK (process_id ~ '^[a-zA-Z0-9._:-]{1,128}$'),
    process_incarnation UUID NOT NULL,
    active_version INTEGER NOT NULL CHECK (active_version > 0),
    observed_authority_revision BIGINT NOT NULL CHECK (observed_authority_revision > 0),
    retirement_requested BOOLEAN NOT NULL DEFAULT FALSE,
    retirement_request_revision BIGINT CHECK (retirement_request_revision IS NULL OR retirement_request_revision > 0),
    lease_expires_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    CHECK (retirement_requested = (retirement_request_revision IS NOT NULL))
);

CREATE TABLE email_identity_aliases (
    project_id UUID NOT NULL,
    identity_id UUID NOT NULL,
    canonicalization_version INTEGER NOT NULL CHECK (canonicalization_version > 0),
    digest_key_version INTEGER NOT NULL CHECK (digest_key_version > 0),
    lookup_digest BYTEA NOT NULL CHECK (octet_length(lookup_digest) = 32),
    created_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (project_id, identity_id, canonicalization_version, digest_key_version),
    FOREIGN KEY (project_id, identity_id)
        REFERENCES email_identities (project_id, id) ON DELETE CASCADE,
    UNIQUE (project_id, canonicalization_version, digest_key_version, lookup_digest)
);

ALTER TABLE project_users
    ADD COLUMN primary_email_identity_id UUID,
    ADD CONSTRAINT project_users_primary_email_identity_fk
        FOREIGN KEY (project_id, primary_email_identity_id, id)
        REFERENCES email_identities (project_id, id, user_id);

CREATE FUNCTION owlauth_enforce_exact_primary_identity()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    current_record project_users%ROWTYPE;
BEGIN
    SELECT * INTO current_record FROM project_users WHERE id = NEW.id;
    IF current_record.primary_source_kind = 'provider' THEN
        IF current_record.primary_profile_identity_id IS NULL
            OR current_record.primary_email_identity_id IS NOT NULL THEN
            RAISE EXCEPTION 'provider primary source must identify exactly one provider identity';
        END IF;
    ELSIF current_record.primary_source_kind = 'email' THEN
        IF current_record.primary_profile_identity_id IS NOT NULL
            OR current_record.primary_email_identity_id IS NULL THEN
            RAISE EXCEPTION 'email primary source must identify exactly one email identity';
        END IF;
    ELSE
        RAISE EXCEPTION 'unsupported primary source kind';
    END IF;
    RETURN NULL;
END
$$;

CREATE CONSTRAINT TRIGGER project_users_exact_primary_identity
AFTER INSERT OR UPDATE OF primary_source_kind, primary_profile_identity_id, primary_email_identity_id
ON project_users
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
EXECUTE FUNCTION owlauth_enforce_exact_primary_identity();

CREATE TABLE email_challenges (
    id UUID PRIMARY KEY,
    project_id UUID NOT NULL,
    application_id UUID NOT NULL,
    transaction_id UUID NOT NULL,
    generation SMALLINT NOT NULL CHECK (generation BETWEEN 1 AND 5),
    status TEXT NOT NULL CHECK (status IN ('pending', 'consumed', 'exhausted', 'expired', 'superseded', 'delivery_unavailable')),
    canonicalization_version INTEGER NOT NULL CHECK (canonicalization_version > 0),
    lookup_digest BYTEA NOT NULL CHECK (octet_length(lookup_digest) = 32),
    lookup_digest_key_version INTEGER NOT NULL CHECK (lookup_digest_key_version > 0),
    address_ciphertext BYTEA CHECK (address_ciphertext IS NULL OR octet_length(address_ciphertext) BETWEEN 41 AND 2048),
    address_key_version INTEGER CHECK (address_key_version IS NULL OR address_key_version > 0),
    otp_digest BYTEA,
    otp_digest_key_version INTEGER,
    otp_attempts SMALLINT NOT NULL DEFAULT 0 CHECK (otp_attempts BETWEEN 0 AND 5),
    otp_max_attempts SMALLINT NOT NULL CHECK (otp_max_attempts BETWEEN 1 AND 5),
    magic_digest BYTEA,
    magic_digest_key_version INTEGER,
    method_policy_revision BIGINT NOT NULL CHECK (method_policy_revision > 0),
    method_security_revision BIGINT NOT NULL CHECK (method_security_revision > 0),
    assignment_security_revision BIGINT NOT NULL CHECK (assignment_security_revision > 0),
    smtp_selection_kind TEXT NOT NULL CHECK (smtp_selection_kind IN ('project', 'deployment_default')),
    smtp_configuration_id UUID,
    smtp_generation INTEGER NOT NULL CHECK (smtp_generation > 0),
    smtp_security_eligibility_revision BIGINT NOT NULL CHECK (smtp_security_eligibility_revision > 0),
    browser_binding_required BOOLEAN NOT NULL,
    issued_at TIMESTAMPTZ NOT NULL,
    otp_expires_at TIMESTAMPTZ,
    magic_expires_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    terminal_at TIMESTAMPTZ,
    redacted_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    FOREIGN KEY (project_id, transaction_id)
        REFERENCES login_transactions (project_id, id) ON DELETE CASCADE,
    FOREIGN KEY (project_id, application_id)
        REFERENCES applications (project_id, id),
    FOREIGN KEY (project_id, smtp_configuration_id)
        REFERENCES project_smtp_configurations (project_id, id),
    UNIQUE (project_id, id),
    UNIQUE (project_id, transaction_id, generation),
    CHECK (expires_at > issued_at AND expires_at <= issued_at + INTERVAL '10 minutes'),
    CHECK ((otp_digest IS NULL AND otp_digest_key_version IS NULL AND otp_expires_at IS NULL)
        OR (octet_length(otp_digest) = 32 AND otp_digest_key_version > 0
            AND otp_expires_at > issued_at AND otp_expires_at <= expires_at)),
    CHECK ((magic_digest IS NULL AND magic_digest_key_version IS NULL AND magic_expires_at IS NULL)
        OR (octet_length(magic_digest) = 32 AND magic_digest_key_version > 0
            AND magic_expires_at > issued_at AND magic_expires_at <= expires_at)),
    CHECK ((otp_digest IS NULL AND otp_digest_key_version IS NULL)
        OR (octet_length(otp_digest) = 32 AND otp_digest_key_version > 0)),
    CHECK ((magic_digest IS NULL AND magic_digest_key_version IS NULL)
        OR (octet_length(magic_digest) = 32 AND magic_digest_key_version > 0)),
    CHECK (otp_digest IS NOT NULL OR magic_digest IS NOT NULL),
    CHECK ((smtp_selection_kind = 'project') = (smtp_configuration_id IS NOT NULL)),
    CHECK ((status = 'consumed') = (consumed_at IS NOT NULL)),
    CHECK ((status IN ('pending')) = (terminal_at IS NULL)),
    CHECK ((address_ciphertext IS NULL) = (address_key_version IS NULL)),
    CHECK ((redacted_at IS NULL) = (address_ciphertext IS NOT NULL))
);
CREATE UNIQUE INDEX email_challenges_one_pending_idx
    ON email_challenges (project_id, transaction_id) WHERE status = 'pending';
CREATE INDEX email_challenges_cleanup_idx
    ON email_challenges (status, expires_at, id);
CREATE INDEX email_challenges_payload_retention_idx
    ON email_challenges (terminal_at, expires_at, id) WHERE address_ciphertext IS NOT NULL;

CREATE TABLE mail_outbox (
    id UUID PRIMARY KEY,
    project_id UUID NOT NULL,
    transaction_id UUID NOT NULL,
    challenge_id UUID NOT NULL,
    challenge_generation SMALLINT NOT NULL CHECK (challenge_generation BETWEEN 1 AND 5),
    status TEXT NOT NULL CHECK (status IN ('pending', 'leased', 'delivered', 'retry', 'permanent_failure', 'ambiguous', 'cancelled', 'expired')),
    smtp_selection_kind TEXT NOT NULL CHECK (smtp_selection_kind IN ('project', 'deployment_default')),
    smtp_configuration_id UUID,
    smtp_generation INTEGER NOT NULL CHECK (smtp_generation > 0),
    smtp_security_eligibility_revision BIGINT NOT NULL CHECK (smtp_security_eligibility_revision > 0),
    message_id TEXT NOT NULL CHECK (char_length(message_id) BETWEEN 16 AND 255),
    envelope_ciphertext BYTEA CHECK (envelope_ciphertext IS NULL OR octet_length(envelope_ciphertext) BETWEEN 41 AND 8192),
    envelope_key_version INTEGER CHECK (envelope_key_version IS NULL OR envelope_key_version > 0),
    body_ciphertext BYTEA CHECK (body_ciphertext IS NULL OR octet_length(body_ciphertext) BETWEEN 41 AND 65536),
    body_key_version INTEGER CHECK (body_key_version IS NULL OR body_key_version > 0),
    attempts SMALLINT NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 8),
    max_attempts SMALLINT NOT NULL DEFAULT 5 CHECK (max_attempts BETWEEN 1 AND 8),
    next_attempt_at TIMESTAMPTZ NOT NULL,
    lease_owner TEXT,
    lease_expires_at TIMESTAMPTZ,
    safe_outcome TEXT CHECK (safe_outcome IS NULL OR safe_outcome IN ('delivered', 'transient', 'permanent', 'ambiguous', 'policy_denied', 'expired')),
    useful_until TIMESTAMPTZ NOT NULL,
    delivered_at TIMESTAMPTZ,
    terminal_at TIMESTAMPTZ,
    redacted_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    FOREIGN KEY (project_id, challenge_id)
        REFERENCES email_challenges (project_id, id) ON DELETE CASCADE,
    FOREIGN KEY (project_id, transaction_id, challenge_generation)
        REFERENCES email_challenges (project_id, transaction_id, generation) ON DELETE CASCADE,
    FOREIGN KEY (project_id, smtp_configuration_id)
        REFERENCES project_smtp_configurations (project_id, id),
    UNIQUE (project_id, id),
    UNIQUE (project_id, challenge_id),
    UNIQUE (message_id),
    CHECK ((smtp_selection_kind = 'project') = (smtp_configuration_id IS NOT NULL)),
    CHECK ((status = 'leased') = (lease_owner IS NOT NULL AND lease_expires_at IS NOT NULL)),
    CHECK ((envelope_ciphertext IS NULL) = (envelope_key_version IS NULL)),
    CHECK ((body_ciphertext IS NULL) = (body_key_version IS NULL)),
    CHECK ((envelope_ciphertext IS NULL) = (body_ciphertext IS NULL)),
    CHECK ((redacted_at IS NULL) = (envelope_ciphertext IS NOT NULL)),
    CHECK (useful_until > created_at),
    CHECK (next_attempt_at <= useful_until)
);
CREATE INDEX mail_outbox_claim_idx
    ON mail_outbox (next_attempt_at, id)
    WHERE status IN ('pending', 'retry', 'ambiguous');
CREATE INDEX mail_outbox_attempt_cleanup_idx
    ON mail_outbox (id)
    WHERE status IN ('pending', 'retry', 'ambiguous', 'leased') AND attempts >= max_attempts;
CREATE INDEX mail_outbox_expiry_cleanup_idx
    ON mail_outbox (useful_until, id)
    WHERE status IN ('pending', 'retry', 'ambiguous', 'leased');
CREATE INDEX mail_outbox_payload_retention_idx
    ON mail_outbox (terminal_at, id) WHERE envelope_ciphertext IS NOT NULL;

CREATE TABLE magic_transfer_contexts (
    id UUID PRIMARY KEY,
    challenge_id UUID NOT NULL,
    context_digest BYTEA NOT NULL CHECK (octet_length(context_digest) = 32),
    context_digest_key_version INTEGER NOT NULL CHECK (context_digest_key_version > 0),
    csrf_digest BYTEA NOT NULL CHECK (octet_length(csrf_digest) = 32),
    csrf_digest_key_version INTEGER NOT NULL CHECK (csrf_digest_key_version > 0),
    browser_binding_required BOOLEAN NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('pending', 'consumed', 'expired')),
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    FOREIGN KEY (challenge_id) REFERENCES email_challenges (id) ON DELETE CASCADE,
    UNIQUE (context_digest_key_version, context_digest),
    CHECK (expires_at > created_at AND expires_at <= created_at + INTERVAL '5 minutes'),
    CHECK ((status = 'consumed') = (consumed_at IS NOT NULL))
);
CREATE INDEX magic_transfer_context_expiry_cleanup_idx
    ON magic_transfer_contexts (expires_at, id);
CREATE INDEX magic_transfer_context_consumed_cleanup_idx
    ON magic_transfer_contexts (consumed_at, id) WHERE consumed_at IS NOT NULL;

-- -----------------------------------------------------------------------------
-- Integrated from pre-release schema slice: 20260801020000_managed_provider_connections.sql
-- -----------------------------------------------------------------------------

-- Managed upstream profile connections. Renewable credentials remain purpose-bound AEAD
-- ciphertext; PostgreSQL owns generation fencing and durable renewal ambiguity.

ALTER TABLE provider_configurations
    ADD COLUMN managed_profile_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN managed_profile_revision BIGINT NOT NULL DEFAULT 1
        CHECK (managed_profile_revision > 0);

-- Provider denials terminalize before code exchange. Relax the foundation's active-provider
-- material checks only for terminal rows so state, nonce, PKCE, browser binding, and CSRF can be
-- erased atomically. Constraint discovery is expression-specific because PostgreSQL generated
-- positional names for the original unnamed checks.
DO $$
DECLARE
    constraint_row RECORD;
BEGIN
    FOR constraint_row IN
        SELECT conname
          FROM pg_constraint
         WHERE conrelid = 'login_transactions'::regclass
           AND contype = 'c'
           AND (
               pg_get_constraintdef(oid) LIKE '%provider_configuration_id IS NULL%callback_url IS NOT NULL%upstream_state_digest IS NOT NULL%'
               OR pg_get_constraintdef(oid) LIKE '%status <>%awaiting_browser_binding%browser_binding_digest IS NOT NULL%'
           )
    LOOP
        EXECUTE format('ALTER TABLE login_transactions DROP CONSTRAINT %I', constraint_row.conname);
    END LOOP;
END;
$$;

ALTER TABLE login_transactions
    ADD CONSTRAINT login_transactions_browser_material_by_status CHECK (
        (status = 'awaiting_browser_binding' AND browser_binding_digest IS NULL)
        OR status IN ('provider_exchange_failed','completed','expired','cancelled')
        OR browser_binding_digest IS NOT NULL
    ),
    ADD CONSTRAINT login_transactions_provider_material_by_status CHECK (
        provider_configuration_id IS NULL
        OR (
            callback_url IS NOT NULL AND char_length(callback_url) BETWEEN 8 AND 2048
            AND provider_revision IS NOT NULL AND provider_revision > 0
            AND assignment_security_revision IS NOT NULL AND assignment_security_revision > 0
            AND (
                (status IN ('provider_exchange_failed','completed','expired','cancelled')
                 AND upstream_state_digest IS NULL
                 AND upstream_state_digest_key_version IS NULL
                 AND oidc_nonce_digest IS NULL
                 AND oidc_nonce_digest_key_version IS NULL
                 AND provider_pkce_ciphertext IS NULL
                 AND provider_pkce_key_version IS NULL)
                OR (
                    upstream_state_digest IS NOT NULL
                    AND octet_length(upstream_state_digest) = 32
                    AND upstream_state_digest_key_version IS NOT NULL
                    AND upstream_state_digest_key_version > 0
                    AND oidc_nonce_digest IS NOT NULL
                    AND octet_length(oidc_nonce_digest) = 32
                    AND oidc_nonce_digest_key_version IS NOT NULL
                    AND oidc_nonce_digest_key_version > 0
                    AND provider_pkce_ciphertext IS NOT NULL
                    AND octet_length(provider_pkce_ciphertext) BETWEEN 17 AND 4096
                    AND provider_pkce_key_version IS NOT NULL
                    AND provider_pkce_key_version > 0
                )
            )
        )
    );

CREATE TABLE managed_provider_connections (
    id UUID PRIMARY KEY,
    project_id UUID NOT NULL,
    provider_configuration_id UUID NOT NULL,
    linked_identity_id UUID NOT NULL,
    user_id UUID NOT NULL,
    state TEXT NOT NULL CHECK (
        state IN ('active', 'reauth_required', 'revoked', 'disconnected')
    ),
    revision BIGINT NOT NULL CHECK (revision > 0),
    generation BIGINT NOT NULL CHECK (generation > 0),
    credential_generation BIGINT NOT NULL CHECK (credential_generation > 0),
    project_security_revision BIGINT NOT NULL CHECK (project_security_revision > 0),
    provider_revision BIGINT NOT NULL CHECK (provider_revision > 0),
    user_security_revision BIGINT NOT NULL CHECK (user_security_revision > 0),
    identity_revision BIGINT NOT NULL CHECK (identity_revision > 0),
    managed_profile_revision BIGINT NOT NULL CHECK (managed_profile_revision > 0),
    adapter_key TEXT NOT NULL CHECK (char_length(adapter_key) BETWEEN 1 AND 64),
    adapter_capability_revision BIGINT NOT NULL CHECK (adapter_capability_revision > 0),
    required_scopes TEXT[] NOT NULL,
    -- Frozen per credential generation. A managed callback is admitted only after exact
    -- discovery proved a revocation endpoint; an authoritative unsupported response clears it.
    supports_revocation BOOLEAN NOT NULL,
    last_safe_outcome TEXT NOT NULL CHECK (char_length(last_safe_outcome) BETWEEN 1 AND 64),
    last_synchronized_at TIMESTAMPTZ,
    next_synchronize_at TIMESTAMPTZ,
    next_renewal_at TIMESTAMPTZ,
    revocation_requested_at TIMESTAMPTZ,
    revocation_disposition TEXT CHECK (revocation_disposition IN ('revoke','disconnect')),
    -- Durable destructive dispatch boundary. Once present, the credential row is already
    -- inaccessible and recovery may only terminalize an unknown remote result, never replay.
    revocation_dispatch_started_at TIMESTAMPTZ,
    revocation_attempt_id UUID,
    consecutive_failures INTEGER NOT NULL DEFAULT 0 CHECK (consecutive_failures BETWEEN 0 AND 32),
    lease_owner UUID,
    lease_kind TEXT CHECK (lease_kind IN ('read', 'renewal', 'revocation', 'rewrap')),
    lease_expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    disconnected_at TIMESTAMPTZ,
    FOREIGN KEY (project_id, provider_configuration_id)
        REFERENCES provider_configurations (project_id, id),
    FOREIGN KEY (project_id, linked_identity_id, user_id)
        REFERENCES linked_identities (project_id, id, user_id) ON DELETE CASCADE,
    UNIQUE (project_id, id),
    UNIQUE (project_id, linked_identity_id),
    CHECK (cardinality(required_scopes) BETWEEN 1 AND 16),
    CHECK ((lease_owner IS NULL) = (lease_kind IS NULL)),
    CHECK ((lease_owner IS NULL) = (lease_expires_at IS NULL)),
    CHECK ((revocation_requested_at IS NULL) = (revocation_disposition IS NULL)),
    CHECK ((revocation_dispatch_started_at IS NULL) = (revocation_attempt_id IS NULL)),
    CHECK (revocation_dispatch_started_at IS NULL OR revocation_requested_at IS NOT NULL),
    CHECK ((state = 'disconnected') = (disconnected_at IS NOT NULL))
);

CREATE INDEX managed_provider_connections_due_idx
    ON managed_provider_connections
        (next_synchronize_at, project_id, provider_configuration_id, id)
    WHERE state = 'active' AND next_synchronize_at IS NOT NULL;

CREATE INDEX managed_provider_connections_renewal_due_idx
    ON managed_provider_connections
        (next_renewal_at, project_id, provider_configuration_id, id)
    WHERE state = 'active' AND next_renewal_at IS NOT NULL;

CREATE INDEX managed_provider_connections_revocation_due_idx
    ON managed_provider_connections
        (revocation_dispatch_started_at, revocation_requested_at,
         project_id, provider_configuration_id, id)
    WHERE state = 'active' AND revocation_requested_at IS NOT NULL;

CREATE TABLE managed_provider_claim_fairness (
    project_id UUID NOT NULL,
    provider_configuration_id UUID NOT NULL,
    queue_kind TEXT NOT NULL CHECK (queue_kind = 'outbound'),
    last_claimed_at TIMESTAMPTZ NOT NULL,
    lease_owner UUID,
    lease_expires_at TIMESTAMPTZ,
    PRIMARY KEY (project_id, provider_configuration_id, queue_kind),
    FOREIGN KEY (project_id, provider_configuration_id)
        REFERENCES provider_configurations (project_id, id) ON DELETE CASCADE,
    CHECK ((lease_owner IS NULL) = (lease_expires_at IS NULL)),
    CHECK (lease_expires_at IS NULL OR lease_expires_at > last_claimed_at)
);

-- Fairness state is write-side materialized exactly once, never reconstructed by a worker claim.
-- The trigger covers every managed-connection installation path (including future adapters); the
-- bounded backfill is the sole migration-time scan for rows that predate trigger installation.
CREATE FUNCTION materialize_managed_provider_claim_fairness()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    INSERT INTO managed_provider_claim_fairness
        (project_id, provider_configuration_id, queue_kind, last_claimed_at,
         lease_owner, lease_expires_at)
    VALUES
        (NEW.project_id, NEW.provider_configuration_id, 'outbound',
         NEW.created_at - INTERVAL '1 microsecond', NULL, NULL)
    ON CONFLICT (project_id, provider_configuration_id, queue_kind) DO NOTHING;
    RETURN NEW;
END;
$$;

CREATE TRIGGER managed_provider_connection_materialize_fairness
AFTER INSERT ON managed_provider_connections
FOR EACH ROW EXECUTE FUNCTION materialize_managed_provider_claim_fairness();

INSERT INTO managed_provider_claim_fairness
    (project_id, provider_configuration_id, queue_kind, last_claimed_at,
     lease_owner, lease_expires_at)
SELECT project_id, provider_configuration_id, 'outbound',
       MIN(created_at) - INTERVAL '1 microsecond', NULL, NULL
  FROM managed_provider_connections
 GROUP BY project_id, provider_configuration_id
ON CONFLICT (project_id, provider_configuration_id, queue_kind) DO NOTHING;

CREATE TABLE managed_provider_credentials (
    project_id UUID NOT NULL,
    connection_id UUID NOT NULL,
    connection_generation BIGINT NOT NULL CHECK (connection_generation > 0),
    credential_generation BIGINT NOT NULL CHECK (credential_generation > 0),
    key_version INTEGER NOT NULL CHECK (key_version > 0),
    ciphertext BYTEA,
    created_at TIMESTAMPTZ NOT NULL,
    superseded_at TIMESTAMPTZ,
    destroyed_at TIMESTAMPTZ,
    PRIMARY KEY (project_id, connection_id, credential_generation),
    FOREIGN KEY (project_id, connection_id)
        REFERENCES managed_provider_connections (project_id, id) ON DELETE CASCADE,
    CHECK (octet_length(ciphertext) BETWEEN 40 AND 16384),
    CHECK ((ciphertext IS NULL) = (destroyed_at IS NOT NULL)),
    CHECK (superseded_at IS NULL OR superseded_at >= created_at),
    CHECK (destroyed_at IS NULL OR destroyed_at >= created_at)
);

CREATE UNIQUE INDEX managed_provider_credentials_live_idx
    ON managed_provider_credentials (project_id, connection_id)
    WHERE ciphertext IS NOT NULL;

CREATE TABLE managed_provider_renewal_operations (
    id UUID PRIMARY KEY,
    project_id UUID NOT NULL,
    connection_id UUID NOT NULL,
    expected_connection_generation BIGINT NOT NULL CHECK (expected_connection_generation > 0),
    expected_credential_generation BIGINT NOT NULL CHECK (expected_credential_generation > 0),
    successor_connection_generation BIGINT NOT NULL CHECK (successor_connection_generation > 1),
    successor_credential_generation BIGINT NOT NULL CHECK (successor_credential_generation > 1),
    attempt_id UUID NOT NULL,
    state TEXT NOT NULL CHECK (
        state IN ('prepared', 'submitted', 'successor_committed', 'reauth_required', 'abandoned',
                  'superseded_by_login')
    ),
    adapter_idempotent_replay BOOLEAN NOT NULL,
    lease_owner UUID,
    lease_expires_at TIMESTAMPTZ,
    safe_outcome TEXT NOT NULL CHECK (char_length(safe_outcome) BETWEEN 1 AND 64),
    prepared_at TIMESTAMPTZ NOT NULL,
    submitted_at TIMESTAMPTZ,
    terminal_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ NOT NULL,
    FOREIGN KEY (project_id, connection_id)
        REFERENCES managed_provider_connections (project_id, id) ON DELETE CASCADE,
    UNIQUE (project_id, id),
    UNIQUE (project_id, connection_id, expected_connection_generation),
    UNIQUE (project_id, connection_id, attempt_id),
    CHECK (successor_connection_generation = expected_connection_generation + 1),
    CHECK (successor_credential_generation = expected_credential_generation + 1),
    CHECK ((state IN ('prepared', 'abandoned', 'reauth_required', 'superseded_by_login'))
           OR submitted_at IS NOT NULL),
    CHECK ((state IN ('successor_committed', 'reauth_required', 'abandoned',
                      'superseded_by_login')) = (terminal_at IS NOT NULL))
);

CREATE INDEX managed_provider_renewal_recovery_idx
    ON managed_provider_renewal_operations (state, lease_expires_at, project_id, connection_id)
    WHERE state IN ('prepared', 'submitted');

CREATE TABLE managed_provider_reauthorization_interactions (
    id UUID PRIMARY KEY,
    project_id UUID NOT NULL,
    project_public_id TEXT NOT NULL,
    connection_id UUID NOT NULL,
    linked_identity_id UUID NOT NULL,
    user_id UUID NOT NULL,
    provider_configuration_id UUID NOT NULL,
    provider_key TEXT NOT NULL,
    issuer TEXT NOT NULL CHECK (char_length(issuer) BETWEEN 8 AND 2048),
    subject TEXT NOT NULL CHECK (char_length(subject) BETWEEN 1 AND 512),
    client_id TEXT NOT NULL CHECK (char_length(client_id) BETWEEN 1 AND 512),
    secret_ref TEXT NOT NULL CHECK (char_length(secret_ref) BETWEEN 8 AND 256),
    application_id UUID NOT NULL,
    expected_connection_generation BIGINT NOT NULL CHECK (expected_connection_generation > 0),
    expected_credential_generation BIGINT NOT NULL CHECK (expected_credential_generation > 0),
    expected_connection_revision BIGINT NOT NULL CHECK (expected_connection_revision > 0),
    project_security_revision BIGINT NOT NULL CHECK (project_security_revision > 0),
    user_security_revision BIGINT NOT NULL CHECK (user_security_revision > 0),
    identity_revision BIGINT NOT NULL CHECK (identity_revision > 0),
    provider_revision BIGINT NOT NULL CHECK (provider_revision > 0),
    managed_profile_revision BIGINT NOT NULL CHECK (managed_profile_revision > 0),
    application_revision BIGINT NOT NULL CHECK (application_revision > 0),
    assignment_security_revision BIGINT NOT NULL CHECK (assignment_security_revision > 0),
    callback_url TEXT NOT NULL CHECK (char_length(callback_url) BETWEEN 8 AND 2048),
    adapter_key TEXT NOT NULL CHECK (char_length(adapter_key) BETWEEN 1 AND 64),
    adapter_capability_revision BIGINT NOT NULL CHECK (adapter_capability_revision > 0),
    supports_revocation BOOLEAN NOT NULL,
    required_scopes TEXT[] NOT NULL CHECK (cardinality(required_scopes) BETWEEN 1 AND 16),
    provider_pkce_required BOOLEAN NOT NULL,
    oidc_nonce_required BOOLEAN NOT NULL CHECK (oidc_nonce_required),
    interaction_digest BYTEA CHECK (octet_length(interaction_digest) = 32),
    interaction_digest_key_version INTEGER CHECK (interaction_digest_key_version > 0),
    browser_binding_digest BYTEA CHECK (octet_length(browser_binding_digest) = 32),
    browser_binding_key_version INTEGER,
    csrf_digest BYTEA CHECK (octet_length(csrf_digest) = 32),
    csrf_key_version INTEGER,
    upstream_state_digest BYTEA CHECK (octet_length(upstream_state_digest) = 32),
    upstream_state_key_version INTEGER,
    provider_pkce_ciphertext BYTEA,
    provider_pkce_key_version INTEGER,
    oidc_nonce_digest BYTEA CHECK (octet_length(oidc_nonce_digest) = 32),
    oidc_nonce_key_version INTEGER,
    revision BIGINT NOT NULL DEFAULT 1 CHECK (revision > 0),
    status TEXT NOT NULL CHECK (status IN (
        'awaiting_browser_binding', 'awaiting_provider_start',
        'provider_authorization_started', 'provider_exchange_in_progress',
        'completed', 'provider_exchange_failed', 'expired', 'cancelled'
    )),
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    provider_started_at TIMESTAMPTZ,
    exchange_claimed_at TIMESTAMPTZ,
    terminal_at TIMESTAMPTZ,
    FOREIGN KEY (project_id, connection_id)
        REFERENCES managed_provider_connections (project_id, id) ON DELETE CASCADE,
    FOREIGN KEY (project_id, linked_identity_id, user_id)
        REFERENCES linked_identities (project_id, id, user_id) ON DELETE CASCADE,
    FOREIGN KEY (project_id, provider_configuration_id)
        REFERENCES provider_configurations (project_id, id),
    FOREIGN KEY (project_id, application_id)
        REFERENCES applications (project_id, id),
    FOREIGN KEY (project_id, application_id, provider_configuration_id)
        REFERENCES application_provider_assignments (project_id, application_id, provider_id),
    UNIQUE (project_id, id),
    UNIQUE (interaction_digest_key_version, interaction_digest),
    CHECK (expires_at > created_at AND expires_at <= created_at + INTERVAL '10 minutes'),
    CHECK ((interaction_digest IS NULL) = (interaction_digest_key_version IS NULL)),
    CHECK ((browser_binding_digest IS NULL) = (browser_binding_key_version IS NULL)),
    CHECK ((csrf_digest IS NULL) = (csrf_key_version IS NULL)),
    CHECK ((browser_binding_digest IS NULL) = (csrf_digest IS NULL)),
    CHECK ((upstream_state_digest IS NULL) = (upstream_state_key_version IS NULL)),
    CHECK ((provider_pkce_ciphertext IS NULL) = (provider_pkce_key_version IS NULL)),
    CHECK ((oidc_nonce_digest IS NULL) = (oidc_nonce_key_version IS NULL)),
    CHECK (status <> 'awaiting_browser_binding' OR browser_binding_digest IS NULL),
    CHECK (status NOT IN ('awaiting_provider_start','provider_authorization_started',
                          'provider_exchange_in_progress') OR browser_binding_digest IS NOT NULL),
    CHECK (status NOT IN ('awaiting_browser_binding','awaiting_provider_start') OR
           upstream_state_digest IS NULL),
    CHECK (status NOT IN ('provider_authorization_started','provider_exchange_in_progress') OR
           upstream_state_digest IS NOT NULL),
    CHECK ((status IN ('completed','provider_exchange_failed','expired','cancelled')) =
           (terminal_at IS NOT NULL))
);

CREATE INDEX managed_reauthorization_state_idx
    ON managed_provider_reauthorization_interactions
       (upstream_state_key_version, upstream_state_digest)
    WHERE status IN ('provider_authorization_started','provider_exchange_in_progress');

CREATE TABLE managed_reauthorization_create_results (
    idempotency_key TEXT PRIMARY KEY REFERENCES control_idempotency_records (idempotency_key),
    project_id UUID NOT NULL,
    interaction_id UUID NOT NULL,
    request_digest BYTEA CHECK (octet_length(request_digest) = 32),
    create_result_key_version INTEGER NOT NULL CHECK (create_result_key_version > 0),
    create_result_ciphertext BYTEA,
    expires_at TIMESTAMPTZ NOT NULL,
    erased_at TIMESTAMPTZ,
    FOREIGN KEY (project_id, interaction_id)
        REFERENCES managed_provider_reauthorization_interactions (project_id, id) ON DELETE CASCADE,
    CHECK (octet_length(create_result_ciphertext) BETWEEN 40 AND 4096),
    CHECK ((create_result_ciphertext IS NULL) = (erased_at IS NOT NULL))
);

-- -----------------------------------------------------------------------------
-- Integrated from pre-release schema slice: 20260801030000_identity_lifecycle_and_projection.sql
-- -----------------------------------------------------------------------------

-- Typed identity-mutation proofs, same-Project merge attribution, callback ownership,
-- and deny-by-default verified-email projection admission.

ALTER TABLE project_policies
    ADD COLUMN projection_verified_email_enabled BOOLEAN NOT NULL DEFAULT FALSE;

ALTER TABLE applications
    ADD COLUMN projection_verified_email_enabled BOOLEAN NOT NULL DEFAULT FALSE;

-- PostgreSQL is the write/acceptance authority for the dedicated projection verified-email ring.
-- Configuration supplies custody only; it cannot silently select a write version. Runtime
-- observations are immutable per process incarnation and authorize lifecycle transitions, never
-- ordinary Control confirmation.
CREATE FUNCTION owlauth_positive_unique_key_versions(versions INTEGER[])
RETURNS BOOLEAN
LANGUAGE plpgsql
IMMUTABLE
STRICT
AS $$
DECLARE
    version INTEGER;
    seen INTEGER[] := ARRAY[]::INTEGER[];
BEGIN
    IF cardinality(versions) NOT BETWEEN 1 AND 16 THEN
        RETURN FALSE;
    END IF;
    FOREACH version IN ARRAY versions LOOP
        IF version <= 0 OR seen @> ARRAY[version] THEN
            RETURN FALSE;
        END IF;
        seen := array_append(seen, version);
    END LOOP;
    RETURN TRUE;
END
$$;

CREATE TABLE projection_email_key_authority (
    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    authority_revision BIGINT NOT NULL CHECK (authority_revision > 0),
    write_version INTEGER NOT NULL CHECK (write_version > 0),
    accepted_versions INTEGER[] NOT NULL,
    target_version INTEGER,
    target_staged_at TIMESTAMPTZ,
    retirement_version INTEGER,
    retirement_authorized_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT projection_email_key_authority_accepted_check CHECK (
        owlauth_positive_unique_key_versions(accepted_versions)
        AND accepted_versions @> ARRAY[write_version]
    ),
    CONSTRAINT projection_email_key_authority_target_check CHECK (
        (target_version IS NULL AND target_staged_at IS NULL)
        OR (target_version IS NOT NULL AND target_version > 0
            AND target_version <> write_version AND target_staged_at IS NOT NULL
            AND accepted_versions @> ARRAY[target_version])
    ),
    CONSTRAINT projection_email_key_authority_retirement_check CHECK (
        (retirement_version IS NULL AND retirement_authorized_at IS NULL)
        OR (retirement_version IS NOT NULL AND retirement_version > 0
            AND retirement_version <> write_version
            AND accepted_versions @> ARRAY[retirement_version]
            AND retirement_authorized_at IS NOT NULL)
    )
);

INSERT INTO projection_email_key_authority
(singleton,authority_revision,write_version,accepted_versions,updated_at)
VALUES (TRUE,1,1,ARRAY[1]::INTEGER[],clock_timestamp());

CREATE TABLE projection_email_runtime_observations (
    process_id TEXT NOT NULL CHECK (process_id <> '' AND length(process_id) <= 128),
    process_incarnation UUID NOT NULL,
    authority_revision BIGINT NOT NULL CHECK (authority_revision > 0),
    readable_versions INTEGER[] NOT NULL,
    observed_at TIMESTAMPTZ NOT NULL,
    lease_expires_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (process_id, process_incarnation),
    CONSTRAINT projection_email_runtime_observations_versions_check CHECK (
        owlauth_positive_unique_key_versions(readable_versions)
    ),
    CONSTRAINT projection_email_runtime_observations_lease_check
        CHECK (lease_expires_at > observed_at)
);
CREATE INDEX projection_email_runtime_observations_live_idx
    ON projection_email_runtime_observations (process_id, lease_expires_at);

-- Durable verified-email projection material remains protected exclusively by the dedicated
-- email-identity key ring. The public JSON document is always the safe wire shape with an
-- explicit null; Runtime overlays plaintext only after context-bound decryption.
ALTER TABLE application_user_projections
    ADD COLUMN verified_email_source_identity_id UUID,
    ADD COLUMN verified_email_ciphertext BYTEA,
    ADD COLUMN verified_email_key_version INTEGER,
    ADD CONSTRAINT application_user_projections_verified_email_material_check CHECK (
        (verified_email_source_identity_id IS NULL
         AND verified_email_ciphertext IS NULL
         AND verified_email_key_version IS NULL)
        OR
        (verified_email_source_identity_id IS NOT NULL
         AND verified_email_ciphertext IS NOT NULL
         AND octet_length(verified_email_ciphertext) BETWEEN 40 AND 4096
         AND verified_email_key_version > 0)
    ),
    ADD CONSTRAINT application_user_projections_safe_document_check CHECK (
        schema_name = 'owlauth.user.v1'
        AND jsonb_typeof(document) = 'object'
        AND (document->>'projection_schema' = 'owlauth.user.v1') IS TRUE
        AND (
            (document ?& ARRAY[
                'user_id','user_revision','projection_schema','projection_revision',
                'display_name','picture_url','locale','verified_email','status',
                'created_at','updated_at'
             ]
             AND (document - ARRAY[
                'user_id','user_revision','projection_schema','projection_revision',
                'display_name','picture_url','locale','verified_email','status',
                'created_at','updated_at'
             ]::TEXT[]) = '{}'::jsonb
             AND document->'verified_email' = 'null'::jsonb)
            OR
            -- Release N-1 has no locale or verified-email keys. Keep that exact non-email shape
            -- writable during rolling overlap; every N reader repairs it before delivery.
            (document ?& ARRAY[
                'user_id','user_revision','projection_schema','projection_revision',
                'display_name','picture_url','status','created_at','updated_at'
             ]
             AND (document - ARRAY[
                'user_id','user_revision','projection_schema','projection_revision',
                'display_name','picture_url','status','created_at','updated_at'
             ]::TEXT[]) = '{}'::jsonb)
        )
    ) NOT VALID;

-- Existing N-1 rows remain untouched during expansion. Runtime lazily repairs requested rows, and
-- operations may use a bounded resumable backfill before a later contract migration validates the
-- constraint. This migration must not rewrite or scan an unbounded projection directory.

-- A merged loser remains as immutable historical credential attribution while every identity
-- moves to the winner. Only this terminal state may have no designated primary identity.
DROP TRIGGER project_users_exact_primary_identity ON project_users;

ALTER TABLE project_users
    DROP CONSTRAINT project_users_status_check,
    DROP CONSTRAINT project_users_primary_source_shape_check,
    ADD COLUMN merged_into_user_id UUID,
    ADD CONSTRAINT project_users_status_check
        CHECK (status IN ('active', 'disabled', 'merged')),
    ADD CONSTRAINT project_users_merged_shape_check CHECK (
        (status = 'merged'
            AND merged_into_user_id IS NOT NULL
            AND merged_into_user_id <> id
            AND primary_profile_identity_id IS NULL
            AND primary_email_identity_id IS NULL)
        OR (status IN ('active', 'disabled')
            AND merged_into_user_id IS NULL
            AND ((primary_source_kind = 'provider'
                    AND primary_email_identity_id IS NULL)
                OR (primary_source_kind = 'email'
                    AND primary_profile_identity_id IS NULL)))
    ),
    ADD CONSTRAINT project_users_merged_into_fk
        FOREIGN KEY (project_id, merged_into_user_id)
        REFERENCES project_users (project_id, id)
        DEFERRABLE INITIALLY DEFERRED;

-- Every final-state check that can add or remove an edge in a Project identity graph takes this
-- one transaction-scoped lock before reading the graph. Deferred checks then serialize reciprocal
-- merges and merge-vs-edge-attach races without widening ordinary repository row locks.
CREATE FUNCTION owlauth_lock_project_identity_graph(target_project_id UUID)
RETURNS VOID
LANGUAGE SQL
AS $$
    SELECT pg_advisory_xact_lock(
        hashtextextended('owlauth-project-identity-graph:' || target_project_id::TEXT, 0)
    )
$$;

CREATE OR REPLACE FUNCTION owlauth_enforce_exact_primary_identity()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    current_record project_users%ROWTYPE;
BEGIN
    PERFORM owlauth_lock_project_identity_graph(NEW.project_id);
    SELECT * INTO STRICT current_record
      FROM project_users
     WHERE project_id = NEW.project_id AND id = NEW.id;
    IF current_record.status = 'merged' THEN
        IF current_record.merged_into_user_id IS NULL
            OR current_record.primary_profile_identity_id IS NOT NULL
            OR current_record.primary_email_identity_id IS NOT NULL
        THEN
            RAISE EXCEPTION 'merged user must retain only an exact winner attribution'
                USING ERRCODE = '23514';
        END IF;
    ELSIF current_record.primary_source_kind = 'provider' THEN
        IF current_record.primary_profile_identity_id IS NULL
            OR current_record.primary_email_identity_id IS NOT NULL
            OR current_record.merged_into_user_id IS NOT NULL
        THEN
            RAISE EXCEPTION 'provider primary source must identify exactly one provider identity'
                USING ERRCODE = '23514';
        END IF;
    ELSIF current_record.primary_source_kind = 'email' THEN
        IF current_record.primary_profile_identity_id IS NOT NULL
            OR current_record.primary_email_identity_id IS NULL
            OR current_record.merged_into_user_id IS NOT NULL
        THEN
            RAISE EXCEPTION 'email primary source must identify exactly one email identity'
                USING ERRCODE = '23514';
        END IF;
    ELSE
        RAISE EXCEPTION 'unsupported primary source kind' USING ERRCODE = '23514';
    END IF;
    RETURN NULL;
END
$$;

CREATE CONSTRAINT TRIGGER project_users_exact_primary_identity
AFTER INSERT OR UPDATE OF status, primary_source_kind, primary_profile_identity_id,
                          primary_email_identity_id, merged_into_user_id
ON project_users
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
EXECUTE FUNCTION owlauth_enforce_exact_primary_identity();

CREATE FUNCTION owlauth_reject_merged_project_user_change()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF OLD.status = 'merged'
        AND (NEW.status, NEW.project_id, NEW.id, NEW.primary_source_kind,
             NEW.primary_profile_identity_id, NEW.primary_email_identity_id,
             NEW.merged_into_user_id)
            IS DISTINCT FROM
            (OLD.status, OLD.project_id, OLD.id, OLD.primary_source_kind,
             OLD.primary_profile_identity_id, OLD.primary_email_identity_id,
             OLD.merged_into_user_id)
    THEN
        RAISE EXCEPTION 'merged Project user attribution is immutable'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER project_users_merged_terminal_state
BEFORE UPDATE ON project_users
FOR EACH ROW
EXECUTE FUNCTION owlauth_reject_merged_project_user_change();

CREATE FUNCTION owlauth_validate_merged_project_user_attribution()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    target_project_id UUID;
    target_loser_user_id UUID;
BEGIN
    IF TG_TABLE_NAME = 'project_users' THEN
        target_project_id := NEW.project_id;
        target_loser_user_id := NEW.id;
    ELSE
        target_project_id := CASE WHEN TG_OP = 'DELETE' THEN OLD.project_id ELSE NEW.project_id END;
        target_loser_user_id := CASE
            WHEN TG_OP = 'DELETE' THEN OLD.loser_user_id
            ELSE NEW.loser_user_id
        END;
    END IF;

    PERFORM owlauth_lock_project_identity_graph(target_project_id);
    IF EXISTS (
        SELECT 1
          FROM project_users AS loser
         WHERE loser.project_id = target_project_id
           AND (loser.id = target_loser_user_id
                OR (TG_TABLE_NAME = 'project_users'
                    AND loser.merged_into_user_id = target_loser_user_id))
           AND loser.status = 'merged'
           AND (NOT EXISTS (
                    SELECT 1
                      FROM project_users AS winner
                     WHERE winner.project_id = loser.project_id
                       AND winner.id = loser.merged_into_user_id
                       AND winner.status = 'active'
                       AND winner.merged_into_user_id IS NULL
                )
                OR NOT EXISTS (
                    SELECT 1
                      FROM project_user_merge_tombstones AS tombstone
                     WHERE tombstone.project_id = loser.project_id
                       AND tombstone.loser_user_id = loser.id
                       AND tombstone.winner_user_id = loser.merged_into_user_id
                )
                OR EXISTS (
                    SELECT 1 FROM linked_identities AS identity
                     WHERE identity.project_id = loser.project_id
                       AND identity.user_id = loser.id
                )
                OR EXISTS (
                    SELECT 1 FROM email_identities AS identity
                     WHERE identity.project_id = loser.project_id
                       AND identity.user_id = loser.id
                ))
    ) THEN
        RAISE EXCEPTION
            'merged Project user requires no owned identities, one active winner and completed tombstone'
            USING ERRCODE = '23514';
    END IF;

    IF EXISTS (
        SELECT 1
          FROM project_user_merge_tombstones AS tombstone
          LEFT JOIN project_users AS loser
            ON loser.project_id = tombstone.project_id
           AND loser.id = tombstone.loser_user_id
          LEFT JOIN project_users AS winner
            ON winner.project_id = tombstone.project_id
           AND winner.id = tombstone.winner_user_id
         WHERE tombstone.project_id = target_project_id
           AND (tombstone.loser_user_id = target_loser_user_id
                OR (TG_TABLE_NAME = 'project_users'
                    AND tombstone.winner_user_id = target_loser_user_id))
           AND (loser.id IS NULL
                OR loser.status <> 'merged'
                OR loser.merged_into_user_id IS DISTINCT FROM tombstone.winner_user_id
                OR loser.primary_profile_identity_id IS NOT NULL
                OR loser.primary_email_identity_id IS NOT NULL
                OR winner.id IS NULL
                OR winner.status <> 'active'
                OR winner.merged_into_user_id IS NOT NULL
                OR EXISTS (
                    SELECT 1 FROM linked_identities AS identity
                     WHERE identity.project_id = tombstone.project_id
                       AND identity.user_id = tombstone.loser_user_id
                )
                OR EXISTS (
                    SELECT 1 FROM email_identities AS identity
                     WHERE identity.project_id = tombstone.project_id
                       AND identity.user_id = tombstone.loser_user_id
                ))
    ) THEN
        RAISE EXCEPTION
            'merge tombstone requires one exact merged loser and active winner graph'
            USING ERRCODE = '23514';
    END IF;
    RETURN NULL;
END
$$;

CREATE CONSTRAINT TRIGGER project_users_exact_merged_attribution
AFTER INSERT OR UPDATE OF status, merged_into_user_id ON project_users
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
EXECUTE FUNCTION owlauth_validate_merged_project_user_attribution();

CREATE CONSTRAINT TRIGGER project_user_merge_tombstones_reverse_attribution
AFTER INSERT OR UPDATE OR DELETE ON project_user_merge_tombstones
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
EXECUTE FUNCTION owlauth_validate_merged_project_user_attribution();

CREATE FUNCTION owlauth_validate_merged_project_user_identity_ownership()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    target_project_id UUID;
    old_user_id UUID;
    new_user_id UUID;
BEGIN
    target_project_id := CASE
        WHEN TG_OP = 'DELETE' THEN OLD.project_id
        ELSE NEW.project_id
    END;
    old_user_id := CASE WHEN TG_OP IN ('UPDATE', 'DELETE') THEN OLD.user_id END;
    new_user_id := CASE WHEN TG_OP IN ('INSERT', 'UPDATE') THEN NEW.user_id END;

    PERFORM owlauth_lock_project_identity_graph(target_project_id);
    IF EXISTS (
        SELECT 1
          FROM project_users AS project_user
         WHERE project_user.project_id = target_project_id
           AND project_user.id IN (old_user_id, new_user_id)
           AND project_user.status = 'merged'
           AND (EXISTS (
                    SELECT 1 FROM linked_identities AS identity
                     WHERE identity.project_id = project_user.project_id
                       AND identity.user_id = project_user.id
                )
                OR EXISTS (
                    SELECT 1 FROM email_identities AS identity
                     WHERE identity.project_id = project_user.project_id
                       AND identity.user_id = project_user.id
                ))
    ) THEN
        RAISE EXCEPTION 'merged Project user cannot retain an identity owner edge'
            USING ERRCODE = '23514';
    END IF;
    RETURN NULL;
END
$$;

CREATE CONSTRAINT TRIGGER linked_identities_no_merged_owner
AFTER INSERT OR UPDATE OF user_id OR DELETE ON linked_identities
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
EXECUTE FUNCTION owlauth_validate_merged_project_user_identity_ownership();

CREATE CONSTRAINT TRIGGER email_identities_no_merged_owner
AFTER INSERT OR UPDATE OF user_id OR DELETE ON email_identities
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
EXECUTE FUNCTION owlauth_validate_merged_project_user_identity_ownership();

-- Live managed connections follow identity ownership atomically during a merge. Historical
-- reauthorization interactions retain their original user attribution and therefore reference
-- only the durable identity after insertion-time ownership was established in the prior schema.
DO $$
DECLARE
    connection_constraint_name TEXT;
    interaction_constraint_name TEXT;
BEGIN
    SELECT constraint_row.conname
      INTO STRICT connection_constraint_name
      FROM pg_constraint AS constraint_row
     WHERE constraint_row.contype = 'f'
       AND constraint_row.conrelid = 'managed_provider_connections'::regclass
       AND constraint_row.confrelid = 'linked_identities'::regclass
       AND ARRAY(
           SELECT attribute.attname::TEXT
             FROM unnest(constraint_row.conkey) WITH ORDINALITY AS key_column(attnum, ordinal)
             JOIN pg_attribute AS attribute
               ON attribute.attrelid = constraint_row.conrelid
              AND attribute.attnum = key_column.attnum
            ORDER BY key_column.ordinal
       ) = ARRAY['project_id','linked_identity_id','user_id']::TEXT[];

    SELECT constraint_row.conname
      INTO STRICT interaction_constraint_name
      FROM pg_constraint AS constraint_row
     WHERE constraint_row.contype = 'f'
       AND constraint_row.conrelid = 'managed_provider_reauthorization_interactions'::regclass
       AND constraint_row.confrelid = 'linked_identities'::regclass
       AND ARRAY(
           SELECT attribute.attname::TEXT
             FROM unnest(constraint_row.conkey) WITH ORDINALITY AS key_column(attnum, ordinal)
             JOIN pg_attribute AS attribute
               ON attribute.attrelid = constraint_row.conrelid
              AND attribute.attnum = key_column.attnum
            ORDER BY key_column.ordinal
       ) = ARRAY['project_id','linked_identity_id','user_id']::TEXT[];

    EXECUTE format(
        'ALTER TABLE managed_provider_connections DROP CONSTRAINT %I',
        connection_constraint_name
    );
    EXECUTE format(
        'ALTER TABLE managed_provider_reauthorization_interactions DROP CONSTRAINT %I',
        interaction_constraint_name
    );
END
$$;

ALTER TABLE managed_provider_connections
    ADD CONSTRAINT managed_provider_connections_identity_owner_fk
        FOREIGN KEY (project_id, linked_identity_id, user_id)
        REFERENCES linked_identities (project_id, id, user_id)
        ON DELETE CASCADE
        DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE managed_provider_reauthorization_interactions
    ADD CONSTRAINT managed_provider_reauthorization_identity_fk
        FOREIGN KEY (project_id, linked_identity_id)
        REFERENCES linked_identities (project_id, id)
        ON DELETE CASCADE;

CREATE FUNCTION owlauth_validate_managed_reauthorization_original_authority()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
          FROM managed_provider_connections AS connection
          JOIN linked_identities AS identity
            ON identity.project_id = connection.project_id
           AND identity.id = connection.linked_identity_id
           AND identity.user_id = connection.user_id
          JOIN provider_configurations AS provider
            ON provider.project_id = connection.project_id
           AND provider.id = connection.provider_configuration_id
          JOIN projects AS project ON project.id = connection.project_id
          JOIN project_users AS project_user
            ON project_user.project_id = connection.project_id
           AND project_user.id = connection.user_id
          JOIN applications AS application
            ON application.project_id = connection.project_id
           AND application.id = NEW.application_id
          JOIN application_provider_assignments AS assignment
            ON assignment.project_id = connection.project_id
           AND assignment.application_id = application.id
           AND assignment.provider_id = provider.id
         WHERE connection.project_id = NEW.project_id
           AND connection.id = NEW.connection_id
           AND connection.linked_identity_id = NEW.linked_identity_id
           AND connection.user_id = NEW.user_id
           AND connection.provider_configuration_id = NEW.provider_configuration_id
           AND connection.generation = NEW.expected_connection_generation
           AND connection.credential_generation = NEW.expected_credential_generation
           AND connection.revision = NEW.expected_connection_revision
           AND identity.issuer = NEW.issuer
           AND identity.subject = NEW.subject
           AND identity.identity_revision = NEW.identity_revision
           AND provider.provider_key = NEW.provider_key
           AND provider.issuer = NEW.issuer
           AND provider.client_id = NEW.client_id
           AND provider.secret_ref = NEW.secret_ref
           AND provider.callback_url = NEW.callback_url
           AND provider.revision = NEW.provider_revision
           AND project.public_id = NEW.project_public_id
           AND project.security_revision = NEW.project_security_revision
           AND project.status = 'active'
           AND project_user.security_revision = NEW.user_security_revision
           AND project_user.status = 'active'
           AND application.revision = NEW.application_revision
           AND application.status = 'active'
           AND assignment.security_revision = NEW.assignment_security_revision
           AND assignment.status = 'active'
    ) THEN
        RAISE EXCEPTION 'managed reauthorization must capture exact current connection authority'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER managed_reauthorization_capture_original_authority
BEFORE INSERT ON managed_provider_reauthorization_interactions
FOR EACH ROW
EXECUTE FUNCTION owlauth_validate_managed_reauthorization_original_authority();

CREATE TRIGGER managed_reauthorization_stable_authority
BEFORE UPDATE ON managed_provider_reauthorization_interactions
FOR EACH ROW
EXECUTE FUNCTION reject_immutable_column_change(
    'project_id', 'project_public_id', 'connection_id', 'linked_identity_id', 'user_id',
    'provider_configuration_id', 'provider_key', 'issuer', 'subject', 'client_id',
    'secret_ref', 'application_id', 'expected_connection_generation',
    'expected_credential_generation', 'expected_connection_revision',
    'project_security_revision', 'user_security_revision', 'identity_revision',
    'provider_revision', 'managed_profile_revision', 'application_revision',
    'assignment_security_revision', 'callback_url', 'adapter_key',
    'adapter_capability_revision', 'required_scopes', 'provider_pkce_required',
    'oidc_nonce_required', 'created_at'
);

CREATE FUNCTION owlauth_validate_managed_reauthorization_revocation_truth()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.supports_revocation IS DISTINCT FROM OLD.supports_revocation
       AND NOT (
           OLD.supports_revocation
           AND NOT NEW.supports_revocation
           AND OLD.status = 'awaiting_provider_start'
           AND NEW.status = 'provider_authorization_started'
       ) THEN
        RAISE EXCEPTION 'managed reauthorization revocation truth may only narrow at provider start'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER managed_reauthorization_bounded_revocation_truth
BEFORE UPDATE OF supports_revocation ON managed_provider_reauthorization_interactions
FOR EACH ROW
EXECUTE FUNCTION owlauth_validate_managed_reauthorization_revocation_truth();

CREATE FUNCTION owlauth_reject_managed_reauthorization_deadline_extension()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.expires_at > OLD.expires_at THEN
        RAISE EXCEPTION 'managed reauthorization deadline cannot be extended'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER managed_reauthorization_bounded_deadline
BEFORE UPDATE OF expires_at ON managed_provider_reauthorization_interactions
FOR EACH ROW
EXECUTE FUNCTION owlauth_reject_managed_reauthorization_deadline_extension();

-- A merged binding remains as immutable credential attribution when both users already had a
-- binding for one Application. A binding moved to the winner keeps its first-delivery timestamp.
ALTER TABLE application_user_bindings
    DROP CONSTRAINT application_user_bindings_status_check,
    ADD COLUMN merged_into_binding_id UUID,
    ADD COLUMN merged_at TIMESTAMPTZ,
    ADD CONSTRAINT application_user_bindings_status_check CHECK (
        status IN ('active', 'disabled', 'merged')
    ),
    ADD CONSTRAINT application_user_bindings_merge_shape_check CHECK (
        (status = 'merged'
            AND merged_into_binding_id IS NOT NULL
            AND merged_into_binding_id <> id
            AND merged_at IS NOT NULL)
        OR (status <> 'merged'
            AND merged_into_binding_id IS NULL
            AND merged_at IS NULL)
    ),
    ADD CONSTRAINT application_user_bindings_project_id_id_application_unique
        UNIQUE (project_id, id, application_id),
    ADD CONSTRAINT application_user_bindings_merged_into_fk
        FOREIGN KEY (project_id, merged_into_binding_id, application_id)
        REFERENCES application_user_bindings (project_id, id, application_id)
        DEFERRABLE INITIALLY DEFERRED;

CREATE FUNCTION owlauth_reject_merged_binding_reopen()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    prior_target application_user_bindings%ROWTYPE;
BEGIN
    IF (NEW.id, NEW.project_id, NEW.application_id, NEW.created_at)
        IS DISTINCT FROM
        (OLD.id, OLD.project_id, OLD.application_id, OLD.created_at)
    THEN
        RAISE EXCEPTION 'Application binding identity and first-delivery time are immutable'
            USING ERRCODE = '23514';
    END IF;
    IF NEW.status = 'merged' AND NEW.user_id IS DISTINCT FROM OLD.user_id THEN
        RAISE EXCEPTION 'merged Application binding must retain its historical owner'
            USING ERRCODE = '23514';
    END IF;
    IF OLD.status = 'merged'
        AND (NEW.status, NEW.merged_at)
            IS DISTINCT FROM
            (OLD.status, OLD.merged_at)
    THEN
        RAISE EXCEPTION 'merged Application binding cannot be reopened'
            USING ERRCODE = '23514';
    END IF;
    IF OLD.status = 'merged'
        AND NEW.merged_into_binding_id IS DISTINCT FROM OLD.merged_into_binding_id
    THEN
        SELECT * INTO prior_target
          FROM application_user_bindings
         WHERE project_id = OLD.project_id
           AND id = OLD.merged_into_binding_id
           AND application_id = OLD.application_id;
        IF NOT FOUND
            OR prior_target.status <> 'merged'
            OR prior_target.merged_into_binding_id
                IS DISTINCT FROM NEW.merged_into_binding_id
        THEN
            RAISE EXCEPTION 'merged Application binding lineage may only be flattened'
                USING ERRCODE = '23514';
        END IF;
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER application_user_bindings_merged_terminal
BEFORE UPDATE ON application_user_bindings
FOR EACH ROW
EXECUTE FUNCTION owlauth_reject_merged_binding_reopen();

CREATE FUNCTION owlauth_enforce_merged_binding_target()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    current_binding application_user_bindings%ROWTYPE;
    retained_binding application_user_bindings%ROWTYPE;
    source_user project_users%ROWTYPE;
BEGIN
    -- Binding lineage participates in the same user/identity graph as a merge. A later committer
    -- must observe the earlier committed winner and owner state.
    PERFORM owlauth_lock_project_identity_graph(NEW.project_id);
    SELECT * INTO current_binding
      FROM application_user_bindings
     WHERE project_id = NEW.project_id AND id = NEW.id;
    IF NOT FOUND THEN
        RETURN NULL;
    END IF;
    IF current_binding.status = 'merged' THEN
        SELECT * INTO STRICT retained_binding
          FROM application_user_bindings
         WHERE project_id = current_binding.project_id
           AND id = current_binding.merged_into_binding_id
           AND application_id = current_binding.application_id;
        SELECT * INTO STRICT source_user
          FROM project_users
         WHERE project_id = current_binding.project_id
           AND id = current_binding.user_id;
        IF retained_binding.status = 'merged'
            OR retained_binding.merged_into_binding_id IS NOT NULL
            OR retained_binding.user_id = current_binding.user_id
            OR source_user.status <> 'merged'
            OR source_user.merged_into_user_id IS DISTINCT FROM retained_binding.user_id
        THEN
            RAISE EXCEPTION
                'merged Application binding must target its Project-user merge winner'
                USING ERRCODE = '23514';
        END IF;
    END IF;
    IF current_binding.status = 'merged'
        AND EXISTS (
            SELECT 1 FROM application_user_bindings
             WHERE project_id = current_binding.project_id
               AND merged_into_binding_id = current_binding.id
        )
    THEN
        RAISE EXCEPTION 'merged Application binding cannot itself be a merge target'
            USING ERRCODE = '23514';
    END IF;
    RETURN NULL;
END
$$;

CREATE CONSTRAINT TRIGGER application_user_bindings_exact_merge_target
AFTER INSERT OR UPDATE OF status, user_id, merged_into_binding_id
ON application_user_bindings
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
EXECUTE FUNCTION owlauth_enforce_merged_binding_target();

CREATE FUNCTION owlauth_enforce_merged_user_binding_ownership()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    target_project_id UUID;
    old_user_id UUID;
    new_user_id UUID;
BEGIN
    IF TG_TABLE_NAME = 'project_users' THEN
        target_project_id := NEW.project_id;
        old_user_id := NEW.id;
        new_user_id := NEW.id;
    ELSE
        target_project_id := CASE WHEN TG_OP = 'DELETE' THEN OLD.project_id ELSE NEW.project_id END;
        old_user_id := CASE WHEN TG_OP IN ('UPDATE', 'DELETE') THEN OLD.user_id END;
        new_user_id := CASE WHEN TG_OP IN ('INSERT', 'UPDATE') THEN NEW.user_id END;
    END IF;

    PERFORM owlauth_lock_project_identity_graph(target_project_id);
    IF EXISTS (
        SELECT 1
          FROM project_users AS project_user
          JOIN application_user_bindings AS binding
            ON binding.project_id = project_user.project_id
           AND binding.user_id = project_user.id
         WHERE project_user.project_id = target_project_id
           AND project_user.id IN (old_user_id, new_user_id)
           AND project_user.status = 'merged'
           AND binding.status <> 'merged'
    ) THEN
        RAISE EXCEPTION 'merged Project user cannot own a live Application binding'
            USING ERRCODE = '23514';
    END IF;

    RETURN NULL;
END
$$;

CREATE CONSTRAINT TRIGGER project_users_no_live_binding_after_merge
AFTER INSERT OR UPDATE OF status, merged_into_user_id ON project_users
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
EXECUTE FUNCTION owlauth_enforce_merged_user_binding_ownership();

CREATE CONSTRAINT TRIGGER application_user_bindings_exact_merged_user
AFTER INSERT OR UPDATE OF status, user_id, merged_into_binding_id OR DELETE
ON application_user_bindings
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
EXECUTE FUNCTION owlauth_enforce_merged_user_binding_ownership();

CREATE FUNCTION owlauth_reject_merged_binding_delete()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF OLD.status = 'merged'
        AND EXISTS (SELECT 1 FROM projects WHERE id = OLD.project_id)
    THEN
        RAISE EXCEPTION 'merged Application binding attribution cannot be deleted'
            USING ERRCODE = '23514';
    END IF;
    RETURN OLD;
END
$$;

CREATE TRIGGER application_user_bindings_preserve_merged_attribution
BEFORE DELETE ON application_user_bindings
FOR EACH ROW
EXECUTE FUNCTION owlauth_reject_merged_binding_delete();

-- Discover the two generated four-column foreign keys by their ordered column sets. Their
-- PostgreSQL-generated names may be identifier-truncated and must not be guessed.
DO $$
DECLARE
    projection_constraint_name TEXT;
    session_constraint_name TEXT;
BEGIN
    SELECT constraint_row.conname
      INTO STRICT projection_constraint_name
      FROM pg_constraint AS constraint_row
     WHERE constraint_row.contype = 'f'
       AND constraint_row.conrelid = 'application_user_projections'::regclass
       AND constraint_row.confrelid = 'application_user_bindings'::regclass
       AND ARRAY(
           SELECT attribute.attname::TEXT
             FROM unnest(constraint_row.conkey) WITH ORDINALITY AS key_column(attnum, ordinal)
             JOIN pg_attribute AS attribute
               ON attribute.attrelid = constraint_row.conrelid
              AND attribute.attnum = key_column.attnum
            ORDER BY key_column.ordinal
       ) = ARRAY['project_id','binding_id','application_id','user_id']::TEXT[]
       AND ARRAY(
           SELECT attribute.attname::TEXT
             FROM unnest(constraint_row.confkey) WITH ORDINALITY AS key_column(attnum, ordinal)
             JOIN pg_attribute AS attribute
               ON attribute.attrelid = constraint_row.confrelid
              AND attribute.attnum = key_column.attnum
            ORDER BY key_column.ordinal
       ) = ARRAY['project_id','id','application_id','user_id']::TEXT[];

    SELECT constraint_row.conname
      INTO STRICT session_constraint_name
      FROM pg_constraint AS constraint_row
     WHERE constraint_row.contype = 'f'
       AND constraint_row.conrelid = 'application_sessions'::regclass
       AND constraint_row.confrelid = 'application_user_bindings'::regclass
       AND ARRAY(
           SELECT attribute.attname::TEXT
             FROM unnest(constraint_row.conkey) WITH ORDINALITY AS key_column(attnum, ordinal)
             JOIN pg_attribute AS attribute
               ON attribute.attrelid = constraint_row.conrelid
              AND attribute.attnum = key_column.attnum
            ORDER BY key_column.ordinal
       ) = ARRAY['project_id','binding_id','application_id','user_id']::TEXT[]
       AND ARRAY(
           SELECT attribute.attname::TEXT
             FROM unnest(constraint_row.confkey) WITH ORDINALITY AS key_column(attnum, ordinal)
             JOIN pg_attribute AS attribute
               ON attribute.attrelid = constraint_row.confrelid
              AND attribute.attnum = key_column.attnum
            ORDER BY key_column.ordinal
       ) = ARRAY['project_id','id','application_id','user_id']::TEXT[];

    EXECUTE format(
        'ALTER TABLE application_user_projections DROP CONSTRAINT %I',
        projection_constraint_name
    );
    EXECUTE format(
        'ALTER TABLE application_sessions DROP CONSTRAINT %I',
        session_constraint_name
    );
END
$$;

ALTER TABLE application_user_projections
    ADD CONSTRAINT application_user_projections_verified_email_source_fk
        FOREIGN KEY (project_id, verified_email_source_identity_id, user_id)
        REFERENCES email_identities (project_id, id, user_id)
        DEFERRABLE INITIALLY DEFERRED,
    ADD CONSTRAINT application_user_projections_binding_owner_fk
    FOREIGN KEY (project_id, binding_id, application_id, user_id)
    REFERENCES application_user_bindings (project_id, id, application_id, user_id)
    ON DELETE CASCADE
    DEFERRABLE INITIALLY DEFERRED;

-- application_sessions.user_id is the immutable credential owner. It deliberately no longer
-- follows the binding's current owner after a merge.
ALTER TABLE application_sessions
    ADD CONSTRAINT application_sessions_binding_identity_fk
        FOREIGN KEY (project_id, binding_id, application_id)
        REFERENCES application_user_bindings (project_id, id, application_id),
    ADD CONSTRAINT application_sessions_credential_user_fk
        FOREIGN KEY (project_id, user_id)
        REFERENCES project_users (project_id, id);

CREATE FUNCTION owlauth_validate_application_session_original_binding_owner()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    binding_user_id UUID;
BEGIN
    SELECT user_id INTO STRICT binding_user_id
      FROM application_user_bindings
     WHERE project_id = NEW.project_id
       AND id = NEW.binding_id
       AND application_id = NEW.application_id
     FOR SHARE;
    IF binding_user_id <> NEW.user_id THEN
        RAISE EXCEPTION 'Application session must capture the binding original owner'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER application_sessions_capture_original_binding_owner
BEFORE INSERT ON application_sessions
FOR EACH ROW
EXECUTE FUNCTION owlauth_validate_application_session_original_binding_owner();

CREATE TRIGGER application_sessions_stable_credential_owner
BEFORE UPDATE ON application_sessions
FOR EACH ROW
EXECUTE FUNCTION reject_immutable_column_change(
    'id', 'project_id', 'application_id', 'binding_id', 'user_id', 'created_at'
);

CREATE TABLE identity_mutation_intents (
    id UUID PRIMARY KEY,
    project_id UUID NOT NULL,
    operation_kind TEXT NOT NULL CHECK (operation_kind IN ('link', 'unlink', 'merge')),
    status TEXT NOT NULL CHECK (
        status IN ('pending_proof', 'ready', 'completed', 'expired', 'cancelled')
    ),
    intent_revision BIGINT NOT NULL DEFAULT 1 CHECK (intent_revision > 0),
    project_metadata_revision BIGINT NOT NULL CHECK (project_metadata_revision > 0),
    project_security_revision BIGINT NOT NULL CHECK (project_security_revision > 0),
    destination_user_id UUID,
    destination_user_revision BIGINT,
    destination_user_security_revision BIGINT,
    identity_owner_user_id UUID,
    identity_owner_user_revision BIGINT,
    identity_owner_user_security_revision BIGINT,
    winner_user_id UUID,
    winner_user_revision BIGINT,
    winner_user_security_revision BIGINT,
    loser_user_id UUID,
    loser_user_revision BIGINT,
    loser_user_security_revision BIGINT,
    primary_source_disposition TEXT NOT NULL CHECK (
        primary_source_disposition IN ('preserve', 'provider', 'email', 'clear')
    ),
    primary_provider_identity_id UUID,
    primary_email_identity_id UUID,
    primary_source_identity_revision BIGINT CHECK (
        primary_source_identity_revision IS NULL OR primary_source_identity_revision > 0
    ),
    sessions_disposition TEXT CHECK (
        sessions_disposition IS NULL OR sessions_disposition = 'loser_revoked'
    ),
    bindings_disposition TEXT CHECK (
        bindings_disposition IS NULL OR bindings_disposition = 'winner_preferred'
    ),
    hosted_handle_digest BYTEA NOT NULL CHECK (octet_length(hosted_handle_digest) = 32),
    hosted_handle_digest_key_version INTEGER NOT NULL CHECK (
        hosted_handle_digest_key_version > 0
    ),
    browser_binding_digest BYTEA,
    browser_binding_digest_key_version INTEGER,
    csrf_digest BYTEA,
    csrf_digest_key_version INTEGER,
    browser_binding_revision BIGINT NOT NULL DEFAULT 0 CHECK (browser_binding_revision >= 0),
    correlation_id UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    expires_at TIMESTAMPTZ NOT NULL,
    ready_at TIMESTAMPTZ,
    terminal_at TIMESTAMPTZ,
    FOREIGN KEY (project_id) REFERENCES projects (id) ON DELETE CASCADE,
    FOREIGN KEY (project_id, destination_user_id)
        REFERENCES project_users (project_id, id),
    FOREIGN KEY (project_id, identity_owner_user_id)
        REFERENCES project_users (project_id, id),
    FOREIGN KEY (project_id, winner_user_id)
        REFERENCES project_users (project_id, id),
    FOREIGN KEY (project_id, loser_user_id)
        REFERENCES project_users (project_id, id),
    FOREIGN KEY (project_id, primary_provider_identity_id)
        REFERENCES linked_identities (project_id, id),
    FOREIGN KEY (project_id, primary_email_identity_id)
        REFERENCES email_identities (project_id, id),
    UNIQUE (project_id, id),
    UNIQUE (hosted_handle_digest_key_version, hosted_handle_digest),
    CHECK (expires_at > created_at AND expires_at <= created_at + INTERVAL '10 minutes'),
    CHECK (
        (browser_binding_digest IS NULL) = (browser_binding_digest_key_version IS NULL)
        AND (csrf_digest IS NULL) = (csrf_digest_key_version IS NULL)
        AND (browser_binding_digest IS NULL) = (csrf_digest IS NULL)
        AND (browser_binding_digest IS NULL OR (
            octet_length(browser_binding_digest) = 32
            AND browser_binding_digest_key_version > 0
            AND octet_length(csrf_digest) = 32
            AND csrf_digest_key_version > 0
            AND browser_binding_revision > 0
        ))
    ),
    CHECK (
        (status = 'pending_proof' AND ready_at IS NULL AND terminal_at IS NULL)
        OR (status = 'ready' AND ready_at IS NOT NULL AND terminal_at IS NULL)
        OR (status = 'completed' AND ready_at IS NOT NULL AND terminal_at IS NOT NULL)
        OR (status IN ('expired', 'cancelled') AND terminal_at IS NOT NULL)
    ),
    CHECK (ready_at IS NULL OR (ready_at >= created_at AND ready_at < expires_at)),
    CHECK (terminal_at IS NULL OR terminal_at >= created_at),
    CHECK (status <> 'completed' OR terminal_at >= ready_at),
    CHECK (
        (primary_source_disposition = 'provider'
            AND primary_provider_identity_id IS NOT NULL
            AND primary_email_identity_id IS NULL
            AND primary_source_identity_revision > 0)
        OR (primary_source_disposition = 'email'
            AND primary_provider_identity_id IS NULL
            AND primary_email_identity_id IS NOT NULL
            AND primary_source_identity_revision > 0)
        OR (primary_source_disposition IN ('preserve', 'clear')
            AND primary_provider_identity_id IS NULL
            AND primary_email_identity_id IS NULL
            AND primary_source_identity_revision IS NULL)
    ),
    CHECK ((
        (operation_kind = 'link'
            AND destination_user_id IS NOT NULL
            AND destination_user_revision > 0
            AND destination_user_security_revision > 0
            AND identity_owner_user_id IS NULL
            AND identity_owner_user_revision IS NULL
            AND identity_owner_user_security_revision IS NULL
            AND winner_user_id IS NULL
            AND winner_user_revision IS NULL
            AND winner_user_security_revision IS NULL
            AND loser_user_id IS NULL
            AND loser_user_revision IS NULL
            AND loser_user_security_revision IS NULL
            AND primary_source_disposition = 'preserve'
            AND sessions_disposition IS NULL
            AND bindings_disposition IS NULL)
        OR (operation_kind = 'unlink'
            AND destination_user_id IS NULL
            AND destination_user_revision IS NULL
            AND destination_user_security_revision IS NULL
            AND identity_owner_user_id IS NOT NULL
            AND identity_owner_user_revision > 0
            AND identity_owner_user_security_revision > 0
            AND winner_user_id IS NULL
            AND winner_user_revision IS NULL
            AND winner_user_security_revision IS NULL
            AND loser_user_id IS NULL
            AND loser_user_revision IS NULL
            AND loser_user_security_revision IS NULL
            AND sessions_disposition IS NULL
            AND bindings_disposition IS NULL)
        OR (operation_kind = 'merge'
            AND destination_user_id IS NULL
            AND destination_user_revision IS NULL
            AND destination_user_security_revision IS NULL
            AND identity_owner_user_id IS NULL
            AND identity_owner_user_revision IS NULL
            AND identity_owner_user_security_revision IS NULL
            AND winner_user_id IS NOT NULL
            AND winner_user_revision > 0
            AND winner_user_security_revision > 0
            AND loser_user_id IS NOT NULL
            AND loser_user_revision > 0
            AND loser_user_security_revision > 0
            AND winner_user_id <> loser_user_id
            AND primary_source_disposition IN ('provider', 'email')
            AND sessions_disposition = 'loser_revoked'
            AND bindings_disposition = 'winner_preferred')
    ) IS TRUE)
);

CREATE FUNCTION owlauth_validate_identity_mutation_primary_source_owner()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    source_user_id UUID;
    source_identity_revision BIGINT;
BEGIN
    IF NEW.primary_provider_identity_id IS NOT NULL THEN
        SELECT user_id, identity_revision INTO source_user_id, source_identity_revision
          FROM linked_identities
         WHERE project_id = NEW.project_id
           AND id = NEW.primary_provider_identity_id
           AND status = 'active';
    ELSIF NEW.primary_email_identity_id IS NOT NULL THEN
        SELECT user_id, identity_revision INTO source_user_id, source_identity_revision
          FROM email_identities
         WHERE project_id = NEW.project_id
           AND id = NEW.primary_email_identity_id
           AND status = 'active';
    ELSE
        RETURN NEW;
    END IF;

    IF source_user_id IS NULL
        OR source_identity_revision IS DISTINCT FROM NEW.primary_source_identity_revision
        OR (NEW.operation_kind = 'unlink'
            AND source_user_id <> NEW.identity_owner_user_id)
        OR (NEW.operation_kind = 'merge'
            AND source_user_id <> NEW.winner_user_id
            AND source_user_id <> NEW.loser_user_id)
        OR NEW.operation_kind = 'link'
    THEN
        RAISE EXCEPTION 'identity-mutation primary source has the wrong frozen owner'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER identity_mutation_intents_primary_source_owner
BEFORE INSERT ON identity_mutation_intents
FOR EACH ROW
EXECUTE FUNCTION owlauth_validate_identity_mutation_primary_source_owner();

CREATE INDEX identity_mutation_intents_cleanup_idx
    ON identity_mutation_intents (status, expires_at, id)
    WHERE status IN ('pending_proof', 'ready');
CREATE INDEX identity_mutation_intents_project_users_idx
    ON identity_mutation_intents
       (project_id, destination_user_id, identity_owner_user_id, winner_user_id,
        loser_user_id, status);

CREATE TRIGGER identity_mutation_intents_stable_authority
BEFORE UPDATE ON identity_mutation_intents
FOR EACH ROW
EXECUTE FUNCTION reject_immutable_column_change(
    'project_id', 'operation_kind', 'project_metadata_revision',
    'project_security_revision', 'destination_user_id', 'destination_user_revision',
    'destination_user_security_revision', 'identity_owner_user_id',
    'identity_owner_user_revision', 'identity_owner_user_security_revision',
    'winner_user_id', 'winner_user_revision', 'winner_user_security_revision',
    'loser_user_id', 'loser_user_revision', 'loser_user_security_revision',
    'primary_source_disposition', 'primary_provider_identity_id',
    'primary_email_identity_id', 'primary_source_identity_revision',
    'sessions_disposition', 'bindings_disposition',
    'hosted_handle_digest', 'hosted_handle_digest_key_version', 'correlation_id',
    'created_at', 'expires_at'
);

CREATE FUNCTION owlauth_enforce_identity_mutation_intent_transition()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.status <> 'pending_proof'
            OR NEW.intent_revision <> 1
            OR NEW.browser_binding_digest IS NOT NULL
            OR NEW.browser_binding_digest_key_version IS NOT NULL
            OR NEW.csrf_digest IS NOT NULL
            OR NEW.csrf_digest_key_version IS NOT NULL
            OR NEW.browser_binding_revision <> 0
            OR NEW.ready_at IS NOT NULL
            OR NEW.terminal_at IS NOT NULL
        THEN
            RAISE EXCEPTION 'identity-mutation intent must start unbound and pending at revision one'
                USING ERRCODE = '23514';
        END IF;
        RETURN NEW;
    END IF;
    IF NEW.intent_revision <= OLD.intent_revision THEN
        RAISE EXCEPTION 'identity-mutation intent revision must advance'
            USING ERRCODE = '23514';
    END IF;
    IF (OLD.ready_at IS NOT NULL AND NEW.ready_at IS DISTINCT FROM OLD.ready_at)
        OR (OLD.terminal_at IS NOT NULL AND NEW.terminal_at IS DISTINCT FROM OLD.terminal_at)
    THEN
        RAISE EXCEPTION 'identity-mutation lifecycle timestamps are write-once'
            USING ERRCODE = '23514';
    END IF;
    IF (NEW.browser_binding_digest, NEW.browser_binding_digest_key_version,
        NEW.csrf_digest, NEW.csrf_digest_key_version, NEW.browser_binding_revision)
        IS DISTINCT FROM
       (OLD.browser_binding_digest, OLD.browser_binding_digest_key_version,
        OLD.csrf_digest, OLD.csrf_digest_key_version, OLD.browser_binding_revision)
    THEN
        IF OLD.browser_binding_digest IS NOT NULL
            OR OLD.csrf_digest IS NOT NULL
            OR OLD.browser_binding_revision <> 0
            OR NEW.browser_binding_digest IS NULL
            OR NEW.csrf_digest IS NULL
            OR NEW.browser_binding_revision <> 1
            OR OLD.status <> 'pending_proof'
            OR NEW.status <> 'pending_proof'
            OR EXISTS (
                SELECT 1 FROM identity_mutation_proof_slots
                 WHERE project_id = OLD.project_id AND intent_id = OLD.id
                   AND state <> 'pending'
            )
            OR EXISTS (
                SELECT 1 FROM identity_proof_receipts
                 WHERE project_id = OLD.project_id AND intent_id = OLD.id
            )
        THEN
            RAISE EXCEPTION 'identity-mutation browser and CSRF authority is bind-once'
                USING ERRCODE = '23514';
        END IF;
    END IF;
    IF NOT (
        NEW.status = OLD.status
        OR (OLD.status = 'pending_proof' AND NEW.status IN ('ready','expired','cancelled'))
        OR (OLD.status = 'ready' AND NEW.status IN ('completed','expired','cancelled'))
    ) THEN
        RAISE EXCEPTION 'invalid identity-mutation intent status transition'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER identity_mutation_intents_one_way_state
BEFORE INSERT OR UPDATE ON identity_mutation_intents
FOR EACH ROW
EXECUTE FUNCTION owlauth_enforce_identity_mutation_intent_transition();

CREATE FUNCTION owlauth_valid_identity_proof_scopes(scopes TEXT[])
RETURNS BOOLEAN
LANGUAGE SQL
IMMUTABLE
STRICT
AS $$
    SELECT array_ndims(scopes) = 1
       AND array_lower(scopes, 1) = 1
       AND cardinality(scopes) BETWEEN 1 AND 16
       AND array_position(scopes, NULL) IS NULL
       AND cardinality(scopes) = (
           SELECT count(DISTINCT scope)::INTEGER FROM unnest(scopes) AS scope
       )
       AND NOT EXISTS (
           SELECT 1
             FROM unnest(scopes) AS scope
            WHERE octet_length(scope) NOT BETWEEN 1 AND 128
               OR scope = 'offline_access'
               OR EXISTS (
                   SELECT 1
                     FROM generate_series(0, octet_length(scope) - 1) AS byte_index
                    WHERE NOT (
                        get_byte(convert_to(scope, 'UTF8'), byte_index) = 33
                        OR get_byte(convert_to(scope, 'UTF8'), byte_index) BETWEEN 35 AND 91
                        OR get_byte(convert_to(scope, 'UTF8'), byte_index) BETWEEN 93 AND 126
                    )
               )
       )
$$;

CREATE TABLE identity_mutation_proof_slots (
    id UUID PRIMARY KEY,
    project_id UUID NOT NULL,
    intent_id UUID NOT NULL,
    slot_ordinal SMALLINT NOT NULL CHECK (slot_ordinal BETWEEN 1 AND 2),
    slot_role TEXT NOT NULL CHECK (
        slot_role IN ('destination_owner', 'candidate_identity', 'identity_owner',
                      'winner_owner', 'loser_owner')
    ),
    purpose TEXT NOT NULL CHECK (
        purpose IN ('link.destination_owner', 'link.candidate_identity',
                    'unlink.identity_owner', 'merge.winner_owner', 'merge.loser_owner')
    ),
    identity_kind TEXT NOT NULL CHECK (identity_kind IN ('provider', 'email')),
    proof_user_id UUID NOT NULL,
    expected_user_revision BIGINT NOT NULL CHECK (expected_user_revision > 0),
    expected_user_security_revision BIGINT NOT NULL CHECK (
        expected_user_security_revision > 0
    ),
    existing_provider_identity_id UUID,
    existing_email_identity_id UUID,
    expected_identity_revision BIGINT,
    application_id UUID NOT NULL,
    application_security_revision BIGINT NOT NULL CHECK (
        application_security_revision > 0
    ),
    method_kind TEXT NOT NULL CHECK (method_kind IN ('provider', 'email')),
    provider_adapter_key TEXT,
    provider_adapter_capability_revision BIGINT,
    provider_configuration_id UUID,
    provider_revision BIGINT,
    provider_assignment_security_revision BIGINT,
    provider_scopes TEXT[],
    callback_url TEXT,
    provider_pkce_required BOOLEAN,
    oidc_nonce_required BOOLEAN,
    email_assignment_application_id UUID,
    email_policy_revision BIGINT,
    email_security_revision BIGINT,
    email_assignment_security_revision BIGINT,
    state TEXT NOT NULL CHECK (
        state IN ('pending', 'provider_authorization_started',
                  'provider_exchange_in_progress', 'provider_exchange_failed',
                  'email_address_entry', 'email_challenge_pending', 'proved', 'expired')
    ),
    slot_revision BIGINT NOT NULL DEFAULT 1 CHECK (slot_revision > 0),
    upstream_state_digest BYTEA,
    upstream_state_digest_key_version INTEGER,
    provider_pkce_ciphertext BYTEA,
    provider_pkce_key_version INTEGER,
    oidc_nonce_digest BYTEA,
    oidc_nonce_digest_key_version INTEGER,
    callback_continuation_ciphertext BYTEA,
    callback_continuation_key_version INTEGER,
    provider_started_at TIMESTAMPTZ,
    exchange_claimed_at TIMESTAMPTZ,
    proved_at TIMESTAMPTZ,
    terminal_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    FOREIGN KEY (project_id, intent_id)
        REFERENCES identity_mutation_intents (project_id, id) ON DELETE CASCADE,
    FOREIGN KEY (project_id, proof_user_id)
        REFERENCES project_users (project_id, id),
    FOREIGN KEY (project_id, existing_provider_identity_id)
        REFERENCES linked_identities (project_id, id),
    FOREIGN KEY (project_id, existing_email_identity_id)
        REFERENCES email_identities (project_id, id),
    FOREIGN KEY (project_id, application_id)
        REFERENCES applications (project_id, id),
    FOREIGN KEY (project_id, provider_configuration_id)
        REFERENCES provider_configurations (project_id, id),
    FOREIGN KEY (project_id, application_id, provider_configuration_id)
        REFERENCES application_provider_assignments (project_id, application_id, provider_id),
    FOREIGN KEY (project_id, email_assignment_application_id)
        REFERENCES application_email_assignments (project_id, application_id),
    UNIQUE (project_id, id),
    UNIQUE (project_id, intent_id, id),
    UNIQUE (project_id, intent_id, slot_ordinal),
    UNIQUE (project_id, intent_id, slot_role),
    CHECK ((
        (slot_role = 'candidate_identity'
            AND existing_provider_identity_id IS NULL
            AND existing_email_identity_id IS NULL
            AND expected_identity_revision IS NULL)
        OR (slot_role <> 'candidate_identity'
            AND expected_identity_revision > 0
            AND ((identity_kind = 'provider'
                    AND existing_provider_identity_id IS NOT NULL
                    AND existing_email_identity_id IS NULL)
                OR (identity_kind = 'email'
                    AND existing_provider_identity_id IS NULL
                    AND existing_email_identity_id IS NOT NULL)))
    ) IS TRUE),
    CHECK ((
        (method_kind = 'provider'
            AND identity_kind = 'provider'
            AND provider_adapter_key IS NOT NULL
            AND octet_length(provider_adapter_key) BETWEEN 1 AND 64
            AND provider_adapter_capability_revision > 0
            AND provider_configuration_id IS NOT NULL
            AND provider_revision > 0
            AND provider_assignment_security_revision > 0
            AND owlauth_valid_identity_proof_scopes(provider_scopes)
            AND callback_url IS NOT NULL
            AND char_length(callback_url) BETWEEN 8 AND 2048
            AND provider_pkce_required IS NOT NULL
            AND oidc_nonce_required = TRUE
            AND email_assignment_application_id IS NULL
            AND email_policy_revision IS NULL
            AND email_security_revision IS NULL
            AND email_assignment_security_revision IS NULL)
        OR (method_kind = 'email'
            AND identity_kind = 'email'
            AND provider_adapter_key IS NULL
            AND provider_adapter_capability_revision IS NULL
            AND provider_configuration_id IS NULL
            AND provider_revision IS NULL
            AND provider_assignment_security_revision IS NULL
            AND provider_scopes IS NULL
            AND callback_url IS NULL
            AND provider_pkce_required IS NULL
            AND oidc_nonce_required IS NULL
            AND email_assignment_application_id = application_id
            AND email_policy_revision > 0
            AND email_security_revision > 0
            AND email_assignment_security_revision > 0)
    ) IS TRUE),
    CHECK (
        (upstream_state_digest IS NULL) = (upstream_state_digest_key_version IS NULL)
        AND (upstream_state_digest IS NULL OR (
            octet_length(upstream_state_digest) = 32
            AND upstream_state_digest_key_version > 0
        ))
    ),
    CHECK (
        (provider_pkce_ciphertext IS NULL) = (provider_pkce_key_version IS NULL)
        AND (provider_pkce_ciphertext IS NULL OR (
            state IN ('provider_authorization_started', 'provider_exchange_in_progress')
            AND octet_length(provider_pkce_ciphertext) BETWEEN 17 AND 4096
            AND provider_pkce_key_version > 0
        ))
    ),
    CHECK (
        (oidc_nonce_digest IS NULL) = (oidc_nonce_digest_key_version IS NULL)
        AND (oidc_nonce_digest IS NULL OR (
            octet_length(oidc_nonce_digest) = 32
            AND oidc_nonce_digest_key_version > 0
        ))
    ),
    CHECK (
        (callback_continuation_ciphertext IS NULL)
            = (callback_continuation_key_version IS NULL)
        AND (callback_continuation_ciphertext IS NULL OR (
            octet_length(callback_continuation_ciphertext) BETWEEN 41 AND 4096
            AND callback_continuation_key_version > 0
        ))
    ),
    CHECK (
        (state IN ('provider_authorization_started', 'provider_exchange_in_progress'))
            = (callback_continuation_ciphertext IS NOT NULL)
    ),
    CHECK (
        state NOT IN ('provider_authorization_started', 'provider_exchange_in_progress')
        OR (method_kind = 'provider'
            AND upstream_state_digest IS NOT NULL
            AND oidc_nonce_digest IS NOT NULL
            AND provider_started_at IS NOT NULL
            AND provider_pkce_required
                = (provider_pkce_ciphertext IS NOT NULL))
    ),
    CHECK ((state = 'provider_exchange_in_progress') = (exchange_claimed_at IS NOT NULL)),
    CHECK ((state = 'proved') = (proved_at IS NOT NULL)),
    CHECK ((state IN ('provider_exchange_failed', 'expired')) = (terminal_at IS NOT NULL))
);

CREATE FUNCTION owlauth_validate_identity_mutation_slot_original_owner()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.existing_provider_identity_id IS NOT NULL
        AND NOT EXISTS (
            SELECT 1 FROM linked_identities
             WHERE project_id = NEW.project_id
               AND id = NEW.existing_provider_identity_id
               AND user_id = NEW.proof_user_id
        )
    THEN
        RAISE EXCEPTION 'provider proof slot must capture the identity original owner'
            USING ERRCODE = '23514';
    END IF;
    IF NEW.existing_email_identity_id IS NOT NULL
        AND NOT EXISTS (
            SELECT 1 FROM email_identities
             WHERE project_id = NEW.project_id
               AND id = NEW.existing_email_identity_id
               AND user_id = NEW.proof_user_id
        )
    THEN
        RAISE EXCEPTION 'email proof slot must capture the identity original owner'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER identity_mutation_slots_capture_original_owner
BEFORE INSERT ON identity_mutation_proof_slots
FOR EACH ROW
EXECUTE FUNCTION owlauth_validate_identity_mutation_slot_original_owner();

CREATE INDEX identity_mutation_proof_slots_state_idx
    ON identity_mutation_proof_slots (project_id, intent_id, state, slot_ordinal);
CREATE UNIQUE INDEX identity_mutation_slots_upstream_state_unique_idx
    ON identity_mutation_proof_slots
       (upstream_state_digest_key_version, upstream_state_digest)
    WHERE upstream_state_digest IS NOT NULL;

CREATE TRIGGER identity_mutation_slots_stable_authority
BEFORE UPDATE ON identity_mutation_proof_slots
FOR EACH ROW
EXECUTE FUNCTION reject_immutable_column_change(
    'project_id', 'intent_id', 'slot_ordinal', 'slot_role', 'purpose', 'identity_kind',
    'proof_user_id', 'expected_user_revision', 'expected_user_security_revision',
    'existing_provider_identity_id', 'existing_email_identity_id',
    'expected_identity_revision', 'application_id', 'application_security_revision',
    'method_kind', 'provider_adapter_key', 'provider_adapter_capability_revision',
    'provider_configuration_id', 'provider_revision',
    'provider_assignment_security_revision', 'provider_scopes', 'callback_url',
    'provider_pkce_required', 'oidc_nonce_required', 'email_assignment_application_id',
    'email_policy_revision', 'email_security_revision',
    'email_assignment_security_revision', 'created_at'
);

CREATE FUNCTION owlauth_enforce_identity_mutation_slot_transition()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.state <> 'pending'
            OR NEW.slot_revision <> 1
            OR NEW.upstream_state_digest IS NOT NULL
            OR NEW.provider_pkce_ciphertext IS NOT NULL
            OR NEW.oidc_nonce_digest IS NOT NULL
            OR NEW.callback_continuation_ciphertext IS NOT NULL
            OR NEW.provider_started_at IS NOT NULL
            OR NEW.exchange_claimed_at IS NOT NULL
            OR NEW.proved_at IS NOT NULL
            OR NEW.terminal_at IS NOT NULL
        THEN
            RAISE EXCEPTION 'identity-mutation proof slot must start pending at revision one'
                USING ERRCODE = '23514';
        END IF;
        RETURN NEW;
    END IF;
    IF NEW.slot_revision <= OLD.slot_revision THEN
        RAISE EXCEPTION 'identity-mutation proof-slot revision must advance'
            USING ERRCODE = '23514';
    END IF;
    IF NEW.state = 'proved'
        AND (NEW.proved_at < transaction_timestamp()
            OR NEW.proved_at > clock_timestamp())
    THEN
        RAISE EXCEPTION 'identity-mutation proof timestamp must be current'
            USING ERRCODE = '23514';
    END IF;
    IF OLD.state = 'proved' AND NEW.state = 'proved'
        AND NEW.proved_at IS DISTINCT FROM OLD.proved_at
    THEN
        RAISE EXCEPTION 'identity-mutation proof timestamp is immutable'
            USING ERRCODE = '23514';
    END IF;
    IF OLD.state IN ('provider_authorization_started', 'provider_exchange_in_progress')
        AND NEW.state IN ('provider_authorization_started', 'provider_exchange_in_progress')
        AND (NEW.upstream_state_digest, NEW.upstream_state_digest_key_version,
             NEW.provider_pkce_ciphertext, NEW.provider_pkce_key_version,
             NEW.oidc_nonce_digest, NEW.oidc_nonce_digest_key_version,
             NEW.callback_continuation_ciphertext, NEW.callback_continuation_key_version,
             NEW.provider_started_at)
            IS DISTINCT FROM
            (OLD.upstream_state_digest, OLD.upstream_state_digest_key_version,
             OLD.provider_pkce_ciphertext, OLD.provider_pkce_key_version,
             OLD.oidc_nonce_digest, OLD.oidc_nonce_digest_key_version,
             OLD.callback_continuation_ciphertext, OLD.callback_continuation_key_version,
             OLD.provider_started_at)
    THEN
        RAISE EXCEPTION 'started identity-mutation provider proof authority is immutable'
            USING ERRCODE = '23514';
    END IF;
    IF NOT (
        NEW.state = OLD.state
        OR (OLD.state = 'pending'
            AND NEW.state IN ('provider_authorization_started','email_address_entry','expired'))
        OR (OLD.state = 'provider_authorization_started'
            AND NEW.state IN ('provider_exchange_in_progress','provider_exchange_failed','expired'))
        OR (OLD.state = 'provider_exchange_in_progress'
            AND NEW.state IN ('proved','provider_exchange_failed','expired'))
        OR (OLD.state = 'email_address_entry'
            AND NEW.state IN ('email_challenge_pending','expired'))
        OR (OLD.state = 'email_challenge_pending'
            AND NEW.state IN ('proved','expired'))
        OR (OLD.state <> 'expired' AND NEW.state = 'expired')
    ) THEN
        RAISE EXCEPTION 'invalid identity-mutation proof-slot state transition'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER identity_mutation_slots_one_way_state
BEFORE INSERT OR UPDATE ON identity_mutation_proof_slots
FOR EACH ROW
EXECUTE FUNCTION owlauth_enforce_identity_mutation_slot_transition();

CREATE FUNCTION owlauth_enforce_identity_mutation_slot_set()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    target_project_id UUID;
    target_intent_id UUID;
    current_intent identity_mutation_intents%ROWTYPE;
    actual_slot_count INTEGER;
    invalid_slot_count INTEGER;
    expected_slot_count INTEGER;
BEGIN
    IF TG_TABLE_NAME = 'identity_mutation_intents' THEN
        target_project_id := NEW.project_id;
        target_intent_id := NEW.id;
    ELSIF TG_OP = 'DELETE' THEN
        target_project_id := OLD.project_id;
        target_intent_id := OLD.intent_id;
    ELSE
        target_project_id := NEW.project_id;
        target_intent_id := NEW.intent_id;
    END IF;

    SELECT * INTO current_intent
      FROM identity_mutation_intents
     WHERE project_id = target_project_id
       AND id = target_intent_id;
    IF NOT FOUND THEN
        RETURN NULL;
    END IF;

    SELECT count(*)::INTEGER,
           (count(*) FILTER (WHERE (
               (current_intent.operation_kind = 'link'
                    AND ((slot_ordinal = 1 AND slot_role = 'destination_owner'
                          AND purpose = 'link.destination_owner'
                          AND proof_user_id = current_intent.destination_user_id
                          AND expected_user_revision = current_intent.destination_user_revision
                          AND expected_user_security_revision
                              = current_intent.destination_user_security_revision)
                      OR (slot_ordinal = 2 AND slot_role = 'candidate_identity'
                          AND purpose = 'link.candidate_identity'
                          AND proof_user_id = current_intent.destination_user_id
                          AND expected_user_revision = current_intent.destination_user_revision
                          AND expected_user_security_revision
                              = current_intent.destination_user_security_revision)))
               OR (current_intent.operation_kind = 'unlink'
                    AND slot_ordinal = 1 AND slot_role = 'identity_owner'
                    AND purpose = 'unlink.identity_owner'
                    AND proof_user_id = current_intent.identity_owner_user_id
                    AND expected_user_revision = current_intent.identity_owner_user_revision
                    AND expected_user_security_revision
                        = current_intent.identity_owner_user_security_revision)
               OR (current_intent.operation_kind = 'merge'
                    AND ((slot_ordinal = 1 AND slot_role = 'winner_owner'
                          AND purpose = 'merge.winner_owner'
                          AND proof_user_id = current_intent.winner_user_id
                          AND expected_user_revision = current_intent.winner_user_revision
                          AND expected_user_security_revision
                              = current_intent.winner_user_security_revision)
                      OR (slot_ordinal = 2 AND slot_role = 'loser_owner'
                          AND purpose = 'merge.loser_owner'
                          AND proof_user_id = current_intent.loser_user_id
                          AND expected_user_revision = current_intent.loser_user_revision
                          AND expected_user_security_revision
                              = current_intent.loser_user_security_revision)))
           ) IS NOT TRUE))::INTEGER
      INTO actual_slot_count, invalid_slot_count
      FROM identity_mutation_proof_slots
     WHERE project_id = current_intent.project_id
       AND intent_id = current_intent.id;

    expected_slot_count := CASE
        WHEN current_intent.operation_kind = 'unlink' THEN 1
        ELSE 2
    END;
    IF actual_slot_count <> expected_slot_count OR invalid_slot_count <> 0 THEN
        RAISE EXCEPTION 'identity-mutation intent has an incomplete or invalid proof-slot set'
            USING ERRCODE = '23514';
    END IF;
    IF current_intent.browser_binding_digest IS NULL
        AND EXISTS (
            SELECT 1 FROM identity_mutation_proof_slots
             WHERE project_id = current_intent.project_id
               AND intent_id = current_intent.id
               AND state NOT IN ('pending', 'expired')
        )
    THEN
        RAISE EXCEPTION 'identity-mutation proof cannot start before browser binding'
            USING ERRCODE = '23514';
    END IF;
    IF current_intent.status IN ('ready', 'completed')
        AND EXISTS (
            SELECT 1 FROM identity_mutation_proof_slots
             WHERE project_id = current_intent.project_id
               AND intent_id = current_intent.id
               AND state <> 'proved'
        )
    THEN
        RAISE EXCEPTION 'ready identity-mutation intent requires every proof slot proved'
            USING ERRCODE = '23514';
    END IF;
    IF EXISTS (
        SELECT 1
          FROM identity_mutation_proof_slots AS slot
          LEFT JOIN identity_proof_receipts AS receipt
            ON receipt.project_id = slot.project_id
           AND receipt.intent_id = slot.intent_id
           AND receipt.slot_id = slot.id
         WHERE slot.project_id = current_intent.project_id
           AND slot.intent_id = current_intent.id
           AND ((slot.state = 'proved' AND receipt.id IS NULL)
                OR (slot.state NOT IN ('proved', 'expired') AND receipt.id IS NOT NULL))
    ) THEN
        RAISE EXCEPTION 'identity-mutation proof-slot state requires exact receipt presence'
            USING ERRCODE = '23514';
    END IF;
    IF EXISTS (
        SELECT 1 FROM identity_proof_receipts AS receipt
         WHERE receipt.project_id = current_intent.project_id
           AND receipt.intent_id = current_intent.id
           AND (receipt.interaction_browser_binding_digest
                    IS DISTINCT FROM current_intent.browser_binding_digest
                OR receipt.interaction_browser_binding_digest_key_version
                    IS DISTINCT FROM current_intent.browser_binding_digest_key_version
                OR receipt.interaction_browser_binding_revision
                    IS DISTINCT FROM current_intent.browser_binding_revision
                OR receipt.captured_intent_revision >= current_intent.intent_revision
                OR receipt.expires_at > current_intent.expires_at)
    ) THEN
        RAISE EXCEPTION 'identity proof receipt no longer matches its exact intent snapshot'
            USING ERRCODE = '23514';
    END IF;
    IF current_intent.status IN ('pending_proof', 'ready')
        AND EXISTS (
            SELECT 1 FROM identity_proof_receipts
             WHERE project_id = current_intent.project_id
               AND intent_id = current_intent.id
               AND status <> 'issued'
        )
    THEN
        RAISE EXCEPTION 'live identity-mutation intent requires issued receipts'
            USING ERRCODE = '23514';
    END IF;
    IF current_intent.status NOT IN ('expired', 'cancelled')
        AND EXISTS (
            SELECT 1 FROM identity_mutation_proof_slots
             WHERE project_id = current_intent.project_id
               AND intent_id = current_intent.id
               AND state = 'expired'
        )
    THEN
        RAISE EXCEPTION 'expired proof slot requires a terminal identity-mutation intent'
            USING ERRCODE = '23514';
    END IF;
    IF current_intent.status = 'ready'
        AND (current_intent.ready_at >= current_intent.expires_at
            OR current_intent.ready_at < transaction_timestamp()
            OR current_intent.ready_at > clock_timestamp()
            OR clock_timestamp() >= current_intent.expires_at
            OR EXISTS (
                SELECT 1 FROM identity_proof_receipts
                 WHERE project_id = current_intent.project_id
                   AND intent_id = current_intent.id
                   AND (status <> 'issued'
                        OR current_intent.ready_at < issued_at
                        OR current_intent.ready_at >= expires_at
                        OR clock_timestamp() >= expires_at)
            ))
    THEN
        RAISE EXCEPTION 'ready identity-mutation intent requires fresh issued receipts'
            USING ERRCODE = '23514';
    END IF;
    IF current_intent.status = 'completed'
        AND (current_intent.terminal_at >= current_intent.expires_at
            OR current_intent.terminal_at < transaction_timestamp()
            OR current_intent.terminal_at > clock_timestamp()
            OR clock_timestamp() >= current_intent.expires_at
            OR EXISTS (
                SELECT 1 FROM identity_proof_receipts
                 WHERE project_id = current_intent.project_id
                   AND intent_id = current_intent.id
                   AND (status <> 'consumed'
                        OR current_intent.terminal_at < consumed_at
                        OR current_intent.terminal_at >= expires_at
                        OR clock_timestamp() >= expires_at)
            ))
    THEN
        RAISE EXCEPTION 'completed identity-mutation intent requires fresh consumed receipts'
            USING ERRCODE = '23514';
    END IF;
    IF current_intent.status IN ('expired', 'cancelled')
        AND (EXISTS (
                SELECT 1 FROM identity_mutation_proof_slots
                 WHERE project_id = current_intent.project_id
                   AND intent_id = current_intent.id
                   AND state <> 'expired'
            )
            OR EXISTS (
                SELECT 1 FROM identity_proof_receipts
                 WHERE project_id = current_intent.project_id
                   AND intent_id = current_intent.id
                   AND status <> 'expired'
            ))
    THEN
        RAISE EXCEPTION 'terminal identity-mutation intent requires expired slots and receipts'
            USING ERRCODE = '23514';
    END IF;
    RETURN NULL;
END
$$;

CREATE CONSTRAINT TRIGGER identity_mutation_intents_exact_slot_set
AFTER INSERT OR UPDATE OF operation_kind, status ON identity_mutation_intents
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
EXECUTE FUNCTION owlauth_enforce_identity_mutation_slot_set();

CREATE CONSTRAINT TRIGGER identity_mutation_slots_exact_slot_set
AFTER INSERT OR UPDATE OR DELETE ON identity_mutation_proof_slots
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
EXECUTE FUNCTION owlauth_enforce_identity_mutation_slot_set();


-- Prospective identity material is one purpose-bound short-term ciphertext. No provider subject,
-- normalized email, alias, or profile PII is exposed as a schema column.
CREATE TABLE identity_mutation_candidate_evidence (
    id UUID PRIMARY KEY,
    project_id UUID NOT NULL,
    intent_id UUID NOT NULL,
    slot_id UUID NOT NULL,
    identity_kind TEXT NOT NULL CHECK (identity_kind IN ('provider', 'email')),
    candidate_revision BIGINT NOT NULL DEFAULT 1 CHECK (candidate_revision > 0),
    protector_key_version INTEGER NOT NULL CHECK (protector_key_version > 0),
    evidence_ciphertext BYTEA NOT NULL CHECK (
        octet_length(evidence_ciphertext) BETWEEN 41 AND 16384
    ),
    evidence_digest BYTEA NOT NULL CHECK (octet_length(evidence_digest) = 32),
    created_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    retain_until TIMESTAMPTZ NOT NULL,
    FOREIGN KEY (project_id, intent_id, slot_id)
        REFERENCES identity_mutation_proof_slots (project_id, intent_id, id)
        ON DELETE CASCADE,
    UNIQUE (project_id, id),
    UNIQUE (project_id, intent_id, slot_id),
    UNIQUE (project_id, intent_id, slot_id, id),
    CHECK (retain_until > created_at
        AND retain_until <= created_at + INTERVAL '25 minutes')
);

CREATE INDEX identity_mutation_candidate_cleanup_idx
    ON identity_mutation_candidate_evidence (retain_until, project_id, intent_id);

CREATE TRIGGER identity_mutation_candidate_evidence_immutable
BEFORE UPDATE ON identity_mutation_candidate_evidence
FOR EACH ROW
EXECUTE FUNCTION reject_immutable_column_change(
    'id', 'project_id', 'intent_id', 'slot_id', 'identity_kind', 'candidate_revision',
    'protector_key_version', 'evidence_ciphertext', 'evidence_digest', 'created_at',
    'retain_until'
);

CREATE FUNCTION owlauth_enforce_identity_mutation_candidate_evidence()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    evidence_project_id UUID;
    evidence_intent_id UUID;
    evidence_slot_id UUID;
    current_evidence identity_mutation_candidate_evidence%ROWTYPE;
    current_slot identity_mutation_proof_slots%ROWTYPE;
    current_intent identity_mutation_intents%ROWTYPE;
BEGIN
    IF TG_TABLE_NAME = 'identity_mutation_proof_slots' THEN
        evidence_project_id := NEW.project_id;
        evidence_intent_id := NEW.intent_id;
        evidence_slot_id := NEW.id;
    ELSIF TG_OP = 'DELETE' THEN
        evidence_project_id := OLD.project_id;
        evidence_intent_id := OLD.intent_id;
        evidence_slot_id := OLD.slot_id;
    ELSE
        evidence_project_id := NEW.project_id;
        evidence_intent_id := NEW.intent_id;
        evidence_slot_id := NEW.slot_id;
    END IF;

    SELECT * INTO current_evidence
      FROM identity_mutation_candidate_evidence
     WHERE project_id = evidence_project_id
       AND intent_id = evidence_intent_id
       AND slot_id = evidence_slot_id;
    IF NOT FOUND THEN
        IF TG_TABLE_NAME = 'identity_mutation_candidate_evidence'
            AND TG_OP = 'DELETE'
            AND EXISTS (
                SELECT 1 FROM identity_mutation_intents
                 WHERE project_id = evidence_project_id
                   AND id = evidence_intent_id
                   AND status NOT IN ('completed', 'expired', 'cancelled')
            )
        THEN
            RAISE EXCEPTION 'live identity-mutation candidate evidence cannot be deleted'
                USING ERRCODE = '23514';
        END IF;
        RETURN NULL;
    END IF;
    SELECT * INTO STRICT current_slot
      FROM identity_mutation_proof_slots
     WHERE project_id = current_evidence.project_id
       AND intent_id = current_evidence.intent_id
       AND id = current_evidence.slot_id;
    SELECT * INTO STRICT current_intent
      FROM identity_mutation_intents
     WHERE project_id = current_evidence.project_id
       AND id = current_evidence.intent_id;
    IF current_slot.slot_role <> 'candidate_identity'
        OR current_slot.state <> 'proved'
        OR current_slot.identity_kind <> current_evidence.identity_kind
        OR current_evidence.retain_until
            > current_intent.expires_at + INTERVAL '15 minutes'
    THEN
        RAISE EXCEPTION 'candidate evidence requires exact slot authority and bounded retention'
            USING ERRCODE = '23514';
    END IF;
    RETURN NULL;
END
$$;

CREATE CONSTRAINT TRIGGER identity_mutation_candidate_evidence_matches_slot
AFTER INSERT OR UPDATE OR DELETE ON identity_mutation_candidate_evidence
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
EXECUTE FUNCTION owlauth_enforce_identity_mutation_candidate_evidence();

CREATE CONSTRAINT TRIGGER identity_mutation_candidate_slot_matches_evidence
AFTER UPDATE OF state, identity_kind, slot_role ON identity_mutation_proof_slots
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
WHEN (NEW.slot_role = 'candidate_identity')
EXECUTE FUNCTION owlauth_enforce_identity_mutation_candidate_evidence();

-- Legacy receipts cannot be mapped to a revisioned intent/slot and are at most five minutes old.
-- Upgrade invalidates them rather than accidentally granting generic proof authority.
LOCK TABLE identity_proof_receipts IN ACCESS EXCLUSIVE MODE;
DROP TABLE identity_proof_receipts;

CREATE TABLE identity_proof_receipts (
    id UUID PRIMARY KEY,
    project_id UUID NOT NULL,
    intent_id UUID NOT NULL,
    slot_id UUID NOT NULL,
    evidence_kind TEXT NOT NULL CHECK (
        evidence_kind IN ('existing_identity', 'candidate_evidence')
    ),
    identity_kind TEXT NOT NULL CHECK (identity_kind IN ('provider', 'email')),
    provider_identity_id UUID,
    email_identity_id UUID,
    candidate_evidence_id UUID,
    evidence_revision BIGINT NOT NULL CHECK (evidence_revision > 0),
    proof_user_id UUID NOT NULL,
    proof_user_revision BIGINT NOT NULL CHECK (proof_user_revision > 0),
    proof_user_security_revision BIGINT NOT NULL CHECK (
        proof_user_security_revision > 0
    ),
    interaction_browser_binding_digest BYTEA NOT NULL CHECK (
        octet_length(interaction_browser_binding_digest) = 32
    ),
    interaction_browser_binding_digest_key_version INTEGER NOT NULL CHECK (
        interaction_browser_binding_digest_key_version > 0
    ),
    interaction_browser_binding_revision BIGINT NOT NULL CHECK (
        interaction_browser_binding_revision > 0
    ),
    captured_intent_revision BIGINT NOT NULL CHECK (captured_intent_revision > 0),
    purpose TEXT NOT NULL CHECK (
        purpose IN ('link.destination_owner', 'link.candidate_identity',
                    'unlink.identity_owner', 'merge.winner_owner', 'merge.loser_owner')
    ),
    receipt_digest BYTEA NOT NULL CHECK (octet_length(receipt_digest) = 32),
    receipt_digest_key_version INTEGER NOT NULL CHECK (receipt_digest_key_version > 0),
    status TEXT NOT NULL CHECK (status IN ('issued', 'consumed', 'expired')),
    issued_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    FOREIGN KEY (project_id, intent_id)
        REFERENCES identity_mutation_intents (project_id, id) ON DELETE CASCADE,
    FOREIGN KEY (project_id, intent_id, slot_id)
        REFERENCES identity_mutation_proof_slots (project_id, intent_id, id)
        ON DELETE CASCADE,
    FOREIGN KEY (project_id, proof_user_id)
        REFERENCES project_users (project_id, id),
    FOREIGN KEY (project_id, provider_identity_id)
        REFERENCES linked_identities (project_id, id),
    FOREIGN KEY (project_id, email_identity_id)
        REFERENCES email_identities (project_id, id),
    -- Candidate evidence is validated at receipt insertion but may be physically erased on
    -- successful confirmation while this consumed receipt remains as bounded audit evidence.
    UNIQUE (project_id, id),
    UNIQUE (project_id, intent_id, slot_id),
    UNIQUE (receipt_digest_key_version, receipt_digest),
    CHECK (expires_at > issued_at AND expires_at <= issued_at + INTERVAL '5 minutes'),
    CHECK (
        (evidence_kind = 'existing_identity'
            AND candidate_evidence_id IS NULL
            AND ((identity_kind = 'provider'
                    AND provider_identity_id IS NOT NULL
                    AND email_identity_id IS NULL)
                OR (identity_kind = 'email'
                    AND provider_identity_id IS NULL
                    AND email_identity_id IS NOT NULL)))
        OR (evidence_kind = 'candidate_evidence'
            AND provider_identity_id IS NULL
            AND email_identity_id IS NULL
            AND candidate_evidence_id IS NOT NULL)
    ),
    CHECK ((status = 'consumed') = (consumed_at IS NOT NULL))
);

CREATE INDEX identity_proof_receipts_intent_status_idx
    ON identity_proof_receipts (project_id, intent_id, status, expires_at, slot_id);
CREATE INDEX identity_proof_receipts_expiry_idx
    ON identity_proof_receipts (status, expires_at, id)
    WHERE status = 'issued';

CREATE TRIGGER identity_proof_receipts_stable_evidence
BEFORE UPDATE ON identity_proof_receipts
FOR EACH ROW
EXECUTE FUNCTION reject_immutable_column_change(
    'project_id', 'intent_id', 'slot_id', 'evidence_kind', 'identity_kind',
    'provider_identity_id', 'email_identity_id', 'candidate_evidence_id',
    'evidence_revision', 'proof_user_id', 'proof_user_revision',
    'proof_user_security_revision', 'interaction_browser_binding_digest',
    'interaction_browser_binding_digest_key_version',
    'interaction_browser_binding_revision', 'captured_intent_revision',
    'purpose', 'receipt_digest', 'receipt_digest_key_version', 'issued_at',
    'expires_at', 'created_at'
);

CREATE FUNCTION owlauth_enforce_identity_proof_receipt()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    current_slot identity_mutation_proof_slots%ROWTYPE;
    current_intent identity_mutation_intents%ROWTYPE;
    candidate_revision BIGINT;
BEGIN
    IF TG_OP = 'UPDATE' THEN
        RETURN NEW;
    END IF;

    SELECT * INTO STRICT current_slot
      FROM identity_mutation_proof_slots
     WHERE project_id = NEW.project_id
       AND intent_id = NEW.intent_id
       AND id = NEW.slot_id;
    SELECT * INTO STRICT current_intent
      FROM identity_mutation_intents
     WHERE project_id = NEW.project_id
       AND id = NEW.intent_id;

    IF NEW.provider_identity_id IS NOT NULL
        AND NOT EXISTS (
            SELECT 1 FROM linked_identities
             WHERE project_id = NEW.project_id
               AND id = NEW.provider_identity_id
               AND user_id = NEW.proof_user_id
        )
    THEN
        RAISE EXCEPTION 'provider proof receipt must capture the identity original owner'
            USING ERRCODE = '23514';
    END IF;
    IF NEW.email_identity_id IS NOT NULL
        AND NOT EXISTS (
            SELECT 1 FROM email_identities
             WHERE project_id = NEW.project_id
               AND id = NEW.email_identity_id
               AND user_id = NEW.proof_user_id
        )
    THEN
        RAISE EXCEPTION 'email proof receipt must capture the identity original owner'
            USING ERRCODE = '23514';
    END IF;

    IF NEW.purpose <> current_slot.purpose
        OR NEW.identity_kind <> current_slot.identity_kind
        OR NEW.proof_user_id <> current_slot.proof_user_id
        OR NEW.proof_user_revision <> current_slot.expected_user_revision
        OR NEW.proof_user_security_revision <> current_slot.expected_user_security_revision
        OR current_intent.browser_binding_digest IS NULL
        OR NEW.interaction_browser_binding_digest
            IS DISTINCT FROM current_intent.browser_binding_digest
        OR NEW.interaction_browser_binding_digest_key_version
            IS DISTINCT FROM current_intent.browser_binding_digest_key_version
        OR NEW.interaction_browser_binding_revision
            IS DISTINCT FROM current_intent.browser_binding_revision
        OR NEW.captured_intent_revision <> current_intent.intent_revision
        OR NEW.expires_at > current_intent.expires_at
        OR NEW.issued_at < current_intent.created_at
        OR NEW.issued_at IS DISTINCT FROM current_slot.proved_at
        OR current_slot.state <> 'proved'
    THEN
        RAISE EXCEPTION 'identity proof receipt does not match its frozen intent and slot'
            USING ERRCODE = '23514';
    END IF;

    IF NEW.evidence_kind = 'existing_identity' THEN
        IF NEW.evidence_revision IS DISTINCT FROM current_slot.expected_identity_revision
            OR NEW.provider_identity_id IS DISTINCT FROM current_slot.existing_provider_identity_id
            OR NEW.email_identity_id IS DISTINCT FROM current_slot.existing_email_identity_id
        THEN
            RAISE EXCEPTION 'identity proof receipt does not match existing identity revision'
                USING ERRCODE = '23514';
        END IF;
    ELSE
        SELECT evidence.candidate_revision INTO STRICT candidate_revision
          FROM identity_mutation_candidate_evidence AS evidence
         WHERE evidence.project_id = NEW.project_id
           AND evidence.intent_id = NEW.intent_id
           AND evidence.slot_id = NEW.slot_id
           AND evidence.id = NEW.candidate_evidence_id;
        IF NEW.evidence_revision IS DISTINCT FROM candidate_revision
            OR current_slot.slot_role <> 'candidate_identity'
        THEN
            RAISE EXCEPTION 'identity proof receipt does not match candidate evidence revision'
                USING ERRCODE = '23514';
        END IF;
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER identity_proof_receipts_match_slot
BEFORE INSERT OR UPDATE ON identity_proof_receipts
FOR EACH ROW
EXECUTE FUNCTION owlauth_enforce_identity_proof_receipt();

CREATE FUNCTION owlauth_enforce_identity_proof_receipt_transition()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.status <> 'issued' OR NEW.consumed_at IS NOT NULL THEN
            RAISE EXCEPTION 'identity proof receipt must start issued and unconsumed'
                USING ERRCODE = '23514';
        END IF;
        IF NEW.issued_at < transaction_timestamp() OR NEW.issued_at > clock_timestamp() THEN
            RAISE EXCEPTION 'identity proof receipt issue timestamp must be current'
                USING ERRCODE = '23514';
        END IF;
        RETURN NEW;
    END IF;
    IF NOT (
        NEW.status = OLD.status
        OR (OLD.status = 'issued' AND NEW.status IN ('consumed', 'expired'))
    ) THEN
        RAISE EXCEPTION 'identity proof receipt cannot be reused or reopened'
            USING ERRCODE = '23514';
    END IF;
    IF NEW.status = 'consumed'
        AND (NEW.consumed_at < NEW.issued_at
            OR NEW.consumed_at >= NEW.expires_at
            OR NEW.consumed_at < transaction_timestamp()
            OR NEW.consumed_at > clock_timestamp()
            OR clock_timestamp() >= NEW.expires_at)
    THEN
        RAISE EXCEPTION 'identity proof receipt must be consumed while fresh'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER identity_proof_receipts_one_way_state
BEFORE INSERT OR UPDATE ON identity_proof_receipts
FOR EACH ROW
EXECUTE FUNCTION owlauth_enforce_identity_proof_receipt_transition();

CREATE CONSTRAINT TRIGGER identity_proof_receipts_exact_slot_state
AFTER INSERT OR UPDATE OR DELETE ON identity_proof_receipts
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
EXECUTE FUNCTION owlauth_enforce_identity_mutation_slot_set();

CREATE TABLE identity_mutation_create_results (
    idempotency_key TEXT PRIMARY KEY
        REFERENCES control_idempotency_records (idempotency_key),
    project_id UUID NOT NULL,
    intent_id UUID NOT NULL,
    request_digest BYTEA NOT NULL CHECK (octet_length(request_digest) = 32),
    create_result_key_version INTEGER NOT NULL CHECK (create_result_key_version > 0),
    create_result_ciphertext BYTEA,
    expires_at TIMESTAMPTZ NOT NULL,
    erased_at TIMESTAMPTZ,
    FOREIGN KEY (project_id, intent_id)
        REFERENCES identity_mutation_intents (project_id, id) ON DELETE CASCADE,
    UNIQUE (project_id, intent_id),
    CHECK (create_result_ciphertext IS NULL
        OR octet_length(create_result_ciphertext) BETWEEN 40 AND 4096),
    CHECK ((create_result_ciphertext IS NULL) = (erased_at IS NOT NULL))
);

CREATE TRIGGER identity_mutation_create_results_stable_authority
BEFORE UPDATE ON identity_mutation_create_results
FOR EACH ROW
EXECUTE FUNCTION reject_immutable_column_change(
    'idempotency_key', 'project_id', 'intent_id', 'request_digest',
    'create_result_key_version', 'expires_at'
);

CREATE FUNCTION owlauth_enforce_identity_mutation_create_result_lifecycle()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    current_intent identity_mutation_intents%ROWTYPE;
    idempotency_authority control_idempotency_records%ROWTYPE;
BEGIN
    SELECT * INTO STRICT current_intent
      FROM identity_mutation_intents
     WHERE project_id = NEW.project_id AND id = NEW.intent_id;
    SELECT * INTO STRICT idempotency_authority
      FROM control_idempotency_records
     WHERE idempotency_key = NEW.idempotency_key
     FOR SHARE;
    IF idempotency_authority.project_id IS DISTINCT FROM NEW.project_id
        OR idempotency_authority.operation_kind <> 'identity_mutation.create'
        OR idempotency_authority.request_digest IS DISTINCT FROM NEW.request_digest
        OR idempotency_authority.request_scope <> NEW.project_id::TEXT
        OR idempotency_authority.result_resource_id IS DISTINCT FROM NEW.intent_id
        OR idempotency_authority.state <> 'completed'
        OR idempotency_authority.completed_at IS NULL
    THEN
        RAISE EXCEPTION 'identity-mutation create result has mismatched idempotency authority'
            USING ERRCODE = '23514';
    END IF;
    IF NEW.expires_at IS DISTINCT FROM current_intent.expires_at THEN
        RAISE EXCEPTION 'identity-mutation create result must retain the exact intent deadline'
            USING ERRCODE = '23514';
    END IF;
    IF TG_OP = 'INSERT' THEN
        IF NEW.create_result_ciphertext IS NULL OR NEW.erased_at IS NOT NULL THEN
            RAISE EXCEPTION 'identity-mutation create result must start live'
                USING ERRCODE = '23514';
        END IF;
        RETURN NEW;
    END IF;
    IF (NEW.create_result_ciphertext, NEW.erased_at)
        IS DISTINCT FROM (OLD.create_result_ciphertext, OLD.erased_at)
        AND NOT (
            OLD.create_result_ciphertext IS NOT NULL
            AND OLD.erased_at IS NULL
            AND NEW.create_result_ciphertext IS NULL
            AND NEW.erased_at >= transaction_timestamp()
            AND NEW.erased_at <= clock_timestamp()
            AND (clock_timestamp() >= OLD.expires_at
                OR (current_intent.status IN ('completed', 'expired', 'cancelled')
                    AND current_intent.terminal_at IS NOT NULL
                    AND NEW.erased_at >= current_intent.terminal_at))
        )
    THEN
        RAISE EXCEPTION 'identity-mutation create result can only be erased after expiry'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER identity_mutation_create_results_one_way_lifecycle
BEFORE INSERT OR UPDATE ON identity_mutation_create_results
FOR EACH ROW
EXECUTE FUNCTION owlauth_enforce_identity_mutation_create_result_lifecycle();

CREATE FUNCTION owlauth_enforce_identity_mutation_create_result_terminal_state()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    target_project_id UUID;
    target_intent_id UUID;
    current_intent identity_mutation_intents%ROWTYPE;
    current_result identity_mutation_create_results%ROWTYPE;
    intent_is_terminal BOOLEAN;
    result_is_erased BOOLEAN;
BEGIN
    IF TG_TABLE_NAME = 'identity_mutation_intents' THEN
        target_project_id := NEW.project_id;
        target_intent_id := NEW.id;
    ELSIF TG_OP = 'DELETE' THEN
        target_project_id := OLD.project_id;
        target_intent_id := OLD.intent_id;
    ELSE
        target_project_id := NEW.project_id;
        target_intent_id := NEW.intent_id;
    END IF;

    SELECT * INTO current_intent
      FROM identity_mutation_intents
     WHERE project_id = target_project_id AND id = target_intent_id;
    IF NOT FOUND THEN
        RETURN NULL;
    END IF;
    SELECT * INTO current_result
      FROM identity_mutation_create_results
     WHERE project_id = target_project_id AND intent_id = target_intent_id;
    IF NOT FOUND THEN
        RETURN NULL;
    END IF;

    intent_is_terminal := current_intent.status IN ('completed', 'expired', 'cancelled');
    result_is_erased := current_result.create_result_ciphertext IS NULL
        AND current_result.erased_at IS NOT NULL;
    IF intent_is_terminal IS DISTINCT FROM result_is_erased THEN
        RAISE EXCEPTION
            'identity-mutation terminal state requires exact create-result ciphertext erasure'
            USING ERRCODE = '23514';
    END IF;
    RETURN NULL;
END
$$;

CREATE CONSTRAINT TRIGGER identity_mutation_intents_exact_create_result_terminal_state
AFTER INSERT OR UPDATE OF status ON identity_mutation_intents
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
EXECUTE FUNCTION owlauth_enforce_identity_mutation_create_result_terminal_state();

CREATE CONSTRAINT TRIGGER identity_mutation_create_results_exact_terminal_state
AFTER INSERT OR UPDATE OR DELETE ON identity_mutation_create_results
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
EXECUTE FUNCTION owlauth_enforce_identity_mutation_create_result_terminal_state();

CREATE FUNCTION owlauth_reject_identity_mutation_create_result_delete()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF EXISTS (SELECT 1 FROM projects WHERE id = OLD.project_id) THEN
        RAISE EXCEPTION 'identity-mutation create-result authority tombstone cannot be deleted'
            USING ERRCODE = '23514';
    END IF;
    RETURN OLD;
END
$$;

CREATE TRIGGER identity_mutation_create_results_no_delete
BEFORE DELETE ON identity_mutation_create_results
FOR EACH ROW
EXECUTE FUNCTION owlauth_reject_identity_mutation_create_result_delete();

CREATE FUNCTION owlauth_reject_identity_mutation_intent_delete_with_result()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF EXISTS (SELECT 1 FROM projects WHERE id = OLD.project_id)
        AND EXISTS (
            SELECT 1 FROM identity_mutation_create_results
             WHERE project_id = OLD.project_id AND intent_id = OLD.id
        )
    THEN
        RAISE EXCEPTION 'identity-mutation intent with durable create authority cannot be deleted'
            USING ERRCODE = '23514';
    END IF;
    RETURN OLD;
END
$$;

CREATE TRIGGER identity_mutation_intents_preserve_create_authority
BEFORE DELETE ON identity_mutation_intents
FOR EACH ROW
EXECUTE FUNCTION owlauth_reject_identity_mutation_intent_delete_with_result();

CREATE FUNCTION owlauth_reject_identity_mutation_idempotency_authority_change()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    create_result identity_mutation_create_results%ROWTYPE;
BEGIN
    SELECT * INTO create_result
      FROM identity_mutation_create_results
     WHERE idempotency_key = OLD.idempotency_key;
    IF FOUND AND (
        NEW.project_id IS DISTINCT FROM create_result.project_id
        OR NEW.operation_kind <> 'identity_mutation.create'
        OR NEW.request_digest IS DISTINCT FROM create_result.request_digest
        OR NEW.request_scope <> create_result.project_id::TEXT
        OR NEW.result_resource_id IS DISTINCT FROM create_result.intent_id
        OR NEW.state <> 'completed'
        OR NEW.completed_at IS NULL
    ) THEN
        RAISE EXCEPTION 'identity-mutation idempotency authority is immutable after result creation'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER control_idempotency_identity_mutation_result_authority
BEFORE UPDATE OF project_id, request_digest, state, result_resource_id,
                 operation_kind, request_scope, completed_at
ON control_idempotency_records
FOR EACH ROW
EXECUTE FUNCTION owlauth_reject_identity_mutation_idempotency_authority_change();

-- Email proofs retain N/N-1 transaction columns but gain an exact XOR mutation owner. The
-- challenge ID plus generation is authoritative for both owner classes.
ALTER TABLE email_challenges
    ADD COLUMN owner_kind TEXT NOT NULL DEFAULT 'login'
        CHECK (owner_kind IN ('login', 'identity_mutation')),
    ALTER COLUMN transaction_id DROP NOT NULL,
    ADD COLUMN identity_mutation_intent_id UUID,
    ADD COLUMN identity_mutation_proof_slot_id UUID,
    ADD CONSTRAINT email_challenges_mutation_slot_fk
        FOREIGN KEY (project_id, identity_mutation_intent_id,
                     identity_mutation_proof_slot_id)
        REFERENCES identity_mutation_proof_slots (project_id, intent_id, id)
        ON DELETE CASCADE,
    ADD CONSTRAINT email_challenges_owner_shape_check CHECK (
        (owner_kind = 'login'
            AND transaction_id IS NOT NULL
            AND identity_mutation_intent_id IS NULL
            AND identity_mutation_proof_slot_id IS NULL)
        OR (owner_kind = 'identity_mutation'
            AND transaction_id IS NULL
            AND identity_mutation_intent_id IS NOT NULL
            AND identity_mutation_proof_slot_id IS NOT NULL)
    ),
    ADD CONSTRAINT email_challenges_project_id_id_generation_unique
        UNIQUE (project_id, id, generation);

DROP INDEX email_challenges_one_pending_idx;
CREATE UNIQUE INDEX email_challenges_login_one_pending_idx
    ON email_challenges (project_id, transaction_id)
    WHERE owner_kind = 'login' AND status = 'pending';
CREATE UNIQUE INDEX email_challenges_mutation_generation_unique_idx
    ON email_challenges
       (project_id, identity_mutation_intent_id,
        identity_mutation_proof_slot_id, generation)
    WHERE owner_kind = 'identity_mutation';
CREATE UNIQUE INDEX email_challenges_mutation_one_pending_idx
    ON email_challenges
       (project_id, identity_mutation_intent_id, identity_mutation_proof_slot_id)
    WHERE owner_kind = 'identity_mutation' AND status = 'pending';

CREATE TRIGGER email_challenges_stable_owner
BEFORE UPDATE ON email_challenges
FOR EACH ROW
EXECUTE FUNCTION reject_immutable_column_change(
    'project_id', 'application_id', 'owner_kind', 'transaction_id',
    'identity_mutation_intent_id', 'identity_mutation_proof_slot_id', 'generation',
    'smtp_selection_kind', 'smtp_configuration_id', 'smtp_generation',
    'smtp_security_eligibility_revision'
);

CREATE FUNCTION owlauth_enforce_email_challenge_typed_owner()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    target_project_id UUID;
    target_intent_id UUID;
    target_slot_id UUID;
BEGIN
    IF TG_TABLE_NAME = 'email_challenges' THEN
        IF (CASE WHEN TG_OP = 'DELETE' THEN OLD.owner_kind ELSE NEW.owner_kind END) = 'login' THEN
            RETURN NULL;
        END IF;
        IF TG_OP = 'DELETE' THEN
            target_project_id := OLD.project_id;
            target_intent_id := OLD.identity_mutation_intent_id;
            target_slot_id := OLD.identity_mutation_proof_slot_id;
        ELSE
            target_project_id := NEW.project_id;
            target_intent_id := NEW.identity_mutation_intent_id;
            target_slot_id := NEW.identity_mutation_proof_slot_id;
        END IF;
    ELSIF TG_TABLE_NAME = 'identity_mutation_proof_slots' THEN
        IF (CASE WHEN TG_OP = 'DELETE' THEN OLD.method_kind ELSE NEW.method_kind END) <> 'email' THEN
            RETURN NULL;
        END IF;
        IF TG_OP = 'DELETE' THEN
            target_project_id := OLD.project_id;
            target_intent_id := OLD.intent_id;
            target_slot_id := OLD.id;
        ELSE
            target_project_id := NEW.project_id;
            target_intent_id := NEW.intent_id;
            target_slot_id := NEW.id;
        END IF;
    ELSE
        target_project_id := NEW.project_id;
        target_intent_id := NEW.id;
        target_slot_id := NULL;
    END IF;

    IF EXISTS (
        SELECT 1
          FROM email_challenges AS challenge
          JOIN identity_mutation_proof_slots AS slot
            ON slot.project_id = challenge.project_id
           AND slot.intent_id = challenge.identity_mutation_intent_id
           AND slot.id = challenge.identity_mutation_proof_slot_id
          JOIN identity_mutation_intents AS intent
            ON intent.project_id = slot.project_id AND intent.id = slot.intent_id
         WHERE challenge.owner_kind = 'identity_mutation'
           AND challenge.project_id = target_project_id
           AND challenge.identity_mutation_intent_id = target_intent_id
           AND (target_slot_id IS NULL
                OR challenge.identity_mutation_proof_slot_id = target_slot_id)
           AND (slot.method_kind <> 'email'
                OR slot.application_id <> challenge.application_id
                OR slot.email_policy_revision <> challenge.method_policy_revision
                OR slot.email_security_revision <> challenge.method_security_revision
                OR slot.email_assignment_security_revision
                    <> challenge.assignment_security_revision
                OR challenge.issued_at < intent.created_at
                OR challenge.expires_at > intent.expires_at
                OR (challenge.status = 'pending'
                    AND (intent.status <> 'pending_proof'
                         OR slot.state <> 'email_challenge_pending'))
                OR (challenge.status = 'consumed' AND slot.state <> 'proved'))
    ) THEN
        RAISE EXCEPTION 'mutation email challenge does not match its frozen proof authority'
            USING ERRCODE = '23514';
    END IF;

    IF EXISTS (
        SELECT 1
          FROM identity_mutation_proof_slots AS slot
         WHERE slot.project_id = target_project_id
           AND slot.intent_id = target_intent_id
           AND slot.method_kind = 'email'
           AND (target_slot_id IS NULL OR slot.id = target_slot_id)
           AND (
                (slot.state = 'email_challenge_pending' AND (
                    (SELECT COUNT(*) FROM email_challenges AS challenge
                      WHERE challenge.owner_kind = 'identity_mutation'
                        AND challenge.project_id = slot.project_id
                        AND challenge.identity_mutation_intent_id = slot.intent_id
                        AND challenge.identity_mutation_proof_slot_id = slot.id
                        AND challenge.status = 'pending') <> 1
                    OR EXISTS (
                        SELECT 1 FROM email_challenges AS challenge
                         WHERE challenge.owner_kind = 'identity_mutation'
                           AND challenge.project_id = slot.project_id
                           AND challenge.identity_mutation_intent_id = slot.intent_id
                           AND challenge.identity_mutation_proof_slot_id = slot.id
                           AND challenge.status = 'consumed'
                    )))
                OR (slot.state = 'proved' AND (
                    (SELECT COUNT(*) FROM email_challenges AS challenge
                      WHERE challenge.owner_kind = 'identity_mutation'
                        AND challenge.project_id = slot.project_id
                        AND challenge.identity_mutation_intent_id = slot.intent_id
                        AND challenge.identity_mutation_proof_slot_id = slot.id
                        AND challenge.status = 'consumed') <> 1
                    OR EXISTS (
                        SELECT 1 FROM email_challenges AS challenge
                         WHERE challenge.owner_kind = 'identity_mutation'
                           AND challenge.project_id = slot.project_id
                           AND challenge.identity_mutation_intent_id = slot.intent_id
                           AND challenge.identity_mutation_proof_slot_id = slot.id
                           AND challenge.status = 'pending'
                    )))
                OR (slot.state NOT IN ('email_challenge_pending', 'proved')
                    AND EXISTS (
                        SELECT 1 FROM email_challenges AS challenge
                         WHERE challenge.owner_kind = 'identity_mutation'
                           AND challenge.project_id = slot.project_id
                           AND challenge.identity_mutation_intent_id = slot.intent_id
                           AND challenge.identity_mutation_proof_slot_id = slot.id
                           AND challenge.status IN ('pending', 'consumed')
                    ))
           )
    ) THEN
        RAISE EXCEPTION 'mutation email slot requires an exact current challenge lifecycle'
            USING ERRCODE = '23514';
    END IF;
    RETURN NULL;
END
$$;

CREATE CONSTRAINT TRIGGER email_challenges_exact_typed_owner
AFTER INSERT OR UPDATE OR DELETE ON email_challenges
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
EXECUTE FUNCTION owlauth_enforce_email_challenge_typed_owner();

CREATE CONSTRAINT TRIGGER identity_mutation_email_slot_reverse_owner
AFTER UPDATE ON identity_mutation_proof_slots
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
EXECUTE FUNCTION owlauth_enforce_email_challenge_typed_owner();

CREATE CONSTRAINT TRIGGER identity_mutation_email_intent_reverse_owner
AFTER UPDATE ON identity_mutation_intents
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
EXECUTE FUNCTION owlauth_enforce_email_challenge_typed_owner();

ALTER TABLE mail_outbox
    ALTER COLUMN transaction_id DROP NOT NULL,
    ADD CONSTRAINT mail_outbox_exact_challenge_generation_fk
        FOREIGN KEY (project_id, challenge_id, challenge_generation)
        REFERENCES email_challenges (project_id, id, generation)
        ON DELETE CASCADE;

CREATE FUNCTION owlauth_enforce_mail_outbox_challenge_owner()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
          FROM email_challenges AS challenge
         WHERE challenge.project_id = NEW.project_id
           AND challenge.id = NEW.challenge_id
           AND challenge.generation = NEW.challenge_generation
           AND challenge.transaction_id IS NOT DISTINCT FROM NEW.transaction_id
           AND challenge.smtp_selection_kind = NEW.smtp_selection_kind
           AND challenge.smtp_configuration_id IS NOT DISTINCT FROM NEW.smtp_configuration_id
           AND challenge.smtp_generation = NEW.smtp_generation
           AND challenge.smtp_security_eligibility_revision
                = NEW.smtp_security_eligibility_revision
    ) THEN
        RAISE EXCEPTION 'mail outbox must match its exact challenge and SMTP authority'
            USING ERRCODE = '23514';
    END IF;
    RETURN NULL;
END
$$;

CREATE CONSTRAINT TRIGGER mail_outbox_exact_challenge_owner
AFTER INSERT OR UPDATE OF project_id, transaction_id, challenge_id, challenge_generation
ON mail_outbox
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
EXECUTE FUNCTION owlauth_enforce_mail_outbox_challenge_owner();

CREATE TRIGGER mail_outbox_stable_challenge_authority
BEFORE UPDATE ON mail_outbox
FOR EACH ROW
EXECUTE FUNCTION reject_immutable_column_change(
    'project_id', 'transaction_id', 'challenge_id', 'challenge_generation',
    'smtp_selection_kind', 'smtp_configuration_id', 'smtp_generation',
    'smtp_security_eligibility_revision', 'created_at'
);

CREATE FUNCTION owlauth_enforce_mutation_email_challenge_outbox()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    target_project_id UUID;
    target_challenge_id UUID;
    target_generation SMALLINT;
    current_challenge email_challenges%ROWTYPE;
BEGIN
    IF TG_TABLE_NAME = 'email_challenges' THEN
        target_project_id := CASE WHEN TG_OP = 'DELETE' THEN OLD.project_id ELSE NEW.project_id END;
        target_challenge_id := CASE WHEN TG_OP = 'DELETE' THEN OLD.id ELSE NEW.id END;
        target_generation := CASE WHEN TG_OP = 'DELETE' THEN OLD.generation ELSE NEW.generation END;
    ELSE
        target_project_id := CASE WHEN TG_OP = 'DELETE' THEN OLD.project_id ELSE NEW.project_id END;
        target_challenge_id := CASE WHEN TG_OP = 'DELETE' THEN OLD.challenge_id ELSE NEW.challenge_id END;
        target_generation := CASE
            WHEN TG_OP = 'DELETE' THEN OLD.challenge_generation
            ELSE NEW.challenge_generation
        END;
    END IF;

    SELECT * INTO current_challenge
      FROM email_challenges
     WHERE project_id = target_project_id
       AND id = target_challenge_id
       AND generation = target_generation;
    IF NOT FOUND THEN
        RETURN NULL;
    END IF;
    IF current_challenge.owner_kind = 'identity_mutation'
        AND current_challenge.status = 'pending'
        AND (SELECT count(*)
               FROM mail_outbox AS outbox
              WHERE outbox.project_id = current_challenge.project_id
                AND outbox.challenge_id = current_challenge.id
                AND outbox.challenge_generation = current_challenge.generation
                AND outbox.transaction_id IS NULL) <> 1
    THEN
        RAISE EXCEPTION 'pending mutation email challenge requires one exact mail outbox row'
            USING ERRCODE = '23514';
    END IF;
    RETURN NULL;
END
$$;

CREATE CONSTRAINT TRIGGER email_challenges_exact_mutation_outbox
AFTER INSERT OR UPDATE OR DELETE ON email_challenges
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
EXECUTE FUNCTION owlauth_enforce_mutation_email_challenge_outbox();

CREATE CONSTRAINT TRIGGER mail_outbox_reverse_mutation_challenge
AFTER INSERT OR UPDATE OR DELETE ON mail_outbox
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
EXECUTE FUNCTION owlauth_enforce_mutation_email_challenge_outbox();

-- The callback state UUID has exactly one persisted interaction class before any provider I/O.
CREATE TABLE provider_callback_owners (
    state_id UUID PRIMARY KEY,
    project_id UUID NOT NULL,
    provider_configuration_id UUID NOT NULL,
    owner_kind TEXT NOT NULL CHECK (
        owner_kind IN ('login', 'identity_mutation', 'managed_reauthorization')
    ),
    login_transaction_id UUID,
    identity_mutation_intent_id UUID,
    identity_mutation_proof_slot_id UUID,
    managed_reauthorization_interaction_id UUID,
    created_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    FOREIGN KEY (project_id, provider_configuration_id)
        REFERENCES provider_configurations (project_id, id),
    FOREIGN KEY (project_id, login_transaction_id)
        REFERENCES login_transactions (project_id, id) ON DELETE CASCADE,
    FOREIGN KEY (project_id, identity_mutation_intent_id,
                 identity_mutation_proof_slot_id)
        REFERENCES identity_mutation_proof_slots (project_id, intent_id, id)
        ON DELETE CASCADE,
    FOREIGN KEY (project_id, managed_reauthorization_interaction_id)
        REFERENCES managed_provider_reauthorization_interactions (project_id, id)
        ON DELETE CASCADE,
    UNIQUE (project_id, state_id),
    CHECK (
        (owner_kind = 'login'
            AND login_transaction_id IS NOT NULL
            AND state_id = login_transaction_id
            AND identity_mutation_intent_id IS NULL
            AND identity_mutation_proof_slot_id IS NULL
            AND managed_reauthorization_interaction_id IS NULL)
        OR (owner_kind = 'identity_mutation'
            AND login_transaction_id IS NULL
            AND identity_mutation_intent_id IS NOT NULL
            AND identity_mutation_proof_slot_id IS NOT NULL
            AND state_id = identity_mutation_proof_slot_id
            AND managed_reauthorization_interaction_id IS NULL)
        OR (owner_kind = 'managed_reauthorization'
            AND login_transaction_id IS NULL
            AND identity_mutation_intent_id IS NULL
            AND identity_mutation_proof_slot_id IS NULL
            AND managed_reauthorization_interaction_id IS NOT NULL
            AND state_id = managed_reauthorization_interaction_id)
    )
);

CREATE INDEX provider_callback_owners_route_idx
    ON provider_callback_owners
       (project_id, provider_configuration_id, owner_kind, state_id);

CREATE TRIGGER provider_callback_owners_immutable
BEFORE UPDATE ON provider_callback_owners
FOR EACH ROW
EXECUTE FUNCTION reject_immutable_column_change(
    'state_id', 'project_id', 'provider_configuration_id', 'owner_kind',
    'login_transaction_id', 'identity_mutation_intent_id',
    'identity_mutation_proof_slot_id', 'managed_reauthorization_interaction_id',
    'created_at'
);

INSERT INTO provider_callback_owners
    (state_id, project_id, provider_configuration_id, owner_kind,
     login_transaction_id)
SELECT id, project_id, provider_configuration_id, 'login', id
  FROM login_transactions
 WHERE provider_configuration_id IS NOT NULL
   AND upstream_state_digest IS NOT NULL;

-- provider_started_at survives terminal material scrubbing and therefore also backfills retained
-- managed callback tombstones. A cross-class UUID collision intentionally aborts this migration.
INSERT INTO provider_callback_owners
    (state_id, project_id, provider_configuration_id, owner_kind,
     managed_reauthorization_interaction_id)
SELECT id, project_id, provider_configuration_id, 'managed_reauthorization', id
  FROM managed_provider_reauthorization_interactions
 WHERE provider_started_at IS NOT NULL;

CREATE FUNCTION owlauth_enforce_provider_callback_owner()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    target_state_id UUID;
    target_project_id UUID;
    target_provider_id UUID;
    target_owner_kind TEXT;
    expected_count INTEGER;
BEGIN
    IF TG_TABLE_NAME = 'provider_callback_owners' THEN
        IF TG_OP = 'DELETE' THEN
            target_state_id := OLD.state_id;
            target_project_id := OLD.project_id;
            target_provider_id := OLD.provider_configuration_id;
            target_owner_kind := OLD.owner_kind;
        ELSE
            target_state_id := NEW.state_id;
            target_project_id := NEW.project_id;
            target_provider_id := NEW.provider_configuration_id;
            target_owner_kind := NEW.owner_kind;
        END IF;
    ELSIF TG_TABLE_NAME = 'login_transactions' THEN
        target_state_id := CASE WHEN TG_OP = 'DELETE' THEN OLD.id ELSE NEW.id END;
        target_project_id := CASE WHEN TG_OP = 'DELETE' THEN OLD.project_id ELSE NEW.project_id END;
        target_provider_id := CASE WHEN TG_OP = 'DELETE' THEN OLD.provider_configuration_id
                                   ELSE NEW.provider_configuration_id END;
        target_owner_kind := 'login';
    ELSIF TG_TABLE_NAME = 'managed_provider_reauthorization_interactions' THEN
        target_state_id := CASE WHEN TG_OP = 'DELETE' THEN OLD.id ELSE NEW.id END;
        target_project_id := CASE WHEN TG_OP = 'DELETE' THEN OLD.project_id ELSE NEW.project_id END;
        target_provider_id := CASE WHEN TG_OP = 'DELETE' THEN OLD.provider_configuration_id
                                   ELSE NEW.provider_configuration_id END;
        target_owner_kind := 'managed_reauthorization';
    ELSE
        target_state_id := CASE WHEN TG_OP = 'DELETE' THEN OLD.id ELSE NEW.id END;
        target_project_id := CASE WHEN TG_OP = 'DELETE' THEN OLD.project_id ELSE NEW.project_id END;
        target_provider_id := CASE WHEN TG_OP = 'DELETE' THEN OLD.provider_configuration_id
                                   ELSE NEW.provider_configuration_id END;
        target_owner_kind := 'identity_mutation';
    END IF;

    IF TG_TABLE_NAME = 'provider_callback_owners' AND TG_OP <> 'DELETE' THEN
        IF NEW.owner_kind = 'login' AND NOT EXISTS (
            SELECT 1 FROM login_transactions
             WHERE id = NEW.login_transaction_id
               AND project_id = NEW.project_id
               AND provider_configuration_id = NEW.provider_configuration_id
        ) THEN
            RAISE EXCEPTION 'login callback owner must match its exact interaction authority'
                USING ERRCODE = '23514';
        ELSIF NEW.owner_kind = 'managed_reauthorization' AND NOT EXISTS (
            SELECT 1 FROM managed_provider_reauthorization_interactions
             WHERE id = NEW.managed_reauthorization_interaction_id
               AND project_id = NEW.project_id
               AND provider_configuration_id = NEW.provider_configuration_id
        ) THEN
            RAISE EXCEPTION 'managed callback owner must match its exact interaction authority'
                USING ERRCODE = '23514';
        ELSIF NEW.owner_kind = 'identity_mutation' AND NOT EXISTS (
            SELECT 1 FROM identity_mutation_proof_slots
             WHERE id = NEW.identity_mutation_proof_slot_id
               AND intent_id = NEW.identity_mutation_intent_id
               AND project_id = NEW.project_id
               AND provider_configuration_id = NEW.provider_configuration_id
               AND method_kind = 'provider'
        ) THEN
            RAISE EXCEPTION 'mutation callback owner must match its exact proof-slot authority'
                USING ERRCODE = '23514';
        END IF;
    END IF;

    -- Expand compatibility for N/N-1 overlap: a legacy writer does not know the owner table.
    -- Its deferred source-row trigger derives only the exact persisted class and authority. New
    -- writers may insert first; ON CONFLICT then becomes a no-op and strict validation follows.
    IF TG_TABLE_NAME = 'login_transactions' AND TG_OP <> 'DELETE' THEN
        INSERT INTO provider_callback_owners
            (state_id, project_id, provider_configuration_id, owner_kind,
             login_transaction_id)
        SELECT id, project_id, provider_configuration_id, 'login', id
          FROM login_transactions
         WHERE id = target_state_id AND project_id = target_project_id
           AND upstream_state_digest IS NOT NULL
        ON CONFLICT (state_id) DO NOTHING;
    ELSIF TG_TABLE_NAME = 'managed_provider_reauthorization_interactions'
        AND TG_OP <> 'DELETE'
    THEN
        INSERT INTO provider_callback_owners
            (state_id, project_id, provider_configuration_id, owner_kind,
             managed_reauthorization_interaction_id)
        SELECT id, project_id, provider_configuration_id, 'managed_reauthorization', id
          FROM managed_provider_reauthorization_interactions
         WHERE id = target_state_id AND project_id = target_project_id
           AND provider_started_at IS NOT NULL
        ON CONFLICT (state_id) DO NOTHING;
    END IF;

    IF target_owner_kind = 'login' THEN
        SELECT count(*)::INTEGER INTO expected_count
          FROM login_transactions AS interaction
          JOIN provider_callback_owners AS owner
            ON owner.state_id = interaction.id
           AND owner.project_id = interaction.project_id
           AND owner.provider_configuration_id = interaction.provider_configuration_id
           AND owner.owner_kind = 'login'
           AND owner.login_transaction_id = interaction.id
         WHERE interaction.id = target_state_id
           AND interaction.project_id = target_project_id
           AND interaction.upstream_state_digest IS NOT NULL;
        IF EXISTS (
            SELECT 1 FROM login_transactions
             WHERE id = target_state_id AND project_id = target_project_id
               AND upstream_state_digest IS NOT NULL
        ) AND expected_count <> 1 THEN
            RAISE EXCEPTION 'started login callback requires its exact typed owner'
                USING ERRCODE = '23514';
        END IF;
    ELSIF target_owner_kind = 'managed_reauthorization' THEN
        SELECT count(*)::INTEGER INTO expected_count
          FROM managed_provider_reauthorization_interactions AS interaction
          JOIN provider_callback_owners AS owner
            ON owner.state_id = interaction.id
           AND owner.project_id = interaction.project_id
           AND owner.provider_configuration_id = interaction.provider_configuration_id
           AND owner.owner_kind = 'managed_reauthorization'
           AND owner.managed_reauthorization_interaction_id = interaction.id
         WHERE interaction.id = target_state_id
           AND interaction.project_id = target_project_id
           AND interaction.provider_started_at IS NOT NULL;
        IF EXISTS (
            SELECT 1 FROM managed_provider_reauthorization_interactions
             WHERE id = target_state_id AND project_id = target_project_id
               AND provider_started_at IS NOT NULL
        ) AND expected_count <> 1 THEN
            RAISE EXCEPTION 'started managed callback requires its exact typed owner'
                USING ERRCODE = '23514';
        END IF;
    ELSE
        SELECT count(*)::INTEGER INTO expected_count
          FROM identity_mutation_proof_slots AS slot
          JOIN provider_callback_owners AS owner
            ON owner.state_id = slot.id
           AND owner.project_id = slot.project_id
           AND owner.provider_configuration_id = slot.provider_configuration_id
           AND owner.owner_kind = 'identity_mutation'
           AND owner.identity_mutation_intent_id = slot.intent_id
           AND owner.identity_mutation_proof_slot_id = slot.id
         WHERE slot.id = target_state_id
           AND slot.project_id = target_project_id
           AND slot.provider_started_at IS NOT NULL;
        IF EXISTS (
            SELECT 1 FROM identity_mutation_proof_slots
             WHERE id = target_state_id AND project_id = target_project_id
               AND provider_started_at IS NOT NULL
        ) AND expected_count <> 1 THEN
            RAISE EXCEPTION 'started identity-mutation callback requires its exact typed owner'
                USING ERRCODE = '23514';
        END IF;
    END IF;
    RETURN NULL;
END
$$;

CREATE CONSTRAINT TRIGGER login_transactions_callback_owner
AFTER INSERT OR UPDATE OF provider_configuration_id, upstream_state_digest OR DELETE
ON login_transactions
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
EXECUTE FUNCTION owlauth_enforce_provider_callback_owner();

CREATE CONSTRAINT TRIGGER managed_reauthorizations_callback_owner
AFTER INSERT OR UPDATE OF provider_configuration_id, provider_started_at OR DELETE
ON managed_provider_reauthorization_interactions
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
EXECUTE FUNCTION owlauth_enforce_provider_callback_owner();

CREATE CONSTRAINT TRIGGER identity_mutation_slots_callback_owner
AFTER INSERT OR UPDATE OF provider_configuration_id, provider_started_at OR DELETE
ON identity_mutation_proof_slots
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
EXECUTE FUNCTION owlauth_enforce_provider_callback_owner();

CREATE CONSTRAINT TRIGGER provider_callback_owners_reverse_presence
AFTER INSERT OR UPDATE OR DELETE ON provider_callback_owners
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
EXECUTE FUNCTION owlauth_enforce_provider_callback_owner();

-- Existing code has no merge-tombstone writer. Refuse to invent intent provenance for an
-- impossible legacy row, then require every future merge tombstone to name its exact intent.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM project_user_merge_tombstones) THEN
        RAISE EXCEPTION
            'legacy merge tombstones cannot be upgraded to typed identity-mutation evidence';
    END IF;
END
$$;

DO $$
DECLARE
    shape_constraint_name TEXT;
    provider_constraint_name TEXT;
BEGIN
    SELECT constraint_row.conname
      INTO STRICT shape_constraint_name
      FROM pg_constraint AS constraint_row
     WHERE constraint_row.conrelid = 'project_user_merge_tombstones'::regclass
       AND constraint_row.contype = 'c'
       AND pg_get_constraintdef(constraint_row.oid)
           LIKE '%primary_source_kind%primary_provider_identity_id%';

    SELECT constraint_row.conname
      INTO STRICT provider_constraint_name
      FROM pg_constraint AS constraint_row
     WHERE constraint_row.contype = 'f'
       AND constraint_row.conrelid = 'project_user_merge_tombstones'::regclass
       AND constraint_row.confrelid = 'linked_identities'::regclass
       AND ARRAY(
           SELECT attribute.attname::TEXT
             FROM unnest(constraint_row.conkey) WITH ORDINALITY AS key_column(attnum, ordinal)
             JOIN pg_attribute AS attribute
               ON attribute.attrelid = constraint_row.conrelid
              AND attribute.attnum = key_column.attnum
            ORDER BY key_column.ordinal
       ) = ARRAY['project_id','primary_provider_identity_id','winner_user_id']::TEXT[];

    EXECUTE format(
        'ALTER TABLE project_user_merge_tombstones DROP CONSTRAINT %I',
        shape_constraint_name
    );
    EXECUTE format(
        'ALTER TABLE project_user_merge_tombstones DROP CONSTRAINT %I',
        provider_constraint_name
    );
END
$$;

ALTER TABLE project_user_merge_tombstones
    ADD COLUMN identity_mutation_intent_id UUID NOT NULL,
    ADD COLUMN primary_email_identity_id UUID,
    ADD CONSTRAINT project_user_merge_tombstones_intent_unique
        UNIQUE (project_id, identity_mutation_intent_id),
    ADD CONSTRAINT project_user_merge_tombstones_intent_fk
        FOREIGN KEY (project_id, identity_mutation_intent_id)
        REFERENCES identity_mutation_intents (project_id, id),
    ADD CONSTRAINT project_user_merge_tombstones_primary_provider_fk
        FOREIGN KEY (project_id, primary_provider_identity_id)
        REFERENCES linked_identities (project_id, id),
    ADD CONSTRAINT project_user_merge_tombstones_primary_email_fk
        FOREIGN KEY (project_id, primary_email_identity_id)
        REFERENCES email_identities (project_id, id),
    ADD CONSTRAINT project_user_merge_tombstones_primary_shape_check CHECK (
        (primary_source_kind = 'provider'
            AND primary_provider_identity_id IS NOT NULL
            AND primary_email_identity_id IS NULL)
        OR (primary_source_kind = 'email'
            AND primary_provider_identity_id IS NULL
            AND primary_email_identity_id IS NOT NULL)
    );


CREATE FUNCTION owlauth_validate_merge_tombstone_primary_original_owner()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.primary_provider_identity_id IS NOT NULL
        AND NOT EXISTS (
            SELECT 1 FROM linked_identities
             WHERE project_id = NEW.project_id
               AND id = NEW.primary_provider_identity_id
               AND user_id = NEW.winner_user_id
        )
    THEN
        RAISE EXCEPTION 'merge tombstone provider source must belong to its winner at insertion'
            USING ERRCODE = '23514';
    END IF;
    IF NEW.primary_email_identity_id IS NOT NULL
        AND NOT EXISTS (
            SELECT 1 FROM email_identities
             WHERE project_id = NEW.project_id
               AND id = NEW.primary_email_identity_id
               AND user_id = NEW.winner_user_id
        )
    THEN
        RAISE EXCEPTION 'merge tombstone email source must belong to its winner at insertion'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER project_user_merge_tombstones_capture_primary_owner
BEFORE INSERT ON project_user_merge_tombstones
FOR EACH ROW
EXECUTE FUNCTION owlauth_validate_merge_tombstone_primary_original_owner();

CREATE FUNCTION owlauth_validate_merge_tombstone_primary_final_owner()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    target_project_id UUID;
    target_identity_id UUID;
    target_loser_user_id UUID;
    target_identity_kind TEXT;
BEGIN
    IF TG_TABLE_NAME = 'project_user_merge_tombstones' THEN
        target_project_id := CASE WHEN TG_OP = 'DELETE' THEN OLD.project_id ELSE NEW.project_id END;
        target_loser_user_id := CASE
            WHEN TG_OP = 'DELETE' THEN OLD.loser_user_id
            ELSE NEW.loser_user_id
        END;
        target_identity_kind := 'tombstone';
    ELSE
        target_project_id := CASE WHEN TG_OP = 'DELETE' THEN OLD.project_id ELSE NEW.project_id END;
        target_identity_id := CASE WHEN TG_OP = 'DELETE' THEN OLD.id ELSE NEW.id END;
        target_identity_kind := CASE
            WHEN TG_TABLE_NAME = 'linked_identities' THEN 'provider'
            ELSE 'email'
        END;
    END IF;

    PERFORM owlauth_lock_project_identity_graph(target_project_id);
    IF EXISTS (
        SELECT 1
          FROM project_user_merge_tombstones AS tombstone
         WHERE tombstone.project_id = target_project_id
           AND ((target_identity_kind = 'tombstone'
                    AND tombstone.loser_user_id = target_loser_user_id)
                OR (target_identity_kind = 'provider'
                    AND tombstone.primary_provider_identity_id = target_identity_id)
                OR (target_identity_kind = 'email'
                    AND tombstone.primary_email_identity_id = target_identity_id))
           AND ((tombstone.primary_provider_identity_id IS NOT NULL
                    AND NOT EXISTS (
                        SELECT 1 FROM linked_identities AS identity
                         WHERE identity.project_id = tombstone.project_id
                           AND identity.id = tombstone.primary_provider_identity_id
                           AND identity.user_id = tombstone.winner_user_id
                    ))
                OR (tombstone.primary_email_identity_id IS NOT NULL
                    AND NOT EXISTS (
                        SELECT 1 FROM email_identities AS identity
                         WHERE identity.project_id = tombstone.project_id
                           AND identity.id = tombstone.primary_email_identity_id
                           AND identity.user_id = tombstone.winner_user_id
                    )))
    ) THEN
        RAISE EXCEPTION 'merge tombstone primary source must belong to its exact winner'
            USING ERRCODE = '23514';
    END IF;
    RETURN NULL;
END
$$;

CREATE CONSTRAINT TRIGGER project_user_merge_tombstones_final_primary_owner
AFTER INSERT OR UPDATE OR DELETE ON project_user_merge_tombstones
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
EXECUTE FUNCTION owlauth_validate_merge_tombstone_primary_final_owner();

CREATE CONSTRAINT TRIGGER linked_identities_merge_tombstone_primary_owner
AFTER INSERT OR UPDATE OF user_id OR DELETE ON linked_identities
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
EXECUTE FUNCTION owlauth_validate_merge_tombstone_primary_final_owner();

CREATE CONSTRAINT TRIGGER email_identities_merge_tombstone_primary_owner
AFTER INSERT OR UPDATE OF user_id OR DELETE ON email_identities
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
EXECUTE FUNCTION owlauth_validate_merge_tombstone_primary_final_owner();

CREATE FUNCTION owlauth_enforce_project_user_merge_tombstone()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    merge_intent identity_mutation_intents%ROWTYPE;
BEGIN
    SELECT * INTO STRICT merge_intent
      FROM identity_mutation_intents
     WHERE project_id = NEW.project_id
       AND id = NEW.identity_mutation_intent_id;
    IF merge_intent.operation_kind <> 'merge'
        OR merge_intent.status <> 'completed'
        OR merge_intent.winner_user_id <> NEW.winner_user_id
        OR merge_intent.loser_user_id <> NEW.loser_user_id
        OR merge_intent.winner_user_revision <> NEW.winner_user_revision
        OR merge_intent.loser_user_revision <> NEW.loser_user_revision
        OR merge_intent.primary_source_disposition <> NEW.primary_source_kind
        OR merge_intent.primary_provider_identity_id
            IS DISTINCT FROM NEW.primary_provider_identity_id
        OR merge_intent.primary_email_identity_id
            IS DISTINCT FROM NEW.primary_email_identity_id
        OR merge_intent.sessions_disposition <> NEW.sessions_disposition
        OR merge_intent.bindings_disposition <> NEW.bindings_disposition
        OR merge_intent.correlation_id <> NEW.correlation_id
        OR merge_intent.terminal_at IS DISTINCT FROM NEW.merged_at
    THEN
        RAISE EXCEPTION 'merge tombstone must match its exact completed mutation intent'
            USING ERRCODE = '23514';
    END IF;
    RETURN NULL;
END
$$;

CREATE CONSTRAINT TRIGGER project_user_merge_tombstones_exact_intent
AFTER INSERT OR UPDATE ON project_user_merge_tombstones
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
EXECUTE FUNCTION owlauth_enforce_project_user_merge_tombstone();

CREATE FUNCTION owlauth_enforce_identity_mutation_merge_tombstone()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    target_project_id UUID;
    target_intent_id UUID;
    current_intent identity_mutation_intents%ROWTYPE;
    matching_tombstones INTEGER;
BEGIN
    IF TG_TABLE_NAME = 'identity_mutation_intents' THEN
        target_project_id := NEW.project_id;
        target_intent_id := NEW.id;
    ELSE
        target_project_id := CASE WHEN TG_OP = 'DELETE' THEN OLD.project_id ELSE NEW.project_id END;
        target_intent_id := CASE
            WHEN TG_OP = 'DELETE' THEN OLD.identity_mutation_intent_id
            ELSE NEW.identity_mutation_intent_id
        END;
    END IF;

    PERFORM owlauth_lock_project_identity_graph(target_project_id);
    SELECT * INTO current_intent
      FROM identity_mutation_intents
     WHERE project_id = target_project_id AND id = target_intent_id;
    IF NOT FOUND THEN
        RETURN NULL;
    END IF;

    SELECT count(*)::INTEGER INTO matching_tombstones
      FROM project_user_merge_tombstones AS tombstone
     WHERE tombstone.project_id = current_intent.project_id
       AND tombstone.identity_mutation_intent_id = current_intent.id
       AND tombstone.winner_user_id = current_intent.winner_user_id
       AND tombstone.winner_user_revision = current_intent.winner_user_revision
       AND tombstone.loser_user_id = current_intent.loser_user_id
       AND tombstone.loser_user_revision = current_intent.loser_user_revision
       AND tombstone.primary_source_kind = current_intent.primary_source_disposition
       AND tombstone.primary_provider_identity_id
            IS NOT DISTINCT FROM current_intent.primary_provider_identity_id
       AND tombstone.primary_email_identity_id
            IS NOT DISTINCT FROM current_intent.primary_email_identity_id
       AND tombstone.sessions_disposition
            IS NOT DISTINCT FROM current_intent.sessions_disposition
       AND tombstone.bindings_disposition
            IS NOT DISTINCT FROM current_intent.bindings_disposition
       AND tombstone.correlation_id = current_intent.correlation_id
       AND tombstone.merged_at IS NOT DISTINCT FROM current_intent.terminal_at;

    IF current_intent.operation_kind = 'merge' AND current_intent.status = 'completed' THEN
        IF matching_tombstones <> 1 THEN
            RAISE EXCEPTION
                'completed merge intent requires one exact merge tombstone'
                USING ERRCODE = '23514';
        END IF;
    ELSIF EXISTS (
        SELECT 1 FROM project_user_merge_tombstones
         WHERE project_id = current_intent.project_id
           AND identity_mutation_intent_id = current_intent.id
    ) THEN
        RAISE EXCEPTION
            'merge tombstone requires an exact completed merge intent'
            USING ERRCODE = '23514';
    END IF;
    RETURN NULL;
END
$$;

CREATE CONSTRAINT TRIGGER identity_mutation_intents_exact_merge_tombstone
AFTER INSERT OR UPDATE OF operation_kind, status, terminal_at ON identity_mutation_intents
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
EXECUTE FUNCTION owlauth_enforce_identity_mutation_merge_tombstone();

CREATE CONSTRAINT TRIGGER project_user_merge_tombstones_reverse_exact_intent
AFTER INSERT OR UPDATE OR DELETE ON project_user_merge_tombstones
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
EXECUTE FUNCTION owlauth_enforce_identity_mutation_merge_tombstone();

CREATE FUNCTION owlauth_reject_project_user_merge_tombstone_mutation()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'Project-user merge tombstones are immutable'
        USING ERRCODE = '23514';
END
$$;

CREATE TRIGGER project_user_merge_tombstones_immutable
BEFORE UPDATE OR DELETE ON project_user_merge_tombstones
FOR EACH ROW
EXECUTE FUNCTION owlauth_reject_project_user_merge_tombstone_mutation();

-- -----------------------------------------------------------------------------
-- Integrated from pre-release schema slice: 20260801040000_application_sync_webhooks.sql
-- -----------------------------------------------------------------------------

-- Durable Application projection expansion, immutable events, and signed webhook delivery.

CREATE TABLE projection_expansion_operations (
    id UUID PRIMARY KEY,
    project_id UUID NOT NULL REFERENCES projects (id),
    application_id UUID,
    scope_kind TEXT NOT NULL CHECK (scope_kind IN ('project', 'application')),
    target_policy_revision BIGINT NOT NULL CHECK (target_policy_revision > 0),
    status TEXT NOT NULL CHECK (status IN ('pending', 'running', 'completed', 'failed')),
    cursor_binding_id UUID,
    processed_count BIGINT NOT NULL DEFAULT 0 CHECK (processed_count >= 0),
    lease_owner TEXT,
    lease_incarnation UUID,
    lease_generation BIGINT NOT NULL DEFAULT 0 CHECK (lease_generation >= 0),
    lease_expires_at TIMESTAMPTZ,
    last_error_class TEXT,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    completed_at TIMESTAMPTZ,
    CONSTRAINT projection_expansion_scope_check CHECK (
        (scope_kind = 'project' AND application_id IS NULL)
        OR (scope_kind = 'application' AND application_id IS NOT NULL)
    ),
    CONSTRAINT projection_expansion_lease_check CHECK (
        (status = 'running' AND lease_owner IS NOT NULL AND lease_incarnation IS NOT NULL AND lease_expires_at IS NOT NULL)
        OR (status <> 'running' AND lease_owner IS NULL AND lease_incarnation IS NULL AND lease_expires_at IS NULL)
    ),
    CONSTRAINT projection_expansion_completion_check CHECK (
        (status = 'completed' AND completed_at IS NOT NULL)
        OR (status <> 'completed' AND completed_at IS NULL)
    ),
    CONSTRAINT projection_expansion_application_fk
        FOREIGN KEY (project_id, application_id)
        REFERENCES applications (project_id, id)
);

CREATE UNIQUE INDEX projection_expansion_project_revision_uq
    ON projection_expansion_operations (project_id, target_policy_revision)
    WHERE scope_kind = 'project';
CREATE UNIQUE INDEX projection_expansion_application_revision_uq
    ON projection_expansion_operations (project_id, application_id, target_policy_revision)
    WHERE scope_kind = 'application';
CREATE INDEX projection_expansion_claim_idx
    ON projection_expansion_operations (status, lease_expires_at, created_at, id)
    WHERE status IN ('pending', 'running');

CREATE TABLE webhook_endpoints (
    id UUID PRIMARY KEY,
    project_id UUID NOT NULL,
    application_id UUID NOT NULL,
    public_id TEXT NOT NULL UNIQUE,
    idempotency_key TEXT NOT NULL,
    secret_request_fingerprint BYTEA NOT NULL CHECK (octet_length(secret_request_fingerprint) = 32),
    url TEXT NOT NULL,
    subscribed_event_types TEXT[] NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('pending', 'active', 'disabled')),
    revision BIGINT NOT NULL CHECK (revision > 0),
    current_secret_generation INTEGER CHECK (current_secret_generation > 0),
    overlap_secret_generation INTEGER CHECK (overlap_secret_generation > 0),
    overlap_expires_at TIMESTAMPTZ,
    consecutive_failure_count INTEGER NOT NULL DEFAULT 0 CHECK (consecutive_failure_count >= 0),
    last_delivery_at TIMESTAMPTZ,
    last_success_at TIMESTAMPTZ,
    last_failure_class TEXT,
    last_tested_at TIMESTAMPTZ,
    last_test_succeeded_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    disabled_at TIMESTAMPTZ,
    CONSTRAINT webhook_endpoint_application_fk
        FOREIGN KEY (project_id, application_id)
        REFERENCES applications (project_id, id),
    CONSTRAINT webhook_endpoints_scope_uq UNIQUE (project_id, application_id, id),
    CONSTRAINT webhook_endpoint_subscriptions_check CHECK (
        cardinality(subscribed_event_types) BETWEEN 1 AND 3
        AND subscribed_event_types <@ ARRAY[
            'user.projection.created',
            'user.projection.updated',
            'user.projection.disabled'
        ]::TEXT[]
    ),
    CONSTRAINT webhook_endpoint_secret_state_check CHECK (
        (status = 'pending' AND current_secret_generation IS NULL)
        OR (status = 'active' AND current_secret_generation IS NOT NULL)
        OR status = 'disabled'
    ),
    CONSTRAINT webhook_endpoint_overlap_check CHECK (
        (overlap_secret_generation IS NULL AND overlap_expires_at IS NULL)
        OR (
            overlap_secret_generation IS NOT NULL
            AND overlap_expires_at IS NOT NULL
            AND overlap_secret_generation <> current_secret_generation
        )
    ),
    CONSTRAINT webhook_endpoint_disabled_check CHECK (
        (status = 'disabled' AND disabled_at IS NOT NULL)
        OR (status <> 'disabled' AND disabled_at IS NULL)
    ),
    CONSTRAINT webhook_endpoint_test_check CHECK (
        (last_test_succeeded_at IS NULL AND last_tested_at IS NULL)
        OR (
            last_test_succeeded_at IS NOT NULL
            AND last_tested_at IS NOT NULL
            AND last_test_succeeded_at = last_tested_at
        )
    ),
    CONSTRAINT webhook_endpoint_activation_test_check CHECK (
        status <> 'active' OR last_test_succeeded_at IS NOT NULL
    )
);

CREATE UNIQUE INDEX webhook_endpoints_application_url_uq
    ON webhook_endpoints (project_id, application_id, url)
    WHERE status <> 'disabled';
CREATE UNIQUE INDEX webhook_endpoints_idempotency_uq
    ON webhook_endpoints (project_id, application_id, idempotency_key);
CREATE INDEX webhook_endpoints_active_application_idx
    ON webhook_endpoints (project_id, application_id, id)
    WHERE status = 'active';

CREATE SEQUENCE webhook_dispatch_claim_sequence;

CREATE TABLE webhook_application_dispatch_state (
    project_id UUID NOT NULL,
    application_id UUID NOT NULL,
    last_claim_sequence BIGINT NOT NULL DEFAULT 0 CHECK (last_claim_sequence >= 0),
    PRIMARY KEY (project_id, application_id),
    CONSTRAINT webhook_dispatch_application_fk
        FOREIGN KEY (project_id, application_id)
        REFERENCES applications (project_id, id)
);

CREATE TABLE webhook_secret_generations (
    endpoint_id UUID NOT NULL REFERENCES webhook_endpoints (id),
    generation INTEGER NOT NULL CHECK (generation > 0),
    idempotency_key TEXT NOT NULL,
    request_fingerprint BYTEA NOT NULL CHECK (octet_length(request_fingerprint) = 32),
    secret_ref TEXT NOT NULL,
    safe_fingerprint TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('pending', 'active', 'overlap', 'retired', 'compromised')),
    created_at TIMESTAMPTZ NOT NULL,
    provisioned_at TIMESTAMPTZ,
    activated_at TIMESTAMPTZ,
    retired_at TIMESTAMPTZ,
    PRIMARY KEY (endpoint_id, generation),
    CONSTRAINT webhook_secret_activation_check CHECK (
        (state = 'pending' AND activated_at IS NULL AND retired_at IS NULL)
        OR (state IN ('active', 'overlap') AND activated_at IS NOT NULL AND retired_at IS NULL)
        OR (state IN ('retired', 'compromised') AND retired_at IS NOT NULL)
    ),
    CONSTRAINT webhook_secret_provisioning_check CHECK (
        state IN ('pending', 'retired') OR provisioned_at IS NOT NULL
    )
);

CREATE UNIQUE INDEX webhook_secret_ref_uq ON webhook_secret_generations (secret_ref);
CREATE UNIQUE INDEX webhook_secret_idempotency_uq
    ON webhook_secret_generations (endpoint_id, idempotency_key);
CREATE UNIQUE INDEX webhook_secret_one_pending_uq
    ON webhook_secret_generations (endpoint_id)
    WHERE state = 'pending';
CREATE UNIQUE INDEX webhook_secret_one_active_uq
    ON webhook_secret_generations (endpoint_id)
    WHERE state = 'active';
CREATE UNIQUE INDEX webhook_secret_one_overlap_uq
    ON webhook_secret_generations (endpoint_id)
    WHERE state = 'overlap';

ALTER TABLE webhook_endpoints
    ADD CONSTRAINT webhook_endpoint_current_secret_fk
        FOREIGN KEY (id, current_secret_generation)
        REFERENCES webhook_secret_generations (endpoint_id, generation)
        DEFERRABLE INITIALLY DEFERRED,
    ADD CONSTRAINT webhook_endpoint_overlap_secret_fk
        FOREIGN KEY (id, overlap_secret_generation)
        REFERENCES webhook_secret_generations (endpoint_id, generation)
        DEFERRABLE INITIALLY DEFERRED;

CREATE TABLE application_user_events (
    id UUID PRIMARY KEY,
    event_id TEXT NOT NULL UNIQUE,
    project_id UUID NOT NULL,
    application_id UUID NOT NULL,
    binding_id UUID NOT NULL,
    user_id UUID NOT NULL,
    event_type TEXT NOT NULL CHECK (event_type IN (
        'user.projection.created',
        'user.projection.updated',
        'user.projection.disabled'
    )),
    user_revision BIGINT NOT NULL CHECK (user_revision > 0),
    projection_revision BIGINT NOT NULL CHECK (projection_revision > 0),
    projection_schema TEXT NOT NULL CHECK (projection_schema = 'owlauth.user.v1'),
    safe_body JSONB NOT NULL,
    canonical_body_digest BYTEA NOT NULL CHECK (octet_length(canonical_body_digest) = 32),
    verified_email_source_identity_id UUID,
    verified_email_ciphertext BYTEA,
    verified_email_key_version INTEGER,
    occurred_at TIMESTAMPTZ NOT NULL,
    replay_until TIMESTAMPTZ NOT NULL,
    retain_until TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT application_user_event_application_fk
        FOREIGN KEY (project_id, application_id)
        REFERENCES applications (project_id, id),
    CONSTRAINT application_user_event_binding_fk
        FOREIGN KEY (project_id, binding_id, application_id)
        REFERENCES application_user_bindings (project_id, id, application_id),
    CONSTRAINT application_user_event_historical_user_fk
        FOREIGN KEY (project_id, user_id)
        REFERENCES project_users (project_id, id),
    CONSTRAINT application_user_event_email_material_check CHECK (
        (verified_email_source_identity_id IS NULL AND verified_email_ciphertext IS NULL AND verified_email_key_version IS NULL)
        OR (
            verified_email_source_identity_id IS NOT NULL
            AND verified_email_ciphertext IS NOT NULL
            AND verified_email_key_version > 0
        )
    ),
    CONSTRAINT application_user_event_safe_body_check CHECK (
        jsonb_typeof(safe_body) = 'object'
        AND safe_body #> '{data,projection,verified_email}' IS NOT DISTINCT FROM 'null'::JSONB
    ),
    CONSTRAINT application_user_event_retention_check CHECK (
        replay_until > occurred_at AND retain_until > replay_until
    ),
    UNIQUE (project_id, application_id, id)
);

CREATE UNIQUE INDEX application_user_events_binding_revision_uq
    ON application_user_events (binding_id, projection_revision);
CREATE INDEX application_user_events_application_time_idx
    ON application_user_events (project_id, application_id, occurred_at DESC, id DESC);
CREATE INDEX application_user_events_user_revision_idx
    ON application_user_events (project_id, application_id, user_id, projection_revision DESC);
CREATE INDEX application_user_events_retention_idx
    ON application_user_events (retain_until, id);
CREATE INDEX application_user_events_email_key_version_idx
    ON application_user_events (verified_email_key_version)
    WHERE verified_email_key_version IS NOT NULL;
CREATE INDEX application_user_projections_email_key_version_idx
    ON application_user_projections (verified_email_key_version)
    WHERE verified_email_key_version IS NOT NULL;

CREATE TABLE webhook_deliveries (
    id UUID PRIMARY KEY,
    project_id UUID NOT NULL,
    application_id UUID NOT NULL,
    endpoint_id UUID NOT NULL REFERENCES webhook_endpoints (id),
    event_id UUID NOT NULL,
    replay_sequence INTEGER NOT NULL DEFAULT 0 CHECK (replay_sequence >= 0),
    replay_of_delivery_id UUID REFERENCES webhook_deliveries (id),
    state TEXT NOT NULL CHECK (state IN ('pending', 'leased', 'delivered', 'terminal', 'cancelled')),
    attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    next_attempt_at TIMESTAMPTZ NOT NULL,
    lease_owner TEXT,
    lease_incarnation UUID,
    lease_generation BIGINT NOT NULL DEFAULT 0 CHECK (lease_generation >= 0),
    lease_expires_at TIMESTAMPTZ,
    claimed_secret_generation INTEGER,
    claimed_overlap_generation INTEGER,
    last_outcome_class TEXT,
    last_http_status INTEGER CHECK (last_http_status BETWEEN 100 AND 599),
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    delivered_at TIMESTAMPTZ,
    terminal_at TIMESTAMPTZ,
    CONSTRAINT webhook_delivery_scope_fk
        FOREIGN KEY (project_id, application_id, endpoint_id)
        REFERENCES webhook_endpoints (project_id, application_id, id),
    CONSTRAINT webhook_delivery_dispatch_state_fk
        FOREIGN KEY (project_id, application_id)
        REFERENCES webhook_application_dispatch_state (project_id, application_id),
    CONSTRAINT webhook_delivery_event_fk
        FOREIGN KEY (project_id, application_id, event_id)
        REFERENCES application_user_events (project_id, application_id, id),
    CONSTRAINT webhook_delivery_replay_parent_fk
        FOREIGN KEY (
            project_id, application_id, endpoint_id, event_id, replay_of_delivery_id
        ) REFERENCES webhook_deliveries (
            project_id, application_id, endpoint_id, event_id, id
        ),
    CONSTRAINT webhook_delivery_replay_check CHECK (
        (replay_sequence = 0 AND replay_of_delivery_id IS NULL)
        OR (replay_sequence > 0 AND replay_of_delivery_id IS NOT NULL)
    ),
    CONSTRAINT webhook_delivery_lease_check CHECK (
        (
            state = 'leased'
            AND lease_owner IS NOT NULL
            AND lease_incarnation IS NOT NULL
            AND lease_expires_at IS NOT NULL
            AND claimed_secret_generation IS NOT NULL
        )
        OR (
            state <> 'leased'
            AND lease_owner IS NULL
            AND lease_incarnation IS NULL
            AND lease_expires_at IS NULL
            AND claimed_secret_generation IS NULL
            AND claimed_overlap_generation IS NULL
        )
    ),
    CONSTRAINT webhook_delivery_terminal_check CHECK (
        (state = 'delivered' AND delivered_at IS NOT NULL AND terminal_at IS NULL)
        OR (state IN ('terminal', 'cancelled') AND terminal_at IS NOT NULL AND delivered_at IS NULL)
        OR (state IN ('pending', 'leased') AND delivered_at IS NULL AND terminal_at IS NULL)
    ),
    UNIQUE (project_id, application_id, endpoint_id, event_id, id)
);

CREATE UNIQUE INDEX webhook_deliveries_event_endpoint_replay_uq
    ON webhook_deliveries (event_id, endpoint_id, replay_sequence);
CREATE INDEX webhook_deliveries_claim_idx
    ON webhook_deliveries (next_attempt_at, endpoint_id, created_at, id)
    WHERE state = 'pending';
CREATE INDEX webhook_deliveries_expired_lease_idx
    ON webhook_deliveries (lease_expires_at, endpoint_id, id)
    WHERE state = 'leased';
CREATE INDEX webhook_deliveries_endpoint_history_idx
    ON webhook_deliveries (project_id, application_id, endpoint_id, created_at DESC, id DESC);

CREATE TABLE webhook_delivery_attempts (
    delivery_id UUID NOT NULL REFERENCES webhook_deliveries (id),
    attempt_number INTEGER NOT NULL CHECK (attempt_number > 0),
    lease_generation BIGINT NOT NULL CHECK (lease_generation > 0),
    attempted_at TIMESTAMPTZ NOT NULL,
    attempt_timestamp BIGINT NOT NULL CHECK (attempt_timestamp > 0),
    outcome_class TEXT NOT NULL,
    http_status INTEGER CHECK (http_status BETWEEN 100 AND 599),
    duration_millis INTEGER NOT NULL CHECK (duration_millis >= 0),
    correlation_id UUID NOT NULL,
    PRIMARY KEY (delivery_id, attempt_number)
);

CREATE INDEX webhook_delivery_attempts_time_idx
    ON webhook_delivery_attempts (attempted_at DESC, delivery_id);

CREATE FUNCTION reject_application_sync_immutable_mutation()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION '% is append-only', TG_TABLE_NAME;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER application_user_events_append_only
BEFORE UPDATE OR DELETE ON application_user_events
FOR EACH ROW EXECUTE FUNCTION reject_application_sync_immutable_mutation();

CREATE TRIGGER webhook_delivery_attempts_append_only
BEFORE UPDATE OR DELETE ON webhook_delivery_attempts
FOR EACH ROW EXECUTE FUNCTION reject_application_sync_immutable_mutation();

CREATE FUNCTION enforce_webhook_endpoint_immutable_target()
RETURNS TRIGGER AS $$
BEGIN
    IF NEW.project_id <> OLD.project_id
        OR NEW.application_id <> OLD.application_id
        OR NEW.url <> OLD.url
        OR NEW.public_id <> OLD.public_id
    THEN
        RAISE EXCEPTION 'webhook endpoint target identity is immutable';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER webhook_endpoint_immutable_target
BEFORE UPDATE ON webhook_endpoints
FOR EACH ROW EXECUTE FUNCTION enforce_webhook_endpoint_immutable_target();

CREATE FUNCTION enforce_webhook_secret_immutable_material()
RETURNS TRIGGER AS $$
BEGIN
    IF NEW.endpoint_id <> OLD.endpoint_id
        OR NEW.generation <> OLD.generation
        OR NEW.idempotency_key <> OLD.idempotency_key
        OR NEW.request_fingerprint <> OLD.request_fingerprint
        OR NEW.secret_ref <> OLD.secret_ref
        OR NEW.safe_fingerprint <> OLD.safe_fingerprint
        OR NEW.created_at <> OLD.created_at
    THEN
        RAISE EXCEPTION 'webhook secret generation material is immutable';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER webhook_secret_immutable_material
BEFORE UPDATE ON webhook_secret_generations
FOR EACH ROW EXECUTE FUNCTION enforce_webhook_secret_immutable_material();

COMMENT ON TABLE projection_expansion_operations IS
    'Durable bounded convergence for monotonic Project/Application projection-policy revisions; Runtime reads remain authoritative through lazy repair.';
COMMENT ON TABLE application_user_events IS
    'Immutable Application-specific projection snapshots. safe_body never stores verified email plaintext; protected event material and digest preserve exact delivery bytes.';
COMMENT ON TABLE webhook_deliveries IS
    'At-least-once per-endpoint delivery state. Replay creates a new row referencing an existing immutable event and original delivery.';
COMMENT ON TABLE webhook_delivery_attempts IS
    'Append-only safe attempt metadata; response bodies and credentials are never retained.';

-- -----------------------------------------------------------------------------
-- Integrated from pre-release schema slice: 20260801050000_provider_kinds.sql
-- -----------------------------------------------------------------------------

-- Establish the initial forward-compatibility floor for checksum-matching history prefixes. The
-- first released baseline may overlap later additive releases until a reviewed contract migration
-- advances this floor beyond the baseline binary's schema level.
CREATE TABLE schema_compatibility (
    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    minimum_binary_schema_level BIGINT NOT NULL CHECK (minimum_binary_schema_level > 0)
);

INSERT INTO schema_compatibility (singleton, minimum_binary_schema_level)
VALUES (TRUE, 20260803000000);

-- Expand provider dispatch without changing the legacy `kind = 'oidc'` representation. The
-- nullable discriminator protects new writes, while current reads infer exact named issuers when
-- legacy rows are still null. No startup-time inventory rewrite is performed.

ALTER TABLE provider_configurations
    ADD COLUMN adapter_kind TEXT;

ALTER TABLE provider_configurations
    ADD CONSTRAINT provider_configurations_adapter_kind_check
        CHECK (adapter_kind IS NULL OR adapter_kind IN ('oidc', 'google', 'github'))
        NOT VALID,
    ADD CONSTRAINT provider_configurations_named_adapter_check CHECK (
        adapter_kind IS NULL
        OR (kind = 'oidc' AND (
            (adapter_kind = 'oidc' AND issuer NOT IN (
                'https://accounts.google.com',
                'https://github.com'
            ))
            OR (adapter_kind = 'google' AND issuer = 'https://accounts.google.com')
            OR (adapter_kind = 'github'
                AND issuer = 'https://github.com'
                AND NOT managed_profile_enabled)
        ))
    ) NOT VALID;

CREATE FUNCTION fill_provider_adapter_kind_compatibility()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.kind <> 'oidc' THEN
        RAISE EXCEPTION 'legacy provider kind must remain oidc'
            USING ERRCODE = '23514';
    END IF;

    IF NEW.adapter_kind IS NULL THEN
        NEW.adapter_kind := CASE NEW.issuer
            WHEN 'https://accounts.google.com' THEN 'google'
            WHEN 'https://github.com' THEN 'github'
            ELSE 'oidc'
        END;
    ELSIF TG_OP = 'UPDATE'
        AND OLD.adapter_kind IS NOT NULL
        AND NEW.adapter_kind <> OLD.adapter_kind
    THEN
        RAISE EXCEPTION 'provider adapter kind is immutable'
            USING ERRCODE = '23514';
    END IF;

    IF NOT (
        (NEW.adapter_kind = 'oidc' AND NEW.issuer NOT IN (
            'https://accounts.google.com',
            'https://github.com'
        ))
        OR (NEW.adapter_kind = 'google' AND NEW.issuer = 'https://accounts.google.com')
        OR (NEW.adapter_kind = 'github'
            AND NEW.issuer = 'https://github.com'
            AND NOT NEW.managed_profile_enabled)
    ) THEN
        RAISE EXCEPTION 'provider adapter kind is inconsistent with issuer or capabilities'
            USING ERRCODE = '23514';
    END IF;

    RETURN NEW;
END
$$;

CREATE TRIGGER provider_adapter_kind_compatibility
BEFORE INSERT OR UPDATE OF kind, adapter_kind, issuer, managed_profile_enabled
ON provider_configurations
FOR EACH ROW
EXECUTE FUNCTION fill_provider_adapter_kind_compatibility();

-- Existing exact Google and GitHub issuers are adopted lazily by the same closed issuer inference
-- used for omitted-kind writes. This avoids an unbounded synchronous backfill and preserves stable
-- provider IDs, keys, assignments, statuses, and semantic revisions. New or subsequently updated
-- rows are materialized by the compatibility trigger.
CREATE INDEX provider_configurations_adapter_kind_backfill_idx
    ON provider_configurations (id)
    WHERE adapter_kind IS NULL;

-- Managed reauthorization freezes adapter dispatch. The compatibility trigger derives the value
-- for preceding binaries whose INSERT column list does not include `provider_kind`.
ALTER TABLE managed_provider_reauthorization_interactions
    ADD COLUMN provider_kind TEXT;

ALTER TABLE managed_provider_reauthorization_interactions
    ADD CONSTRAINT managed_reauthorization_provider_kind_check
        CHECK (provider_kind IS NULL OR provider_kind IN ('oidc', 'google'))
        NOT VALID;

CREATE FUNCTION fill_managed_reauthorization_provider_kind_compatibility()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    authoritative_kind TEXT;
BEGIN
    SELECT COALESCE(
               provider.adapter_kind,
               CASE provider.issuer
                   WHEN 'https://accounts.google.com' THEN 'google'
                   WHEN 'https://github.com' THEN 'github'
                   ELSE 'oidc'
               END
           )
      INTO authoritative_kind
      FROM provider_configurations AS provider
     WHERE provider.project_id = NEW.project_id
       AND provider.id = NEW.provider_configuration_id
     FOR KEY SHARE;

    IF authoritative_kind IS NULL OR authoritative_kind NOT IN ('oidc', 'google') THEN
        RAISE EXCEPTION 'provider does not support managed reauthorization'
            USING ERRCODE = '23514';
    END IF;

    IF NEW.provider_kind IS NULL THEN
        NEW.provider_kind := authoritative_kind;
    ELSIF NEW.provider_kind <> authoritative_kind THEN
        RAISE EXCEPTION 'managed reauthorization provider kind mismatch'
            USING ERRCODE = '23514';
    END IF;

    RETURN NEW;
END
$$;

CREATE TRIGGER managed_reauthorization_provider_kind_compatibility
BEFORE INSERT ON managed_provider_reauthorization_interactions
FOR EACH ROW
EXECUTE FUNCTION fill_managed_reauthorization_provider_kind_compatibility();

CREATE INDEX managed_reauthorization_provider_kind_backfill_idx
    ON managed_provider_reauthorization_interactions (id)
    WHERE provider_kind IS NULL;

-- New writes are protected immediately without forcing a startup-time scan of the complete
-- identity directory. A later bounded inventory may validate this constraint.
ALTER TABLE linked_identities
    ADD CONSTRAINT linked_identities_github_numeric_subject_check CHECK (
        issuer <> 'https://github.com'
        OR subject ~ '^[1-9][0-9]{0,19}$'
    ) NOT VALID;

-- A fresh baseline has no legacy rows to backfill. Close the temporary expansion shapes inside
-- this same migration so the installed schema exposes only the final non-null authorities.
ALTER TABLE provider_configurations
    VALIDATE CONSTRAINT provider_configurations_adapter_kind_check;
ALTER TABLE provider_configurations
    VALIDATE CONSTRAINT provider_configurations_named_adapter_check;
ALTER TABLE provider_configurations
    ALTER COLUMN adapter_kind SET NOT NULL;
DROP INDEX provider_configurations_adapter_kind_backfill_idx;

ALTER TABLE managed_provider_reauthorization_interactions
    VALIDATE CONSTRAINT managed_reauthorization_provider_kind_check;
ALTER TABLE managed_provider_reauthorization_interactions
    ALTER COLUMN provider_kind SET NOT NULL;
DROP INDEX managed_reauthorization_provider_kind_backfill_idx;

ALTER TABLE linked_identities
    VALIDATE CONSTRAINT linked_identities_github_numeric_subject_check;

-- -----------------------------------------------------------------------------
-- Integrated from pre-release schema slice: application sync hardening
-- -----------------------------------------------------------------------------
-- -----------------------------------------------------------------------------

-- Durable webhook-secret erasure and bounded Application event retention.

CREATE TABLE webhook_secret_cleanup_operations (
    id UUID PRIMARY KEY,
    endpoint_id UUID NOT NULL,
    generation INTEGER NOT NULL CHECK (generation > 0),
    secret_ref TEXT NOT NULL CHECK (char_length(secret_ref) BETWEEN 1 AND 512),
    state TEXT NOT NULL CHECK (state IN ('pending', 'leased', 'erased')),
    lease_owner TEXT,
    lease_incarnation UUID,
    lease_generation BIGINT NOT NULL DEFAULT 0 CHECK (lease_generation >= 0),
    lease_expires_at TIMESTAMPTZ,
    not_before TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    erased_at TIMESTAMPTZ,
    CONSTRAINT webhook_secret_cleanup_generation_fk
        FOREIGN KEY (endpoint_id, generation)
        REFERENCES webhook_secret_generations (endpoint_id, generation),
    CONSTRAINT webhook_secret_cleanup_generation_uq UNIQUE (endpoint_id, generation),
    CONSTRAINT webhook_secret_cleanup_ref_uq UNIQUE (secret_ref),
    CONSTRAINT webhook_secret_cleanup_lease_check CHECK (
        (state = 'leased' AND lease_owner IS NOT NULL AND lease_incarnation IS NOT NULL
            AND lease_expires_at IS NOT NULL)
        OR (state <> 'leased' AND lease_owner IS NULL AND lease_incarnation IS NULL
            AND lease_expires_at IS NULL)
    ),
    CONSTRAINT webhook_secret_cleanup_erased_check CHECK (
        (state = 'erased') = (erased_at IS NOT NULL)
    )
);

CREATE INDEX webhook_secret_cleanup_claim_idx
    ON webhook_secret_cleanup_operations (state, not_before, lease_expires_at, created_at, id)
    WHERE state IN ('pending', 'leased');

CREATE TABLE webhook_secret_reference_reservations (
    secret_ref TEXT PRIMARY KEY CHECK (char_length(secret_ref) BETWEEN 1 AND 512),
    state TEXT NOT NULL CHECK (state IN ('live', 'reserved', 'erased')),
    cleanup_id UUID REFERENCES webhook_secret_cleanup_operations (id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    erased_at TIMESTAMPTZ,
    CONSTRAINT webhook_secret_reservation_cleanup_check CHECK (
        (state = 'reserved') = (cleanup_id IS NOT NULL)
    ),
    CONSTRAINT webhook_secret_reservation_erased_check CHECK (
        (state = 'erased') = (erased_at IS NOT NULL)
    )
);

INSERT INTO webhook_secret_reference_reservations (secret_ref, state)
SELECT secret_ref, 'live' FROM webhook_secret_generations;

CREATE FUNCTION enforce_webhook_secret_reference_lifecycle()
RETURNS TRIGGER AS $$
DECLARE
    reservation_state TEXT;
BEGIN
    SELECT state INTO reservation_state
      FROM webhook_secret_reference_reservations
     WHERE secret_ref = NEW.secret_ref;
    IF reservation_state IS DISTINCT FROM 'live' THEN
        RAISE EXCEPTION 'webhook secret reference is not live';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER webhook_secret_reference_lifecycle
BEFORE INSERT ON webhook_secret_generations
FOR EACH ROW EXECUTE FUNCTION enforce_webhook_secret_reference_lifecycle();

-- Retention cleanup is the only permitted delete path. The database clock and complete terminal
-- delivery state remain authoritative even if a caller attempts a direct delete.
CREATE OR REPLACE FUNCTION reject_application_sync_immutable_mutation()
RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP = 'DELETE'
       AND OLD.retain_until <= transaction_timestamp()
       AND NOT EXISTS (
           SELECT 1 FROM webhook_deliveries delivery
            WHERE delivery.event_id = OLD.id
              AND delivery.state NOT IN ('delivered', 'terminal', 'cancelled')
       )
    THEN
        RETURN OLD;
    END IF;
    RAISE EXCEPTION '% is append-only', TG_TABLE_NAME;
END;
$$ LANGUAGE plpgsql;

CREATE FUNCTION reject_webhook_attempt_immutable_mutation()
RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP = 'DELETE'
       AND EXISTS (
           SELECT 1
             FROM webhook_deliveries delivery
             JOIN application_user_events event ON event.id = delivery.event_id
            WHERE delivery.id = OLD.delivery_id
              AND delivery.state IN ('delivered', 'terminal', 'cancelled')
              AND event.retain_until <= transaction_timestamp()
       )
    THEN
        RETURN OLD;
    END IF;
    RAISE EXCEPTION '% is append-only', TG_TABLE_NAME;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER webhook_delivery_attempts_append_only ON webhook_delivery_attempts;
CREATE TRIGGER webhook_delivery_attempts_append_only
BEFORE UPDATE OR DELETE ON webhook_delivery_attempts
FOR EACH ROW EXECUTE FUNCTION reject_webhook_attempt_immutable_mutation();

COMMENT ON TABLE webhook_secret_cleanup_operations IS
    'Restart-safe Runtime authority for permanent webhook secret alias erasure.';
COMMENT ON TABLE webhook_secret_reference_reservations IS
    'Database-side live -> reserved -> erased lifecycle tombstone for each webhook secret alias.';
