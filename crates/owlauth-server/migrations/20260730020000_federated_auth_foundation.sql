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
