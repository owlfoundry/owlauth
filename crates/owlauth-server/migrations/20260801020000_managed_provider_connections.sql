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
