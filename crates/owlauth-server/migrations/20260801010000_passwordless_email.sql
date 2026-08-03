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
