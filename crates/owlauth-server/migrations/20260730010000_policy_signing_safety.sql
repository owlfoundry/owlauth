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
