-- Add Project-scoped customer-backend credentials and verifier-fleet readiness authority.
-- Raw client credentials are never durable: only one purpose/owner-bound digest is stored.

CREATE TABLE project_client_keys (
    id UUID PRIMARY KEY,
    project_id UUID NOT NULL REFERENCES projects (id) ON DELETE RESTRICT,
    public_key_id TEXT NOT NULL UNIQUE
        CHECK (public_key_id COLLATE "C" ~ '^[A-Za-z0-9_-]{22}$'),
    label TEXT NOT NULL
        CHECK (
            char_length(label) BETWEEN 1 AND 64
            AND label = btrim(label)
            AND label !~ '[[:cntrl:]]'
        ),
    status TEXT NOT NULL CHECK (status IN ('active', 'revoked')),
    digest_key_version INTEGER NOT NULL CHECK (digest_key_version > 0),
    credential_digest BYTEA NOT NULL CHECK (octet_length(credential_digest) = 32),
    display_prefix TEXT NOT NULL
        CHECK (display_prefix = 'owl_client_v1.' || public_key_id),
    revision BIGINT NOT NULL CHECK (revision > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    last_used_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    UNIQUE (project_id, id),
    CHECK (
        (status = 'active' AND revoked_at IS NULL)
        OR (status = 'revoked' AND revoked_at IS NOT NULL)
    ),
    CHECK (last_used_at IS NULL OR last_used_at >= created_at),
    CHECK (revoked_at IS NULL OR revoked_at >= created_at)
);

CREATE INDEX project_client_keys_project_created_idx
    ON project_client_keys (project_id, created_at, id);

-- Client directory pagination includes every lifecycle status, so it needs an index without
-- `status` between the Project qualifier and immutable keyset ordering tuple.
CREATE INDEX project_users_client_list_idx
    ON project_users (project_id, created_at, id);

CREATE INDEX project_client_keys_active_project_idx
    ON project_client_keys (project_id, id)
    WHERE status = 'active';

CREATE FUNCTION enforce_project_client_key_lifecycle()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.id IS DISTINCT FROM OLD.id
        OR NEW.project_id IS DISTINCT FROM OLD.project_id
        OR NEW.public_key_id IS DISTINCT FROM OLD.public_key_id
        OR NEW.digest_key_version IS DISTINCT FROM OLD.digest_key_version
        OR NEW.credential_digest IS DISTINCT FROM OLD.credential_digest
        OR NEW.display_prefix IS DISTINCT FROM OLD.display_prefix
        OR NEW.created_at IS DISTINCT FROM OLD.created_at
    THEN
        RAISE EXCEPTION 'project client key immutable authority changed'
            USING ERRCODE = '23514';
    END IF;

    IF OLD.status = 'revoked' THEN
        RAISE EXCEPTION 'revoked project client key is immutable'
            USING ERRCODE = '23514';
    END IF;

    IF NEW.status = 'revoked' THEN
        IF NEW.revision <> OLD.revision + 1
            OR NEW.revoked_at IS NULL
            OR NEW.label IS DISTINCT FROM OLD.label
            OR NEW.last_used_at IS DISTINCT FROM OLD.last_used_at
        THEN
            RAISE EXCEPTION 'invalid project client key revocation transition'
                USING ERRCODE = '23514';
        END IF;
        RETURN NEW;
    END IF;

    IF NEW.status <> 'active'
        OR NEW.revision <> OLD.revision
        OR NEW.revoked_at IS NOT NULL
        OR NEW.label IS DISTINCT FROM OLD.label
        OR (NEW.last_used_at IS NULL AND OLD.last_used_at IS NOT NULL)
        OR (
            NEW.last_used_at IS NOT NULL
            AND OLD.last_used_at IS NOT NULL
            AND NEW.last_used_at < OLD.last_used_at
        )
    THEN
        RAISE EXCEPTION 'invalid project client key usage update'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER project_client_keys_lifecycle
BEFORE UPDATE ON project_client_keys
FOR EACH ROW
EXECUTE FUNCTION enforce_project_client_key_lifecycle();

CREATE TABLE client_process_incarnations (
    process_id TEXT PRIMARY KEY
        CHECK (process_id COLLATE "C" ~ '^[A-Za-z0-9._:-]{1,128}$'),
    process_incarnation UUID NOT NULL,
    started_at TIMESTAMPTZ NOT NULL,
    UNIQUE (process_id, process_incarnation)
);

CREATE TABLE client_key_digest_readiness (
    process_id TEXT PRIMARY KEY,
    process_incarnation UUID NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('ready', 'failed')),
    supported_digest_versions INTEGER[] NOT NULL,
    failure_class TEXT,
    checked_at TIMESTAMPTZ NOT NULL,
    lease_expires_at TIMESTAMPTZ NOT NULL,
    FOREIGN KEY (process_id, process_incarnation)
        REFERENCES client_process_incarnations (process_id, process_incarnation)
        ON DELETE CASCADE,
    CHECK (
        cardinality(supported_digest_versions) <= 32
        AND array_position(supported_digest_versions, NULL) IS NULL
        AND 0 < ALL (supported_digest_versions)
    ),
    CHECK (
        (state = 'ready' AND cardinality(supported_digest_versions) BETWEEN 1 AND 32
            AND failure_class IS NULL)
        OR (state = 'failed' AND cardinality(supported_digest_versions) = 0
            AND failure_class IS NOT NULL
            AND char_length(failure_class) BETWEEN 1 AND 64)
    ),
    CHECK (
        lease_expires_at > checked_at
        AND lease_expires_at <= checked_at + INTERVAL '5 minutes'
    )
);

CREATE INDEX client_key_digest_readiness_lease_idx
    ON client_key_digest_readiness (lease_expires_at, process_id);
