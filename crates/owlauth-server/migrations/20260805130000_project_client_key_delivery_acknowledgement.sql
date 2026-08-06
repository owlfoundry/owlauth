-- Persist only the safe fact that an operator confirmed external storage of a one-time
-- Project client credential. Raw credential bytes remain non-durable.

ALTER TABLE project_client_keys
    ADD COLUMN credential_acknowledged_at TIMESTAMPTZ;

-- Rows created before this protocol existed already completed the legacy delivery flow. Treat
-- those historical rows as acknowledged so an upgrade does not unexpectedly block rotation.
UPDATE project_client_keys
SET credential_acknowledged_at = created_at
WHERE status = 'active';

ALTER TABLE project_client_keys
    ADD CONSTRAINT project_client_keys_acknowledged_after_create
    CHECK (
        credential_acknowledged_at IS NULL
        OR credential_acknowledged_at >= created_at
    );

-- The Project row lock is the transaction-level serialization authority. This index additionally
-- makes the fail-closed invariant durable against accidental writers outside that repository.
CREATE UNIQUE INDEX project_client_keys_one_unacknowledged_active_idx
    ON project_client_keys (project_id)
    WHERE status = 'active' AND credential_acknowledged_at IS NULL;

CREATE OR REPLACE FUNCTION enforce_project_client_key_lifecycle()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.credential_acknowledged_at IS NOT NULL THEN
            RAISE EXCEPTION 'new project client key delivery cannot start acknowledged'
                USING ERRCODE = '23514';
        END IF;
        RETURN NEW;
    END IF;

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
            OR NEW.credential_acknowledged_at IS DISTINCT FROM OLD.credential_acknowledged_at
        THEN
            RAISE EXCEPTION 'invalid project client key revocation transition'
                USING ERRCODE = '23514';
        END IF;
        RETURN NEW;
    END IF;

    IF OLD.credential_acknowledged_at IS NULL
        AND NEW.credential_acknowledged_at IS NOT NULL
    THEN
        IF NEW.status <> 'active'
            OR NEW.revision <> OLD.revision + 1
            OR NEW.revoked_at IS NOT NULL
            OR NEW.label IS DISTINCT FROM OLD.label
            OR NEW.last_used_at IS DISTINCT FROM OLD.last_used_at
        THEN
            RAISE EXCEPTION 'invalid project client key delivery acknowledgement'
                USING ERRCODE = '23514';
        END IF;
        RETURN NEW;
    END IF;

    IF NEW.status <> 'active'
        OR NEW.revision <> OLD.revision
        OR NEW.revoked_at IS NOT NULL
        OR NEW.label IS DISTINCT FROM OLD.label
        OR NEW.credential_acknowledged_at IS DISTINCT FROM OLD.credential_acknowledged_at
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

DROP TRIGGER project_client_keys_lifecycle ON project_client_keys;
CREATE TRIGGER project_client_keys_lifecycle
BEFORE INSERT OR UPDATE ON project_client_keys
FOR EACH ROW
EXECUTE FUNCTION enforce_project_client_key_lifecycle();
