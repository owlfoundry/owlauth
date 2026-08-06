-- Install custody functions and integrity triggers only after every typed owner column, unique
-- authority, backfill, and validation step has completed.

-- The pre-release immutable trigger predates protected material finalization. Keep generation identity
-- immutable while allowing the one pending-to-live safe-fingerprint write.
CREATE OR REPLACE FUNCTION enforce_webhook_secret_immutable_material()
RETURNS TRIGGER AS $$
DECLARE
    guarded_import_attachment BOOLEAN := FALSE;
BEGIN
    IF OLD.material_id IS NULL AND NEW.material_id IS NOT NULL THEN
        SELECT EXISTS (
            SELECT 1
            FROM custody_cutover_authority AS authority
            JOIN protected_materials AS material
              ON material.id = NEW.material_id
             AND material.owner_kind = 'webhook_secret'
             AND material.owner_id = NEW.endpoint_id
             AND material.generation = NEW.generation
             AND material.project_id = (
                 SELECT endpoint.project_id
                 FROM webhook_endpoints AS endpoint
                 WHERE endpoint.id = NEW.endpoint_id
             )
             AND material.custody_mode = 'importing'
             AND material.custody_revision = authority.revision
            WHERE authority.singleton
              AND authority.mode = 'importing'
        ) INTO guarded_import_attachment;
    END IF;

    IF NEW.endpoint_id IS DISTINCT FROM OLD.endpoint_id
        OR NEW.generation IS DISTINCT FROM OLD.generation
        OR NEW.idempotency_key IS DISTINCT FROM OLD.idempotency_key
        OR NEW.request_fingerprint IS DISTINCT FROM OLD.request_fingerprint
        OR NEW.secret_ref IS DISTINCT FROM OLD.secret_ref
        OR (
            NEW.material_id IS DISTINCT FROM OLD.material_id
            AND NOT guarded_import_attachment
        )
        OR NEW.created_at IS DISTINCT FROM OLD.created_at
        OR (
            NEW.safe_fingerprint IS DISTINCT FROM OLD.safe_fingerprint
            AND NOT (
                (
                    OLD.safe_fingerprint IS NULL
                    AND NEW.safe_fingerprint IS NOT NULL
                    AND OLD.state = 'pending'
                )
                OR (
                    guarded_import_attachment
                    AND NEW.safe_fingerprint IS NOT NULL
                )
            )
        )
    THEN
        RAISE EXCEPTION 'webhook secret generation material is immutable';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;


-- Live material must be attached to the exact typed owner by the final commit. Pending reservations
-- intentionally have no owner attachment yet. A never-finalized pending configuration-secret
-- reservation may be erased without publishing an owner attachment; its immutable tuple remains the
-- cleanup tombstone. Signing material always requires its owner because an external key may exist.
CREATE FUNCTION owlauth_validate_protected_material_owner()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    owner_matches BOOLEAN;
BEGIN
    IF NEW.state = 'pending'
        OR (
            TG_OP = 'UPDATE'
            AND OLD.state = 'pending'
            AND NEW.state = 'erased'
            AND NEW.material_kind = 'configuration_secret'
        )
    THEN
        RETURN NEW;
    END IF;

    owner_matches := CASE NEW.owner_kind
        WHEN 'signing_key' THEN EXISTS (
            SELECT 1
            FROM project_signing_keys AS owner
            WHERE owner.id = NEW.owner_id
              AND owner.project_id = NEW.project_id
              AND owner.signer_material_generation = NEW.generation
              AND owner.signer_material_id = NEW.id
        )
        WHEN 'provider_secret' THEN EXISTS (
            SELECT 1
            FROM provider_configurations AS owner
            WHERE owner.id = NEW.owner_id
              AND owner.project_id = NEW.project_id
              AND owner.secret_generation = NEW.generation
              AND owner.secret_material_id = NEW.id
        )
        WHEN 'project_smtp' THEN EXISTS (
            SELECT 1
            FROM project_smtp_configurations AS owner
            WHERE owner.id = NEW.owner_id
              AND owner.project_id = NEW.project_id
              AND owner.generation = NEW.generation
              AND owner.credential_material_id = NEW.id
        )
        WHEN 'deployment_smtp' THEN EXISTS (
            SELECT 1
            FROM deployment_smtp_generations AS owner
            WHERE owner.material_owner_id = NEW.owner_id
              AND owner.generation = NEW.generation
              AND owner.credential_material_id = NEW.id
              AND NEW.project_id IS NULL
        )
        WHEN 'smtp_test_recipient' THEN EXISTS (
            SELECT 1
            FROM project_smtp_test_operations AS owner
            WHERE owner.id = NEW.owner_id
              AND owner.project_id = NEW.project_id
              AND NEW.generation = 1
              AND owner.recipient_material_id = NEW.id
        )
        WHEN 'webhook_secret' THEN EXISTS (
            SELECT 1
            FROM webhook_secret_generations AS secret
            JOIN webhook_endpoints AS owner ON owner.id = secret.endpoint_id
            WHERE owner.id = NEW.owner_id
              AND owner.project_id = NEW.project_id
              AND secret.generation = NEW.generation
              AND secret.material_id = NEW.id
        )
        ELSE FALSE
    END;

    IF NOT owner_matches THEN
        RAISE EXCEPTION 'protected material owner tuple is inconsistent'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE CONSTRAINT TRIGGER protected_material_owner_integrity
AFTER INSERT OR UPDATE OF project_id, owner_kind, owner_id, generation, state
ON protected_materials
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
EXECUTE FUNCTION owlauth_validate_protected_material_owner();

-- A stable material identity, provider dispatch tuple, context, owner, and generation cannot be
-- retargeted. Lifecycle may only replace opaque bytes while pending/live or erase them terminally.
CREATE FUNCTION owlauth_protected_material_identity_immutable()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF ROW(
        NEW.id,
        NEW.scope_kind,
        NEW.project_id,
        NEW.owner_kind,
        NEW.owner_id,
        NEW.generation,
        NEW.material_kind,
        NEW.provider_id,
        NEW.provider_format_version,
        NEW.context_version,
        NEW.context_digest,
        NEW.custody_mode,
        NEW.custody_revision,
        NEW.created_at
    ) IS DISTINCT FROM ROW(
        OLD.id,
        OLD.scope_kind,
        OLD.project_id,
        OLD.owner_kind,
        OLD.owner_id,
        OLD.generation,
        OLD.material_kind,
        OLD.provider_id,
        OLD.provider_format_version,
        OLD.context_version,
        OLD.context_digest,
        OLD.custody_mode,
        OLD.custody_revision,
        OLD.created_at
    ) THEN
        RAISE EXCEPTION 'protected material identity is immutable'
            USING ERRCODE = '23514';
    END IF;
    IF OLD.state = 'erased' AND NEW IS DISTINCT FROM OLD THEN
        RAISE EXCEPTION 'erased protected material is immutable'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER protected_material_identity_immutable
BEFORE UPDATE ON protected_materials
FOR EACH ROW
EXECUTE FUNCTION owlauth_protected_material_identity_immutable();
