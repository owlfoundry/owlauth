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
