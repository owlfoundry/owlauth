-- Freeze the bounded provider display used by each managed reauthorization ceremony.
-- The compatibility trigger preserves rolling writes from preceding binaries while ensuring that
-- new explicit snapshots match the authoritative provider row locked by the create transaction.

ALTER TABLE managed_provider_reauthorization_interactions
    ADD COLUMN provider_display_name TEXT;

ALTER TABLE managed_provider_reauthorization_interactions
    ADD CONSTRAINT managed_reauthorization_provider_display_name_check
        CHECK (
            provider_display_name IS NULL
            OR char_length(provider_display_name) BETWEEN 1 AND 128
        ) NOT VALID;

CREATE FUNCTION fill_managed_reauthorization_provider_display_name_compatibility()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    authoritative_display_name TEXT;
BEGIN
    SELECT display_name
      INTO STRICT authoritative_display_name
      FROM provider_configurations
     WHERE project_id = NEW.project_id
       AND id = NEW.provider_configuration_id;

    IF NEW.provider_display_name IS NULL THEN
        NEW.provider_display_name := authoritative_display_name;
    ELSIF NEW.provider_display_name <> authoritative_display_name THEN
        RAISE EXCEPTION 'managed reauthorization provider display mismatch'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER managed_reauthorization_provider_display_name_compatibility
BEFORE INSERT ON managed_provider_reauthorization_interactions
FOR EACH ROW
EXECUTE FUNCTION fill_managed_reauthorization_provider_display_name_compatibility();

UPDATE managed_provider_reauthorization_interactions AS interaction
   SET provider_display_name = provider.display_name
  FROM provider_configurations AS provider
 WHERE provider.project_id = interaction.project_id
   AND provider.id = interaction.provider_configuration_id
   AND interaction.provider_display_name IS NULL;

ALTER TABLE managed_provider_reauthorization_interactions
    VALIDATE CONSTRAINT managed_reauthorization_provider_display_name_check;
ALTER TABLE managed_provider_reauthorization_interactions
    ALTER COLUMN provider_display_name SET NOT NULL;

-- The original stable-authority trigger predates the custody, provider-kind, egress-policy, and
-- presentation expansions. Keep its original authority closure, but delegate the dual-form secret
-- snapshot to the compatibility-aware trigger below so a fenced legacy -> protected import remains
-- possible exactly once.
DROP TRIGGER managed_reauthorization_stable_authority
    ON managed_provider_reauthorization_interactions;
CREATE TRIGGER managed_reauthorization_stable_authority
BEFORE UPDATE ON managed_provider_reauthorization_interactions
FOR EACH ROW
EXECUTE FUNCTION reject_immutable_column_change(
    'project_id', 'project_public_id', 'connection_id', 'linked_identity_id', 'user_id',
    'provider_configuration_id', 'provider_key', 'issuer', 'subject', 'client_id',
    'application_id', 'expected_connection_generation',
    'expected_credential_generation', 'expected_connection_revision',
    'project_security_revision', 'user_security_revision', 'identity_revision',
    'provider_revision', 'managed_profile_revision', 'application_revision',
    'assignment_security_revision', 'callback_url', 'adapter_key',
    'adapter_capability_revision', 'required_scopes', 'provider_pkce_required',
    'oidc_nonce_required', 'created_at'
);

CREATE FUNCTION owlauth_validate_managed_reauthorization_expanded_authority_update()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    bridge_state TEXT;
    custody_mode TEXT;
BEGIN
    IF NEW.provider_kind IS DISTINCT FROM OLD.provider_kind THEN
        RAISE EXCEPTION 'managed reauthorization provider kind is immutable'
            USING ERRCODE = '23514';
    END IF;

    IF NEW.provider_display_name IS DISTINCT FROM OLD.provider_display_name THEN
        RAISE EXCEPTION 'managed reauthorization provider display is immutable'
            USING ERRCODE = '23514';
    END IF;

    IF NEW.provider_egress_policy_revision
       IS DISTINCT FROM OLD.provider_egress_policy_revision THEN
        SELECT state INTO STRICT bridge_state
          FROM provider_egress_policy_bridge_authority
         WHERE singleton;
        IF NOT (
            bridge_state = 'pending'
            AND OLD.provider_kind = 'oidc'
            AND OLD.provider_egress_policy_revision IS NULL
            AND NEW.provider_egress_policy_revision = 1
            AND EXISTS (
                SELECT 1
                  FROM project_provider_egress_policies AS policy
                 WHERE policy.project_id = NEW.project_id
                   AND policy.revision = 1
            )
        ) THEN
            RAISE EXCEPTION 'managed reauthorization provider egress authority is immutable'
                USING ERRCODE = '23514';
        END IF;
    END IF;

    IF NEW.secret_ref IS DISTINCT FROM OLD.secret_ref
       OR NEW.secret_material_id IS DISTINCT FROM OLD.secret_material_id THEN
        SELECT mode INTO STRICT custody_mode
          FROM custody_cutover_authority
         WHERE singleton;
        IF NOT (
            custody_mode = 'importing'
            AND OLD.secret_ref IS NOT NULL
            AND OLD.secret_material_id IS NULL
            AND NEW.secret_ref IS NULL
            AND NEW.secret_material_id IS NOT NULL
            AND EXISTS (
                SELECT 1
                  FROM protected_materials AS material
                 WHERE material.id = NEW.secret_material_id
                   AND material.scope_kind = 'project'
                   AND material.project_id = NEW.project_id
                   AND material.owner_kind = 'provider_secret'
                   AND material.owner_id = NEW.provider_configuration_id
                   AND material.state = 'live'
            )
        ) THEN
            RAISE EXCEPTION 'managed reauthorization provider secret authority is immutable'
                USING ERRCODE = '23514';
        END IF;
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER managed_reauthorization_expanded_authority
BEFORE UPDATE OF provider_kind, provider_egress_policy_revision, secret_ref, secret_material_id,
                 provider_display_name
ON managed_provider_reauthorization_interactions
FOR EACH ROW
EXECUTE FUNCTION owlauth_validate_managed_reauthorization_expanded_authority_update();
