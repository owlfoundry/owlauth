-- Retire issuer-derived compatibility behavior and install descriptive authority metadata without
-- retaining locks acquired by populated-table expansion or index construction.

COMMENT ON TABLE project_provider_egress_policies IS
    'Project authority for Custom OIDC origins. allow_all stores []; exact_origins stores 1-1024 sorted unique canonical origins.';
COMMENT ON TABLE provider_egress_policy_bridge_authority IS
    'Bounded legacy deployment-origin migration input state; it is never steady-state dispatch authority.';
COMMENT ON COLUMN identity_mutation_proof_slots.provider_egress_policy_revision IS
    'Frozen Project Custom OIDC egress revision; NULL for named providers and email proofs.';
COMMENT ON COLUMN managed_provider_reauthorization_interactions.provider_egress_policy_revision IS
    'Frozen Project Custom OIDC egress revision; NULL for named providers.';
COMMENT ON COLUMN managed_provider_renewal_operations.provider_egress_policy_revision IS
    'Frozen Project Custom OIDC egress revision for a prepared renewal; NULL for named providers.';

-- Supported legacy databases may still contain NULL adapter kinds at the reserved Google/GitHub
-- roots. Those rows remain unavailable until explicitly recreated as a named preset; an unrelated
-- update must never promote their dispatch authority.
CREATE OR REPLACE FUNCTION fill_provider_adapter_kind_compatibility()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.kind <> 'oidc' THEN
        RAISE EXCEPTION 'legacy provider kind must remain oidc'
            USING ERRCODE = '23514';
    END IF;

    IF NEW.adapter_kind IS NULL THEN
        IF NEW.issuer NOT IN (
            'https://accounts.google.com',
            'https://github.com'
        ) THEN
            NEW.adapter_kind := 'oidc';
        END IF;
    ELSIF TG_OP = 'UPDATE'
        AND OLD.adapter_kind IS NOT NULL
        AND NEW.adapter_kind <> OLD.adapter_kind
    THEN
        RAISE EXCEPTION 'provider adapter kind is immutable'
            USING ERRCODE = '23514';
    END IF;

    IF NEW.adapter_kind IS NOT NULL AND NOT (
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

CREATE OR REPLACE FUNCTION fill_managed_reauthorization_provider_kind_compatibility()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    authoritative_kind TEXT;
BEGIN
    SELECT provider.adapter_kind
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


-- The frozen bridge trigger compared the legacy reference with ordinary equality. PostgreSQL NULL
-- equality makes every software-custody provider fail that check after its legacy reference is
-- retired. Replace the trigger function with the complete dual-authority snapshot validation and
-- include the provider-policy authority introduced by this migration series.
CREATE OR REPLACE FUNCTION owlauth_validate_managed_reauthorization_original_authority()
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
          LEFT JOIN project_provider_egress_policies AS egress
            ON egress.project_id = provider.project_id
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
           AND provider.secret_ref IS NOT DISTINCT FROM NEW.secret_ref
           AND provider.secret_material_id IS NOT DISTINCT FROM NEW.secret_material_id
           AND provider.callback_url = NEW.callback_url
           AND provider.revision = NEW.provider_revision
           AND provider.managed_profile_revision = NEW.managed_profile_revision
           AND (
               (provider.adapter_kind = 'oidc'
                AND NEW.provider_kind = 'oidc'
                AND egress.revision = NEW.provider_egress_policy_revision)
               OR (provider.adapter_kind = 'google'
                   AND NEW.provider_kind = 'google'
                   AND NEW.provider_egress_policy_revision IS NULL)
           )
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
