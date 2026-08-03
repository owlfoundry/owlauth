-- Typed identity-mutation proofs, same-Project merge attribution, callback ownership,
-- and deny-by-default verified-email projection admission.

ALTER TABLE project_policies
    ADD COLUMN projection_verified_email_enabled BOOLEAN NOT NULL DEFAULT FALSE;

ALTER TABLE applications
    ADD COLUMN projection_verified_email_enabled BOOLEAN NOT NULL DEFAULT FALSE;

-- PostgreSQL is the write/acceptance authority for the dedicated projection verified-email ring.
-- Configuration supplies custody only; it cannot silently select a write version. Runtime
-- observations are immutable per process incarnation and authorize lifecycle transitions, never
-- ordinary Control confirmation.
CREATE FUNCTION owlauth_positive_unique_key_versions(versions INTEGER[])
RETURNS BOOLEAN
LANGUAGE plpgsql
IMMUTABLE
STRICT
AS $$
DECLARE
    version INTEGER;
    seen INTEGER[] := ARRAY[]::INTEGER[];
BEGIN
    IF cardinality(versions) NOT BETWEEN 1 AND 16 THEN
        RETURN FALSE;
    END IF;
    FOREACH version IN ARRAY versions LOOP
        IF version <= 0 OR seen @> ARRAY[version] THEN
            RETURN FALSE;
        END IF;
        seen := array_append(seen, version);
    END LOOP;
    RETURN TRUE;
END
$$;

CREATE TABLE projection_email_key_authority (
    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    authority_revision BIGINT NOT NULL CHECK (authority_revision > 0),
    write_version INTEGER NOT NULL CHECK (write_version > 0),
    accepted_versions INTEGER[] NOT NULL,
    target_version INTEGER,
    target_staged_at TIMESTAMPTZ,
    retirement_version INTEGER,
    retirement_authorized_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT projection_email_key_authority_accepted_check CHECK (
        owlauth_positive_unique_key_versions(accepted_versions)
        AND accepted_versions @> ARRAY[write_version]
    ),
    CONSTRAINT projection_email_key_authority_target_check CHECK (
        (target_version IS NULL AND target_staged_at IS NULL)
        OR (target_version IS NOT NULL AND target_version > 0
            AND target_version <> write_version AND target_staged_at IS NOT NULL
            AND accepted_versions @> ARRAY[target_version])
    ),
    CONSTRAINT projection_email_key_authority_retirement_check CHECK (
        (retirement_version IS NULL AND retirement_authorized_at IS NULL)
        OR (retirement_version IS NOT NULL AND retirement_version > 0
            AND retirement_version <> write_version
            AND accepted_versions @> ARRAY[retirement_version]
            AND retirement_authorized_at IS NOT NULL)
    )
);

INSERT INTO projection_email_key_authority
(singleton,authority_revision,write_version,accepted_versions,updated_at)
VALUES (TRUE,1,1,ARRAY[1]::INTEGER[],clock_timestamp());

CREATE TABLE projection_email_runtime_observations (
    process_id TEXT NOT NULL CHECK (process_id <> '' AND length(process_id) <= 128),
    process_incarnation UUID NOT NULL,
    authority_revision BIGINT NOT NULL CHECK (authority_revision > 0),
    readable_versions INTEGER[] NOT NULL,
    observed_at TIMESTAMPTZ NOT NULL,
    lease_expires_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (process_id, process_incarnation),
    CONSTRAINT projection_email_runtime_observations_versions_check CHECK (
        owlauth_positive_unique_key_versions(readable_versions)
    ),
    CONSTRAINT projection_email_runtime_observations_lease_check
        CHECK (lease_expires_at > observed_at)
);
CREATE INDEX projection_email_runtime_observations_live_idx
    ON projection_email_runtime_observations (process_id, lease_expires_at);

-- Durable verified-email projection material remains protected exclusively by the dedicated
-- email-identity key ring. The public JSON document is always the safe wire shape with an
-- explicit null; Runtime overlays plaintext only after context-bound decryption.
ALTER TABLE application_user_projections
    ADD COLUMN verified_email_source_identity_id UUID,
    ADD COLUMN verified_email_ciphertext BYTEA,
    ADD COLUMN verified_email_key_version INTEGER,
    ADD CONSTRAINT application_user_projections_verified_email_material_check CHECK (
        (verified_email_source_identity_id IS NULL
         AND verified_email_ciphertext IS NULL
         AND verified_email_key_version IS NULL)
        OR
        (verified_email_source_identity_id IS NOT NULL
         AND verified_email_ciphertext IS NOT NULL
         AND octet_length(verified_email_ciphertext) BETWEEN 40 AND 4096
         AND verified_email_key_version > 0)
    ),
    ADD CONSTRAINT application_user_projections_safe_document_check CHECK (
        schema_name = 'owlauth.user.v1'
        AND jsonb_typeof(document) = 'object'
        AND (document->>'projection_schema' = 'owlauth.user.v1') IS TRUE
        AND (
            (document ?& ARRAY[
                'user_id','user_revision','projection_schema','projection_revision',
                'display_name','picture_url','locale','verified_email','status',
                'created_at','updated_at'
             ]
             AND (document - ARRAY[
                'user_id','user_revision','projection_schema','projection_revision',
                'display_name','picture_url','locale','verified_email','status',
                'created_at','updated_at'
             ]::TEXT[]) = '{}'::jsonb
             AND document->'verified_email' = 'null'::jsonb)
            OR
            -- Release N-1 has no locale or verified-email keys. Keep that exact non-email shape
            -- writable during rolling overlap; every N reader repairs it before delivery.
            (document ?& ARRAY[
                'user_id','user_revision','projection_schema','projection_revision',
                'display_name','picture_url','status','created_at','updated_at'
             ]
             AND (document - ARRAY[
                'user_id','user_revision','projection_schema','projection_revision',
                'display_name','picture_url','status','created_at','updated_at'
             ]::TEXT[]) = '{}'::jsonb)
        )
    ) NOT VALID;

-- Existing N-1 rows remain untouched during expansion. Runtime lazily repairs requested rows, and
-- operations may use a bounded resumable backfill before a later contract migration validates the
-- constraint. This migration must not rewrite or scan an unbounded projection directory.

-- A merged loser remains as immutable historical credential attribution while every identity
-- moves to the winner. Only this terminal state may have no designated primary identity.
DROP TRIGGER project_users_exact_primary_identity ON project_users;

ALTER TABLE project_users
    DROP CONSTRAINT project_users_status_check,
    DROP CONSTRAINT project_users_primary_source_shape_check,
    ADD COLUMN merged_into_user_id UUID,
    ADD CONSTRAINT project_users_status_check
        CHECK (status IN ('active', 'disabled', 'merged')),
    ADD CONSTRAINT project_users_merged_shape_check CHECK (
        (status = 'merged'
            AND merged_into_user_id IS NOT NULL
            AND merged_into_user_id <> id
            AND primary_profile_identity_id IS NULL
            AND primary_email_identity_id IS NULL)
        OR (status IN ('active', 'disabled')
            AND merged_into_user_id IS NULL
            AND ((primary_source_kind = 'provider'
                    AND primary_email_identity_id IS NULL)
                OR (primary_source_kind = 'email'
                    AND primary_profile_identity_id IS NULL)))
    ),
    ADD CONSTRAINT project_users_merged_into_fk
        FOREIGN KEY (project_id, merged_into_user_id)
        REFERENCES project_users (project_id, id)
        DEFERRABLE INITIALLY DEFERRED;

-- Every final-state check that can add or remove an edge in a Project identity graph takes this
-- one transaction-scoped lock before reading the graph. Deferred checks then serialize reciprocal
-- merges and merge-vs-edge-attach races without widening ordinary repository row locks.
CREATE FUNCTION owlauth_lock_project_identity_graph(target_project_id UUID)
RETURNS VOID
LANGUAGE SQL
AS $$
    SELECT pg_advisory_xact_lock(
        hashtextextended('owlauth-project-identity-graph:' || target_project_id::TEXT, 0)
    )
$$;

CREATE OR REPLACE FUNCTION owlauth_enforce_exact_primary_identity()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    current_record project_users%ROWTYPE;
BEGIN
    PERFORM owlauth_lock_project_identity_graph(NEW.project_id);
    SELECT * INTO STRICT current_record
      FROM project_users
     WHERE project_id = NEW.project_id AND id = NEW.id;
    IF current_record.status = 'merged' THEN
        IF current_record.merged_into_user_id IS NULL
            OR current_record.primary_profile_identity_id IS NOT NULL
            OR current_record.primary_email_identity_id IS NOT NULL
        THEN
            RAISE EXCEPTION 'merged user must retain only an exact winner attribution'
                USING ERRCODE = '23514';
        END IF;
    ELSIF current_record.primary_source_kind = 'provider' THEN
        IF current_record.primary_profile_identity_id IS NULL
            OR current_record.primary_email_identity_id IS NOT NULL
            OR current_record.merged_into_user_id IS NOT NULL
        THEN
            RAISE EXCEPTION 'provider primary source must identify exactly one provider identity'
                USING ERRCODE = '23514';
        END IF;
    ELSIF current_record.primary_source_kind = 'email' THEN
        IF current_record.primary_profile_identity_id IS NOT NULL
            OR current_record.primary_email_identity_id IS NULL
            OR current_record.merged_into_user_id IS NOT NULL
        THEN
            RAISE EXCEPTION 'email primary source must identify exactly one email identity'
                USING ERRCODE = '23514';
        END IF;
    ELSE
        RAISE EXCEPTION 'unsupported primary source kind' USING ERRCODE = '23514';
    END IF;
    RETURN NULL;
END
$$;

CREATE CONSTRAINT TRIGGER project_users_exact_primary_identity
AFTER INSERT OR UPDATE OF status, primary_source_kind, primary_profile_identity_id,
                          primary_email_identity_id, merged_into_user_id
ON project_users
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
EXECUTE FUNCTION owlauth_enforce_exact_primary_identity();

CREATE FUNCTION owlauth_reject_merged_project_user_change()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF OLD.status = 'merged'
        AND (NEW.status, NEW.project_id, NEW.id, NEW.primary_source_kind,
             NEW.primary_profile_identity_id, NEW.primary_email_identity_id,
             NEW.merged_into_user_id)
            IS DISTINCT FROM
            (OLD.status, OLD.project_id, OLD.id, OLD.primary_source_kind,
             OLD.primary_profile_identity_id, OLD.primary_email_identity_id,
             OLD.merged_into_user_id)
    THEN
        RAISE EXCEPTION 'merged Project user attribution is immutable'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER project_users_merged_terminal_state
BEFORE UPDATE ON project_users
FOR EACH ROW
EXECUTE FUNCTION owlauth_reject_merged_project_user_change();

CREATE FUNCTION owlauth_validate_merged_project_user_attribution()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    target_project_id UUID;
    target_loser_user_id UUID;
BEGIN
    IF TG_TABLE_NAME = 'project_users' THEN
        target_project_id := NEW.project_id;
        target_loser_user_id := NEW.id;
    ELSE
        target_project_id := CASE WHEN TG_OP = 'DELETE' THEN OLD.project_id ELSE NEW.project_id END;
        target_loser_user_id := CASE
            WHEN TG_OP = 'DELETE' THEN OLD.loser_user_id
            ELSE NEW.loser_user_id
        END;
    END IF;

    PERFORM owlauth_lock_project_identity_graph(target_project_id);
    IF EXISTS (
        SELECT 1
          FROM project_users AS loser
         WHERE loser.project_id = target_project_id
           AND (loser.id = target_loser_user_id
                OR (TG_TABLE_NAME = 'project_users'
                    AND loser.merged_into_user_id = target_loser_user_id))
           AND loser.status = 'merged'
           AND (NOT EXISTS (
                    SELECT 1
                      FROM project_users AS winner
                     WHERE winner.project_id = loser.project_id
                       AND winner.id = loser.merged_into_user_id
                       AND winner.status = 'active'
                       AND winner.merged_into_user_id IS NULL
                )
                OR NOT EXISTS (
                    SELECT 1
                      FROM project_user_merge_tombstones AS tombstone
                     WHERE tombstone.project_id = loser.project_id
                       AND tombstone.loser_user_id = loser.id
                       AND tombstone.winner_user_id = loser.merged_into_user_id
                )
                OR EXISTS (
                    SELECT 1 FROM linked_identities AS identity
                     WHERE identity.project_id = loser.project_id
                       AND identity.user_id = loser.id
                )
                OR EXISTS (
                    SELECT 1 FROM email_identities AS identity
                     WHERE identity.project_id = loser.project_id
                       AND identity.user_id = loser.id
                ))
    ) THEN
        RAISE EXCEPTION
            'merged Project user requires no owned identities, one active winner and completed tombstone'
            USING ERRCODE = '23514';
    END IF;

    IF EXISTS (
        SELECT 1
          FROM project_user_merge_tombstones AS tombstone
          LEFT JOIN project_users AS loser
            ON loser.project_id = tombstone.project_id
           AND loser.id = tombstone.loser_user_id
          LEFT JOIN project_users AS winner
            ON winner.project_id = tombstone.project_id
           AND winner.id = tombstone.winner_user_id
         WHERE tombstone.project_id = target_project_id
           AND (tombstone.loser_user_id = target_loser_user_id
                OR (TG_TABLE_NAME = 'project_users'
                    AND tombstone.winner_user_id = target_loser_user_id))
           AND (loser.id IS NULL
                OR loser.status <> 'merged'
                OR loser.merged_into_user_id IS DISTINCT FROM tombstone.winner_user_id
                OR loser.primary_profile_identity_id IS NOT NULL
                OR loser.primary_email_identity_id IS NOT NULL
                OR winner.id IS NULL
                OR winner.status <> 'active'
                OR winner.merged_into_user_id IS NOT NULL
                OR EXISTS (
                    SELECT 1 FROM linked_identities AS identity
                     WHERE identity.project_id = tombstone.project_id
                       AND identity.user_id = tombstone.loser_user_id
                )
                OR EXISTS (
                    SELECT 1 FROM email_identities AS identity
                     WHERE identity.project_id = tombstone.project_id
                       AND identity.user_id = tombstone.loser_user_id
                ))
    ) THEN
        RAISE EXCEPTION
            'merge tombstone requires one exact merged loser and active winner graph'
            USING ERRCODE = '23514';
    END IF;
    RETURN NULL;
END
$$;

CREATE CONSTRAINT TRIGGER project_users_exact_merged_attribution
AFTER INSERT OR UPDATE OF status, merged_into_user_id ON project_users
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
EXECUTE FUNCTION owlauth_validate_merged_project_user_attribution();

CREATE CONSTRAINT TRIGGER project_user_merge_tombstones_reverse_attribution
AFTER INSERT OR UPDATE OR DELETE ON project_user_merge_tombstones
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
EXECUTE FUNCTION owlauth_validate_merged_project_user_attribution();

CREATE FUNCTION owlauth_validate_merged_project_user_identity_ownership()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    target_project_id UUID;
    old_user_id UUID;
    new_user_id UUID;
BEGIN
    target_project_id := CASE
        WHEN TG_OP = 'DELETE' THEN OLD.project_id
        ELSE NEW.project_id
    END;
    old_user_id := CASE WHEN TG_OP IN ('UPDATE', 'DELETE') THEN OLD.user_id END;
    new_user_id := CASE WHEN TG_OP IN ('INSERT', 'UPDATE') THEN NEW.user_id END;

    PERFORM owlauth_lock_project_identity_graph(target_project_id);
    IF EXISTS (
        SELECT 1
          FROM project_users AS project_user
         WHERE project_user.project_id = target_project_id
           AND project_user.id IN (old_user_id, new_user_id)
           AND project_user.status = 'merged'
           AND (EXISTS (
                    SELECT 1 FROM linked_identities AS identity
                     WHERE identity.project_id = project_user.project_id
                       AND identity.user_id = project_user.id
                )
                OR EXISTS (
                    SELECT 1 FROM email_identities AS identity
                     WHERE identity.project_id = project_user.project_id
                       AND identity.user_id = project_user.id
                ))
    ) THEN
        RAISE EXCEPTION 'merged Project user cannot retain an identity owner edge'
            USING ERRCODE = '23514';
    END IF;
    RETURN NULL;
END
$$;

CREATE CONSTRAINT TRIGGER linked_identities_no_merged_owner
AFTER INSERT OR UPDATE OF user_id OR DELETE ON linked_identities
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
EXECUTE FUNCTION owlauth_validate_merged_project_user_identity_ownership();

CREATE CONSTRAINT TRIGGER email_identities_no_merged_owner
AFTER INSERT OR UPDATE OF user_id OR DELETE ON email_identities
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
EXECUTE FUNCTION owlauth_validate_merged_project_user_identity_ownership();

-- Live managed connections follow identity ownership atomically during a merge. Historical
-- reauthorization interactions retain their original user attribution and therefore reference
-- only the durable identity after insertion-time ownership was established in the prior schema.
DO $$
DECLARE
    connection_constraint_name TEXT;
    interaction_constraint_name TEXT;
BEGIN
    SELECT constraint_row.conname
      INTO STRICT connection_constraint_name
      FROM pg_constraint AS constraint_row
     WHERE constraint_row.contype = 'f'
       AND constraint_row.conrelid = 'managed_provider_connections'::regclass
       AND constraint_row.confrelid = 'linked_identities'::regclass
       AND ARRAY(
           SELECT attribute.attname::TEXT
             FROM unnest(constraint_row.conkey) WITH ORDINALITY AS key_column(attnum, ordinal)
             JOIN pg_attribute AS attribute
               ON attribute.attrelid = constraint_row.conrelid
              AND attribute.attnum = key_column.attnum
            ORDER BY key_column.ordinal
       ) = ARRAY['project_id','linked_identity_id','user_id']::TEXT[];

    SELECT constraint_row.conname
      INTO STRICT interaction_constraint_name
      FROM pg_constraint AS constraint_row
     WHERE constraint_row.contype = 'f'
       AND constraint_row.conrelid = 'managed_provider_reauthorization_interactions'::regclass
       AND constraint_row.confrelid = 'linked_identities'::regclass
       AND ARRAY(
           SELECT attribute.attname::TEXT
             FROM unnest(constraint_row.conkey) WITH ORDINALITY AS key_column(attnum, ordinal)
             JOIN pg_attribute AS attribute
               ON attribute.attrelid = constraint_row.conrelid
              AND attribute.attnum = key_column.attnum
            ORDER BY key_column.ordinal
       ) = ARRAY['project_id','linked_identity_id','user_id']::TEXT[];

    EXECUTE format(
        'ALTER TABLE managed_provider_connections DROP CONSTRAINT %I',
        connection_constraint_name
    );
    EXECUTE format(
        'ALTER TABLE managed_provider_reauthorization_interactions DROP CONSTRAINT %I',
        interaction_constraint_name
    );
END
$$;

ALTER TABLE managed_provider_connections
    ADD CONSTRAINT managed_provider_connections_identity_owner_fk
        FOREIGN KEY (project_id, linked_identity_id, user_id)
        REFERENCES linked_identities (project_id, id, user_id)
        ON DELETE CASCADE
        DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE managed_provider_reauthorization_interactions
    ADD CONSTRAINT managed_provider_reauthorization_identity_fk
        FOREIGN KEY (project_id, linked_identity_id)
        REFERENCES linked_identities (project_id, id)
        ON DELETE CASCADE;

CREATE FUNCTION owlauth_validate_managed_reauthorization_original_authority()
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
           AND provider.secret_ref = NEW.secret_ref
           AND provider.callback_url = NEW.callback_url
           AND provider.revision = NEW.provider_revision
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

CREATE TRIGGER managed_reauthorization_capture_original_authority
BEFORE INSERT ON managed_provider_reauthorization_interactions
FOR EACH ROW
EXECUTE FUNCTION owlauth_validate_managed_reauthorization_original_authority();

CREATE TRIGGER managed_reauthorization_stable_authority
BEFORE UPDATE ON managed_provider_reauthorization_interactions
FOR EACH ROW
EXECUTE FUNCTION reject_immutable_column_change(
    'project_id', 'project_public_id', 'connection_id', 'linked_identity_id', 'user_id',
    'provider_configuration_id', 'provider_key', 'issuer', 'subject', 'client_id',
    'secret_ref', 'application_id', 'expected_connection_generation',
    'expected_credential_generation', 'expected_connection_revision',
    'project_security_revision', 'user_security_revision', 'identity_revision',
    'provider_revision', 'managed_profile_revision', 'application_revision',
    'assignment_security_revision', 'callback_url', 'adapter_key',
    'adapter_capability_revision', 'required_scopes', 'provider_pkce_required',
    'oidc_nonce_required', 'created_at'
);

CREATE FUNCTION owlauth_validate_managed_reauthorization_revocation_truth()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.supports_revocation IS DISTINCT FROM OLD.supports_revocation
       AND NOT (
           OLD.supports_revocation
           AND NOT NEW.supports_revocation
           AND OLD.status = 'awaiting_provider_start'
           AND NEW.status = 'provider_authorization_started'
       ) THEN
        RAISE EXCEPTION 'managed reauthorization revocation truth may only narrow at provider start'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER managed_reauthorization_bounded_revocation_truth
BEFORE UPDATE OF supports_revocation ON managed_provider_reauthorization_interactions
FOR EACH ROW
EXECUTE FUNCTION owlauth_validate_managed_reauthorization_revocation_truth();

CREATE FUNCTION owlauth_reject_managed_reauthorization_deadline_extension()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.expires_at > OLD.expires_at THEN
        RAISE EXCEPTION 'managed reauthorization deadline cannot be extended'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER managed_reauthorization_bounded_deadline
BEFORE UPDATE OF expires_at ON managed_provider_reauthorization_interactions
FOR EACH ROW
EXECUTE FUNCTION owlauth_reject_managed_reauthorization_deadline_extension();

-- A merged binding remains as immutable credential attribution when both users already had a
-- binding for one Application. A binding moved to the winner keeps its first-delivery timestamp.
ALTER TABLE application_user_bindings
    DROP CONSTRAINT application_user_bindings_status_check,
    ADD COLUMN merged_into_binding_id UUID,
    ADD COLUMN merged_at TIMESTAMPTZ,
    ADD CONSTRAINT application_user_bindings_status_check CHECK (
        status IN ('active', 'disabled', 'merged')
    ),
    ADD CONSTRAINT application_user_bindings_merge_shape_check CHECK (
        (status = 'merged'
            AND merged_into_binding_id IS NOT NULL
            AND merged_into_binding_id <> id
            AND merged_at IS NOT NULL)
        OR (status <> 'merged'
            AND merged_into_binding_id IS NULL
            AND merged_at IS NULL)
    ),
    ADD CONSTRAINT application_user_bindings_project_id_id_application_unique
        UNIQUE (project_id, id, application_id),
    ADD CONSTRAINT application_user_bindings_merged_into_fk
        FOREIGN KEY (project_id, merged_into_binding_id, application_id)
        REFERENCES application_user_bindings (project_id, id, application_id)
        DEFERRABLE INITIALLY DEFERRED;

CREATE FUNCTION owlauth_reject_merged_binding_reopen()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    prior_target application_user_bindings%ROWTYPE;
BEGIN
    IF (NEW.id, NEW.project_id, NEW.application_id, NEW.created_at)
        IS DISTINCT FROM
        (OLD.id, OLD.project_id, OLD.application_id, OLD.created_at)
    THEN
        RAISE EXCEPTION 'Application binding identity and first-delivery time are immutable'
            USING ERRCODE = '23514';
    END IF;
    IF NEW.status = 'merged' AND NEW.user_id IS DISTINCT FROM OLD.user_id THEN
        RAISE EXCEPTION 'merged Application binding must retain its historical owner'
            USING ERRCODE = '23514';
    END IF;
    IF OLD.status = 'merged'
        AND (NEW.status, NEW.merged_at)
            IS DISTINCT FROM
            (OLD.status, OLD.merged_at)
    THEN
        RAISE EXCEPTION 'merged Application binding cannot be reopened'
            USING ERRCODE = '23514';
    END IF;
    IF OLD.status = 'merged'
        AND NEW.merged_into_binding_id IS DISTINCT FROM OLD.merged_into_binding_id
    THEN
        SELECT * INTO prior_target
          FROM application_user_bindings
         WHERE project_id = OLD.project_id
           AND id = OLD.merged_into_binding_id
           AND application_id = OLD.application_id;
        IF NOT FOUND
            OR prior_target.status <> 'merged'
            OR prior_target.merged_into_binding_id
                IS DISTINCT FROM NEW.merged_into_binding_id
        THEN
            RAISE EXCEPTION 'merged Application binding lineage may only be flattened'
                USING ERRCODE = '23514';
        END IF;
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER application_user_bindings_merged_terminal
BEFORE UPDATE ON application_user_bindings
FOR EACH ROW
EXECUTE FUNCTION owlauth_reject_merged_binding_reopen();

CREATE FUNCTION owlauth_enforce_merged_binding_target()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    current_binding application_user_bindings%ROWTYPE;
    retained_binding application_user_bindings%ROWTYPE;
    source_user project_users%ROWTYPE;
BEGIN
    -- Binding lineage participates in the same user/identity graph as a merge. A later committer
    -- must observe the earlier committed winner and owner state.
    PERFORM owlauth_lock_project_identity_graph(NEW.project_id);
    SELECT * INTO current_binding
      FROM application_user_bindings
     WHERE project_id = NEW.project_id AND id = NEW.id;
    IF NOT FOUND THEN
        RETURN NULL;
    END IF;
    IF current_binding.status = 'merged' THEN
        SELECT * INTO STRICT retained_binding
          FROM application_user_bindings
         WHERE project_id = current_binding.project_id
           AND id = current_binding.merged_into_binding_id
           AND application_id = current_binding.application_id;
        SELECT * INTO STRICT source_user
          FROM project_users
         WHERE project_id = current_binding.project_id
           AND id = current_binding.user_id;
        IF retained_binding.status = 'merged'
            OR retained_binding.merged_into_binding_id IS NOT NULL
            OR retained_binding.user_id = current_binding.user_id
            OR source_user.status <> 'merged'
            OR source_user.merged_into_user_id IS DISTINCT FROM retained_binding.user_id
        THEN
            RAISE EXCEPTION
                'merged Application binding must target its Project-user merge winner'
                USING ERRCODE = '23514';
        END IF;
    END IF;
    IF current_binding.status = 'merged'
        AND EXISTS (
            SELECT 1 FROM application_user_bindings
             WHERE project_id = current_binding.project_id
               AND merged_into_binding_id = current_binding.id
        )
    THEN
        RAISE EXCEPTION 'merged Application binding cannot itself be a merge target'
            USING ERRCODE = '23514';
    END IF;
    RETURN NULL;
END
$$;

CREATE CONSTRAINT TRIGGER application_user_bindings_exact_merge_target
AFTER INSERT OR UPDATE OF status, user_id, merged_into_binding_id
ON application_user_bindings
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
EXECUTE FUNCTION owlauth_enforce_merged_binding_target();

CREATE FUNCTION owlauth_enforce_merged_user_binding_ownership()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    target_project_id UUID;
    old_user_id UUID;
    new_user_id UUID;
BEGIN
    IF TG_TABLE_NAME = 'project_users' THEN
        target_project_id := NEW.project_id;
        old_user_id := NEW.id;
        new_user_id := NEW.id;
    ELSE
        target_project_id := CASE WHEN TG_OP = 'DELETE' THEN OLD.project_id ELSE NEW.project_id END;
        old_user_id := CASE WHEN TG_OP IN ('UPDATE', 'DELETE') THEN OLD.user_id END;
        new_user_id := CASE WHEN TG_OP IN ('INSERT', 'UPDATE') THEN NEW.user_id END;
    END IF;

    PERFORM owlauth_lock_project_identity_graph(target_project_id);
    IF EXISTS (
        SELECT 1
          FROM project_users AS project_user
          JOIN application_user_bindings AS binding
            ON binding.project_id = project_user.project_id
           AND binding.user_id = project_user.id
         WHERE project_user.project_id = target_project_id
           AND project_user.id IN (old_user_id, new_user_id)
           AND project_user.status = 'merged'
           AND binding.status <> 'merged'
    ) THEN
        RAISE EXCEPTION 'merged Project user cannot own a live Application binding'
            USING ERRCODE = '23514';
    END IF;

    RETURN NULL;
END
$$;

CREATE CONSTRAINT TRIGGER project_users_no_live_binding_after_merge
AFTER INSERT OR UPDATE OF status, merged_into_user_id ON project_users
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
EXECUTE FUNCTION owlauth_enforce_merged_user_binding_ownership();

CREATE CONSTRAINT TRIGGER application_user_bindings_exact_merged_user
AFTER INSERT OR UPDATE OF status, user_id, merged_into_binding_id OR DELETE
ON application_user_bindings
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
EXECUTE FUNCTION owlauth_enforce_merged_user_binding_ownership();

CREATE FUNCTION owlauth_reject_merged_binding_delete()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF OLD.status = 'merged'
        AND EXISTS (SELECT 1 FROM projects WHERE id = OLD.project_id)
    THEN
        RAISE EXCEPTION 'merged Application binding attribution cannot be deleted'
            USING ERRCODE = '23514';
    END IF;
    RETURN OLD;
END
$$;

CREATE TRIGGER application_user_bindings_preserve_merged_attribution
BEFORE DELETE ON application_user_bindings
FOR EACH ROW
EXECUTE FUNCTION owlauth_reject_merged_binding_delete();

-- Discover the two generated four-column foreign keys by their ordered column sets. Their
-- PostgreSQL-generated names may be identifier-truncated and must not be guessed.
DO $$
DECLARE
    projection_constraint_name TEXT;
    session_constraint_name TEXT;
BEGIN
    SELECT constraint_row.conname
      INTO STRICT projection_constraint_name
      FROM pg_constraint AS constraint_row
     WHERE constraint_row.contype = 'f'
       AND constraint_row.conrelid = 'application_user_projections'::regclass
       AND constraint_row.confrelid = 'application_user_bindings'::regclass
       AND ARRAY(
           SELECT attribute.attname::TEXT
             FROM unnest(constraint_row.conkey) WITH ORDINALITY AS key_column(attnum, ordinal)
             JOIN pg_attribute AS attribute
               ON attribute.attrelid = constraint_row.conrelid
              AND attribute.attnum = key_column.attnum
            ORDER BY key_column.ordinal
       ) = ARRAY['project_id','binding_id','application_id','user_id']::TEXT[]
       AND ARRAY(
           SELECT attribute.attname::TEXT
             FROM unnest(constraint_row.confkey) WITH ORDINALITY AS key_column(attnum, ordinal)
             JOIN pg_attribute AS attribute
               ON attribute.attrelid = constraint_row.confrelid
              AND attribute.attnum = key_column.attnum
            ORDER BY key_column.ordinal
       ) = ARRAY['project_id','id','application_id','user_id']::TEXT[];

    SELECT constraint_row.conname
      INTO STRICT session_constraint_name
      FROM pg_constraint AS constraint_row
     WHERE constraint_row.contype = 'f'
       AND constraint_row.conrelid = 'application_sessions'::regclass
       AND constraint_row.confrelid = 'application_user_bindings'::regclass
       AND ARRAY(
           SELECT attribute.attname::TEXT
             FROM unnest(constraint_row.conkey) WITH ORDINALITY AS key_column(attnum, ordinal)
             JOIN pg_attribute AS attribute
               ON attribute.attrelid = constraint_row.conrelid
              AND attribute.attnum = key_column.attnum
            ORDER BY key_column.ordinal
       ) = ARRAY['project_id','binding_id','application_id','user_id']::TEXT[]
       AND ARRAY(
           SELECT attribute.attname::TEXT
             FROM unnest(constraint_row.confkey) WITH ORDINALITY AS key_column(attnum, ordinal)
             JOIN pg_attribute AS attribute
               ON attribute.attrelid = constraint_row.confrelid
              AND attribute.attnum = key_column.attnum
            ORDER BY key_column.ordinal
       ) = ARRAY['project_id','id','application_id','user_id']::TEXT[];

    EXECUTE format(
        'ALTER TABLE application_user_projections DROP CONSTRAINT %I',
        projection_constraint_name
    );
    EXECUTE format(
        'ALTER TABLE application_sessions DROP CONSTRAINT %I',
        session_constraint_name
    );
END
$$;

ALTER TABLE application_user_projections
    ADD CONSTRAINT application_user_projections_verified_email_source_fk
        FOREIGN KEY (project_id, verified_email_source_identity_id, user_id)
        REFERENCES email_identities (project_id, id, user_id)
        DEFERRABLE INITIALLY DEFERRED,
    ADD CONSTRAINT application_user_projections_binding_owner_fk
    FOREIGN KEY (project_id, binding_id, application_id, user_id)
    REFERENCES application_user_bindings (project_id, id, application_id, user_id)
    ON DELETE CASCADE
    DEFERRABLE INITIALLY DEFERRED;

-- application_sessions.user_id is the immutable credential owner. It deliberately no longer
-- follows the binding's current owner after a merge.
ALTER TABLE application_sessions
    ADD CONSTRAINT application_sessions_binding_identity_fk
        FOREIGN KEY (project_id, binding_id, application_id)
        REFERENCES application_user_bindings (project_id, id, application_id),
    ADD CONSTRAINT application_sessions_credential_user_fk
        FOREIGN KEY (project_id, user_id)
        REFERENCES project_users (project_id, id);

CREATE FUNCTION owlauth_validate_application_session_original_binding_owner()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    binding_user_id UUID;
BEGIN
    SELECT user_id INTO STRICT binding_user_id
      FROM application_user_bindings
     WHERE project_id = NEW.project_id
       AND id = NEW.binding_id
       AND application_id = NEW.application_id
     FOR SHARE;
    IF binding_user_id <> NEW.user_id THEN
        RAISE EXCEPTION 'Application session must capture the binding original owner'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER application_sessions_capture_original_binding_owner
BEFORE INSERT ON application_sessions
FOR EACH ROW
EXECUTE FUNCTION owlauth_validate_application_session_original_binding_owner();

CREATE TRIGGER application_sessions_stable_credential_owner
BEFORE UPDATE ON application_sessions
FOR EACH ROW
EXECUTE FUNCTION reject_immutable_column_change(
    'id', 'project_id', 'application_id', 'binding_id', 'user_id', 'created_at'
);

CREATE TABLE identity_mutation_intents (
    id UUID PRIMARY KEY,
    project_id UUID NOT NULL,
    operation_kind TEXT NOT NULL CHECK (operation_kind IN ('link', 'unlink', 'merge')),
    status TEXT NOT NULL CHECK (
        status IN ('pending_proof', 'ready', 'completed', 'expired', 'cancelled')
    ),
    intent_revision BIGINT NOT NULL DEFAULT 1 CHECK (intent_revision > 0),
    project_metadata_revision BIGINT NOT NULL CHECK (project_metadata_revision > 0),
    project_security_revision BIGINT NOT NULL CHECK (project_security_revision > 0),
    destination_user_id UUID,
    destination_user_revision BIGINT,
    destination_user_security_revision BIGINT,
    identity_owner_user_id UUID,
    identity_owner_user_revision BIGINT,
    identity_owner_user_security_revision BIGINT,
    winner_user_id UUID,
    winner_user_revision BIGINT,
    winner_user_security_revision BIGINT,
    loser_user_id UUID,
    loser_user_revision BIGINT,
    loser_user_security_revision BIGINT,
    primary_source_disposition TEXT NOT NULL CHECK (
        primary_source_disposition IN ('preserve', 'provider', 'email', 'clear')
    ),
    primary_provider_identity_id UUID,
    primary_email_identity_id UUID,
    primary_source_identity_revision BIGINT CHECK (
        primary_source_identity_revision IS NULL OR primary_source_identity_revision > 0
    ),
    sessions_disposition TEXT CHECK (
        sessions_disposition IS NULL OR sessions_disposition = 'loser_revoked'
    ),
    bindings_disposition TEXT CHECK (
        bindings_disposition IS NULL OR bindings_disposition = 'winner_preferred'
    ),
    hosted_handle_digest BYTEA NOT NULL CHECK (octet_length(hosted_handle_digest) = 32),
    hosted_handle_digest_key_version INTEGER NOT NULL CHECK (
        hosted_handle_digest_key_version > 0
    ),
    browser_binding_digest BYTEA,
    browser_binding_digest_key_version INTEGER,
    csrf_digest BYTEA,
    csrf_digest_key_version INTEGER,
    browser_binding_revision BIGINT NOT NULL DEFAULT 0 CHECK (browser_binding_revision >= 0),
    correlation_id UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    expires_at TIMESTAMPTZ NOT NULL,
    ready_at TIMESTAMPTZ,
    terminal_at TIMESTAMPTZ,
    FOREIGN KEY (project_id) REFERENCES projects (id) ON DELETE CASCADE,
    FOREIGN KEY (project_id, destination_user_id)
        REFERENCES project_users (project_id, id),
    FOREIGN KEY (project_id, identity_owner_user_id)
        REFERENCES project_users (project_id, id),
    FOREIGN KEY (project_id, winner_user_id)
        REFERENCES project_users (project_id, id),
    FOREIGN KEY (project_id, loser_user_id)
        REFERENCES project_users (project_id, id),
    FOREIGN KEY (project_id, primary_provider_identity_id)
        REFERENCES linked_identities (project_id, id),
    FOREIGN KEY (project_id, primary_email_identity_id)
        REFERENCES email_identities (project_id, id),
    UNIQUE (project_id, id),
    UNIQUE (hosted_handle_digest_key_version, hosted_handle_digest),
    CHECK (expires_at > created_at AND expires_at <= created_at + INTERVAL '10 minutes'),
    CHECK (
        (browser_binding_digest IS NULL) = (browser_binding_digest_key_version IS NULL)
        AND (csrf_digest IS NULL) = (csrf_digest_key_version IS NULL)
        AND (browser_binding_digest IS NULL) = (csrf_digest IS NULL)
        AND (browser_binding_digest IS NULL OR (
            octet_length(browser_binding_digest) = 32
            AND browser_binding_digest_key_version > 0
            AND octet_length(csrf_digest) = 32
            AND csrf_digest_key_version > 0
            AND browser_binding_revision > 0
        ))
    ),
    CHECK (
        (status = 'pending_proof' AND ready_at IS NULL AND terminal_at IS NULL)
        OR (status = 'ready' AND ready_at IS NOT NULL AND terminal_at IS NULL)
        OR (status = 'completed' AND ready_at IS NOT NULL AND terminal_at IS NOT NULL)
        OR (status IN ('expired', 'cancelled') AND terminal_at IS NOT NULL)
    ),
    CHECK (ready_at IS NULL OR (ready_at >= created_at AND ready_at < expires_at)),
    CHECK (terminal_at IS NULL OR terminal_at >= created_at),
    CHECK (status <> 'completed' OR terminal_at >= ready_at),
    CHECK (
        (primary_source_disposition = 'provider'
            AND primary_provider_identity_id IS NOT NULL
            AND primary_email_identity_id IS NULL
            AND primary_source_identity_revision > 0)
        OR (primary_source_disposition = 'email'
            AND primary_provider_identity_id IS NULL
            AND primary_email_identity_id IS NOT NULL
            AND primary_source_identity_revision > 0)
        OR (primary_source_disposition IN ('preserve', 'clear')
            AND primary_provider_identity_id IS NULL
            AND primary_email_identity_id IS NULL
            AND primary_source_identity_revision IS NULL)
    ),
    CHECK ((
        (operation_kind = 'link'
            AND destination_user_id IS NOT NULL
            AND destination_user_revision > 0
            AND destination_user_security_revision > 0
            AND identity_owner_user_id IS NULL
            AND identity_owner_user_revision IS NULL
            AND identity_owner_user_security_revision IS NULL
            AND winner_user_id IS NULL
            AND winner_user_revision IS NULL
            AND winner_user_security_revision IS NULL
            AND loser_user_id IS NULL
            AND loser_user_revision IS NULL
            AND loser_user_security_revision IS NULL
            AND primary_source_disposition = 'preserve'
            AND sessions_disposition IS NULL
            AND bindings_disposition IS NULL)
        OR (operation_kind = 'unlink'
            AND destination_user_id IS NULL
            AND destination_user_revision IS NULL
            AND destination_user_security_revision IS NULL
            AND identity_owner_user_id IS NOT NULL
            AND identity_owner_user_revision > 0
            AND identity_owner_user_security_revision > 0
            AND winner_user_id IS NULL
            AND winner_user_revision IS NULL
            AND winner_user_security_revision IS NULL
            AND loser_user_id IS NULL
            AND loser_user_revision IS NULL
            AND loser_user_security_revision IS NULL
            AND sessions_disposition IS NULL
            AND bindings_disposition IS NULL)
        OR (operation_kind = 'merge'
            AND destination_user_id IS NULL
            AND destination_user_revision IS NULL
            AND destination_user_security_revision IS NULL
            AND identity_owner_user_id IS NULL
            AND identity_owner_user_revision IS NULL
            AND identity_owner_user_security_revision IS NULL
            AND winner_user_id IS NOT NULL
            AND winner_user_revision > 0
            AND winner_user_security_revision > 0
            AND loser_user_id IS NOT NULL
            AND loser_user_revision > 0
            AND loser_user_security_revision > 0
            AND winner_user_id <> loser_user_id
            AND primary_source_disposition IN ('provider', 'email')
            AND sessions_disposition = 'loser_revoked'
            AND bindings_disposition = 'winner_preferred')
    ) IS TRUE)
);

CREATE FUNCTION owlauth_validate_identity_mutation_primary_source_owner()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    source_user_id UUID;
    source_identity_revision BIGINT;
BEGIN
    IF NEW.primary_provider_identity_id IS NOT NULL THEN
        SELECT user_id, identity_revision INTO source_user_id, source_identity_revision
          FROM linked_identities
         WHERE project_id = NEW.project_id
           AND id = NEW.primary_provider_identity_id
           AND status = 'active';
    ELSIF NEW.primary_email_identity_id IS NOT NULL THEN
        SELECT user_id, identity_revision INTO source_user_id, source_identity_revision
          FROM email_identities
         WHERE project_id = NEW.project_id
           AND id = NEW.primary_email_identity_id
           AND status = 'active';
    ELSE
        RETURN NEW;
    END IF;

    IF source_user_id IS NULL
        OR source_identity_revision IS DISTINCT FROM NEW.primary_source_identity_revision
        OR (NEW.operation_kind = 'unlink'
            AND source_user_id <> NEW.identity_owner_user_id)
        OR (NEW.operation_kind = 'merge'
            AND source_user_id <> NEW.winner_user_id
            AND source_user_id <> NEW.loser_user_id)
        OR NEW.operation_kind = 'link'
    THEN
        RAISE EXCEPTION 'identity-mutation primary source has the wrong frozen owner'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER identity_mutation_intents_primary_source_owner
BEFORE INSERT ON identity_mutation_intents
FOR EACH ROW
EXECUTE FUNCTION owlauth_validate_identity_mutation_primary_source_owner();

CREATE INDEX identity_mutation_intents_cleanup_idx
    ON identity_mutation_intents (status, expires_at, id)
    WHERE status IN ('pending_proof', 'ready');
CREATE INDEX identity_mutation_intents_project_users_idx
    ON identity_mutation_intents
       (project_id, destination_user_id, identity_owner_user_id, winner_user_id,
        loser_user_id, status);

CREATE TRIGGER identity_mutation_intents_stable_authority
BEFORE UPDATE ON identity_mutation_intents
FOR EACH ROW
EXECUTE FUNCTION reject_immutable_column_change(
    'project_id', 'operation_kind', 'project_metadata_revision',
    'project_security_revision', 'destination_user_id', 'destination_user_revision',
    'destination_user_security_revision', 'identity_owner_user_id',
    'identity_owner_user_revision', 'identity_owner_user_security_revision',
    'winner_user_id', 'winner_user_revision', 'winner_user_security_revision',
    'loser_user_id', 'loser_user_revision', 'loser_user_security_revision',
    'primary_source_disposition', 'primary_provider_identity_id',
    'primary_email_identity_id', 'primary_source_identity_revision',
    'sessions_disposition', 'bindings_disposition',
    'hosted_handle_digest', 'hosted_handle_digest_key_version', 'correlation_id',
    'created_at', 'expires_at'
);

CREATE FUNCTION owlauth_enforce_identity_mutation_intent_transition()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.status <> 'pending_proof'
            OR NEW.intent_revision <> 1
            OR NEW.browser_binding_digest IS NOT NULL
            OR NEW.browser_binding_digest_key_version IS NOT NULL
            OR NEW.csrf_digest IS NOT NULL
            OR NEW.csrf_digest_key_version IS NOT NULL
            OR NEW.browser_binding_revision <> 0
            OR NEW.ready_at IS NOT NULL
            OR NEW.terminal_at IS NOT NULL
        THEN
            RAISE EXCEPTION 'identity-mutation intent must start unbound and pending at revision one'
                USING ERRCODE = '23514';
        END IF;
        RETURN NEW;
    END IF;
    IF NEW.intent_revision <= OLD.intent_revision THEN
        RAISE EXCEPTION 'identity-mutation intent revision must advance'
            USING ERRCODE = '23514';
    END IF;
    IF (OLD.ready_at IS NOT NULL AND NEW.ready_at IS DISTINCT FROM OLD.ready_at)
        OR (OLD.terminal_at IS NOT NULL AND NEW.terminal_at IS DISTINCT FROM OLD.terminal_at)
    THEN
        RAISE EXCEPTION 'identity-mutation lifecycle timestamps are write-once'
            USING ERRCODE = '23514';
    END IF;
    IF (NEW.browser_binding_digest, NEW.browser_binding_digest_key_version,
        NEW.csrf_digest, NEW.csrf_digest_key_version, NEW.browser_binding_revision)
        IS DISTINCT FROM
       (OLD.browser_binding_digest, OLD.browser_binding_digest_key_version,
        OLD.csrf_digest, OLD.csrf_digest_key_version, OLD.browser_binding_revision)
    THEN
        IF OLD.browser_binding_digest IS NOT NULL
            OR OLD.csrf_digest IS NOT NULL
            OR OLD.browser_binding_revision <> 0
            OR NEW.browser_binding_digest IS NULL
            OR NEW.csrf_digest IS NULL
            OR NEW.browser_binding_revision <> 1
            OR OLD.status <> 'pending_proof'
            OR NEW.status <> 'pending_proof'
            OR EXISTS (
                SELECT 1 FROM identity_mutation_proof_slots
                 WHERE project_id = OLD.project_id AND intent_id = OLD.id
                   AND state <> 'pending'
            )
            OR EXISTS (
                SELECT 1 FROM identity_proof_receipts
                 WHERE project_id = OLD.project_id AND intent_id = OLD.id
            )
        THEN
            RAISE EXCEPTION 'identity-mutation browser and CSRF authority is bind-once'
                USING ERRCODE = '23514';
        END IF;
    END IF;
    IF NOT (
        NEW.status = OLD.status
        OR (OLD.status = 'pending_proof' AND NEW.status IN ('ready','expired','cancelled'))
        OR (OLD.status = 'ready' AND NEW.status IN ('completed','expired','cancelled'))
    ) THEN
        RAISE EXCEPTION 'invalid identity-mutation intent status transition'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER identity_mutation_intents_one_way_state
BEFORE INSERT OR UPDATE ON identity_mutation_intents
FOR EACH ROW
EXECUTE FUNCTION owlauth_enforce_identity_mutation_intent_transition();

CREATE FUNCTION owlauth_valid_identity_proof_scopes(scopes TEXT[])
RETURNS BOOLEAN
LANGUAGE SQL
IMMUTABLE
STRICT
AS $$
    SELECT array_ndims(scopes) = 1
       AND array_lower(scopes, 1) = 1
       AND cardinality(scopes) BETWEEN 1 AND 16
       AND array_position(scopes, NULL) IS NULL
       AND cardinality(scopes) = (
           SELECT count(DISTINCT scope)::INTEGER FROM unnest(scopes) AS scope
       )
       AND NOT EXISTS (
           SELECT 1
             FROM unnest(scopes) AS scope
            WHERE octet_length(scope) NOT BETWEEN 1 AND 128
               OR scope = 'offline_access'
               OR EXISTS (
                   SELECT 1
                     FROM generate_series(0, octet_length(scope) - 1) AS byte_index
                    WHERE NOT (
                        get_byte(convert_to(scope, 'UTF8'), byte_index) = 33
                        OR get_byte(convert_to(scope, 'UTF8'), byte_index) BETWEEN 35 AND 91
                        OR get_byte(convert_to(scope, 'UTF8'), byte_index) BETWEEN 93 AND 126
                    )
               )
       )
$$;

CREATE TABLE identity_mutation_proof_slots (
    id UUID PRIMARY KEY,
    project_id UUID NOT NULL,
    intent_id UUID NOT NULL,
    slot_ordinal SMALLINT NOT NULL CHECK (slot_ordinal BETWEEN 1 AND 2),
    slot_role TEXT NOT NULL CHECK (
        slot_role IN ('destination_owner', 'candidate_identity', 'identity_owner',
                      'winner_owner', 'loser_owner')
    ),
    purpose TEXT NOT NULL CHECK (
        purpose IN ('link.destination_owner', 'link.candidate_identity',
                    'unlink.identity_owner', 'merge.winner_owner', 'merge.loser_owner')
    ),
    identity_kind TEXT NOT NULL CHECK (identity_kind IN ('provider', 'email')),
    proof_user_id UUID NOT NULL,
    expected_user_revision BIGINT NOT NULL CHECK (expected_user_revision > 0),
    expected_user_security_revision BIGINT NOT NULL CHECK (
        expected_user_security_revision > 0
    ),
    existing_provider_identity_id UUID,
    existing_email_identity_id UUID,
    expected_identity_revision BIGINT,
    application_id UUID NOT NULL,
    application_security_revision BIGINT NOT NULL CHECK (
        application_security_revision > 0
    ),
    method_kind TEXT NOT NULL CHECK (method_kind IN ('provider', 'email')),
    provider_adapter_key TEXT,
    provider_adapter_capability_revision BIGINT,
    provider_configuration_id UUID,
    provider_revision BIGINT,
    provider_assignment_security_revision BIGINT,
    provider_scopes TEXT[],
    callback_url TEXT,
    provider_pkce_required BOOLEAN,
    oidc_nonce_required BOOLEAN,
    email_assignment_application_id UUID,
    email_policy_revision BIGINT,
    email_security_revision BIGINT,
    email_assignment_security_revision BIGINT,
    state TEXT NOT NULL CHECK (
        state IN ('pending', 'provider_authorization_started',
                  'provider_exchange_in_progress', 'provider_exchange_failed',
                  'email_address_entry', 'email_challenge_pending', 'proved', 'expired')
    ),
    slot_revision BIGINT NOT NULL DEFAULT 1 CHECK (slot_revision > 0),
    upstream_state_digest BYTEA,
    upstream_state_digest_key_version INTEGER,
    provider_pkce_ciphertext BYTEA,
    provider_pkce_key_version INTEGER,
    oidc_nonce_digest BYTEA,
    oidc_nonce_digest_key_version INTEGER,
    callback_continuation_ciphertext BYTEA,
    callback_continuation_key_version INTEGER,
    provider_started_at TIMESTAMPTZ,
    exchange_claimed_at TIMESTAMPTZ,
    proved_at TIMESTAMPTZ,
    terminal_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    FOREIGN KEY (project_id, intent_id)
        REFERENCES identity_mutation_intents (project_id, id) ON DELETE CASCADE,
    FOREIGN KEY (project_id, proof_user_id)
        REFERENCES project_users (project_id, id),
    FOREIGN KEY (project_id, existing_provider_identity_id)
        REFERENCES linked_identities (project_id, id),
    FOREIGN KEY (project_id, existing_email_identity_id)
        REFERENCES email_identities (project_id, id),
    FOREIGN KEY (project_id, application_id)
        REFERENCES applications (project_id, id),
    FOREIGN KEY (project_id, provider_configuration_id)
        REFERENCES provider_configurations (project_id, id),
    FOREIGN KEY (project_id, application_id, provider_configuration_id)
        REFERENCES application_provider_assignments (project_id, application_id, provider_id),
    FOREIGN KEY (project_id, email_assignment_application_id)
        REFERENCES application_email_assignments (project_id, application_id),
    UNIQUE (project_id, id),
    UNIQUE (project_id, intent_id, id),
    UNIQUE (project_id, intent_id, slot_ordinal),
    UNIQUE (project_id, intent_id, slot_role),
    CHECK ((
        (slot_role = 'candidate_identity'
            AND existing_provider_identity_id IS NULL
            AND existing_email_identity_id IS NULL
            AND expected_identity_revision IS NULL)
        OR (slot_role <> 'candidate_identity'
            AND expected_identity_revision > 0
            AND ((identity_kind = 'provider'
                    AND existing_provider_identity_id IS NOT NULL
                    AND existing_email_identity_id IS NULL)
                OR (identity_kind = 'email'
                    AND existing_provider_identity_id IS NULL
                    AND existing_email_identity_id IS NOT NULL)))
    ) IS TRUE),
    CHECK ((
        (method_kind = 'provider'
            AND identity_kind = 'provider'
            AND provider_adapter_key IS NOT NULL
            AND octet_length(provider_adapter_key) BETWEEN 1 AND 64
            AND provider_adapter_capability_revision > 0
            AND provider_configuration_id IS NOT NULL
            AND provider_revision > 0
            AND provider_assignment_security_revision > 0
            AND owlauth_valid_identity_proof_scopes(provider_scopes)
            AND callback_url IS NOT NULL
            AND char_length(callback_url) BETWEEN 8 AND 2048
            AND provider_pkce_required IS NOT NULL
            AND oidc_nonce_required = TRUE
            AND email_assignment_application_id IS NULL
            AND email_policy_revision IS NULL
            AND email_security_revision IS NULL
            AND email_assignment_security_revision IS NULL)
        OR (method_kind = 'email'
            AND identity_kind = 'email'
            AND provider_adapter_key IS NULL
            AND provider_adapter_capability_revision IS NULL
            AND provider_configuration_id IS NULL
            AND provider_revision IS NULL
            AND provider_assignment_security_revision IS NULL
            AND provider_scopes IS NULL
            AND callback_url IS NULL
            AND provider_pkce_required IS NULL
            AND oidc_nonce_required IS NULL
            AND email_assignment_application_id = application_id
            AND email_policy_revision > 0
            AND email_security_revision > 0
            AND email_assignment_security_revision > 0)
    ) IS TRUE),
    CHECK (
        (upstream_state_digest IS NULL) = (upstream_state_digest_key_version IS NULL)
        AND (upstream_state_digest IS NULL OR (
            octet_length(upstream_state_digest) = 32
            AND upstream_state_digest_key_version > 0
        ))
    ),
    CHECK (
        (provider_pkce_ciphertext IS NULL) = (provider_pkce_key_version IS NULL)
        AND (provider_pkce_ciphertext IS NULL OR (
            state IN ('provider_authorization_started', 'provider_exchange_in_progress')
            AND octet_length(provider_pkce_ciphertext) BETWEEN 17 AND 4096
            AND provider_pkce_key_version > 0
        ))
    ),
    CHECK (
        (oidc_nonce_digest IS NULL) = (oidc_nonce_digest_key_version IS NULL)
        AND (oidc_nonce_digest IS NULL OR (
            octet_length(oidc_nonce_digest) = 32
            AND oidc_nonce_digest_key_version > 0
        ))
    ),
    CHECK (
        (callback_continuation_ciphertext IS NULL)
            = (callback_continuation_key_version IS NULL)
        AND (callback_continuation_ciphertext IS NULL OR (
            octet_length(callback_continuation_ciphertext) BETWEEN 41 AND 4096
            AND callback_continuation_key_version > 0
        ))
    ),
    CHECK (
        (state IN ('provider_authorization_started', 'provider_exchange_in_progress'))
            = (callback_continuation_ciphertext IS NOT NULL)
    ),
    CHECK (
        state NOT IN ('provider_authorization_started', 'provider_exchange_in_progress')
        OR (method_kind = 'provider'
            AND upstream_state_digest IS NOT NULL
            AND oidc_nonce_digest IS NOT NULL
            AND provider_started_at IS NOT NULL
            AND provider_pkce_required
                = (provider_pkce_ciphertext IS NOT NULL))
    ),
    CHECK ((state = 'provider_exchange_in_progress') = (exchange_claimed_at IS NOT NULL)),
    CHECK ((state = 'proved') = (proved_at IS NOT NULL)),
    CHECK ((state IN ('provider_exchange_failed', 'expired')) = (terminal_at IS NOT NULL))
);

CREATE FUNCTION owlauth_validate_identity_mutation_slot_original_owner()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.existing_provider_identity_id IS NOT NULL
        AND NOT EXISTS (
            SELECT 1 FROM linked_identities
             WHERE project_id = NEW.project_id
               AND id = NEW.existing_provider_identity_id
               AND user_id = NEW.proof_user_id
        )
    THEN
        RAISE EXCEPTION 'provider proof slot must capture the identity original owner'
            USING ERRCODE = '23514';
    END IF;
    IF NEW.existing_email_identity_id IS NOT NULL
        AND NOT EXISTS (
            SELECT 1 FROM email_identities
             WHERE project_id = NEW.project_id
               AND id = NEW.existing_email_identity_id
               AND user_id = NEW.proof_user_id
        )
    THEN
        RAISE EXCEPTION 'email proof slot must capture the identity original owner'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER identity_mutation_slots_capture_original_owner
BEFORE INSERT ON identity_mutation_proof_slots
FOR EACH ROW
EXECUTE FUNCTION owlauth_validate_identity_mutation_slot_original_owner();

CREATE INDEX identity_mutation_proof_slots_state_idx
    ON identity_mutation_proof_slots (project_id, intent_id, state, slot_ordinal);
CREATE UNIQUE INDEX identity_mutation_slots_upstream_state_unique_idx
    ON identity_mutation_proof_slots
       (upstream_state_digest_key_version, upstream_state_digest)
    WHERE upstream_state_digest IS NOT NULL;

CREATE TRIGGER identity_mutation_slots_stable_authority
BEFORE UPDATE ON identity_mutation_proof_slots
FOR EACH ROW
EXECUTE FUNCTION reject_immutable_column_change(
    'project_id', 'intent_id', 'slot_ordinal', 'slot_role', 'purpose', 'identity_kind',
    'proof_user_id', 'expected_user_revision', 'expected_user_security_revision',
    'existing_provider_identity_id', 'existing_email_identity_id',
    'expected_identity_revision', 'application_id', 'application_security_revision',
    'method_kind', 'provider_adapter_key', 'provider_adapter_capability_revision',
    'provider_configuration_id', 'provider_revision',
    'provider_assignment_security_revision', 'provider_scopes', 'callback_url',
    'provider_pkce_required', 'oidc_nonce_required', 'email_assignment_application_id',
    'email_policy_revision', 'email_security_revision',
    'email_assignment_security_revision', 'created_at'
);

CREATE FUNCTION owlauth_enforce_identity_mutation_slot_transition()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.state <> 'pending'
            OR NEW.slot_revision <> 1
            OR NEW.upstream_state_digest IS NOT NULL
            OR NEW.provider_pkce_ciphertext IS NOT NULL
            OR NEW.oidc_nonce_digest IS NOT NULL
            OR NEW.callback_continuation_ciphertext IS NOT NULL
            OR NEW.provider_started_at IS NOT NULL
            OR NEW.exchange_claimed_at IS NOT NULL
            OR NEW.proved_at IS NOT NULL
            OR NEW.terminal_at IS NOT NULL
        THEN
            RAISE EXCEPTION 'identity-mutation proof slot must start pending at revision one'
                USING ERRCODE = '23514';
        END IF;
        RETURN NEW;
    END IF;
    IF NEW.slot_revision <= OLD.slot_revision THEN
        RAISE EXCEPTION 'identity-mutation proof-slot revision must advance'
            USING ERRCODE = '23514';
    END IF;
    IF NEW.state = 'proved'
        AND (NEW.proved_at < transaction_timestamp()
            OR NEW.proved_at > clock_timestamp())
    THEN
        RAISE EXCEPTION 'identity-mutation proof timestamp must be current'
            USING ERRCODE = '23514';
    END IF;
    IF OLD.state = 'proved' AND NEW.state = 'proved'
        AND NEW.proved_at IS DISTINCT FROM OLD.proved_at
    THEN
        RAISE EXCEPTION 'identity-mutation proof timestamp is immutable'
            USING ERRCODE = '23514';
    END IF;
    IF OLD.state IN ('provider_authorization_started', 'provider_exchange_in_progress')
        AND NEW.state IN ('provider_authorization_started', 'provider_exchange_in_progress')
        AND (NEW.upstream_state_digest, NEW.upstream_state_digest_key_version,
             NEW.provider_pkce_ciphertext, NEW.provider_pkce_key_version,
             NEW.oidc_nonce_digest, NEW.oidc_nonce_digest_key_version,
             NEW.callback_continuation_ciphertext, NEW.callback_continuation_key_version,
             NEW.provider_started_at)
            IS DISTINCT FROM
            (OLD.upstream_state_digest, OLD.upstream_state_digest_key_version,
             OLD.provider_pkce_ciphertext, OLD.provider_pkce_key_version,
             OLD.oidc_nonce_digest, OLD.oidc_nonce_digest_key_version,
             OLD.callback_continuation_ciphertext, OLD.callback_continuation_key_version,
             OLD.provider_started_at)
    THEN
        RAISE EXCEPTION 'started identity-mutation provider proof authority is immutable'
            USING ERRCODE = '23514';
    END IF;
    IF NOT (
        NEW.state = OLD.state
        OR (OLD.state = 'pending'
            AND NEW.state IN ('provider_authorization_started','email_address_entry','expired'))
        OR (OLD.state = 'provider_authorization_started'
            AND NEW.state IN ('provider_exchange_in_progress','provider_exchange_failed','expired'))
        OR (OLD.state = 'provider_exchange_in_progress'
            AND NEW.state IN ('proved','provider_exchange_failed','expired'))
        OR (OLD.state = 'email_address_entry'
            AND NEW.state IN ('email_challenge_pending','expired'))
        OR (OLD.state = 'email_challenge_pending'
            AND NEW.state IN ('proved','expired'))
        OR (OLD.state <> 'expired' AND NEW.state = 'expired')
    ) THEN
        RAISE EXCEPTION 'invalid identity-mutation proof-slot state transition'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER identity_mutation_slots_one_way_state
BEFORE INSERT OR UPDATE ON identity_mutation_proof_slots
FOR EACH ROW
EXECUTE FUNCTION owlauth_enforce_identity_mutation_slot_transition();

CREATE FUNCTION owlauth_enforce_identity_mutation_slot_set()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    target_project_id UUID;
    target_intent_id UUID;
    current_intent identity_mutation_intents%ROWTYPE;
    actual_slot_count INTEGER;
    invalid_slot_count INTEGER;
    expected_slot_count INTEGER;
BEGIN
    IF TG_TABLE_NAME = 'identity_mutation_intents' THEN
        target_project_id := NEW.project_id;
        target_intent_id := NEW.id;
    ELSIF TG_OP = 'DELETE' THEN
        target_project_id := OLD.project_id;
        target_intent_id := OLD.intent_id;
    ELSE
        target_project_id := NEW.project_id;
        target_intent_id := NEW.intent_id;
    END IF;

    SELECT * INTO current_intent
      FROM identity_mutation_intents
     WHERE project_id = target_project_id
       AND id = target_intent_id;
    IF NOT FOUND THEN
        RETURN NULL;
    END IF;

    SELECT count(*)::INTEGER,
           (count(*) FILTER (WHERE (
               (current_intent.operation_kind = 'link'
                    AND ((slot_ordinal = 1 AND slot_role = 'destination_owner'
                          AND purpose = 'link.destination_owner'
                          AND proof_user_id = current_intent.destination_user_id
                          AND expected_user_revision = current_intent.destination_user_revision
                          AND expected_user_security_revision
                              = current_intent.destination_user_security_revision)
                      OR (slot_ordinal = 2 AND slot_role = 'candidate_identity'
                          AND purpose = 'link.candidate_identity'
                          AND proof_user_id = current_intent.destination_user_id
                          AND expected_user_revision = current_intent.destination_user_revision
                          AND expected_user_security_revision
                              = current_intent.destination_user_security_revision)))
               OR (current_intent.operation_kind = 'unlink'
                    AND slot_ordinal = 1 AND slot_role = 'identity_owner'
                    AND purpose = 'unlink.identity_owner'
                    AND proof_user_id = current_intent.identity_owner_user_id
                    AND expected_user_revision = current_intent.identity_owner_user_revision
                    AND expected_user_security_revision
                        = current_intent.identity_owner_user_security_revision)
               OR (current_intent.operation_kind = 'merge'
                    AND ((slot_ordinal = 1 AND slot_role = 'winner_owner'
                          AND purpose = 'merge.winner_owner'
                          AND proof_user_id = current_intent.winner_user_id
                          AND expected_user_revision = current_intent.winner_user_revision
                          AND expected_user_security_revision
                              = current_intent.winner_user_security_revision)
                      OR (slot_ordinal = 2 AND slot_role = 'loser_owner'
                          AND purpose = 'merge.loser_owner'
                          AND proof_user_id = current_intent.loser_user_id
                          AND expected_user_revision = current_intent.loser_user_revision
                          AND expected_user_security_revision
                              = current_intent.loser_user_security_revision)))
           ) IS NOT TRUE))::INTEGER
      INTO actual_slot_count, invalid_slot_count
      FROM identity_mutation_proof_slots
     WHERE project_id = current_intent.project_id
       AND intent_id = current_intent.id;

    expected_slot_count := CASE
        WHEN current_intent.operation_kind = 'unlink' THEN 1
        ELSE 2
    END;
    IF actual_slot_count <> expected_slot_count OR invalid_slot_count <> 0 THEN
        RAISE EXCEPTION 'identity-mutation intent has an incomplete or invalid proof-slot set'
            USING ERRCODE = '23514';
    END IF;
    IF current_intent.browser_binding_digest IS NULL
        AND EXISTS (
            SELECT 1 FROM identity_mutation_proof_slots
             WHERE project_id = current_intent.project_id
               AND intent_id = current_intent.id
               AND state NOT IN ('pending', 'expired')
        )
    THEN
        RAISE EXCEPTION 'identity-mutation proof cannot start before browser binding'
            USING ERRCODE = '23514';
    END IF;
    IF current_intent.status IN ('ready', 'completed')
        AND EXISTS (
            SELECT 1 FROM identity_mutation_proof_slots
             WHERE project_id = current_intent.project_id
               AND intent_id = current_intent.id
               AND state <> 'proved'
        )
    THEN
        RAISE EXCEPTION 'ready identity-mutation intent requires every proof slot proved'
            USING ERRCODE = '23514';
    END IF;
    IF EXISTS (
        SELECT 1
          FROM identity_mutation_proof_slots AS slot
          LEFT JOIN identity_proof_receipts AS receipt
            ON receipt.project_id = slot.project_id
           AND receipt.intent_id = slot.intent_id
           AND receipt.slot_id = slot.id
         WHERE slot.project_id = current_intent.project_id
           AND slot.intent_id = current_intent.id
           AND ((slot.state = 'proved' AND receipt.id IS NULL)
                OR (slot.state NOT IN ('proved', 'expired') AND receipt.id IS NOT NULL))
    ) THEN
        RAISE EXCEPTION 'identity-mutation proof-slot state requires exact receipt presence'
            USING ERRCODE = '23514';
    END IF;
    IF EXISTS (
        SELECT 1 FROM identity_proof_receipts AS receipt
         WHERE receipt.project_id = current_intent.project_id
           AND receipt.intent_id = current_intent.id
           AND (receipt.interaction_browser_binding_digest
                    IS DISTINCT FROM current_intent.browser_binding_digest
                OR receipt.interaction_browser_binding_digest_key_version
                    IS DISTINCT FROM current_intent.browser_binding_digest_key_version
                OR receipt.interaction_browser_binding_revision
                    IS DISTINCT FROM current_intent.browser_binding_revision
                OR receipt.captured_intent_revision >= current_intent.intent_revision
                OR receipt.expires_at > current_intent.expires_at)
    ) THEN
        RAISE EXCEPTION 'identity proof receipt no longer matches its exact intent snapshot'
            USING ERRCODE = '23514';
    END IF;
    IF current_intent.status IN ('pending_proof', 'ready')
        AND EXISTS (
            SELECT 1 FROM identity_proof_receipts
             WHERE project_id = current_intent.project_id
               AND intent_id = current_intent.id
               AND status <> 'issued'
        )
    THEN
        RAISE EXCEPTION 'live identity-mutation intent requires issued receipts'
            USING ERRCODE = '23514';
    END IF;
    IF current_intent.status NOT IN ('expired', 'cancelled')
        AND EXISTS (
            SELECT 1 FROM identity_mutation_proof_slots
             WHERE project_id = current_intent.project_id
               AND intent_id = current_intent.id
               AND state = 'expired'
        )
    THEN
        RAISE EXCEPTION 'expired proof slot requires a terminal identity-mutation intent'
            USING ERRCODE = '23514';
    END IF;
    IF current_intent.status = 'ready'
        AND (current_intent.ready_at >= current_intent.expires_at
            OR current_intent.ready_at < transaction_timestamp()
            OR current_intent.ready_at > clock_timestamp()
            OR clock_timestamp() >= current_intent.expires_at
            OR EXISTS (
                SELECT 1 FROM identity_proof_receipts
                 WHERE project_id = current_intent.project_id
                   AND intent_id = current_intent.id
                   AND (status <> 'issued'
                        OR current_intent.ready_at < issued_at
                        OR current_intent.ready_at >= expires_at
                        OR clock_timestamp() >= expires_at)
            ))
    THEN
        RAISE EXCEPTION 'ready identity-mutation intent requires fresh issued receipts'
            USING ERRCODE = '23514';
    END IF;
    IF current_intent.status = 'completed'
        AND (current_intent.terminal_at >= current_intent.expires_at
            OR current_intent.terminal_at < transaction_timestamp()
            OR current_intent.terminal_at > clock_timestamp()
            OR clock_timestamp() >= current_intent.expires_at
            OR EXISTS (
                SELECT 1 FROM identity_proof_receipts
                 WHERE project_id = current_intent.project_id
                   AND intent_id = current_intent.id
                   AND (status <> 'consumed'
                        OR current_intent.terminal_at < consumed_at
                        OR current_intent.terminal_at >= expires_at
                        OR clock_timestamp() >= expires_at)
            ))
    THEN
        RAISE EXCEPTION 'completed identity-mutation intent requires fresh consumed receipts'
            USING ERRCODE = '23514';
    END IF;
    IF current_intent.status IN ('expired', 'cancelled')
        AND (EXISTS (
                SELECT 1 FROM identity_mutation_proof_slots
                 WHERE project_id = current_intent.project_id
                   AND intent_id = current_intent.id
                   AND state <> 'expired'
            )
            OR EXISTS (
                SELECT 1 FROM identity_proof_receipts
                 WHERE project_id = current_intent.project_id
                   AND intent_id = current_intent.id
                   AND status <> 'expired'
            ))
    THEN
        RAISE EXCEPTION 'terminal identity-mutation intent requires expired slots and receipts'
            USING ERRCODE = '23514';
    END IF;
    RETURN NULL;
END
$$;

CREATE CONSTRAINT TRIGGER identity_mutation_intents_exact_slot_set
AFTER INSERT OR UPDATE OF operation_kind, status ON identity_mutation_intents
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
EXECUTE FUNCTION owlauth_enforce_identity_mutation_slot_set();

CREATE CONSTRAINT TRIGGER identity_mutation_slots_exact_slot_set
AFTER INSERT OR UPDATE OR DELETE ON identity_mutation_proof_slots
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
EXECUTE FUNCTION owlauth_enforce_identity_mutation_slot_set();


-- Prospective identity material is one purpose-bound short-term ciphertext. No provider subject,
-- normalized email, alias, or profile PII is exposed as a schema column.
CREATE TABLE identity_mutation_candidate_evidence (
    id UUID PRIMARY KEY,
    project_id UUID NOT NULL,
    intent_id UUID NOT NULL,
    slot_id UUID NOT NULL,
    identity_kind TEXT NOT NULL CHECK (identity_kind IN ('provider', 'email')),
    candidate_revision BIGINT NOT NULL DEFAULT 1 CHECK (candidate_revision > 0),
    protector_key_version INTEGER NOT NULL CHECK (protector_key_version > 0),
    evidence_ciphertext BYTEA NOT NULL CHECK (
        octet_length(evidence_ciphertext) BETWEEN 41 AND 16384
    ),
    evidence_digest BYTEA NOT NULL CHECK (octet_length(evidence_digest) = 32),
    created_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    retain_until TIMESTAMPTZ NOT NULL,
    FOREIGN KEY (project_id, intent_id, slot_id)
        REFERENCES identity_mutation_proof_slots (project_id, intent_id, id)
        ON DELETE CASCADE,
    UNIQUE (project_id, id),
    UNIQUE (project_id, intent_id, slot_id),
    UNIQUE (project_id, intent_id, slot_id, id),
    CHECK (retain_until > created_at
        AND retain_until <= created_at + INTERVAL '25 minutes')
);

CREATE INDEX identity_mutation_candidate_cleanup_idx
    ON identity_mutation_candidate_evidence (retain_until, project_id, intent_id);

CREATE TRIGGER identity_mutation_candidate_evidence_immutable
BEFORE UPDATE ON identity_mutation_candidate_evidence
FOR EACH ROW
EXECUTE FUNCTION reject_immutable_column_change(
    'id', 'project_id', 'intent_id', 'slot_id', 'identity_kind', 'candidate_revision',
    'protector_key_version', 'evidence_ciphertext', 'evidence_digest', 'created_at',
    'retain_until'
);

CREATE FUNCTION owlauth_enforce_identity_mutation_candidate_evidence()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    evidence_project_id UUID;
    evidence_intent_id UUID;
    evidence_slot_id UUID;
    current_evidence identity_mutation_candidate_evidence%ROWTYPE;
    current_slot identity_mutation_proof_slots%ROWTYPE;
    current_intent identity_mutation_intents%ROWTYPE;
BEGIN
    IF TG_TABLE_NAME = 'identity_mutation_proof_slots' THEN
        evidence_project_id := NEW.project_id;
        evidence_intent_id := NEW.intent_id;
        evidence_slot_id := NEW.id;
    ELSIF TG_OP = 'DELETE' THEN
        evidence_project_id := OLD.project_id;
        evidence_intent_id := OLD.intent_id;
        evidence_slot_id := OLD.slot_id;
    ELSE
        evidence_project_id := NEW.project_id;
        evidence_intent_id := NEW.intent_id;
        evidence_slot_id := NEW.slot_id;
    END IF;

    SELECT * INTO current_evidence
      FROM identity_mutation_candidate_evidence
     WHERE project_id = evidence_project_id
       AND intent_id = evidence_intent_id
       AND slot_id = evidence_slot_id;
    IF NOT FOUND THEN
        IF TG_TABLE_NAME = 'identity_mutation_candidate_evidence'
            AND TG_OP = 'DELETE'
            AND EXISTS (
                SELECT 1 FROM identity_mutation_intents
                 WHERE project_id = evidence_project_id
                   AND id = evidence_intent_id
                   AND status NOT IN ('completed', 'expired', 'cancelled')
            )
        THEN
            RAISE EXCEPTION 'live identity-mutation candidate evidence cannot be deleted'
                USING ERRCODE = '23514';
        END IF;
        RETURN NULL;
    END IF;
    SELECT * INTO STRICT current_slot
      FROM identity_mutation_proof_slots
     WHERE project_id = current_evidence.project_id
       AND intent_id = current_evidence.intent_id
       AND id = current_evidence.slot_id;
    SELECT * INTO STRICT current_intent
      FROM identity_mutation_intents
     WHERE project_id = current_evidence.project_id
       AND id = current_evidence.intent_id;
    IF current_slot.slot_role <> 'candidate_identity'
        OR current_slot.state <> 'proved'
        OR current_slot.identity_kind <> current_evidence.identity_kind
        OR current_evidence.retain_until
            > current_intent.expires_at + INTERVAL '15 minutes'
    THEN
        RAISE EXCEPTION 'candidate evidence requires exact slot authority and bounded retention'
            USING ERRCODE = '23514';
    END IF;
    RETURN NULL;
END
$$;

CREATE CONSTRAINT TRIGGER identity_mutation_candidate_evidence_matches_slot
AFTER INSERT OR UPDATE OR DELETE ON identity_mutation_candidate_evidence
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
EXECUTE FUNCTION owlauth_enforce_identity_mutation_candidate_evidence();

CREATE CONSTRAINT TRIGGER identity_mutation_candidate_slot_matches_evidence
AFTER UPDATE OF state, identity_kind, slot_role ON identity_mutation_proof_slots
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
WHEN (NEW.slot_role = 'candidate_identity')
EXECUTE FUNCTION owlauth_enforce_identity_mutation_candidate_evidence();

-- Legacy receipts cannot be mapped to a revisioned intent/slot and are at most five minutes old.
-- Upgrade invalidates them rather than accidentally granting generic proof authority.
LOCK TABLE identity_proof_receipts IN ACCESS EXCLUSIVE MODE;
DROP TABLE identity_proof_receipts;

CREATE TABLE identity_proof_receipts (
    id UUID PRIMARY KEY,
    project_id UUID NOT NULL,
    intent_id UUID NOT NULL,
    slot_id UUID NOT NULL,
    evidence_kind TEXT NOT NULL CHECK (
        evidence_kind IN ('existing_identity', 'candidate_evidence')
    ),
    identity_kind TEXT NOT NULL CHECK (identity_kind IN ('provider', 'email')),
    provider_identity_id UUID,
    email_identity_id UUID,
    candidate_evidence_id UUID,
    evidence_revision BIGINT NOT NULL CHECK (evidence_revision > 0),
    proof_user_id UUID NOT NULL,
    proof_user_revision BIGINT NOT NULL CHECK (proof_user_revision > 0),
    proof_user_security_revision BIGINT NOT NULL CHECK (
        proof_user_security_revision > 0
    ),
    interaction_browser_binding_digest BYTEA NOT NULL CHECK (
        octet_length(interaction_browser_binding_digest) = 32
    ),
    interaction_browser_binding_digest_key_version INTEGER NOT NULL CHECK (
        interaction_browser_binding_digest_key_version > 0
    ),
    interaction_browser_binding_revision BIGINT NOT NULL CHECK (
        interaction_browser_binding_revision > 0
    ),
    captured_intent_revision BIGINT NOT NULL CHECK (captured_intent_revision > 0),
    purpose TEXT NOT NULL CHECK (
        purpose IN ('link.destination_owner', 'link.candidate_identity',
                    'unlink.identity_owner', 'merge.winner_owner', 'merge.loser_owner')
    ),
    receipt_digest BYTEA NOT NULL CHECK (octet_length(receipt_digest) = 32),
    receipt_digest_key_version INTEGER NOT NULL CHECK (receipt_digest_key_version > 0),
    status TEXT NOT NULL CHECK (status IN ('issued', 'consumed', 'expired')),
    issued_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    FOREIGN KEY (project_id, intent_id)
        REFERENCES identity_mutation_intents (project_id, id) ON DELETE CASCADE,
    FOREIGN KEY (project_id, intent_id, slot_id)
        REFERENCES identity_mutation_proof_slots (project_id, intent_id, id)
        ON DELETE CASCADE,
    FOREIGN KEY (project_id, proof_user_id)
        REFERENCES project_users (project_id, id),
    FOREIGN KEY (project_id, provider_identity_id)
        REFERENCES linked_identities (project_id, id),
    FOREIGN KEY (project_id, email_identity_id)
        REFERENCES email_identities (project_id, id),
    -- Candidate evidence is validated at receipt insertion but may be physically erased on
    -- successful confirmation while this consumed receipt remains as bounded audit evidence.
    UNIQUE (project_id, id),
    UNIQUE (project_id, intent_id, slot_id),
    UNIQUE (receipt_digest_key_version, receipt_digest),
    CHECK (expires_at > issued_at AND expires_at <= issued_at + INTERVAL '5 minutes'),
    CHECK (
        (evidence_kind = 'existing_identity'
            AND candidate_evidence_id IS NULL
            AND ((identity_kind = 'provider'
                    AND provider_identity_id IS NOT NULL
                    AND email_identity_id IS NULL)
                OR (identity_kind = 'email'
                    AND provider_identity_id IS NULL
                    AND email_identity_id IS NOT NULL)))
        OR (evidence_kind = 'candidate_evidence'
            AND provider_identity_id IS NULL
            AND email_identity_id IS NULL
            AND candidate_evidence_id IS NOT NULL)
    ),
    CHECK ((status = 'consumed') = (consumed_at IS NOT NULL))
);

CREATE INDEX identity_proof_receipts_intent_status_idx
    ON identity_proof_receipts (project_id, intent_id, status, expires_at, slot_id);
CREATE INDEX identity_proof_receipts_expiry_idx
    ON identity_proof_receipts (status, expires_at, id)
    WHERE status = 'issued';

CREATE TRIGGER identity_proof_receipts_stable_evidence
BEFORE UPDATE ON identity_proof_receipts
FOR EACH ROW
EXECUTE FUNCTION reject_immutable_column_change(
    'project_id', 'intent_id', 'slot_id', 'evidence_kind', 'identity_kind',
    'provider_identity_id', 'email_identity_id', 'candidate_evidence_id',
    'evidence_revision', 'proof_user_id', 'proof_user_revision',
    'proof_user_security_revision', 'interaction_browser_binding_digest',
    'interaction_browser_binding_digest_key_version',
    'interaction_browser_binding_revision', 'captured_intent_revision',
    'purpose', 'receipt_digest', 'receipt_digest_key_version', 'issued_at',
    'expires_at', 'created_at'
);

CREATE FUNCTION owlauth_enforce_identity_proof_receipt()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    current_slot identity_mutation_proof_slots%ROWTYPE;
    current_intent identity_mutation_intents%ROWTYPE;
    candidate_revision BIGINT;
BEGIN
    IF TG_OP = 'UPDATE' THEN
        RETURN NEW;
    END IF;

    SELECT * INTO STRICT current_slot
      FROM identity_mutation_proof_slots
     WHERE project_id = NEW.project_id
       AND intent_id = NEW.intent_id
       AND id = NEW.slot_id;
    SELECT * INTO STRICT current_intent
      FROM identity_mutation_intents
     WHERE project_id = NEW.project_id
       AND id = NEW.intent_id;

    IF NEW.provider_identity_id IS NOT NULL
        AND NOT EXISTS (
            SELECT 1 FROM linked_identities
             WHERE project_id = NEW.project_id
               AND id = NEW.provider_identity_id
               AND user_id = NEW.proof_user_id
        )
    THEN
        RAISE EXCEPTION 'provider proof receipt must capture the identity original owner'
            USING ERRCODE = '23514';
    END IF;
    IF NEW.email_identity_id IS NOT NULL
        AND NOT EXISTS (
            SELECT 1 FROM email_identities
             WHERE project_id = NEW.project_id
               AND id = NEW.email_identity_id
               AND user_id = NEW.proof_user_id
        )
    THEN
        RAISE EXCEPTION 'email proof receipt must capture the identity original owner'
            USING ERRCODE = '23514';
    END IF;

    IF NEW.purpose <> current_slot.purpose
        OR NEW.identity_kind <> current_slot.identity_kind
        OR NEW.proof_user_id <> current_slot.proof_user_id
        OR NEW.proof_user_revision <> current_slot.expected_user_revision
        OR NEW.proof_user_security_revision <> current_slot.expected_user_security_revision
        OR current_intent.browser_binding_digest IS NULL
        OR NEW.interaction_browser_binding_digest
            IS DISTINCT FROM current_intent.browser_binding_digest
        OR NEW.interaction_browser_binding_digest_key_version
            IS DISTINCT FROM current_intent.browser_binding_digest_key_version
        OR NEW.interaction_browser_binding_revision
            IS DISTINCT FROM current_intent.browser_binding_revision
        OR NEW.captured_intent_revision <> current_intent.intent_revision
        OR NEW.expires_at > current_intent.expires_at
        OR NEW.issued_at < current_intent.created_at
        OR NEW.issued_at IS DISTINCT FROM current_slot.proved_at
        OR current_slot.state <> 'proved'
    THEN
        RAISE EXCEPTION 'identity proof receipt does not match its frozen intent and slot'
            USING ERRCODE = '23514';
    END IF;

    IF NEW.evidence_kind = 'existing_identity' THEN
        IF NEW.evidence_revision IS DISTINCT FROM current_slot.expected_identity_revision
            OR NEW.provider_identity_id IS DISTINCT FROM current_slot.existing_provider_identity_id
            OR NEW.email_identity_id IS DISTINCT FROM current_slot.existing_email_identity_id
        THEN
            RAISE EXCEPTION 'identity proof receipt does not match existing identity revision'
                USING ERRCODE = '23514';
        END IF;
    ELSE
        SELECT evidence.candidate_revision INTO STRICT candidate_revision
          FROM identity_mutation_candidate_evidence AS evidence
         WHERE evidence.project_id = NEW.project_id
           AND evidence.intent_id = NEW.intent_id
           AND evidence.slot_id = NEW.slot_id
           AND evidence.id = NEW.candidate_evidence_id;
        IF NEW.evidence_revision IS DISTINCT FROM candidate_revision
            OR current_slot.slot_role <> 'candidate_identity'
        THEN
            RAISE EXCEPTION 'identity proof receipt does not match candidate evidence revision'
                USING ERRCODE = '23514';
        END IF;
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER identity_proof_receipts_match_slot
BEFORE INSERT OR UPDATE ON identity_proof_receipts
FOR EACH ROW
EXECUTE FUNCTION owlauth_enforce_identity_proof_receipt();

CREATE FUNCTION owlauth_enforce_identity_proof_receipt_transition()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.status <> 'issued' OR NEW.consumed_at IS NOT NULL THEN
            RAISE EXCEPTION 'identity proof receipt must start issued and unconsumed'
                USING ERRCODE = '23514';
        END IF;
        IF NEW.issued_at < transaction_timestamp() OR NEW.issued_at > clock_timestamp() THEN
            RAISE EXCEPTION 'identity proof receipt issue timestamp must be current'
                USING ERRCODE = '23514';
        END IF;
        RETURN NEW;
    END IF;
    IF NOT (
        NEW.status = OLD.status
        OR (OLD.status = 'issued' AND NEW.status IN ('consumed', 'expired'))
    ) THEN
        RAISE EXCEPTION 'identity proof receipt cannot be reused or reopened'
            USING ERRCODE = '23514';
    END IF;
    IF NEW.status = 'consumed'
        AND (NEW.consumed_at < NEW.issued_at
            OR NEW.consumed_at >= NEW.expires_at
            OR NEW.consumed_at < transaction_timestamp()
            OR NEW.consumed_at > clock_timestamp()
            OR clock_timestamp() >= NEW.expires_at)
    THEN
        RAISE EXCEPTION 'identity proof receipt must be consumed while fresh'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER identity_proof_receipts_one_way_state
BEFORE INSERT OR UPDATE ON identity_proof_receipts
FOR EACH ROW
EXECUTE FUNCTION owlauth_enforce_identity_proof_receipt_transition();

CREATE CONSTRAINT TRIGGER identity_proof_receipts_exact_slot_state
AFTER INSERT OR UPDATE OR DELETE ON identity_proof_receipts
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
EXECUTE FUNCTION owlauth_enforce_identity_mutation_slot_set();

CREATE TABLE identity_mutation_create_results (
    idempotency_key TEXT PRIMARY KEY
        REFERENCES control_idempotency_records (idempotency_key),
    project_id UUID NOT NULL,
    intent_id UUID NOT NULL,
    request_digest BYTEA NOT NULL CHECK (octet_length(request_digest) = 32),
    create_result_key_version INTEGER NOT NULL CHECK (create_result_key_version > 0),
    create_result_ciphertext BYTEA,
    expires_at TIMESTAMPTZ NOT NULL,
    erased_at TIMESTAMPTZ,
    FOREIGN KEY (project_id, intent_id)
        REFERENCES identity_mutation_intents (project_id, id) ON DELETE CASCADE,
    UNIQUE (project_id, intent_id),
    CHECK (create_result_ciphertext IS NULL
        OR octet_length(create_result_ciphertext) BETWEEN 40 AND 4096),
    CHECK ((create_result_ciphertext IS NULL) = (erased_at IS NOT NULL))
);

CREATE TRIGGER identity_mutation_create_results_stable_authority
BEFORE UPDATE ON identity_mutation_create_results
FOR EACH ROW
EXECUTE FUNCTION reject_immutable_column_change(
    'idempotency_key', 'project_id', 'intent_id', 'request_digest',
    'create_result_key_version', 'expires_at'
);

CREATE FUNCTION owlauth_enforce_identity_mutation_create_result_lifecycle()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    current_intent identity_mutation_intents%ROWTYPE;
    idempotency_authority control_idempotency_records%ROWTYPE;
BEGIN
    SELECT * INTO STRICT current_intent
      FROM identity_mutation_intents
     WHERE project_id = NEW.project_id AND id = NEW.intent_id;
    SELECT * INTO STRICT idempotency_authority
      FROM control_idempotency_records
     WHERE idempotency_key = NEW.idempotency_key
     FOR SHARE;
    IF idempotency_authority.project_id IS DISTINCT FROM NEW.project_id
        OR idempotency_authority.operation_kind <> 'identity_mutation.create'
        OR idempotency_authority.request_digest IS DISTINCT FROM NEW.request_digest
        OR idempotency_authority.request_scope <> NEW.project_id::TEXT
        OR idempotency_authority.result_resource_id IS DISTINCT FROM NEW.intent_id
        OR idempotency_authority.state <> 'completed'
        OR idempotency_authority.completed_at IS NULL
    THEN
        RAISE EXCEPTION 'identity-mutation create result has mismatched idempotency authority'
            USING ERRCODE = '23514';
    END IF;
    IF NEW.expires_at IS DISTINCT FROM current_intent.expires_at THEN
        RAISE EXCEPTION 'identity-mutation create result must retain the exact intent deadline'
            USING ERRCODE = '23514';
    END IF;
    IF TG_OP = 'INSERT' THEN
        IF NEW.create_result_ciphertext IS NULL OR NEW.erased_at IS NOT NULL THEN
            RAISE EXCEPTION 'identity-mutation create result must start live'
                USING ERRCODE = '23514';
        END IF;
        RETURN NEW;
    END IF;
    IF (NEW.create_result_ciphertext, NEW.erased_at)
        IS DISTINCT FROM (OLD.create_result_ciphertext, OLD.erased_at)
        AND NOT (
            OLD.create_result_ciphertext IS NOT NULL
            AND OLD.erased_at IS NULL
            AND NEW.create_result_ciphertext IS NULL
            AND NEW.erased_at >= transaction_timestamp()
            AND NEW.erased_at <= clock_timestamp()
            AND (clock_timestamp() >= OLD.expires_at
                OR (current_intent.status IN ('completed', 'expired', 'cancelled')
                    AND current_intent.terminal_at IS NOT NULL
                    AND NEW.erased_at >= current_intent.terminal_at))
        )
    THEN
        RAISE EXCEPTION 'identity-mutation create result can only be erased after expiry'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER identity_mutation_create_results_one_way_lifecycle
BEFORE INSERT OR UPDATE ON identity_mutation_create_results
FOR EACH ROW
EXECUTE FUNCTION owlauth_enforce_identity_mutation_create_result_lifecycle();

CREATE FUNCTION owlauth_enforce_identity_mutation_create_result_terminal_state()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    target_project_id UUID;
    target_intent_id UUID;
    current_intent identity_mutation_intents%ROWTYPE;
    current_result identity_mutation_create_results%ROWTYPE;
    intent_is_terminal BOOLEAN;
    result_is_erased BOOLEAN;
BEGIN
    IF TG_TABLE_NAME = 'identity_mutation_intents' THEN
        target_project_id := NEW.project_id;
        target_intent_id := NEW.id;
    ELSIF TG_OP = 'DELETE' THEN
        target_project_id := OLD.project_id;
        target_intent_id := OLD.intent_id;
    ELSE
        target_project_id := NEW.project_id;
        target_intent_id := NEW.intent_id;
    END IF;

    SELECT * INTO current_intent
      FROM identity_mutation_intents
     WHERE project_id = target_project_id AND id = target_intent_id;
    IF NOT FOUND THEN
        RETURN NULL;
    END IF;
    SELECT * INTO current_result
      FROM identity_mutation_create_results
     WHERE project_id = target_project_id AND intent_id = target_intent_id;
    IF NOT FOUND THEN
        RETURN NULL;
    END IF;

    intent_is_terminal := current_intent.status IN ('completed', 'expired', 'cancelled');
    result_is_erased := current_result.create_result_ciphertext IS NULL
        AND current_result.erased_at IS NOT NULL;
    IF intent_is_terminal IS DISTINCT FROM result_is_erased THEN
        RAISE EXCEPTION
            'identity-mutation terminal state requires exact create-result ciphertext erasure'
            USING ERRCODE = '23514';
    END IF;
    RETURN NULL;
END
$$;

CREATE CONSTRAINT TRIGGER identity_mutation_intents_exact_create_result_terminal_state
AFTER INSERT OR UPDATE OF status ON identity_mutation_intents
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
EXECUTE FUNCTION owlauth_enforce_identity_mutation_create_result_terminal_state();

CREATE CONSTRAINT TRIGGER identity_mutation_create_results_exact_terminal_state
AFTER INSERT OR UPDATE OR DELETE ON identity_mutation_create_results
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
EXECUTE FUNCTION owlauth_enforce_identity_mutation_create_result_terminal_state();

CREATE FUNCTION owlauth_reject_identity_mutation_create_result_delete()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF EXISTS (SELECT 1 FROM projects WHERE id = OLD.project_id) THEN
        RAISE EXCEPTION 'identity-mutation create-result authority tombstone cannot be deleted'
            USING ERRCODE = '23514';
    END IF;
    RETURN OLD;
END
$$;

CREATE TRIGGER identity_mutation_create_results_no_delete
BEFORE DELETE ON identity_mutation_create_results
FOR EACH ROW
EXECUTE FUNCTION owlauth_reject_identity_mutation_create_result_delete();

CREATE FUNCTION owlauth_reject_identity_mutation_intent_delete_with_result()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF EXISTS (SELECT 1 FROM projects WHERE id = OLD.project_id)
        AND EXISTS (
            SELECT 1 FROM identity_mutation_create_results
             WHERE project_id = OLD.project_id AND intent_id = OLD.id
        )
    THEN
        RAISE EXCEPTION 'identity-mutation intent with durable create authority cannot be deleted'
            USING ERRCODE = '23514';
    END IF;
    RETURN OLD;
END
$$;

CREATE TRIGGER identity_mutation_intents_preserve_create_authority
BEFORE DELETE ON identity_mutation_intents
FOR EACH ROW
EXECUTE FUNCTION owlauth_reject_identity_mutation_intent_delete_with_result();

CREATE FUNCTION owlauth_reject_identity_mutation_idempotency_authority_change()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    create_result identity_mutation_create_results%ROWTYPE;
BEGIN
    SELECT * INTO create_result
      FROM identity_mutation_create_results
     WHERE idempotency_key = OLD.idempotency_key;
    IF FOUND AND (
        NEW.project_id IS DISTINCT FROM create_result.project_id
        OR NEW.operation_kind <> 'identity_mutation.create'
        OR NEW.request_digest IS DISTINCT FROM create_result.request_digest
        OR NEW.request_scope <> create_result.project_id::TEXT
        OR NEW.result_resource_id IS DISTINCT FROM create_result.intent_id
        OR NEW.state <> 'completed'
        OR NEW.completed_at IS NULL
    ) THEN
        RAISE EXCEPTION 'identity-mutation idempotency authority is immutable after result creation'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER control_idempotency_identity_mutation_result_authority
BEFORE UPDATE OF project_id, request_digest, state, result_resource_id,
                 operation_kind, request_scope, completed_at
ON control_idempotency_records
FOR EACH ROW
EXECUTE FUNCTION owlauth_reject_identity_mutation_idempotency_authority_change();

-- Email proofs retain N/N-1 transaction columns but gain an exact XOR mutation owner. The
-- challenge ID plus generation is authoritative for both owner classes.
ALTER TABLE email_challenges
    ADD COLUMN owner_kind TEXT NOT NULL DEFAULT 'login'
        CHECK (owner_kind IN ('login', 'identity_mutation')),
    ALTER COLUMN transaction_id DROP NOT NULL,
    ADD COLUMN identity_mutation_intent_id UUID,
    ADD COLUMN identity_mutation_proof_slot_id UUID,
    ADD CONSTRAINT email_challenges_mutation_slot_fk
        FOREIGN KEY (project_id, identity_mutation_intent_id,
                     identity_mutation_proof_slot_id)
        REFERENCES identity_mutation_proof_slots (project_id, intent_id, id)
        ON DELETE CASCADE,
    ADD CONSTRAINT email_challenges_owner_shape_check CHECK (
        (owner_kind = 'login'
            AND transaction_id IS NOT NULL
            AND identity_mutation_intent_id IS NULL
            AND identity_mutation_proof_slot_id IS NULL)
        OR (owner_kind = 'identity_mutation'
            AND transaction_id IS NULL
            AND identity_mutation_intent_id IS NOT NULL
            AND identity_mutation_proof_slot_id IS NOT NULL)
    ),
    ADD CONSTRAINT email_challenges_project_id_id_generation_unique
        UNIQUE (project_id, id, generation);

DROP INDEX email_challenges_one_pending_idx;
CREATE UNIQUE INDEX email_challenges_login_one_pending_idx
    ON email_challenges (project_id, transaction_id)
    WHERE owner_kind = 'login' AND status = 'pending';
CREATE UNIQUE INDEX email_challenges_mutation_generation_unique_idx
    ON email_challenges
       (project_id, identity_mutation_intent_id,
        identity_mutation_proof_slot_id, generation)
    WHERE owner_kind = 'identity_mutation';
CREATE UNIQUE INDEX email_challenges_mutation_one_pending_idx
    ON email_challenges
       (project_id, identity_mutation_intent_id, identity_mutation_proof_slot_id)
    WHERE owner_kind = 'identity_mutation' AND status = 'pending';

CREATE TRIGGER email_challenges_stable_owner
BEFORE UPDATE ON email_challenges
FOR EACH ROW
EXECUTE FUNCTION reject_immutable_column_change(
    'project_id', 'application_id', 'owner_kind', 'transaction_id',
    'identity_mutation_intent_id', 'identity_mutation_proof_slot_id', 'generation',
    'smtp_selection_kind', 'smtp_configuration_id', 'smtp_generation',
    'smtp_security_eligibility_revision'
);

CREATE FUNCTION owlauth_enforce_email_challenge_typed_owner()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    target_project_id UUID;
    target_intent_id UUID;
    target_slot_id UUID;
BEGIN
    IF TG_TABLE_NAME = 'email_challenges' THEN
        IF (CASE WHEN TG_OP = 'DELETE' THEN OLD.owner_kind ELSE NEW.owner_kind END) = 'login' THEN
            RETURN NULL;
        END IF;
        IF TG_OP = 'DELETE' THEN
            target_project_id := OLD.project_id;
            target_intent_id := OLD.identity_mutation_intent_id;
            target_slot_id := OLD.identity_mutation_proof_slot_id;
        ELSE
            target_project_id := NEW.project_id;
            target_intent_id := NEW.identity_mutation_intent_id;
            target_slot_id := NEW.identity_mutation_proof_slot_id;
        END IF;
    ELSIF TG_TABLE_NAME = 'identity_mutation_proof_slots' THEN
        IF (CASE WHEN TG_OP = 'DELETE' THEN OLD.method_kind ELSE NEW.method_kind END) <> 'email' THEN
            RETURN NULL;
        END IF;
        IF TG_OP = 'DELETE' THEN
            target_project_id := OLD.project_id;
            target_intent_id := OLD.intent_id;
            target_slot_id := OLD.id;
        ELSE
            target_project_id := NEW.project_id;
            target_intent_id := NEW.intent_id;
            target_slot_id := NEW.id;
        END IF;
    ELSE
        target_project_id := NEW.project_id;
        target_intent_id := NEW.id;
        target_slot_id := NULL;
    END IF;

    IF EXISTS (
        SELECT 1
          FROM email_challenges AS challenge
          JOIN identity_mutation_proof_slots AS slot
            ON slot.project_id = challenge.project_id
           AND slot.intent_id = challenge.identity_mutation_intent_id
           AND slot.id = challenge.identity_mutation_proof_slot_id
          JOIN identity_mutation_intents AS intent
            ON intent.project_id = slot.project_id AND intent.id = slot.intent_id
         WHERE challenge.owner_kind = 'identity_mutation'
           AND challenge.project_id = target_project_id
           AND challenge.identity_mutation_intent_id = target_intent_id
           AND (target_slot_id IS NULL
                OR challenge.identity_mutation_proof_slot_id = target_slot_id)
           AND (slot.method_kind <> 'email'
                OR slot.application_id <> challenge.application_id
                OR slot.email_policy_revision <> challenge.method_policy_revision
                OR slot.email_security_revision <> challenge.method_security_revision
                OR slot.email_assignment_security_revision
                    <> challenge.assignment_security_revision
                OR challenge.issued_at < intent.created_at
                OR challenge.expires_at > intent.expires_at
                OR (challenge.status = 'pending'
                    AND (intent.status <> 'pending_proof'
                         OR slot.state <> 'email_challenge_pending'))
                OR (challenge.status = 'consumed' AND slot.state <> 'proved'))
    ) THEN
        RAISE EXCEPTION 'mutation email challenge does not match its frozen proof authority'
            USING ERRCODE = '23514';
    END IF;

    IF EXISTS (
        SELECT 1
          FROM identity_mutation_proof_slots AS slot
         WHERE slot.project_id = target_project_id
           AND slot.intent_id = target_intent_id
           AND slot.method_kind = 'email'
           AND (target_slot_id IS NULL OR slot.id = target_slot_id)
           AND (
                (slot.state = 'email_challenge_pending' AND (
                    (SELECT COUNT(*) FROM email_challenges AS challenge
                      WHERE challenge.owner_kind = 'identity_mutation'
                        AND challenge.project_id = slot.project_id
                        AND challenge.identity_mutation_intent_id = slot.intent_id
                        AND challenge.identity_mutation_proof_slot_id = slot.id
                        AND challenge.status = 'pending') <> 1
                    OR EXISTS (
                        SELECT 1 FROM email_challenges AS challenge
                         WHERE challenge.owner_kind = 'identity_mutation'
                           AND challenge.project_id = slot.project_id
                           AND challenge.identity_mutation_intent_id = slot.intent_id
                           AND challenge.identity_mutation_proof_slot_id = slot.id
                           AND challenge.status = 'consumed'
                    )))
                OR (slot.state = 'proved' AND (
                    (SELECT COUNT(*) FROM email_challenges AS challenge
                      WHERE challenge.owner_kind = 'identity_mutation'
                        AND challenge.project_id = slot.project_id
                        AND challenge.identity_mutation_intent_id = slot.intent_id
                        AND challenge.identity_mutation_proof_slot_id = slot.id
                        AND challenge.status = 'consumed') <> 1
                    OR EXISTS (
                        SELECT 1 FROM email_challenges AS challenge
                         WHERE challenge.owner_kind = 'identity_mutation'
                           AND challenge.project_id = slot.project_id
                           AND challenge.identity_mutation_intent_id = slot.intent_id
                           AND challenge.identity_mutation_proof_slot_id = slot.id
                           AND challenge.status = 'pending'
                    )))
                OR (slot.state NOT IN ('email_challenge_pending', 'proved')
                    AND EXISTS (
                        SELECT 1 FROM email_challenges AS challenge
                         WHERE challenge.owner_kind = 'identity_mutation'
                           AND challenge.project_id = slot.project_id
                           AND challenge.identity_mutation_intent_id = slot.intent_id
                           AND challenge.identity_mutation_proof_slot_id = slot.id
                           AND challenge.status IN ('pending', 'consumed')
                    ))
           )
    ) THEN
        RAISE EXCEPTION 'mutation email slot requires an exact current challenge lifecycle'
            USING ERRCODE = '23514';
    END IF;
    RETURN NULL;
END
$$;

CREATE CONSTRAINT TRIGGER email_challenges_exact_typed_owner
AFTER INSERT OR UPDATE OR DELETE ON email_challenges
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
EXECUTE FUNCTION owlauth_enforce_email_challenge_typed_owner();

CREATE CONSTRAINT TRIGGER identity_mutation_email_slot_reverse_owner
AFTER UPDATE ON identity_mutation_proof_slots
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
EXECUTE FUNCTION owlauth_enforce_email_challenge_typed_owner();

CREATE CONSTRAINT TRIGGER identity_mutation_email_intent_reverse_owner
AFTER UPDATE ON identity_mutation_intents
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
EXECUTE FUNCTION owlauth_enforce_email_challenge_typed_owner();

ALTER TABLE mail_outbox
    ALTER COLUMN transaction_id DROP NOT NULL,
    ADD CONSTRAINT mail_outbox_exact_challenge_generation_fk
        FOREIGN KEY (project_id, challenge_id, challenge_generation)
        REFERENCES email_challenges (project_id, id, generation)
        ON DELETE CASCADE;

CREATE FUNCTION owlauth_enforce_mail_outbox_challenge_owner()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
          FROM email_challenges AS challenge
         WHERE challenge.project_id = NEW.project_id
           AND challenge.id = NEW.challenge_id
           AND challenge.generation = NEW.challenge_generation
           AND challenge.transaction_id IS NOT DISTINCT FROM NEW.transaction_id
           AND challenge.smtp_selection_kind = NEW.smtp_selection_kind
           AND challenge.smtp_configuration_id IS NOT DISTINCT FROM NEW.smtp_configuration_id
           AND challenge.smtp_generation = NEW.smtp_generation
           AND challenge.smtp_security_eligibility_revision
                = NEW.smtp_security_eligibility_revision
    ) THEN
        RAISE EXCEPTION 'mail outbox must match its exact challenge and SMTP authority'
            USING ERRCODE = '23514';
    END IF;
    RETURN NULL;
END
$$;

CREATE CONSTRAINT TRIGGER mail_outbox_exact_challenge_owner
AFTER INSERT OR UPDATE OF project_id, transaction_id, challenge_id, challenge_generation
ON mail_outbox
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
EXECUTE FUNCTION owlauth_enforce_mail_outbox_challenge_owner();

CREATE TRIGGER mail_outbox_stable_challenge_authority
BEFORE UPDATE ON mail_outbox
FOR EACH ROW
EXECUTE FUNCTION reject_immutable_column_change(
    'project_id', 'transaction_id', 'challenge_id', 'challenge_generation',
    'smtp_selection_kind', 'smtp_configuration_id', 'smtp_generation',
    'smtp_security_eligibility_revision', 'created_at'
);

CREATE FUNCTION owlauth_enforce_mutation_email_challenge_outbox()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    target_project_id UUID;
    target_challenge_id UUID;
    target_generation SMALLINT;
    current_challenge email_challenges%ROWTYPE;
BEGIN
    IF TG_TABLE_NAME = 'email_challenges' THEN
        target_project_id := CASE WHEN TG_OP = 'DELETE' THEN OLD.project_id ELSE NEW.project_id END;
        target_challenge_id := CASE WHEN TG_OP = 'DELETE' THEN OLD.id ELSE NEW.id END;
        target_generation := CASE WHEN TG_OP = 'DELETE' THEN OLD.generation ELSE NEW.generation END;
    ELSE
        target_project_id := CASE WHEN TG_OP = 'DELETE' THEN OLD.project_id ELSE NEW.project_id END;
        target_challenge_id := CASE WHEN TG_OP = 'DELETE' THEN OLD.challenge_id ELSE NEW.challenge_id END;
        target_generation := CASE
            WHEN TG_OP = 'DELETE' THEN OLD.challenge_generation
            ELSE NEW.challenge_generation
        END;
    END IF;

    SELECT * INTO current_challenge
      FROM email_challenges
     WHERE project_id = target_project_id
       AND id = target_challenge_id
       AND generation = target_generation;
    IF NOT FOUND THEN
        RETURN NULL;
    END IF;
    IF current_challenge.owner_kind = 'identity_mutation'
        AND current_challenge.status = 'pending'
        AND (SELECT count(*)
               FROM mail_outbox AS outbox
              WHERE outbox.project_id = current_challenge.project_id
                AND outbox.challenge_id = current_challenge.id
                AND outbox.challenge_generation = current_challenge.generation
                AND outbox.transaction_id IS NULL) <> 1
    THEN
        RAISE EXCEPTION 'pending mutation email challenge requires one exact mail outbox row'
            USING ERRCODE = '23514';
    END IF;
    RETURN NULL;
END
$$;

CREATE CONSTRAINT TRIGGER email_challenges_exact_mutation_outbox
AFTER INSERT OR UPDATE OR DELETE ON email_challenges
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
EXECUTE FUNCTION owlauth_enforce_mutation_email_challenge_outbox();

CREATE CONSTRAINT TRIGGER mail_outbox_reverse_mutation_challenge
AFTER INSERT OR UPDATE OR DELETE ON mail_outbox
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
EXECUTE FUNCTION owlauth_enforce_mutation_email_challenge_outbox();

-- The callback state UUID has exactly one persisted interaction class before any provider I/O.
CREATE TABLE provider_callback_owners (
    state_id UUID PRIMARY KEY,
    project_id UUID NOT NULL,
    provider_configuration_id UUID NOT NULL,
    owner_kind TEXT NOT NULL CHECK (
        owner_kind IN ('login', 'identity_mutation', 'managed_reauthorization')
    ),
    login_transaction_id UUID,
    identity_mutation_intent_id UUID,
    identity_mutation_proof_slot_id UUID,
    managed_reauthorization_interaction_id UUID,
    created_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    FOREIGN KEY (project_id, provider_configuration_id)
        REFERENCES provider_configurations (project_id, id),
    FOREIGN KEY (project_id, login_transaction_id)
        REFERENCES login_transactions (project_id, id) ON DELETE CASCADE,
    FOREIGN KEY (project_id, identity_mutation_intent_id,
                 identity_mutation_proof_slot_id)
        REFERENCES identity_mutation_proof_slots (project_id, intent_id, id)
        ON DELETE CASCADE,
    FOREIGN KEY (project_id, managed_reauthorization_interaction_id)
        REFERENCES managed_provider_reauthorization_interactions (project_id, id)
        ON DELETE CASCADE,
    UNIQUE (project_id, state_id),
    CHECK (
        (owner_kind = 'login'
            AND login_transaction_id IS NOT NULL
            AND state_id = login_transaction_id
            AND identity_mutation_intent_id IS NULL
            AND identity_mutation_proof_slot_id IS NULL
            AND managed_reauthorization_interaction_id IS NULL)
        OR (owner_kind = 'identity_mutation'
            AND login_transaction_id IS NULL
            AND identity_mutation_intent_id IS NOT NULL
            AND identity_mutation_proof_slot_id IS NOT NULL
            AND state_id = identity_mutation_proof_slot_id
            AND managed_reauthorization_interaction_id IS NULL)
        OR (owner_kind = 'managed_reauthorization'
            AND login_transaction_id IS NULL
            AND identity_mutation_intent_id IS NULL
            AND identity_mutation_proof_slot_id IS NULL
            AND managed_reauthorization_interaction_id IS NOT NULL
            AND state_id = managed_reauthorization_interaction_id)
    )
);

CREATE INDEX provider_callback_owners_route_idx
    ON provider_callback_owners
       (project_id, provider_configuration_id, owner_kind, state_id);

CREATE TRIGGER provider_callback_owners_immutable
BEFORE UPDATE ON provider_callback_owners
FOR EACH ROW
EXECUTE FUNCTION reject_immutable_column_change(
    'state_id', 'project_id', 'provider_configuration_id', 'owner_kind',
    'login_transaction_id', 'identity_mutation_intent_id',
    'identity_mutation_proof_slot_id', 'managed_reauthorization_interaction_id',
    'created_at'
);

INSERT INTO provider_callback_owners
    (state_id, project_id, provider_configuration_id, owner_kind,
     login_transaction_id)
SELECT id, project_id, provider_configuration_id, 'login', id
  FROM login_transactions
 WHERE provider_configuration_id IS NOT NULL
   AND upstream_state_digest IS NOT NULL;

-- provider_started_at survives terminal material scrubbing and therefore also backfills retained
-- managed callback tombstones. A cross-class UUID collision intentionally aborts this migration.
INSERT INTO provider_callback_owners
    (state_id, project_id, provider_configuration_id, owner_kind,
     managed_reauthorization_interaction_id)
SELECT id, project_id, provider_configuration_id, 'managed_reauthorization', id
  FROM managed_provider_reauthorization_interactions
 WHERE provider_started_at IS NOT NULL;

CREATE FUNCTION owlauth_enforce_provider_callback_owner()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    target_state_id UUID;
    target_project_id UUID;
    target_provider_id UUID;
    target_owner_kind TEXT;
    expected_count INTEGER;
BEGIN
    IF TG_TABLE_NAME = 'provider_callback_owners' THEN
        IF TG_OP = 'DELETE' THEN
            target_state_id := OLD.state_id;
            target_project_id := OLD.project_id;
            target_provider_id := OLD.provider_configuration_id;
            target_owner_kind := OLD.owner_kind;
        ELSE
            target_state_id := NEW.state_id;
            target_project_id := NEW.project_id;
            target_provider_id := NEW.provider_configuration_id;
            target_owner_kind := NEW.owner_kind;
        END IF;
    ELSIF TG_TABLE_NAME = 'login_transactions' THEN
        target_state_id := CASE WHEN TG_OP = 'DELETE' THEN OLD.id ELSE NEW.id END;
        target_project_id := CASE WHEN TG_OP = 'DELETE' THEN OLD.project_id ELSE NEW.project_id END;
        target_provider_id := CASE WHEN TG_OP = 'DELETE' THEN OLD.provider_configuration_id
                                   ELSE NEW.provider_configuration_id END;
        target_owner_kind := 'login';
    ELSIF TG_TABLE_NAME = 'managed_provider_reauthorization_interactions' THEN
        target_state_id := CASE WHEN TG_OP = 'DELETE' THEN OLD.id ELSE NEW.id END;
        target_project_id := CASE WHEN TG_OP = 'DELETE' THEN OLD.project_id ELSE NEW.project_id END;
        target_provider_id := CASE WHEN TG_OP = 'DELETE' THEN OLD.provider_configuration_id
                                   ELSE NEW.provider_configuration_id END;
        target_owner_kind := 'managed_reauthorization';
    ELSE
        target_state_id := CASE WHEN TG_OP = 'DELETE' THEN OLD.id ELSE NEW.id END;
        target_project_id := CASE WHEN TG_OP = 'DELETE' THEN OLD.project_id ELSE NEW.project_id END;
        target_provider_id := CASE WHEN TG_OP = 'DELETE' THEN OLD.provider_configuration_id
                                   ELSE NEW.provider_configuration_id END;
        target_owner_kind := 'identity_mutation';
    END IF;

    IF TG_TABLE_NAME = 'provider_callback_owners' AND TG_OP <> 'DELETE' THEN
        IF NEW.owner_kind = 'login' AND NOT EXISTS (
            SELECT 1 FROM login_transactions
             WHERE id = NEW.login_transaction_id
               AND project_id = NEW.project_id
               AND provider_configuration_id = NEW.provider_configuration_id
        ) THEN
            RAISE EXCEPTION 'login callback owner must match its exact interaction authority'
                USING ERRCODE = '23514';
        ELSIF NEW.owner_kind = 'managed_reauthorization' AND NOT EXISTS (
            SELECT 1 FROM managed_provider_reauthorization_interactions
             WHERE id = NEW.managed_reauthorization_interaction_id
               AND project_id = NEW.project_id
               AND provider_configuration_id = NEW.provider_configuration_id
        ) THEN
            RAISE EXCEPTION 'managed callback owner must match its exact interaction authority'
                USING ERRCODE = '23514';
        ELSIF NEW.owner_kind = 'identity_mutation' AND NOT EXISTS (
            SELECT 1 FROM identity_mutation_proof_slots
             WHERE id = NEW.identity_mutation_proof_slot_id
               AND intent_id = NEW.identity_mutation_intent_id
               AND project_id = NEW.project_id
               AND provider_configuration_id = NEW.provider_configuration_id
               AND method_kind = 'provider'
        ) THEN
            RAISE EXCEPTION 'mutation callback owner must match its exact proof-slot authority'
                USING ERRCODE = '23514';
        END IF;
    END IF;

    -- Expand compatibility for N/N-1 overlap: a legacy writer does not know the owner table.
    -- Its deferred source-row trigger derives only the exact persisted class and authority. New
    -- writers may insert first; ON CONFLICT then becomes a no-op and strict validation follows.
    IF TG_TABLE_NAME = 'login_transactions' AND TG_OP <> 'DELETE' THEN
        INSERT INTO provider_callback_owners
            (state_id, project_id, provider_configuration_id, owner_kind,
             login_transaction_id)
        SELECT id, project_id, provider_configuration_id, 'login', id
          FROM login_transactions
         WHERE id = target_state_id AND project_id = target_project_id
           AND upstream_state_digest IS NOT NULL
        ON CONFLICT (state_id) DO NOTHING;
    ELSIF TG_TABLE_NAME = 'managed_provider_reauthorization_interactions'
        AND TG_OP <> 'DELETE'
    THEN
        INSERT INTO provider_callback_owners
            (state_id, project_id, provider_configuration_id, owner_kind,
             managed_reauthorization_interaction_id)
        SELECT id, project_id, provider_configuration_id, 'managed_reauthorization', id
          FROM managed_provider_reauthorization_interactions
         WHERE id = target_state_id AND project_id = target_project_id
           AND provider_started_at IS NOT NULL
        ON CONFLICT (state_id) DO NOTHING;
    END IF;

    IF target_owner_kind = 'login' THEN
        SELECT count(*)::INTEGER INTO expected_count
          FROM login_transactions AS interaction
          JOIN provider_callback_owners AS owner
            ON owner.state_id = interaction.id
           AND owner.project_id = interaction.project_id
           AND owner.provider_configuration_id = interaction.provider_configuration_id
           AND owner.owner_kind = 'login'
           AND owner.login_transaction_id = interaction.id
         WHERE interaction.id = target_state_id
           AND interaction.project_id = target_project_id
           AND interaction.upstream_state_digest IS NOT NULL;
        IF EXISTS (
            SELECT 1 FROM login_transactions
             WHERE id = target_state_id AND project_id = target_project_id
               AND upstream_state_digest IS NOT NULL
        ) AND expected_count <> 1 THEN
            RAISE EXCEPTION 'started login callback requires its exact typed owner'
                USING ERRCODE = '23514';
        END IF;
    ELSIF target_owner_kind = 'managed_reauthorization' THEN
        SELECT count(*)::INTEGER INTO expected_count
          FROM managed_provider_reauthorization_interactions AS interaction
          JOIN provider_callback_owners AS owner
            ON owner.state_id = interaction.id
           AND owner.project_id = interaction.project_id
           AND owner.provider_configuration_id = interaction.provider_configuration_id
           AND owner.owner_kind = 'managed_reauthorization'
           AND owner.managed_reauthorization_interaction_id = interaction.id
         WHERE interaction.id = target_state_id
           AND interaction.project_id = target_project_id
           AND interaction.provider_started_at IS NOT NULL;
        IF EXISTS (
            SELECT 1 FROM managed_provider_reauthorization_interactions
             WHERE id = target_state_id AND project_id = target_project_id
               AND provider_started_at IS NOT NULL
        ) AND expected_count <> 1 THEN
            RAISE EXCEPTION 'started managed callback requires its exact typed owner'
                USING ERRCODE = '23514';
        END IF;
    ELSE
        SELECT count(*)::INTEGER INTO expected_count
          FROM identity_mutation_proof_slots AS slot
          JOIN provider_callback_owners AS owner
            ON owner.state_id = slot.id
           AND owner.project_id = slot.project_id
           AND owner.provider_configuration_id = slot.provider_configuration_id
           AND owner.owner_kind = 'identity_mutation'
           AND owner.identity_mutation_intent_id = slot.intent_id
           AND owner.identity_mutation_proof_slot_id = slot.id
         WHERE slot.id = target_state_id
           AND slot.project_id = target_project_id
           AND slot.provider_started_at IS NOT NULL;
        IF EXISTS (
            SELECT 1 FROM identity_mutation_proof_slots
             WHERE id = target_state_id AND project_id = target_project_id
               AND provider_started_at IS NOT NULL
        ) AND expected_count <> 1 THEN
            RAISE EXCEPTION 'started identity-mutation callback requires its exact typed owner'
                USING ERRCODE = '23514';
        END IF;
    END IF;
    RETURN NULL;
END
$$;

CREATE CONSTRAINT TRIGGER login_transactions_callback_owner
AFTER INSERT OR UPDATE OF provider_configuration_id, upstream_state_digest OR DELETE
ON login_transactions
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
EXECUTE FUNCTION owlauth_enforce_provider_callback_owner();

CREATE CONSTRAINT TRIGGER managed_reauthorizations_callback_owner
AFTER INSERT OR UPDATE OF provider_configuration_id, provider_started_at OR DELETE
ON managed_provider_reauthorization_interactions
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
EXECUTE FUNCTION owlauth_enforce_provider_callback_owner();

CREATE CONSTRAINT TRIGGER identity_mutation_slots_callback_owner
AFTER INSERT OR UPDATE OF provider_configuration_id, provider_started_at OR DELETE
ON identity_mutation_proof_slots
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
EXECUTE FUNCTION owlauth_enforce_provider_callback_owner();

CREATE CONSTRAINT TRIGGER provider_callback_owners_reverse_presence
AFTER INSERT OR UPDATE OR DELETE ON provider_callback_owners
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
EXECUTE FUNCTION owlauth_enforce_provider_callback_owner();

-- Existing code has no merge-tombstone writer. Refuse to invent intent provenance for an
-- impossible legacy row, then require every future merge tombstone to name its exact intent.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM project_user_merge_tombstones) THEN
        RAISE EXCEPTION
            'legacy merge tombstones cannot be upgraded to typed identity-mutation evidence';
    END IF;
END
$$;

DO $$
DECLARE
    shape_constraint_name TEXT;
    provider_constraint_name TEXT;
BEGIN
    SELECT constraint_row.conname
      INTO STRICT shape_constraint_name
      FROM pg_constraint AS constraint_row
     WHERE constraint_row.conrelid = 'project_user_merge_tombstones'::regclass
       AND constraint_row.contype = 'c'
       AND pg_get_constraintdef(constraint_row.oid)
           LIKE '%primary_source_kind%primary_provider_identity_id%';

    SELECT constraint_row.conname
      INTO STRICT provider_constraint_name
      FROM pg_constraint AS constraint_row
     WHERE constraint_row.contype = 'f'
       AND constraint_row.conrelid = 'project_user_merge_tombstones'::regclass
       AND constraint_row.confrelid = 'linked_identities'::regclass
       AND ARRAY(
           SELECT attribute.attname::TEXT
             FROM unnest(constraint_row.conkey) WITH ORDINALITY AS key_column(attnum, ordinal)
             JOIN pg_attribute AS attribute
               ON attribute.attrelid = constraint_row.conrelid
              AND attribute.attnum = key_column.attnum
            ORDER BY key_column.ordinal
       ) = ARRAY['project_id','primary_provider_identity_id','winner_user_id']::TEXT[];

    EXECUTE format(
        'ALTER TABLE project_user_merge_tombstones DROP CONSTRAINT %I',
        shape_constraint_name
    );
    EXECUTE format(
        'ALTER TABLE project_user_merge_tombstones DROP CONSTRAINT %I',
        provider_constraint_name
    );
END
$$;

ALTER TABLE project_user_merge_tombstones
    ADD COLUMN identity_mutation_intent_id UUID NOT NULL,
    ADD COLUMN primary_email_identity_id UUID,
    ADD CONSTRAINT project_user_merge_tombstones_intent_unique
        UNIQUE (project_id, identity_mutation_intent_id),
    ADD CONSTRAINT project_user_merge_tombstones_intent_fk
        FOREIGN KEY (project_id, identity_mutation_intent_id)
        REFERENCES identity_mutation_intents (project_id, id),
    ADD CONSTRAINT project_user_merge_tombstones_primary_provider_fk
        FOREIGN KEY (project_id, primary_provider_identity_id)
        REFERENCES linked_identities (project_id, id),
    ADD CONSTRAINT project_user_merge_tombstones_primary_email_fk
        FOREIGN KEY (project_id, primary_email_identity_id)
        REFERENCES email_identities (project_id, id),
    ADD CONSTRAINT project_user_merge_tombstones_primary_shape_check CHECK (
        (primary_source_kind = 'provider'
            AND primary_provider_identity_id IS NOT NULL
            AND primary_email_identity_id IS NULL)
        OR (primary_source_kind = 'email'
            AND primary_provider_identity_id IS NULL
            AND primary_email_identity_id IS NOT NULL)
    );


CREATE FUNCTION owlauth_validate_merge_tombstone_primary_original_owner()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.primary_provider_identity_id IS NOT NULL
        AND NOT EXISTS (
            SELECT 1 FROM linked_identities
             WHERE project_id = NEW.project_id
               AND id = NEW.primary_provider_identity_id
               AND user_id = NEW.winner_user_id
        )
    THEN
        RAISE EXCEPTION 'merge tombstone provider source must belong to its winner at insertion'
            USING ERRCODE = '23514';
    END IF;
    IF NEW.primary_email_identity_id IS NOT NULL
        AND NOT EXISTS (
            SELECT 1 FROM email_identities
             WHERE project_id = NEW.project_id
               AND id = NEW.primary_email_identity_id
               AND user_id = NEW.winner_user_id
        )
    THEN
        RAISE EXCEPTION 'merge tombstone email source must belong to its winner at insertion'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER project_user_merge_tombstones_capture_primary_owner
BEFORE INSERT ON project_user_merge_tombstones
FOR EACH ROW
EXECUTE FUNCTION owlauth_validate_merge_tombstone_primary_original_owner();

CREATE FUNCTION owlauth_validate_merge_tombstone_primary_final_owner()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    target_project_id UUID;
    target_identity_id UUID;
    target_loser_user_id UUID;
    target_identity_kind TEXT;
BEGIN
    IF TG_TABLE_NAME = 'project_user_merge_tombstones' THEN
        target_project_id := CASE WHEN TG_OP = 'DELETE' THEN OLD.project_id ELSE NEW.project_id END;
        target_loser_user_id := CASE
            WHEN TG_OP = 'DELETE' THEN OLD.loser_user_id
            ELSE NEW.loser_user_id
        END;
        target_identity_kind := 'tombstone';
    ELSE
        target_project_id := CASE WHEN TG_OP = 'DELETE' THEN OLD.project_id ELSE NEW.project_id END;
        target_identity_id := CASE WHEN TG_OP = 'DELETE' THEN OLD.id ELSE NEW.id END;
        target_identity_kind := CASE
            WHEN TG_TABLE_NAME = 'linked_identities' THEN 'provider'
            ELSE 'email'
        END;
    END IF;

    PERFORM owlauth_lock_project_identity_graph(target_project_id);
    IF EXISTS (
        SELECT 1
          FROM project_user_merge_tombstones AS tombstone
         WHERE tombstone.project_id = target_project_id
           AND ((target_identity_kind = 'tombstone'
                    AND tombstone.loser_user_id = target_loser_user_id)
                OR (target_identity_kind = 'provider'
                    AND tombstone.primary_provider_identity_id = target_identity_id)
                OR (target_identity_kind = 'email'
                    AND tombstone.primary_email_identity_id = target_identity_id))
           AND ((tombstone.primary_provider_identity_id IS NOT NULL
                    AND NOT EXISTS (
                        SELECT 1 FROM linked_identities AS identity
                         WHERE identity.project_id = tombstone.project_id
                           AND identity.id = tombstone.primary_provider_identity_id
                           AND identity.user_id = tombstone.winner_user_id
                    ))
                OR (tombstone.primary_email_identity_id IS NOT NULL
                    AND NOT EXISTS (
                        SELECT 1 FROM email_identities AS identity
                         WHERE identity.project_id = tombstone.project_id
                           AND identity.id = tombstone.primary_email_identity_id
                           AND identity.user_id = tombstone.winner_user_id
                    )))
    ) THEN
        RAISE EXCEPTION 'merge tombstone primary source must belong to its exact winner'
            USING ERRCODE = '23514';
    END IF;
    RETURN NULL;
END
$$;

CREATE CONSTRAINT TRIGGER project_user_merge_tombstones_final_primary_owner
AFTER INSERT OR UPDATE OR DELETE ON project_user_merge_tombstones
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
EXECUTE FUNCTION owlauth_validate_merge_tombstone_primary_final_owner();

CREATE CONSTRAINT TRIGGER linked_identities_merge_tombstone_primary_owner
AFTER INSERT OR UPDATE OF user_id OR DELETE ON linked_identities
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
EXECUTE FUNCTION owlauth_validate_merge_tombstone_primary_final_owner();

CREATE CONSTRAINT TRIGGER email_identities_merge_tombstone_primary_owner
AFTER INSERT OR UPDATE OF user_id OR DELETE ON email_identities
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
EXECUTE FUNCTION owlauth_validate_merge_tombstone_primary_final_owner();

CREATE FUNCTION owlauth_enforce_project_user_merge_tombstone()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    merge_intent identity_mutation_intents%ROWTYPE;
BEGIN
    SELECT * INTO STRICT merge_intent
      FROM identity_mutation_intents
     WHERE project_id = NEW.project_id
       AND id = NEW.identity_mutation_intent_id;
    IF merge_intent.operation_kind <> 'merge'
        OR merge_intent.status <> 'completed'
        OR merge_intent.winner_user_id <> NEW.winner_user_id
        OR merge_intent.loser_user_id <> NEW.loser_user_id
        OR merge_intent.winner_user_revision <> NEW.winner_user_revision
        OR merge_intent.loser_user_revision <> NEW.loser_user_revision
        OR merge_intent.primary_source_disposition <> NEW.primary_source_kind
        OR merge_intent.primary_provider_identity_id
            IS DISTINCT FROM NEW.primary_provider_identity_id
        OR merge_intent.primary_email_identity_id
            IS DISTINCT FROM NEW.primary_email_identity_id
        OR merge_intent.sessions_disposition <> NEW.sessions_disposition
        OR merge_intent.bindings_disposition <> NEW.bindings_disposition
        OR merge_intent.correlation_id <> NEW.correlation_id
        OR merge_intent.terminal_at IS DISTINCT FROM NEW.merged_at
    THEN
        RAISE EXCEPTION 'merge tombstone must match its exact completed mutation intent'
            USING ERRCODE = '23514';
    END IF;
    RETURN NULL;
END
$$;

CREATE CONSTRAINT TRIGGER project_user_merge_tombstones_exact_intent
AFTER INSERT OR UPDATE ON project_user_merge_tombstones
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
EXECUTE FUNCTION owlauth_enforce_project_user_merge_tombstone();

CREATE FUNCTION owlauth_enforce_identity_mutation_merge_tombstone()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    target_project_id UUID;
    target_intent_id UUID;
    current_intent identity_mutation_intents%ROWTYPE;
    matching_tombstones INTEGER;
BEGIN
    IF TG_TABLE_NAME = 'identity_mutation_intents' THEN
        target_project_id := NEW.project_id;
        target_intent_id := NEW.id;
    ELSE
        target_project_id := CASE WHEN TG_OP = 'DELETE' THEN OLD.project_id ELSE NEW.project_id END;
        target_intent_id := CASE
            WHEN TG_OP = 'DELETE' THEN OLD.identity_mutation_intent_id
            ELSE NEW.identity_mutation_intent_id
        END;
    END IF;

    PERFORM owlauth_lock_project_identity_graph(target_project_id);
    SELECT * INTO current_intent
      FROM identity_mutation_intents
     WHERE project_id = target_project_id AND id = target_intent_id;
    IF NOT FOUND THEN
        RETURN NULL;
    END IF;

    SELECT count(*)::INTEGER INTO matching_tombstones
      FROM project_user_merge_tombstones AS tombstone
     WHERE tombstone.project_id = current_intent.project_id
       AND tombstone.identity_mutation_intent_id = current_intent.id
       AND tombstone.winner_user_id = current_intent.winner_user_id
       AND tombstone.winner_user_revision = current_intent.winner_user_revision
       AND tombstone.loser_user_id = current_intent.loser_user_id
       AND tombstone.loser_user_revision = current_intent.loser_user_revision
       AND tombstone.primary_source_kind = current_intent.primary_source_disposition
       AND tombstone.primary_provider_identity_id
            IS NOT DISTINCT FROM current_intent.primary_provider_identity_id
       AND tombstone.primary_email_identity_id
            IS NOT DISTINCT FROM current_intent.primary_email_identity_id
       AND tombstone.sessions_disposition
            IS NOT DISTINCT FROM current_intent.sessions_disposition
       AND tombstone.bindings_disposition
            IS NOT DISTINCT FROM current_intent.bindings_disposition
       AND tombstone.correlation_id = current_intent.correlation_id
       AND tombstone.merged_at IS NOT DISTINCT FROM current_intent.terminal_at;

    IF current_intent.operation_kind = 'merge' AND current_intent.status = 'completed' THEN
        IF matching_tombstones <> 1 THEN
            RAISE EXCEPTION
                'completed merge intent requires one exact merge tombstone'
                USING ERRCODE = '23514';
        END IF;
    ELSIF EXISTS (
        SELECT 1 FROM project_user_merge_tombstones
         WHERE project_id = current_intent.project_id
           AND identity_mutation_intent_id = current_intent.id
    ) THEN
        RAISE EXCEPTION
            'merge tombstone requires an exact completed merge intent'
            USING ERRCODE = '23514';
    END IF;
    RETURN NULL;
END
$$;

CREATE CONSTRAINT TRIGGER identity_mutation_intents_exact_merge_tombstone
AFTER INSERT OR UPDATE OF operation_kind, status, terminal_at ON identity_mutation_intents
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
EXECUTE FUNCTION owlauth_enforce_identity_mutation_merge_tombstone();

CREATE CONSTRAINT TRIGGER project_user_merge_tombstones_reverse_exact_intent
AFTER INSERT OR UPDATE OR DELETE ON project_user_merge_tombstones
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
EXECUTE FUNCTION owlauth_enforce_identity_mutation_merge_tombstone();

CREATE FUNCTION owlauth_reject_project_user_merge_tombstone_mutation()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'Project-user merge tombstones are immutable'
        USING ERRCODE = '23514';
END
$$;

CREATE TRIGGER project_user_merge_tombstones_immutable
BEFORE UPDATE OR DELETE ON project_user_merge_tombstones
FOR EACH ROW
EXECUTE FUNCTION owlauth_reject_project_user_merge_tombstone_mutation();
