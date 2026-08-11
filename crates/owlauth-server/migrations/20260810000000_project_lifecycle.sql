-- Project re-enablement and provider-safe permanent deletion.
--
-- The 20260806 baselines have shipped and remain immutable. This ordered migration extends the
-- deployed schema without rewriting prior migration bytes.

ALTER TABLE public.projects
    ADD COLUMN deletion_requested_at timestamp with time zone;

ALTER TABLE public.projects
    DROP CONSTRAINT projects_status_check;
ALTER TABLE public.projects
    ADD CONSTRAINT projects_status_check
    CHECK (status = ANY (ARRAY['active'::text, 'disabled'::text, 'deleting'::text]));
ALTER TABLE public.projects
    ADD CONSTRAINT projects_deletion_shape_check
    CHECK ((status = 'deleting'::text) = (deletion_requested_at IS NOT NULL));

CREATE FUNCTION public.owlauth_enforce_project_lifecycle() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF OLD.status = 'deleting' THEN
        RAISE EXCEPTION 'deleting Project is terminal'
            USING ERRCODE = '23514';
    END IF;
    IF NEW.status IS DISTINCT FROM OLD.status THEN
        IF NOT (
            (OLD.status = 'active' AND NEW.status IN ('disabled', 'deleting'))
            OR (OLD.status = 'disabled' AND NEW.status IN ('active', 'deleting'))
        ) OR NEW.security_revision <> OLD.security_revision + 1 THEN
            RAISE EXCEPTION 'invalid Project lifecycle transition'
                USING ERRCODE = '23514';
        END IF;
    ELSIF NEW.deletion_requested_at IS DISTINCT FROM OLD.deletion_requested_at THEN
        RAISE EXCEPTION 'Project deletion timestamp is lifecycle-owned'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER projects_enforce_lifecycle
    BEFORE UPDATE ON public.projects
    FOR EACH ROW EXECUTE FUNCTION public.owlauth_enforce_project_lifecycle();

-- The owner-executed finalizer sets this transaction-local value only after locking and proving one
-- exact deleting Project has no outstanding protected material or provider cleanup. Immutable-row
-- triggers use the exact Project context while the reviewed cascade is in progress.
CREATE FUNCTION public.owlauth_project_deletion_allowed(target_project_id uuid) RETURNS boolean
    LANGUAGE sql STABLE
    SET search_path = pg_catalog
    AS $$
SELECT current_user = pg_catalog.pg_get_userbyid((
           SELECT relation.relowner
             FROM pg_catalog.pg_class AS relation
            WHERE relation.oid = 'public.projects'::pg_catalog.regclass
       ))
   AND pg_catalog.current_setting('owlauth.project_deletion_id', true) = target_project_id::text
$$;

CREATE OR REPLACE FUNCTION public.owlauth_reject_identity_mutation_create_result_delete() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF public.owlauth_project_deletion_allowed(OLD.project_id) THEN
        RETURN OLD;
    END IF;
    IF EXISTS (SELECT 1 FROM projects WHERE id = OLD.project_id) THEN
        RAISE EXCEPTION 'identity-mutation create-result authority tombstone cannot be deleted'
            USING ERRCODE = '23514';
    END IF;
    RETURN OLD;
END
$$;

CREATE OR REPLACE FUNCTION public.owlauth_reject_identity_mutation_intent_delete_with_result() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF public.owlauth_project_deletion_allowed(OLD.project_id) THEN
        RETURN OLD;
    END IF;
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

CREATE OR REPLACE FUNCTION public.owlauth_reject_merged_binding_delete() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF public.owlauth_project_deletion_allowed(OLD.project_id) THEN
        RETURN OLD;
    END IF;
    IF OLD.status = 'merged'
        AND EXISTS (SELECT 1 FROM projects WHERE id = OLD.project_id)
    THEN
        RAISE EXCEPTION 'merged Application binding attribution cannot be deleted'
            USING ERRCODE = '23514';
    END IF;
    RETURN OLD;
END
$$;

CREATE OR REPLACE FUNCTION public.owlauth_reject_project_user_merge_tombstone_mutation() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF TG_OP = 'DELETE' AND public.owlauth_project_deletion_allowed(OLD.project_id) THEN
        RETURN OLD;
    END IF;
    RAISE EXCEPTION 'Project-user merge tombstones are immutable'
        USING ERRCODE = '23514';
END
$$;

CREATE OR REPLACE FUNCTION public.reject_application_sync_immutable_mutation() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF TG_OP = 'DELETE' AND public.owlauth_project_deletion_allowed(OLD.project_id) THEN
        RETURN OLD;
    END IF;
    IF TG_OP = 'DELETE'
       AND OLD.retain_until <= transaction_timestamp()
       AND NOT EXISTS (
           SELECT 1 FROM webhook_deliveries delivery
            WHERE delivery.event_id = OLD.id
              AND delivery.state NOT IN ('delivered', 'terminal', 'cancelled')
       )
    THEN
        RETURN OLD;
    END IF;
    RAISE EXCEPTION '% is append-only', TG_TABLE_NAME;
END;
$$;

CREATE OR REPLACE FUNCTION public.reject_audit_event_mutation() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF TG_OP = 'DELETE' AND public.owlauth_project_deletion_allowed(OLD.project_id) THEN
        RETURN OLD;
    END IF;
    RAISE EXCEPTION '% is append-only', TG_TABLE_NAME
        USING ERRCODE = '23514';
END
$$;

CREATE OR REPLACE FUNCTION public.reject_webhook_attempt_immutable_mutation() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF TG_OP = 'DELETE'
       AND EXISTS (
           SELECT 1
             FROM webhook_deliveries delivery
            WHERE delivery.id = OLD.delivery_id
              AND public.owlauth_project_deletion_allowed(delivery.project_id)
       )
    THEN
        RETURN OLD;
    END IF;
    IF TG_OP = 'DELETE'
       AND EXISTS (
           SELECT 1
             FROM webhook_deliveries delivery
             JOIN application_user_events event ON event.id = delivery.event_id
            WHERE delivery.id = OLD.delivery_id
              AND delivery.state IN ('delivered', 'terminal', 'cancelled')
              AND event.retain_until <= transaction_timestamp()
       )
    THEN
        RETURN OLD;
    END IF;
    RAISE EXCEPTION '% is append-only', TG_TABLE_NAME;
END;
$$;

-- Existing root constraints that intentionally retained Project state become cascading only for the
-- reviewed whole-Project finalizer. All ordinary child deletes remain governed by their existing
-- constraints and immutable-history triggers.
ALTER TABLE public.applications DROP CONSTRAINT applications_project_id_fkey;
ALTER TABLE public.applications
    ADD CONSTRAINT applications_project_id_fkey
    FOREIGN KEY (project_id) REFERENCES public.projects(id) ON DELETE CASCADE NOT VALID;
ALTER TABLE public.applications VALIDATE CONSTRAINT applications_project_id_fkey;

ALTER TABLE public.audit_events DROP CONSTRAINT audit_events_project_id_fkey;
ALTER TABLE public.audit_events
    ADD CONSTRAINT audit_events_project_id_fkey
    FOREIGN KEY (project_id) REFERENCES public.projects(id) ON DELETE CASCADE NOT VALID;
ALTER TABLE public.audit_events VALIDATE CONSTRAINT audit_events_project_id_fkey;

ALTER TABLE public.control_idempotency_records DROP CONSTRAINT control_idempotency_records_project_id_fkey;
ALTER TABLE public.control_idempotency_records
    ADD CONSTRAINT control_idempotency_records_project_id_fkey
    FOREIGN KEY (project_id) REFERENCES public.projects(id) ON DELETE CASCADE NOT VALID;
ALTER TABLE public.control_idempotency_records VALIDATE CONSTRAINT control_idempotency_records_project_id_fkey;

ALTER TABLE public.project_server_keys DROP CONSTRAINT project_server_keys_project_id_fkey;
ALTER TABLE public.project_server_keys
    ADD CONSTRAINT project_server_keys_project_id_fkey
    FOREIGN KEY (project_id) REFERENCES public.projects(id) ON DELETE CASCADE NOT VALID;
ALTER TABLE public.project_server_keys VALIDATE CONSTRAINT project_server_keys_project_id_fkey;

ALTER TABLE public.protected_materials DROP CONSTRAINT protected_materials_project_id_fkey;
ALTER TABLE public.protected_materials
    ADD CONSTRAINT protected_materials_project_id_fkey
    FOREIGN KEY (project_id) REFERENCES public.projects(id) ON DELETE CASCADE NOT VALID;
ALTER TABLE public.protected_materials VALIDATE CONSTRAINT protected_materials_project_id_fkey;

-- Complete the natural ownership graph at the few deployed NO ACTION edges that otherwise retain
-- Project-owned rows. This reuses existing parents instead of adding a second Project FK to every
-- child table.
ALTER TABLE public.application_sessions
    DROP CONSTRAINT application_sessions_binding_identity_fk;
ALTER TABLE public.application_sessions
    ADD CONSTRAINT application_sessions_binding_identity_fk
    FOREIGN KEY (project_id, binding_id, application_id)
    REFERENCES public.application_user_bindings(project_id, id, application_id)
    ON DELETE CASCADE NOT VALID;
ALTER TABLE public.application_sessions
    VALIDATE CONSTRAINT application_sessions_binding_identity_fk;

ALTER TABLE public.application_user_events
    DROP CONSTRAINT application_user_event_binding_fk;
ALTER TABLE public.application_user_events
    ADD CONSTRAINT application_user_event_binding_fk
    FOREIGN KEY (project_id, binding_id, application_id)
    REFERENCES public.application_user_bindings(project_id, id, application_id)
    ON DELETE CASCADE NOT VALID;
ALTER TABLE public.application_user_events
    VALIDATE CONSTRAINT application_user_event_binding_fk;

ALTER TABLE public.email_challenges
    DROP CONSTRAINT email_challenges_project_id_application_id_fkey;
ALTER TABLE public.email_challenges
    ADD CONSTRAINT email_challenges_project_id_application_id_fkey
    FOREIGN KEY (project_id, application_id)
    REFERENCES public.applications(project_id, id)
    ON DELETE CASCADE NOT VALID;
ALTER TABLE public.email_challenges
    VALIDATE CONSTRAINT email_challenges_project_id_application_id_fkey;

ALTER TABLE public.key_state_events
    DROP CONSTRAINT key_state_events_project_id_ring_id_signing_key_id_fkey;
ALTER TABLE public.key_state_events
    ADD CONSTRAINT key_state_events_project_id_ring_id_signing_key_id_fkey
    FOREIGN KEY (project_id, ring_id, signing_key_id)
    REFERENCES public.project_signing_keys(project_id, ring_id, id)
    ON DELETE CASCADE NOT VALID;
ALTER TABLE public.key_state_events
    VALIDATE CONSTRAINT key_state_events_project_id_ring_id_signing_key_id_fkey;

ALTER TABLE public.project_browser_logout_interactions
    DROP CONSTRAINT project_browser_logout_intera_project_id_application_sessi_fkey;
ALTER TABLE public.project_browser_logout_interactions
    ADD CONSTRAINT project_browser_logout_intera_project_id_application_sessi_fkey
    FOREIGN KEY (project_id, application_session_id, application_id, user_id)
    REFERENCES public.application_sessions(project_id, id, application_id, user_id)
    ON DELETE CASCADE NOT VALID;
ALTER TABLE public.project_browser_logout_interactions
    VALIDATE CONSTRAINT project_browser_logout_intera_project_id_application_sessi_fkey;

ALTER TABLE public.project_user_merge_tombstones
    DROP CONSTRAINT project_user_merge_tombstones_intent_fk;
ALTER TABLE public.project_user_merge_tombstones
    ADD CONSTRAINT project_user_merge_tombstones_intent_fk
    FOREIGN KEY (project_id, identity_mutation_intent_id)
    REFERENCES public.identity_mutation_intents(project_id, id)
    ON DELETE CASCADE NOT VALID;
ALTER TABLE public.project_user_merge_tombstones
    VALIDATE CONSTRAINT project_user_merge_tombstones_intent_fk;

ALTER TABLE public.provider_callback_owners
    DROP CONSTRAINT provider_callback_owners_project_id_provider_configuration_fkey;
ALTER TABLE public.provider_callback_owners
    ADD CONSTRAINT provider_callback_owners_project_id_provider_configuration_fkey
    FOREIGN KEY (project_id, provider_configuration_id)
    REFERENCES public.provider_configurations(project_id, id)
    ON DELETE CASCADE NOT VALID;
ALTER TABLE public.provider_callback_owners
    VALIDATE CONSTRAINT provider_callback_owners_project_id_provider_configuration_fkey;

ALTER TABLE public.webhook_application_dispatch_state
    DROP CONSTRAINT webhook_dispatch_application_fk;
ALTER TABLE public.webhook_application_dispatch_state
    ADD CONSTRAINT webhook_dispatch_application_fk
    FOREIGN KEY (project_id, application_id)
    REFERENCES public.applications(project_id, id)
    ON DELETE CASCADE NOT VALID;
ALTER TABLE public.webhook_application_dispatch_state
    VALIDATE CONSTRAINT webhook_dispatch_application_fk;

ALTER TABLE public.webhook_endpoints
    DROP CONSTRAINT webhook_endpoint_application_fk;
ALTER TABLE public.webhook_endpoints
    ADD CONSTRAINT webhook_endpoint_application_fk
    FOREIGN KEY (project_id, application_id)
    REFERENCES public.applications(project_id, id)
    ON DELETE CASCADE NOT VALID;
ALTER TABLE public.webhook_endpoints
    VALIDATE CONSTRAINT webhook_endpoint_application_fk;

ALTER TABLE public.webhook_deliveries
    DROP CONSTRAINT webhook_delivery_event_fk;
ALTER TABLE public.webhook_deliveries
    ADD CONSTRAINT webhook_delivery_event_fk
    FOREIGN KEY (project_id, application_id, event_id)
    REFERENCES public.application_user_events(project_id, application_id, id)
    ON DELETE CASCADE NOT VALID;
ALTER TABLE public.webhook_deliveries
    VALIDATE CONSTRAINT webhook_delivery_event_fk;

-- These two blocker tables already cascade through their natural parents. A direct root edge is
-- retained only as an insertion fence after the finalizer locks the Project and proves no cleanup
-- blocker remains.
ALTER TABLE public.key_provisioning_operations
    ADD CONSTRAINT key_provisioning_operations_project_root_fkey
    FOREIGN KEY (project_id) REFERENCES public.projects(id) ON DELETE CASCADE NOT VALID;
ALTER TABLE public.key_provisioning_operations
    VALIDATE CONSTRAINT key_provisioning_operations_project_root_fkey;

ALTER TABLE public.managed_provider_credentials
    ADD CONSTRAINT managed_provider_credentials_project_root_fkey
    FOREIGN KEY (project_id) REFERENCES public.projects(id) ON DELETE CASCADE NOT VALID;
ALTER TABLE public.managed_provider_credentials
    VALIDATE CONSTRAINT managed_provider_credentials_project_root_fkey;

-- Secret generations and cleanup operations carry no direct Project edge. Cascade their natural
-- endpoint ownership so the Project root reaches that child-only graph.
ALTER TABLE public.webhook_secret_cleanup_operations
    DROP CONSTRAINT webhook_secret_cleanup_generation_fk;
ALTER TABLE public.webhook_secret_cleanup_operations
    ADD CONSTRAINT webhook_secret_cleanup_generation_fk
    FOREIGN KEY (endpoint_id, generation)
    REFERENCES public.webhook_secret_generations(endpoint_id, generation)
    ON DELETE CASCADE NOT VALID;
ALTER TABLE public.webhook_secret_cleanup_operations
    VALIDATE CONSTRAINT webhook_secret_cleanup_generation_fk;

ALTER TABLE public.webhook_secret_generations
    DROP CONSTRAINT webhook_secret_generations_endpoint_id_fkey;
ALTER TABLE public.webhook_secret_generations
    ADD CONSTRAINT webhook_secret_generations_endpoint_id_fkey
    FOREIGN KEY (endpoint_id) REFERENCES public.webhook_endpoints(id) ON DELETE CASCADE NOT VALID;
ALTER TABLE public.webhook_secret_generations
    VALIDATE CONSTRAINT webhook_secret_generations_endpoint_id_fkey;

-- Cross-links inside the cascade closure remain NO ACTION authorities for ordinary operations.
-- Make them deferrable but initially immediate so only the reviewed finalizer can postpone their
-- ordering checks while the complete graph is removed.
ALTER TABLE public.application_sessions
    ALTER CONSTRAINT application_sessions_credential_user_fk DEFERRABLE INITIALLY IMMEDIATE,
    ALTER CONSTRAINT application_sessions_project_id_browser_session_id_user_id_fkey
        DEFERRABLE INITIALLY IMMEDIATE;
ALTER TABLE public.application_user_events
    ALTER CONSTRAINT application_user_event_application_fk DEFERRABLE INITIALLY IMMEDIATE,
    ALTER CONSTRAINT application_user_event_historical_user_fk DEFERRABLE INITIALLY IMMEDIATE;
ALTER TABLE public.email_challenges
    ALTER CONSTRAINT email_challenges_project_id_smtp_configuration_id_fkey
        DEFERRABLE INITIALLY IMMEDIATE;
ALTER TABLE public.handoff_tickets
    ALTER CONSTRAINT handoff_tickets_project_id_application_id_fkey
        DEFERRABLE INITIALLY IMMEDIATE,
    ALTER CONSTRAINT handoff_tickets_project_id_browser_session_id_user_id_fkey
        DEFERRABLE INITIALLY IMMEDIATE,
    ALTER CONSTRAINT handoff_tickets_project_id_provider_configuration_id_fkey
        DEFERRABLE INITIALLY IMMEDIATE,
    ALTER CONSTRAINT handoff_tickets_project_id_user_id_fkey DEFERRABLE INITIALLY IMMEDIATE;
ALTER TABLE public.identity_mutation_create_results
    ALTER CONSTRAINT identity_mutation_create_results_idempotency_key_fkey
        DEFERRABLE INITIALLY IMMEDIATE;
ALTER TABLE public.identity_mutation_intents
    ALTER CONSTRAINT identity_mutation_intents_project_id_destination_user_id_fkey
        DEFERRABLE INITIALLY IMMEDIATE,
    ALTER CONSTRAINT identity_mutation_intents_project_id_identity_owner_user_i_fkey
        DEFERRABLE INITIALLY IMMEDIATE,
    ALTER CONSTRAINT identity_mutation_intents_project_id_loser_user_id_fkey
        DEFERRABLE INITIALLY IMMEDIATE,
    ALTER CONSTRAINT identity_mutation_intents_project_id_primary_email_identit_fkey
        DEFERRABLE INITIALLY IMMEDIATE,
    ALTER CONSTRAINT identity_mutation_intents_project_id_primary_provider_iden_fkey
        DEFERRABLE INITIALLY IMMEDIATE,
    ALTER CONSTRAINT identity_mutation_intents_project_id_winner_user_id_fkey
        DEFERRABLE INITIALLY IMMEDIATE;
ALTER TABLE public.identity_mutation_proof_slots
    ALTER CONSTRAINT identity_mutation_proof_slots_project_id_application_id_fkey
        DEFERRABLE INITIALLY IMMEDIATE,
    ALTER CONSTRAINT identity_mutation_proof_slots_project_id_application_id_pr_fkey
        DEFERRABLE INITIALLY IMMEDIATE,
    ALTER CONSTRAINT identity_mutation_proof_slots_project_id_email_assignment__fkey
        DEFERRABLE INITIALLY IMMEDIATE,
    ALTER CONSTRAINT identity_mutation_proof_slots_project_id_existing_email_id_fkey
        DEFERRABLE INITIALLY IMMEDIATE,
    ALTER CONSTRAINT identity_mutation_proof_slots_project_id_existing_provider_fkey
        DEFERRABLE INITIALLY IMMEDIATE,
    ALTER CONSTRAINT identity_mutation_proof_slots_project_id_proof_user_id_fkey
        DEFERRABLE INITIALLY IMMEDIATE,
    ALTER CONSTRAINT identity_mutation_proof_slots_project_id_provider_configur_fkey
        DEFERRABLE INITIALLY IMMEDIATE;
ALTER TABLE public.identity_proof_receipts
    ALTER CONSTRAINT identity_proof_receipts_project_id_email_identity_id_fkey
        DEFERRABLE INITIALLY IMMEDIATE,
    ALTER CONSTRAINT identity_proof_receipts_project_id_proof_user_id_fkey
        DEFERRABLE INITIALLY IMMEDIATE,
    ALTER CONSTRAINT identity_proof_receipts_project_id_provider_identity_id_fkey
        DEFERRABLE INITIALLY IMMEDIATE;
ALTER TABLE public.linked_identities
    ALTER CONSTRAINT linked_identities_project_id_created_via_provider_configur_fkey
        DEFERRABLE INITIALLY IMMEDIATE;
ALTER TABLE public.login_email_method_snapshots
    ALTER CONSTRAINT login_email_method_snapshots_project_id_application_id_fkey
        DEFERRABLE INITIALLY IMMEDIATE,
    ALTER CONSTRAINT login_email_method_snapshots_project_id_smtp_configuration_fkey
        DEFERRABLE INITIALLY IMMEDIATE;
ALTER TABLE public.login_transaction_methods
    ALTER CONSTRAINT login_transaction_methods_project_id_provider_configuratio_fkey
        DEFERRABLE INITIALLY IMMEDIATE;
ALTER TABLE public.login_transactions
    ALTER CONSTRAINT login_transactions_project_id_provider_configuration_id_fkey
        DEFERRABLE INITIALLY IMMEDIATE,
    ALTER CONSTRAINT login_transactions_project_id_user_id_fkey DEFERRABLE INITIALLY IMMEDIATE;
ALTER TABLE public.mail_outbox
    ALTER CONSTRAINT mail_outbox_project_id_smtp_configuration_id_fkey
        DEFERRABLE INITIALLY IMMEDIATE;
ALTER TABLE public.managed_provider_connections
    ALTER CONSTRAINT managed_provider_connections_project_id_provider_configura_fkey
        DEFERRABLE INITIALLY IMMEDIATE;
ALTER TABLE public.managed_provider_reauthorization_interactions
    ALTER CONSTRAINT managed_provider_reauthorizat_project_id_application_id_pr_fkey
        DEFERRABLE INITIALLY IMMEDIATE,
    ALTER CONSTRAINT managed_provider_reauthorizat_project_id_provider_configur_fkey
        DEFERRABLE INITIALLY IMMEDIATE,
    ALTER CONSTRAINT managed_provider_reauthorization_project_id_application_id_fkey
        DEFERRABLE INITIALLY IMMEDIATE;
ALTER TABLE public.managed_reauthorization_create_results
    ALTER CONSTRAINT managed_reauthorization_create_results_idempotency_key_fkey
        DEFERRABLE INITIALLY IMMEDIATE;
ALTER TABLE public.project_browser_logout_interactions
    ALTER CONSTRAINT project_browser_logout_intera_project_id_browser_session_i_fkey
        DEFERRABLE INITIALLY IMMEDIATE;
ALTER TABLE public.project_user_merge_tombstones
    ALTER CONSTRAINT project_user_merge_tombstones_primary_email_fk
        DEFERRABLE INITIALLY IMMEDIATE,
    ALTER CONSTRAINT project_user_merge_tombstones_primary_provider_fk
        DEFERRABLE INITIALLY IMMEDIATE,
    ALTER CONSTRAINT project_user_merge_tombstones_project_id_loser_user_id_fkey
        DEFERRABLE INITIALLY IMMEDIATE,
    ALTER CONSTRAINT project_user_merge_tombstones_project_id_winner_user_id_fkey
        DEFERRABLE INITIALLY IMMEDIATE;
ALTER TABLE public.project_users
    ALTER CONSTRAINT project_users_primary_email_identity_fk DEFERRABLE INITIALLY IMMEDIATE,
    ALTER CONSTRAINT project_users_primary_profile_identity_fk DEFERRABLE INITIALLY IMMEDIATE;
ALTER TABLE public.webhook_deliveries
    ALTER CONSTRAINT webhook_deliveries_endpoint_id_fkey DEFERRABLE INITIALLY IMMEDIATE,
    ALTER CONSTRAINT webhook_deliveries_replay_of_delivery_id_fkey
        DEFERRABLE INITIALLY IMMEDIATE,
    ALTER CONSTRAINT webhook_delivery_dispatch_state_fk DEFERRABLE INITIALLY IMMEDIATE,
    ALTER CONSTRAINT webhook_delivery_replay_parent_fk DEFERRABLE INITIALLY IMMEDIATE,
    ALTER CONSTRAINT webhook_delivery_scope_fk DEFERRABLE INITIALLY IMMEDIATE;

-- Reject accidental direct Project deletion unless the reviewed finalizer has selected this exact
-- row and installed its transaction-local cascade context.
CREATE FUNCTION public.owlauth_require_project_finalizer() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path = pg_catalog
    AS $$
BEGIN
    IF NOT public.owlauth_project_deletion_allowed(OLD.id) THEN
        RAISE EXCEPTION 'Project deletion requires the reviewed finalizer'
            USING ERRCODE = '42501';
    END IF;
    RETURN OLD;
END
$$;

CREATE TRIGGER projects_require_finalizer
    BEFORE DELETE ON public.projects
    FOR EACH ROW EXECUTE FUNCTION public.owlauth_require_project_finalizer();

-- This owner-owned, fixed-search-path function selects and locks one eligible Project, repeats
-- every cleanup proof under that lock, enters the
-- exact trigger context, cascades the complete graph, and appends detached deployment audit in the
-- same transaction. A NULL result means no Project is currently safe to finalize.
CREATE FUNCTION public.owlauth_finalize_project_deletion(
    audit_id uuid,
    correlation_id uuid
) RETURNS uuid
    LANGUAGE plpgsql
    SECURITY DEFINER
    SET search_path = pg_catalog, public
    AS $$
DECLARE
    target_project_id uuid;
BEGIN
    IF pg_catalog.current_setting('transaction_isolation') <> 'read committed' THEN
        RAISE EXCEPTION 'Project finalization requires READ COMMITTED isolation'
            USING ERRCODE = '25001';
    END IF;

    FOR target_project_id IN
        SELECT candidate.id
          FROM public.projects AS candidate
         WHERE candidate.status = 'deleting'
         ORDER BY candidate.deletion_requested_at, candidate.id
         FOR UPDATE OF candidate SKIP LOCKED
    LOOP
        -- Each statement in a READ COMMITTED function receives a fresh snapshot. Repeat every
        -- provider-cleanup proof only after the Project row is locked so a writer that committed
        -- while finalization waited cannot be hidden behind the candidate-selection snapshot.
        IF EXISTS (
               SELECT 1
                 FROM public.protected_materials AS material
                WHERE material.project_id = target_project_id
                  AND material.state <> 'erased'
           ) OR EXISTS (
               SELECT 1
                 FROM public.managed_provider_credentials AS credential
                WHERE credential.project_id = target_project_id
                  AND credential.ciphertext IS NOT NULL
           ) OR EXISTS (
               SELECT 1
                 FROM public.key_provisioning_operations AS operation
                WHERE operation.project_id = target_project_id
                  AND operation.state IN (
                      'prepared', 'submitted', 'stored', 'cleanup_pending',
                      'cleanup_leased', 'cleanup_blocked'
                  )
           )
        THEN
            CONTINUE;
        END IF;

        PERFORM pg_catalog.set_config(
            'owlauth.project_deletion_id', target_project_id::text, true
        );
        SET CONSTRAINTS ALL DEFERRED;
        -- Attempt rows are append-only and do not carry project_id. Delete them while their delivery
        -- parent is still visible so the immutable-history trigger can derive and verify the exact
        -- finalizer context; the remaining webhook graph then follows reviewed cascading edges.
        DELETE FROM public.webhook_delivery_attempts AS attempt
         USING public.webhook_deliveries AS delivery
         WHERE attempt.delivery_id = delivery.id
           AND delivery.project_id = target_project_id;
        DELETE FROM public.projects
         WHERE id = target_project_id
           AND status = 'deleting';
        IF NOT FOUND THEN
            RAISE EXCEPTION 'Project finalization lost its locked target'
                USING ERRCODE = '40001';
        END IF;

        INSERT INTO public.audit_events(
            id, project_id, actor_kind, action, target_kind, target_id,
            outcome, correlation_id, safe_context
        ) VALUES (
            audit_id, NULL, 'deployment_operator', 'project.deleted', 'project',
            target_project_id, 'succeeded', correlation_id, '{}'::pg_catalog.jsonb
        );
        RETURN target_project_id;
    END LOOP;
    RETURN NULL;
END
$$;

REVOKE ALL ON FUNCTION public.owlauth_finalize_project_deletion(uuid, uuid) FROM PUBLIC;
