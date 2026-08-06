-- OwlAuth clean baseline: schemas, functions, and tables.
-- Pre-deployment history was intentionally rebuilt before the first production schema.

-- PostgreSQL database dump
--


-- Dumped from database version 17.10
-- Dumped by pg_dump version 17.10

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- Name: enforce_project_client_key_lifecycle(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.enforce_project_client_key_lifecycle() RETURNS trigger
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


--
-- Name: enforce_webhook_endpoint_immutable_target(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.enforce_webhook_endpoint_immutable_target() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NEW.project_id <> OLD.project_id
        OR NEW.application_id <> OLD.application_id
        OR NEW.url <> OLD.url
        OR NEW.public_id <> OLD.public_id
    THEN
        RAISE EXCEPTION 'webhook endpoint target identity is immutable';
    END IF;
    RETURN NEW;
END;
$$;


--
-- Name: enforce_webhook_secret_immutable_material(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.enforce_webhook_secret_immutable_material() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NEW.endpoint_id IS DISTINCT FROM OLD.endpoint_id
        OR NEW.generation IS DISTINCT FROM OLD.generation
        OR NEW.idempotency_key IS DISTINCT FROM OLD.idempotency_key
        OR NEW.request_fingerprint IS DISTINCT FROM OLD.request_fingerprint
        OR NEW.material_id IS DISTINCT FROM OLD.material_id
        OR NEW.created_at IS DISTINCT FROM OLD.created_at
        OR (
            NEW.safe_fingerprint IS DISTINCT FROM OLD.safe_fingerprint
            AND NOT (
                OLD.safe_fingerprint IS NULL
                AND NEW.safe_fingerprint IS NOT NULL
                AND OLD.state = 'pending'
            )
        )
    THEN
        RAISE EXCEPTION 'webhook secret generation material is immutable';
    END IF;
    RETURN NEW;
END;
$$;


--
-- Name: materialize_managed_provider_claim_fairness(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.materialize_managed_provider_claim_fairness() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    INSERT INTO managed_provider_claim_fairness
        (project_id, provider_configuration_id, queue_kind, last_claimed_at,
         lease_owner, lease_expires_at)
    VALUES
        (NEW.project_id, NEW.provider_configuration_id, 'outbound',
         NEW.created_at - INTERVAL '1 microsecond', NULL, NULL)
    ON CONFLICT (project_id, provider_configuration_id, queue_kind) DO NOTHING;
    RETURN NEW;
END;
$$;


--
-- Name: owlauth_bump_material_inventory_revision(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.owlauth_bump_material_inventory_revision() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
  UPDATE protected_material_inventory_authority
     SET revision=revision+1, updated_at=transaction_timestamp()
   WHERE singleton;
  RETURN NULL;
END
$$;


--
-- Name: owlauth_enforce_email_challenge_typed_owner(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.owlauth_enforce_email_challenge_typed_owner() RETURNS trigger
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


--
-- Name: owlauth_enforce_exact_primary_identity(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.owlauth_enforce_exact_primary_identity() RETURNS trigger
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


--
-- Name: owlauth_enforce_identity_mutation_candidate_evidence(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.owlauth_enforce_identity_mutation_candidate_evidence() RETURNS trigger
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


--
-- Name: owlauth_enforce_identity_mutation_create_result_lifecycle(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.owlauth_enforce_identity_mutation_create_result_lifecycle() RETURNS trigger
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


--
-- Name: owlauth_enforce_identity_mutation_create_result_terminal_state(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.owlauth_enforce_identity_mutation_create_result_terminal_state() RETURNS trigger
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


--
-- Name: owlauth_enforce_identity_mutation_intent_transition(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.owlauth_enforce_identity_mutation_intent_transition() RETURNS trigger
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


--
-- Name: owlauth_enforce_identity_mutation_merge_tombstone(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.owlauth_enforce_identity_mutation_merge_tombstone() RETURNS trigger
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


--
-- Name: owlauth_enforce_identity_mutation_slot_set(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.owlauth_enforce_identity_mutation_slot_set() RETURNS trigger
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


--
-- Name: owlauth_enforce_identity_mutation_slot_transition(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.owlauth_enforce_identity_mutation_slot_transition() RETURNS trigger
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


--
-- Name: owlauth_enforce_identity_proof_receipt(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.owlauth_enforce_identity_proof_receipt() RETURNS trigger
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


--
-- Name: owlauth_enforce_identity_proof_receipt_transition(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.owlauth_enforce_identity_proof_receipt_transition() RETURNS trigger
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


--
-- Name: owlauth_enforce_mail_outbox_challenge_owner(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.owlauth_enforce_mail_outbox_challenge_owner() RETURNS trigger
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


--
-- Name: owlauth_enforce_merged_binding_target(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.owlauth_enforce_merged_binding_target() RETURNS trigger
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


--
-- Name: owlauth_enforce_merged_user_binding_ownership(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.owlauth_enforce_merged_user_binding_ownership() RETURNS trigger
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


--
-- Name: owlauth_enforce_mutation_email_challenge_outbox(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.owlauth_enforce_mutation_email_challenge_outbox() RETURNS trigger
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


--
-- Name: owlauth_enforce_project_user_merge_tombstone(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.owlauth_enforce_project_user_merge_tombstone() RETURNS trigger
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


--
-- Name: owlauth_enforce_provider_callback_owner(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.owlauth_enforce_provider_callback_owner() RETURNS trigger
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


--
-- Name: owlauth_initialize_project_email_policy(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.owlauth_initialize_project_email_policy() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    INSERT INTO project_email_policies (project_id, status) VALUES (NEW.id, 'disabled');
    RETURN NEW;
END
$$;


--
-- Name: owlauth_initialize_project_provider_egress_policy(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.owlauth_initialize_project_provider_egress_policy() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    INSERT INTO project_provider_egress_policies (
        project_id,
        mode,
        exact_origins
    ) VALUES (
        NEW.id,
        'allow_all',
        '[]'::jsonb
    );
    RETURN NEW;
END;
$$;


--
-- Name: owlauth_lock_project_identity_graph(uuid); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.owlauth_lock_project_identity_graph(target_project_id uuid) RETURNS void
    LANGUAGE sql
    AS $$
    SELECT pg_advisory_xact_lock(
        hashtextextended('owlauth-project-identity-graph:' || target_project_id::TEXT, 0)
    )
$$;


--
-- Name: owlauth_positive_unique_key_versions(integer[]); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.owlauth_positive_unique_key_versions(versions integer[]) RETURNS boolean
    LANGUAGE plpgsql IMMUTABLE STRICT
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


--
-- Name: owlauth_protected_material_identity_immutable(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.owlauth_protected_material_identity_immutable() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
  IF ROW(NEW.id,NEW.scope_kind,NEW.project_id,NEW.owner_kind,NEW.owner_id,NEW.generation,
         NEW.material_kind,NEW.provider_id,NEW.provider_format_version,NEW.context_version,
         NEW.context_digest,NEW.created_at)
     IS DISTINCT FROM
     ROW(OLD.id,OLD.scope_kind,OLD.project_id,OLD.owner_kind,OLD.owner_id,OLD.generation,
         OLD.material_kind,OLD.provider_id,OLD.provider_format_version,OLD.context_version,
         OLD.context_digest,OLD.created_at) THEN
    RAISE EXCEPTION 'protected material identity is immutable' USING ERRCODE='23514';
  END IF;
  RETURN NEW;
END
$$;


--
-- Name: owlauth_provider_source_profile_digest(text, text, text); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.owlauth_provider_source_profile_digest(profile_display_name text, profile_picture_url text, profile_locale text) RETURNS bytea
    LANGUAGE sql IMMUTABLE PARALLEL SAFE
    RETURN sha256(convert_to(((((('{"display_name":'::text || COALESCE((to_json(profile_display_name))::text, 'null'::text)) || CASE WHEN (profile_locale IS NULL) THEN ''::text ELSE (',"locale":'::text || (to_json(profile_locale))::text) END) || ',"picture_url":'::text) || COALESCE((to_json(profile_picture_url))::text, 'null'::text)) || '}'::text), 'UTF8'::name));


--
-- Name: owlauth_reject_identity_mutation_create_result_delete(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.owlauth_reject_identity_mutation_create_result_delete() RETURNS trigger
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


--
-- Name: owlauth_reject_identity_mutation_idempotency_authority_change(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.owlauth_reject_identity_mutation_idempotency_authority_change() RETURNS trigger
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


--
-- Name: owlauth_reject_identity_mutation_intent_delete_with_result(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.owlauth_reject_identity_mutation_intent_delete_with_result() RETURNS trigger
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


--
-- Name: owlauth_reject_managed_reauthorization_deadline_extension(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.owlauth_reject_managed_reauthorization_deadline_extension() RETURNS trigger
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


--
-- Name: owlauth_reject_merged_binding_delete(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.owlauth_reject_merged_binding_delete() RETURNS trigger
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


--
-- Name: owlauth_reject_merged_binding_reopen(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.owlauth_reject_merged_binding_reopen() RETURNS trigger
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


--
-- Name: owlauth_reject_merged_project_user_change(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.owlauth_reject_merged_project_user_change() RETURNS trigger
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


--
-- Name: owlauth_reject_project_user_merge_tombstone_mutation(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.owlauth_reject_project_user_merge_tombstone_mutation() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    RAISE EXCEPTION 'Project-user merge tombstones are immutable'
        USING ERRCODE = '23514';
END
$$;


--
-- Name: owlauth_valid_identity_proof_scopes(text[]); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.owlauth_valid_identity_proof_scopes(scopes text[]) RETURNS boolean
    LANGUAGE sql IMMUTABLE STRICT
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


--
-- Name: owlauth_validate_application_session_original_binding_owner(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.owlauth_validate_application_session_original_binding_owner() RETURNS trigger
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


--
-- Name: owlauth_validate_identity_mutation_primary_source_owner(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.owlauth_validate_identity_mutation_primary_source_owner() RETURNS trigger
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


--
-- Name: owlauth_validate_identity_mutation_slot_original_owner(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.owlauth_validate_identity_mutation_slot_original_owner() RETURNS trigger
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


--
-- Name: owlauth_validate_managed_reauthorization_expanded_authority_upd(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.owlauth_validate_managed_reauthorization_expanded_authority_upd() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
  IF NEW.provider_kind IS DISTINCT FROM OLD.provider_kind
     OR NEW.provider_display_name IS DISTINCT FROM OLD.provider_display_name
     OR NEW.provider_egress_policy_revision IS DISTINCT FROM OLD.provider_egress_policy_revision
     OR NEW.secret_material_id IS DISTINCT FROM OLD.secret_material_id THEN
    RAISE EXCEPTION 'managed reauthorization authority snapshot is immutable' USING ERRCODE='23514';
  END IF;
  RETURN NEW;
END
$$;


--
-- Name: owlauth_validate_managed_reauthorization_original_authority(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.owlauth_validate_managed_reauthorization_original_authority() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
      FROM managed_provider_connections AS connection
      JOIN linked_identities AS identity
        ON identity.project_id=connection.project_id AND identity.id=connection.linked_identity_id
       AND identity.user_id=connection.user_id
      JOIN provider_configurations AS provider
        ON provider.project_id=connection.project_id AND provider.id=connection.provider_configuration_id
      LEFT JOIN project_provider_egress_policies AS egress ON egress.project_id=provider.project_id
      JOIN projects AS project ON project.id=connection.project_id
      JOIN project_users AS project_user
        ON project_user.project_id=connection.project_id AND project_user.id=connection.user_id
      JOIN applications AS application
        ON application.project_id=connection.project_id AND application.id=NEW.application_id
      JOIN application_provider_assignments AS assignment
        ON assignment.project_id=connection.project_id AND assignment.application_id=application.id
       AND assignment.provider_id=provider.id
     WHERE connection.project_id=NEW.project_id AND connection.id=NEW.connection_id
       AND connection.linked_identity_id=NEW.linked_identity_id AND connection.user_id=NEW.user_id
       AND connection.provider_configuration_id=NEW.provider_configuration_id
       AND connection.generation=NEW.expected_connection_generation
       AND connection.credential_generation=NEW.expected_credential_generation
       AND connection.revision=NEW.expected_connection_revision
       AND identity.issuer=NEW.issuer AND identity.subject=NEW.subject
       AND identity.identity_revision=NEW.identity_revision
       AND provider.provider_key=NEW.provider_key AND provider.issuer=NEW.issuer
       AND provider.client_id=NEW.client_id
       AND provider.secret_material_id=NEW.secret_material_id
       AND provider.callback_url=NEW.callback_url
       AND provider.revision=NEW.provider_revision
       AND provider.managed_profile_revision=NEW.managed_profile_revision
       AND provider.kind=NEW.provider_kind
       AND ((provider.kind='oidc' AND egress.revision=NEW.provider_egress_policy_revision)
            OR (provider.kind<>'oidc' AND NEW.provider_egress_policy_revision IS NULL))
       AND project.public_id=NEW.project_public_id
       AND project.security_revision=NEW.project_security_revision AND project.status='active'
       AND project_user.security_revision=NEW.user_security_revision AND project_user.status='active'
       AND application.revision=NEW.application_revision AND application.status='active'
       AND assignment.security_revision=NEW.assignment_security_revision AND assignment.status='active'
  ) THEN
    RAISE EXCEPTION 'managed reauthorization must capture exact current connection authority'
      USING ERRCODE='23514';
  END IF;
  RETURN NEW;
END
$$;


--
-- Name: owlauth_validate_managed_reauthorization_revocation_truth(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.owlauth_validate_managed_reauthorization_revocation_truth() RETURNS trigger
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


--
-- Name: owlauth_validate_merge_tombstone_primary_final_owner(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.owlauth_validate_merge_tombstone_primary_final_owner() RETURNS trigger
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


--
-- Name: owlauth_validate_merge_tombstone_primary_original_owner(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.owlauth_validate_merge_tombstone_primary_original_owner() RETURNS trigger
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


--
-- Name: owlauth_validate_merged_project_user_attribution(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.owlauth_validate_merged_project_user_attribution() RETURNS trigger
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


--
-- Name: owlauth_validate_merged_project_user_identity_ownership(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.owlauth_validate_merged_project_user_identity_ownership() RETURNS trigger
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


--
-- Name: owlauth_validate_protected_material_owner(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.owlauth_validate_protected_material_owner() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    owner_matches BOOLEAN;
BEGIN
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


--
-- Name: owlauth_validate_provider_method_snapshot(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.owlauth_validate_provider_method_snapshot() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NEW.method_kind = 'email' THEN
        IF NEW.provider_kind IS NOT NULL OR NEW.provider_egress_policy_revision IS NOT NULL THEN
            RAISE EXCEPTION 'email method cannot carry provider authority'
                USING ERRCODE = '23514';
        END IF;
    ELSIF NEW.provider_kind IS NULL THEN
        RAISE EXCEPTION 'provider method requires a closed provider kind'
            USING ERRCODE = '23514';
    ELSIF NEW.provider_kind = 'oidc' AND NEW.provider_egress_policy_revision IS NULL THEN
        RAISE EXCEPTION 'Custom OIDC method requires Project egress authority'
            USING ERRCODE = '23514';
    ELSIF NEW.provider_kind <> 'oidc' AND NEW.provider_egress_policy_revision IS NOT NULL THEN
        RAISE EXCEPTION 'named provider method cannot carry Custom OIDC authority'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;


--
-- Name: reject_application_sync_immutable_mutation(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.reject_application_sync_immutable_mutation() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
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


--
-- Name: reject_audit_event_mutation(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.reject_audit_event_mutation() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    RAISE EXCEPTION '% is append-only', TG_TABLE_NAME
        USING ERRCODE = '23514';
END
$$;


--
-- Name: reject_immutable_column_change(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.reject_immutable_column_change() RETURNS trigger
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


--
-- Name: reject_published_jwk_change(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.reject_published_jwk_change() RETURNS trigger
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


--
-- Name: reject_webhook_attempt_immutable_mutation(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.reject_webhook_attempt_immutable_mutation() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
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


SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: application_email_assignments; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.application_email_assignments (
    project_id uuid NOT NULL,
    application_id uuid NOT NULL,
    status text NOT NULL,
    security_revision bigint DEFAULT 1 NOT NULL,
    created_at timestamp with time zone DEFAULT transaction_timestamp() NOT NULL,
    updated_at timestamp with time zone DEFAULT transaction_timestamp() NOT NULL,
    CONSTRAINT application_email_assignments_security_revision_check CHECK ((security_revision > 0)),
    CONSTRAINT application_email_assignments_status_check CHECK ((status = ANY (ARRAY['active'::text, 'disabled'::text])))
);


--
-- Name: application_origins; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.application_origins (
    project_id uuid NOT NULL,
    application_id uuid NOT NULL,
    origin text NOT NULL,
    created_at timestamp with time zone DEFAULT transaction_timestamp() NOT NULL,
    CONSTRAINT application_origins_origin_check CHECK (((char_length(origin) >= 8) AND (char_length(origin) <= 512)))
);


--
-- Name: application_provider_assignments; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.application_provider_assignments (
    project_id uuid NOT NULL,
    application_id uuid NOT NULL,
    provider_id uuid NOT NULL,
    status text NOT NULL,
    security_revision bigint NOT NULL,
    created_at timestamp with time zone DEFAULT transaction_timestamp() NOT NULL,
    updated_at timestamp with time zone DEFAULT transaction_timestamp() NOT NULL,
    CONSTRAINT application_provider_assignments_security_revision_check CHECK ((security_revision > 0)),
    CONSTRAINT application_provider_assignments_status_check CHECK ((status = ANY (ARRAY['active'::text, 'disabled'::text])))
);


--
-- Name: application_publishable_keys; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.application_publishable_keys (
    id uuid NOT NULL,
    project_id uuid NOT NULL,
    application_id uuid NOT NULL,
    public_id text NOT NULL,
    status text NOT NULL,
    revision bigint NOT NULL,
    created_at timestamp with time zone DEFAULT transaction_timestamp() NOT NULL,
    updated_at timestamp with time zone DEFAULT transaction_timestamp() NOT NULL,
    CONSTRAINT application_publishable_keys_public_id_shape_check CHECK ((public_id ~ '^[A-Za-z0-9_-]+$'::text)),
    CONSTRAINT application_publishable_keys_revision_check CHECK ((revision > 0)),
    CONSTRAINT application_publishable_keys_status_check CHECK ((status = ANY (ARRAY['active'::text, 'disabled'::text])))
);


--
-- Name: application_redirects; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.application_redirects (
    project_id uuid NOT NULL,
    application_id uuid NOT NULL,
    redirect_uri text NOT NULL,
    redirect_type text NOT NULL,
    created_at timestamp with time zone DEFAULT transaction_timestamp() NOT NULL,
    CONSTRAINT application_redirects_redirect_type_check CHECK ((redirect_type = ANY (ARRAY['web'::text, 'loopback'::text, 'custom_scheme'::text]))),
    CONSTRAINT application_redirects_redirect_uri_check CHECK (((char_length(redirect_uri) >= 8) AND (char_length(redirect_uri) <= 2048)))
);


--
-- Name: application_sessions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.application_sessions (
    id uuid NOT NULL,
    project_id uuid NOT NULL,
    application_id uuid NOT NULL,
    user_id uuid NOT NULL,
    binding_id uuid NOT NULL,
    browser_session_id uuid,
    status text NOT NULL,
    session_revision bigint DEFAULT 1 NOT NULL,
    project_security_revision bigint NOT NULL,
    application_security_revision bigint NOT NULL,
    user_security_revision bigint NOT NULL,
    claims_revision bigint NOT NULL,
    policy_session_revision bigint NOT NULL,
    authenticated_at timestamp with time zone NOT NULL,
    absolute_expires_at timestamp with time zone NOT NULL,
    revoked_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT transaction_timestamp() NOT NULL,
    updated_at timestamp with time zone DEFAULT transaction_timestamp() NOT NULL,
    CONSTRAINT application_sessions_application_security_revision_check CHECK ((application_security_revision > 0)),
    CONSTRAINT application_sessions_check CHECK ((absolute_expires_at = (created_at + '30 days'::interval))),
    CONSTRAINT application_sessions_check1 CHECK (((status = 'revoked'::text) = (revoked_at IS NOT NULL))),
    CONSTRAINT application_sessions_claims_revision_check CHECK ((claims_revision > 0)),
    CONSTRAINT application_sessions_policy_session_revision_check CHECK ((policy_session_revision > 0)),
    CONSTRAINT application_sessions_project_security_revision_check CHECK ((project_security_revision > 0)),
    CONSTRAINT application_sessions_session_revision_check CHECK ((session_revision > 0)),
    CONSTRAINT application_sessions_status_check CHECK ((status = ANY (ARRAY['active'::text, 'revoked'::text, 'expired'::text]))),
    CONSTRAINT application_sessions_user_security_revision_check CHECK ((user_security_revision > 0))
);


--
-- Name: application_user_bindings; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.application_user_bindings (
    id uuid NOT NULL,
    project_id uuid NOT NULL,
    application_id uuid NOT NULL,
    user_id uuid NOT NULL,
    status text NOT NULL,
    binding_revision bigint DEFAULT 1 NOT NULL,
    created_at timestamp with time zone DEFAULT transaction_timestamp() NOT NULL,
    updated_at timestamp with time zone DEFAULT transaction_timestamp() NOT NULL,
    merged_into_binding_id uuid,
    merged_at timestamp with time zone,
    CONSTRAINT application_user_bindings_binding_revision_check CHECK ((binding_revision > 0)),
    CONSTRAINT application_user_bindings_merge_shape_check CHECK ((((status = 'merged'::text) AND (merged_into_binding_id IS NOT NULL) AND (merged_into_binding_id <> id) AND (merged_at IS NOT NULL)) OR ((status <> 'merged'::text) AND (merged_into_binding_id IS NULL) AND (merged_at IS NULL)))),
    CONSTRAINT application_user_bindings_status_check CHECK ((status = ANY (ARRAY['active'::text, 'disabled'::text, 'merged'::text])))
);


--
-- Name: application_user_events; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.application_user_events (
    id uuid NOT NULL,
    event_id text NOT NULL,
    project_id uuid NOT NULL,
    application_id uuid NOT NULL,
    binding_id uuid NOT NULL,
    user_id uuid NOT NULL,
    event_type text NOT NULL,
    user_revision bigint NOT NULL,
    projection_revision bigint NOT NULL,
    projection_schema text NOT NULL,
    safe_body jsonb NOT NULL,
    canonical_body_digest bytea NOT NULL,
    verified_email_source_identity_id uuid,
    verified_email_ciphertext bytea,
    verified_email_key_version integer,
    occurred_at timestamp with time zone NOT NULL,
    replay_until timestamp with time zone NOT NULL,
    retain_until timestamp with time zone NOT NULL,
    created_at timestamp with time zone NOT NULL,
    CONSTRAINT application_user_event_email_material_check CHECK ((((verified_email_source_identity_id IS NULL) AND (verified_email_ciphertext IS NULL) AND (verified_email_key_version IS NULL)) OR ((verified_email_source_identity_id IS NOT NULL) AND (verified_email_ciphertext IS NOT NULL) AND (verified_email_key_version > 0)))),
    CONSTRAINT application_user_event_retention_check CHECK (((replay_until > occurred_at) AND (retain_until > replay_until))),
    CONSTRAINT application_user_event_safe_body_check CHECK (((jsonb_typeof(safe_body) = 'object'::text) AND (NOT ((safe_body #> '{data,projection,verified_email}'::text[]) IS DISTINCT FROM 'null'::jsonb)))),
    CONSTRAINT application_user_events_canonical_body_digest_check CHECK ((octet_length(canonical_body_digest) = 32)),
    CONSTRAINT application_user_events_event_type_check CHECK ((event_type = ANY (ARRAY['user.projection.created'::text, 'user.projection.updated'::text, 'user.projection.disabled'::text]))),
    CONSTRAINT application_user_events_projection_revision_check CHECK ((projection_revision > 0)),
    CONSTRAINT application_user_events_projection_schema_check CHECK ((projection_schema = 'owlauth.user.v1'::text)),
    CONSTRAINT application_user_events_user_revision_check CHECK ((user_revision > 0))
);


--
-- Name: TABLE application_user_events; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.application_user_events IS 'Immutable Application-specific projection snapshots. safe_body never stores verified email plaintext; protected event material and digest preserve exact delivery bytes.';


--
-- Name: application_user_projections; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.application_user_projections (
    id uuid NOT NULL,
    project_id uuid NOT NULL,
    binding_id uuid NOT NULL,
    application_id uuid NOT NULL,
    user_id uuid NOT NULL,
    schema_name text NOT NULL,
    projection_revision bigint DEFAULT 1 NOT NULL,
    source_user_revision bigint NOT NULL,
    canonical_digest bytea NOT NULL,
    document jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT transaction_timestamp() NOT NULL,
    updated_at timestamp with time zone DEFAULT transaction_timestamp() NOT NULL,
    source_base_profile_digest bytea NOT NULL,
    verified_email_source_identity_id uuid,
    verified_email_ciphertext bytea,
    verified_email_key_version integer,
    CONSTRAINT application_user_projections_canonical_digest_check CHECK ((octet_length(canonical_digest) = 32)),
    CONSTRAINT application_user_projections_document_check CHECK ((jsonb_typeof(document) = 'object'::text)),
    CONSTRAINT application_user_projections_document_check1 CHECK ((octet_length((document)::text) <= 16384)),
    CONSTRAINT application_user_projections_projection_revision_check CHECK ((projection_revision > 0)),
    CONSTRAINT application_user_projections_schema_name_check CHECK ((schema_name = 'owlauth.user.v1'::text)),
    CONSTRAINT application_user_projections_source_user_revision_check CHECK ((source_user_revision > 0)),
    CONSTRAINT application_user_projections_verified_email_material_check CHECK ((((verified_email_source_identity_id IS NULL) AND (verified_email_ciphertext IS NULL) AND (verified_email_key_version IS NULL)) OR ((verified_email_source_identity_id IS NOT NULL) AND (verified_email_ciphertext IS NOT NULL) AND ((octet_length(verified_email_ciphertext) >= 40) AND (octet_length(verified_email_ciphertext) <= 4096)) AND (verified_email_key_version > 0))))
);


--
-- Name: applications; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.applications (
    id uuid NOT NULL,
    project_id uuid NOT NULL,
    public_id text NOT NULL,
    status text NOT NULL,
    revision bigint NOT NULL,
    created_at timestamp with time zone DEFAULT transaction_timestamp() NOT NULL,
    updated_at timestamp with time zone DEFAULT transaction_timestamp() NOT NULL,
    display_name text DEFAULT 'Untitled application'::text NOT NULL,
    application_type text DEFAULT 'web'::text NOT NULL,
    metadata_revision bigint DEFAULT 1 NOT NULL,
    security_revision bigint DEFAULT 1 NOT NULL,
    CONSTRAINT applications_display_name_length CHECK (((char_length(display_name) >= 1) AND (char_length(display_name) <= 128))),
    CONSTRAINT applications_metadata_revision_check CHECK ((metadata_revision > 0)),
    CONSTRAINT applications_public_id_length CHECK (((char_length(public_id) >= 8) AND (char_length(public_id) <= 96))),
    CONSTRAINT applications_public_id_shape_check CHECK ((public_id ~ '^[A-Za-z0-9_-]+$'::text)),
    CONSTRAINT applications_revision_check CHECK ((revision > 0)),
    CONSTRAINT applications_security_revision_check CHECK ((security_revision > 0)),
    CONSTRAINT applications_status_check CHECK ((status = ANY (ARRAY['active'::text, 'disabled'::text]))),
    CONSTRAINT applications_type_check CHECK ((application_type = ANY (ARRAY['web'::text, 'native'::text])))
);


--
-- Name: audit_events; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.audit_events (
    id uuid NOT NULL,
    project_id uuid,
    actor_kind text NOT NULL,
    action text NOT NULL,
    target_kind text NOT NULL,
    target_id uuid,
    outcome text NOT NULL,
    correlation_id uuid NOT NULL,
    safe_context jsonb DEFAULT '{}'::jsonb NOT NULL,
    occurred_at timestamp with time zone DEFAULT transaction_timestamp() NOT NULL
);


--
-- Name: client_key_digest_readiness; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.client_key_digest_readiness (
    process_id text NOT NULL,
    process_incarnation uuid NOT NULL,
    state text NOT NULL,
    supported_digest_versions integer[] NOT NULL,
    failure_class text,
    checked_at timestamp with time zone NOT NULL,
    lease_expires_at timestamp with time zone NOT NULL,
    CONSTRAINT client_key_digest_readiness_check CHECK ((((state = 'ready'::text) AND ((cardinality(supported_digest_versions) >= 1) AND (cardinality(supported_digest_versions) <= 32)) AND (failure_class IS NULL)) OR ((state = 'failed'::text) AND (cardinality(supported_digest_versions) = 0) AND (failure_class IS NOT NULL) AND ((char_length(failure_class) >= 1) AND (char_length(failure_class) <= 64))))),
    CONSTRAINT client_key_digest_readiness_check1 CHECK (((lease_expires_at > checked_at) AND (lease_expires_at <= (checked_at + '00:05:00'::interval)))),
    CONSTRAINT client_key_digest_readiness_state_check CHECK ((state = ANY (ARRAY['ready'::text, 'failed'::text]))),
    CONSTRAINT client_key_digest_readiness_supported_digest_versions_check CHECK (((cardinality(supported_digest_versions) <= 32) AND (array_position(supported_digest_versions, NULL::integer) IS NULL) AND (0 < ALL (supported_digest_versions))))
);


--
-- Name: client_process_incarnations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.client_process_incarnations (
    process_id text NOT NULL,
    process_incarnation uuid NOT NULL,
    started_at timestamp with time zone NOT NULL,
    CONSTRAINT client_process_incarnations_process_id_check CHECK (((process_id COLLATE "C") ~ '^[A-Za-z0-9._:-]{1,128}$'::text))
);


--
-- Name: control_idempotency_records; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.control_idempotency_records (
    idempotency_key text NOT NULL,
    project_id uuid,
    request_digest bytea NOT NULL,
    state text NOT NULL,
    result_resource_id uuid,
    response jsonb,
    created_at timestamp with time zone DEFAULT transaction_timestamp() NOT NULL,
    completed_at timestamp with time zone,
    operation_kind text DEFAULT 'project.create'::text NOT NULL,
    request_scope text DEFAULT 'deployment'::text NOT NULL,
    expires_at timestamp with time zone,
    CONSTRAINT control_idempotency_digest_length CHECK ((octet_length(request_digest) = 32)),
    CONSTRAINT control_idempotency_expiry_check CHECK (((expires_at IS NULL) OR (expires_at > created_at))),
    CONSTRAINT control_idempotency_key_length CHECK (((char_length(idempotency_key) >= 8) AND (char_length(idempotency_key) <= 128))),
    CONSTRAINT control_idempotency_operation_length CHECK (((char_length(operation_kind) >= 3) AND (char_length(operation_kind) <= 96))),
    CONSTRAINT control_idempotency_records_check CHECK ((((state = 'pending'::text) AND (completed_at IS NULL) AND (response IS NULL)) OR ((state = 'completed'::text) AND (completed_at IS NOT NULL) AND (response IS NOT NULL)))),
    CONSTRAINT control_idempotency_records_state_check CHECK ((state = ANY (ARRAY['pending'::text, 'completed'::text]))),
    CONSTRAINT control_idempotency_scope_length CHECK (((char_length(request_scope) >= 1) AND (char_length(request_scope) <= 128)))
);


--
-- Name: deployment_smtp_generations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.deployment_smtp_generations (
    generation integer NOT NULL,
    status text NOT NULL,
    revision bigint DEFAULT 1 NOT NULL,
    security_eligibility_revision bigint DEFAULT 1 NOT NULL,
    host text NOT NULL,
    port integer NOT NULL,
    tls_mode text NOT NULL,
    sender_address text NOT NULL,
    safe_fingerprint bytea,
    explicitly_allowed_private_ips jsonb DEFAULT '[]'::jsonb NOT NULL,
    retained_until timestamp with time zone,
    created_at timestamp with time zone DEFAULT transaction_timestamp() NOT NULL,
    updated_at timestamp with time zone DEFAULT transaction_timestamp() NOT NULL,
    material_owner_id uuid NOT NULL,
    credential_material_id uuid NOT NULL,
    CONSTRAINT deployment_smtp_generations_check CHECK (((status = 'retained'::text) = (retained_until IS NOT NULL))),
    CONSTRAINT deployment_smtp_generations_explicitly_allowed_private_ip_check CHECK (((jsonb_typeof(explicitly_allowed_private_ips) = 'array'::text) AND (jsonb_array_length(explicitly_allowed_private_ips) <= 16))),
    CONSTRAINT deployment_smtp_generations_generation_check CHECK ((generation > 0)),
    CONSTRAINT deployment_smtp_generations_host_check CHECK (((char_length(host) >= 1) AND (char_length(host) <= 253))),
    CONSTRAINT deployment_smtp_generations_port_check CHECK (((port >= 1) AND (port <= 65535))),
    CONSTRAINT deployment_smtp_generations_revision_check CHECK ((revision > 0)),
    CONSTRAINT deployment_smtp_generations_safe_fingerprint_check CHECK ((octet_length(safe_fingerprint) = 32)),
    CONSTRAINT deployment_smtp_generations_security_eligibility_revision_check CHECK ((security_eligibility_revision > 0)),
    CONSTRAINT deployment_smtp_generations_sender_address_check CHECK (((char_length(sender_address) >= 3) AND (char_length(sender_address) <= 254))),
    CONSTRAINT deployment_smtp_generations_status_check CHECK ((status = ANY (ARRAY['reconciled'::text, 'active'::text, 'retained'::text, 'disabled'::text, 'compromised'::text, 'retired'::text]))),
    CONSTRAINT deployment_smtp_generations_tls_mode_check CHECK ((tls_mode = ANY (ARRAY['implicit_tls'::text, 'starttls_required'::text])))
);


--
-- Name: deployment_smtp_secret_operations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.deployment_smtp_secret_operations (
    id uuid NOT NULL,
    idempotency_key text NOT NULL,
    generation integer NOT NULL,
    material_id uuid NOT NULL,
    request_digest bytea NOT NULL,
    secret_fingerprint bytea,
    state text NOT NULL,
    correlation_id uuid NOT NULL,
    created_at timestamp with time zone DEFAULT transaction_timestamp() NOT NULL,
    completed_at timestamp with time zone,
    CONSTRAINT deployment_smtp_secret_operations_check CHECK (((state = 'completed'::text) = (completed_at IS NOT NULL))),
    CONSTRAINT deployment_smtp_secret_operations_check1 CHECK (((state = 'completed'::text) = (secret_fingerprint IS NOT NULL))),
    CONSTRAINT deployment_smtp_secret_operations_idempotency_key_check CHECK (((char_length(idempotency_key) >= 8) AND (char_length(idempotency_key) <= 128))),
    CONSTRAINT deployment_smtp_secret_operations_request_digest_check CHECK ((octet_length(request_digest) = 32)),
    CONSTRAINT deployment_smtp_secret_operations_secret_fingerprint_check CHECK (((secret_fingerprint IS NULL) OR (octet_length(secret_fingerprint) = 32))),
    CONSTRAINT deployment_smtp_secret_operations_state_check CHECK ((state = ANY (ARRAY['prepared'::text, 'completed'::text])))
);


--
-- Name: email_challenges; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.email_challenges (
    id uuid NOT NULL,
    project_id uuid NOT NULL,
    application_id uuid NOT NULL,
    transaction_id uuid,
    generation smallint NOT NULL,
    status text NOT NULL,
    canonicalization_version integer NOT NULL,
    lookup_digest bytea NOT NULL,
    lookup_digest_key_version integer NOT NULL,
    address_ciphertext bytea,
    address_key_version integer,
    otp_digest bytea,
    otp_digest_key_version integer,
    otp_attempts smallint DEFAULT 0 NOT NULL,
    otp_max_attempts smallint NOT NULL,
    magic_digest bytea,
    magic_digest_key_version integer,
    method_policy_revision bigint NOT NULL,
    method_security_revision bigint NOT NULL,
    assignment_security_revision bigint NOT NULL,
    smtp_selection_kind text NOT NULL,
    smtp_configuration_id uuid,
    smtp_generation integer NOT NULL,
    smtp_security_eligibility_revision bigint NOT NULL,
    browser_binding_required boolean NOT NULL,
    issued_at timestamp with time zone NOT NULL,
    otp_expires_at timestamp with time zone,
    magic_expires_at timestamp with time zone,
    expires_at timestamp with time zone NOT NULL,
    consumed_at timestamp with time zone,
    terminal_at timestamp with time zone,
    redacted_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT transaction_timestamp() NOT NULL,
    updated_at timestamp with time zone DEFAULT transaction_timestamp() NOT NULL,
    owner_kind text DEFAULT 'login'::text NOT NULL,
    identity_mutation_intent_id uuid,
    identity_mutation_proof_slot_id uuid,
    CONSTRAINT email_challenges_address_ciphertext_check CHECK (((address_ciphertext IS NULL) OR ((octet_length(address_ciphertext) >= 41) AND (octet_length(address_ciphertext) <= 2048)))),
    CONSTRAINT email_challenges_address_key_version_check CHECK (((address_key_version IS NULL) OR (address_key_version > 0))),
    CONSTRAINT email_challenges_assignment_security_revision_check CHECK ((assignment_security_revision > 0)),
    CONSTRAINT email_challenges_canonicalization_version_check CHECK ((canonicalization_version > 0)),
    CONSTRAINT email_challenges_check CHECK (((expires_at > issued_at) AND (expires_at <= (issued_at + '00:10:00'::interval)))),
    CONSTRAINT email_challenges_check1 CHECK ((((otp_digest IS NULL) AND (otp_digest_key_version IS NULL) AND (otp_expires_at IS NULL)) OR ((octet_length(otp_digest) = 32) AND (otp_digest_key_version > 0) AND (otp_expires_at > issued_at) AND (otp_expires_at <= expires_at)))),
    CONSTRAINT email_challenges_check10 CHECK (((redacted_at IS NULL) = (address_ciphertext IS NOT NULL))),
    CONSTRAINT email_challenges_check2 CHECK ((((magic_digest IS NULL) AND (magic_digest_key_version IS NULL) AND (magic_expires_at IS NULL)) OR ((octet_length(magic_digest) = 32) AND (magic_digest_key_version > 0) AND (magic_expires_at > issued_at) AND (magic_expires_at <= expires_at)))),
    CONSTRAINT email_challenges_check3 CHECK ((((otp_digest IS NULL) AND (otp_digest_key_version IS NULL)) OR ((octet_length(otp_digest) = 32) AND (otp_digest_key_version > 0)))),
    CONSTRAINT email_challenges_check4 CHECK ((((magic_digest IS NULL) AND (magic_digest_key_version IS NULL)) OR ((octet_length(magic_digest) = 32) AND (magic_digest_key_version > 0)))),
    CONSTRAINT email_challenges_check5 CHECK (((otp_digest IS NOT NULL) OR (magic_digest IS NOT NULL))),
    CONSTRAINT email_challenges_check6 CHECK (((smtp_selection_kind = 'project'::text) = (smtp_configuration_id IS NOT NULL))),
    CONSTRAINT email_challenges_check7 CHECK (((status = 'consumed'::text) = (consumed_at IS NOT NULL))),
    CONSTRAINT email_challenges_check8 CHECK (((status = 'pending'::text) = (terminal_at IS NULL))),
    CONSTRAINT email_challenges_check9 CHECK (((address_ciphertext IS NULL) = (address_key_version IS NULL))),
    CONSTRAINT email_challenges_generation_check CHECK (((generation >= 1) AND (generation <= 5))),
    CONSTRAINT email_challenges_lookup_digest_check CHECK ((octet_length(lookup_digest) = 32)),
    CONSTRAINT email_challenges_lookup_digest_key_version_check CHECK ((lookup_digest_key_version > 0)),
    CONSTRAINT email_challenges_method_policy_revision_check CHECK ((method_policy_revision > 0)),
    CONSTRAINT email_challenges_method_security_revision_check CHECK ((method_security_revision > 0)),
    CONSTRAINT email_challenges_otp_attempts_check CHECK (((otp_attempts >= 0) AND (otp_attempts <= 5))),
    CONSTRAINT email_challenges_otp_max_attempts_check CHECK (((otp_max_attempts >= 1) AND (otp_max_attempts <= 5))),
    CONSTRAINT email_challenges_owner_kind_check CHECK ((owner_kind = ANY (ARRAY['login'::text, 'identity_mutation'::text]))),
    CONSTRAINT email_challenges_owner_shape_check CHECK ((((owner_kind = 'login'::text) AND (transaction_id IS NOT NULL) AND (identity_mutation_intent_id IS NULL) AND (identity_mutation_proof_slot_id IS NULL)) OR ((owner_kind = 'identity_mutation'::text) AND (transaction_id IS NULL) AND (identity_mutation_intent_id IS NOT NULL) AND (identity_mutation_proof_slot_id IS NOT NULL)))),
    CONSTRAINT email_challenges_smtp_generation_check CHECK ((smtp_generation > 0)),
    CONSTRAINT email_challenges_smtp_security_eligibility_revision_check CHECK ((smtp_security_eligibility_revision > 0)),
    CONSTRAINT email_challenges_smtp_selection_kind_check CHECK ((smtp_selection_kind = ANY (ARRAY['project'::text, 'deployment_default'::text]))),
    CONSTRAINT email_challenges_status_check CHECK ((status = ANY (ARRAY['pending'::text, 'consumed'::text, 'exhausted'::text, 'expired'::text, 'superseded'::text, 'delivery_unavailable'::text])))
);


--
-- Name: email_identities; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.email_identities (
    id uuid NOT NULL,
    project_id uuid NOT NULL,
    user_id uuid NOT NULL,
    status text NOT NULL,
    identity_revision bigint DEFAULT 1 NOT NULL,
    canonicalization_version integer NOT NULL,
    address_ciphertext bytea NOT NULL,
    address_key_version integer NOT NULL,
    verified_at timestamp with time zone NOT NULL,
    created_at timestamp with time zone DEFAULT transaction_timestamp() NOT NULL,
    updated_at timestamp with time zone DEFAULT transaction_timestamp() NOT NULL,
    CONSTRAINT email_identities_address_ciphertext_check CHECK (((octet_length(address_ciphertext) >= 41) AND (octet_length(address_ciphertext) <= 2048))),
    CONSTRAINT email_identities_address_key_version_check CHECK ((address_key_version > 0)),
    CONSTRAINT email_identities_canonicalization_version_check CHECK ((canonicalization_version > 0)),
    CONSTRAINT email_identities_identity_revision_check CHECK ((identity_revision > 0)),
    CONSTRAINT email_identities_status_check CHECK ((status = ANY (ARRAY['active'::text, 'disabled'::text])))
);


--
-- Name: email_identity_alias_authority; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.email_identity_alias_authority (
    singleton boolean DEFAULT true NOT NULL,
    revision bigint NOT NULL,
    write_version integer NOT NULL,
    target_version integer NOT NULL,
    retirement_version integer,
    overlap_verified_revision bigint,
    accepted_versions jsonb NOT NULL,
    updated_at timestamp with time zone DEFAULT transaction_timestamp() NOT NULL,
    CONSTRAINT email_identity_alias_authority_accepted_versions_check CHECK (((jsonb_typeof(accepted_versions) = 'array'::text) AND ((jsonb_array_length(accepted_versions) >= 1) AND (jsonb_array_length(accepted_versions) <= 16)))),
    CONSTRAINT email_identity_alias_authority_check CHECK ((target_version >= write_version)),
    CONSTRAINT email_identity_alias_authority_check1 CHECK (((retirement_version IS NULL) OR (retirement_version = write_version))),
    CONSTRAINT email_identity_alias_authority_check2 CHECK (((overlap_verified_revision IS NULL) OR (overlap_verified_revision <= revision))),
    CONSTRAINT email_identity_alias_authority_overlap_verified_revision_check CHECK (((overlap_verified_revision IS NULL) OR (overlap_verified_revision > 0))),
    CONSTRAINT email_identity_alias_authority_revision_check CHECK ((revision > 0)),
    CONSTRAINT email_identity_alias_authority_singleton_check CHECK (singleton),
    CONSTRAINT email_identity_alias_authority_write_version_check CHECK ((write_version > 0))
);


--
-- Name: email_identity_alias_authority_events; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.email_identity_alias_authority_events (
    id bigint NOT NULL,
    authority_revision bigint NOT NULL,
    action text NOT NULL,
    from_write_version integer,
    to_write_version integer NOT NULL,
    affected_rows bigint DEFAULT 0 NOT NULL,
    created_at timestamp with time zone DEFAULT transaction_timestamp() NOT NULL,
    CONSTRAINT email_identity_alias_authority_events_action_check CHECK ((action = ANY (ARRAY['initialized'::text, 'staged'::text, 'cutover'::text, 'rollback'::text, 'overlap_verified'::text, 'retirement_authorized'::text, 'aliases_retired'::text]))),
    CONSTRAINT email_identity_alias_authority_events_affected_rows_check CHECK ((affected_rows >= 0)),
    CONSTRAINT email_identity_alias_authority_events_authority_revision_check CHECK ((authority_revision > 0)),
    CONSTRAINT email_identity_alias_authority_events_to_write_version_check CHECK ((to_write_version > 0))
);


--
-- Name: email_identity_alias_authority_events_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.email_identity_alias_authority_events_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: email_identity_alias_authority_events_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.email_identity_alias_authority_events_id_seq OWNED BY public.email_identity_alias_authority_events.id;


--
-- Name: email_identity_alias_runtime_observations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.email_identity_alias_runtime_observations (
    process_id text NOT NULL,
    process_incarnation uuid NOT NULL,
    active_version integer NOT NULL,
    observed_authority_revision bigint NOT NULL,
    retirement_requested boolean DEFAULT false NOT NULL,
    retirement_request_revision bigint,
    lease_expires_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone DEFAULT transaction_timestamp() NOT NULL,
    CONSTRAINT email_identity_alias_runtime__observed_authority_revision_check CHECK ((observed_authority_revision > 0)),
    CONSTRAINT email_identity_alias_runtime__retirement_request_revision_check CHECK (((retirement_request_revision IS NULL) OR (retirement_request_revision > 0))),
    CONSTRAINT email_identity_alias_runtime_observations_active_version_check CHECK ((active_version > 0)),
    CONSTRAINT email_identity_alias_runtime_observations_check CHECK ((retirement_requested = (retirement_request_revision IS NOT NULL))),
    CONSTRAINT email_identity_alias_runtime_observations_process_id_check CHECK ((process_id ~ '^[a-zA-Z0-9._:-]{1,128}$'::text))
);


--
-- Name: email_identity_aliases; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.email_identity_aliases (
    project_id uuid NOT NULL,
    identity_id uuid NOT NULL,
    canonicalization_version integer NOT NULL,
    digest_key_version integer NOT NULL,
    lookup_digest bytea NOT NULL,
    created_at timestamp with time zone DEFAULT transaction_timestamp() NOT NULL,
    CONSTRAINT email_identity_aliases_canonicalization_version_check CHECK ((canonicalization_version > 0)),
    CONSTRAINT email_identity_aliases_digest_key_version_check CHECK ((digest_key_version > 0)),
    CONSTRAINT email_identity_aliases_lookup_digest_check CHECK ((octet_length(lookup_digest) = 32))
);


--
-- Name: email_protection_runtime_readiness; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.email_protection_runtime_readiness (
    process_id text NOT NULL,
    process_incarnation uuid NOT NULL,
    state text NOT NULL,
    failure_class text,
    checked_at timestamp with time zone NOT NULL,
    lease_expires_at timestamp with time zone NOT NULL,
    CONSTRAINT email_protection_runtime_readiness_check CHECK ((lease_expires_at > checked_at)),
    CONSTRAINT email_protection_runtime_readiness_check1 CHECK (((state = 'ready'::text) = (failure_class IS NULL))),
    CONSTRAINT email_protection_runtime_readiness_failure_class_check CHECK (((failure_class IS NULL) OR (failure_class = ANY (ARRAY['key_unavailable'::text, 'integrity'::text, 'persistence'::text])))),
    CONSTRAINT email_protection_runtime_readiness_process_id_check CHECK ((process_id ~ '^[a-zA-Z0-9._:-]{1,128}$'::text)),
    CONSTRAINT email_protection_runtime_readiness_state_check CHECK ((state = ANY (ARRAY['ready'::text, 'unavailable'::text])))
);


--
-- Name: handoff_tickets; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.handoff_tickets (
    id uuid NOT NULL,
    project_id uuid NOT NULL,
    login_transaction_id uuid NOT NULL,
    application_id uuid NOT NULL,
    user_id uuid NOT NULL,
    browser_session_id uuid NOT NULL,
    provider_configuration_id uuid,
    ticket_digest bytea NOT NULL,
    ticket_digest_key_version integer NOT NULL,
    status text NOT NULL,
    redirect_uri text NOT NULL,
    application_pkce_challenge text NOT NULL,
    authentication_method text NOT NULL,
    authenticated_at timestamp with time zone NOT NULL,
    project_security_revision bigint NOT NULL,
    application_security_revision bigint NOT NULL,
    user_security_revision bigint NOT NULL,
    provider_revision bigint,
    assignment_security_revision bigint,
    claims_revision bigint NOT NULL,
    policy_session_revision bigint NOT NULL,
    issued_at timestamp with time zone NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    consumed_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT transaction_timestamp() NOT NULL,
    CONSTRAINT handoff_tickets_application_pkce_challenge_check CHECK ((char_length(application_pkce_challenge) = 43)),
    CONSTRAINT handoff_tickets_application_security_revision_check CHECK ((application_security_revision > 0)),
    CONSTRAINT handoff_tickets_authentication_method_check CHECK ((authentication_method = ANY (ARRAY['provider'::text, 'email'::text, 'session_reuse'::text]))),
    CONSTRAINT handoff_tickets_check CHECK ((expires_at > issued_at)),
    CONSTRAINT handoff_tickets_check1 CHECK ((expires_at <= (issued_at + '00:01:00'::interval))),
    CONSTRAINT handoff_tickets_check2 CHECK ((((authentication_method = 'provider'::text) AND (provider_configuration_id IS NOT NULL) AND (provider_revision IS NOT NULL) AND (provider_revision > 0) AND (assignment_security_revision IS NOT NULL) AND (assignment_security_revision > 0)) OR ((authentication_method <> 'provider'::text) AND (provider_configuration_id IS NULL) AND (provider_revision IS NULL) AND (assignment_security_revision IS NULL)))),
    CONSTRAINT handoff_tickets_check3 CHECK (((status = 'consumed'::text) = (consumed_at IS NOT NULL))),
    CONSTRAINT handoff_tickets_claims_revision_check CHECK ((claims_revision > 0)),
    CONSTRAINT handoff_tickets_policy_session_revision_check CHECK ((policy_session_revision > 0)),
    CONSTRAINT handoff_tickets_project_security_revision_check CHECK ((project_security_revision > 0)),
    CONSTRAINT handoff_tickets_redirect_uri_check CHECK (((char_length(redirect_uri) >= 8) AND (char_length(redirect_uri) <= 2048))),
    CONSTRAINT handoff_tickets_status_check CHECK ((status = ANY (ARRAY['issued'::text, 'consumed'::text, 'expired'::text]))),
    CONSTRAINT handoff_tickets_ticket_digest_check CHECK ((octet_length(ticket_digest) = 32)),
    CONSTRAINT handoff_tickets_ticket_digest_key_version_check CHECK ((ticket_digest_key_version > 0)),
    CONSTRAINT handoff_tickets_user_security_revision_check CHECK ((user_security_revision > 0))
);


--
-- Name: identity_mutation_candidate_evidence; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.identity_mutation_candidate_evidence (
    id uuid NOT NULL,
    project_id uuid NOT NULL,
    intent_id uuid NOT NULL,
    slot_id uuid NOT NULL,
    identity_kind text NOT NULL,
    candidate_revision bigint DEFAULT 1 NOT NULL,
    protector_key_version integer NOT NULL,
    evidence_ciphertext bytea NOT NULL,
    evidence_digest bytea NOT NULL,
    created_at timestamp with time zone DEFAULT transaction_timestamp() NOT NULL,
    retain_until timestamp with time zone NOT NULL,
    CONSTRAINT identity_mutation_candidate_evidenc_protector_key_version_check CHECK ((protector_key_version > 0)),
    CONSTRAINT identity_mutation_candidate_evidence_candidate_revision_check CHECK ((candidate_revision > 0)),
    CONSTRAINT identity_mutation_candidate_evidence_check CHECK (((retain_until > created_at) AND (retain_until <= (created_at + '00:25:00'::interval)))),
    CONSTRAINT identity_mutation_candidate_evidence_evidence_ciphertext_check CHECK (((octet_length(evidence_ciphertext) >= 41) AND (octet_length(evidence_ciphertext) <= 16384))),
    CONSTRAINT identity_mutation_candidate_evidence_evidence_digest_check CHECK ((octet_length(evidence_digest) = 32)),
    CONSTRAINT identity_mutation_candidate_evidence_identity_kind_check CHECK ((identity_kind = ANY (ARRAY['provider'::text, 'email'::text])))
);


--
-- Name: identity_mutation_create_results; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.identity_mutation_create_results (
    idempotency_key text NOT NULL,
    project_id uuid NOT NULL,
    intent_id uuid NOT NULL,
    request_digest bytea NOT NULL,
    create_result_key_version integer NOT NULL,
    create_result_ciphertext bytea,
    expires_at timestamp with time zone NOT NULL,
    erased_at timestamp with time zone,
    CONSTRAINT identity_mutation_create_result_create_result_key_version_check CHECK ((create_result_key_version > 0)),
    CONSTRAINT identity_mutation_create_results_check CHECK (((create_result_ciphertext IS NULL) = (erased_at IS NOT NULL))),
    CONSTRAINT identity_mutation_create_results_create_result_ciphertext_check CHECK (((create_result_ciphertext IS NULL) OR ((octet_length(create_result_ciphertext) >= 40) AND (octet_length(create_result_ciphertext) <= 4096)))),
    CONSTRAINT identity_mutation_create_results_request_digest_check CHECK ((octet_length(request_digest) = 32))
);


--
-- Name: identity_mutation_intents; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.identity_mutation_intents (
    id uuid NOT NULL,
    project_id uuid NOT NULL,
    operation_kind text NOT NULL,
    status text NOT NULL,
    intent_revision bigint DEFAULT 1 NOT NULL,
    project_metadata_revision bigint NOT NULL,
    project_security_revision bigint NOT NULL,
    destination_user_id uuid,
    destination_user_revision bigint,
    destination_user_security_revision bigint,
    identity_owner_user_id uuid,
    identity_owner_user_revision bigint,
    identity_owner_user_security_revision bigint,
    winner_user_id uuid,
    winner_user_revision bigint,
    winner_user_security_revision bigint,
    loser_user_id uuid,
    loser_user_revision bigint,
    loser_user_security_revision bigint,
    primary_source_disposition text NOT NULL,
    primary_provider_identity_id uuid,
    primary_email_identity_id uuid,
    primary_source_identity_revision bigint,
    sessions_disposition text,
    bindings_disposition text,
    hosted_handle_digest bytea NOT NULL,
    hosted_handle_digest_key_version integer NOT NULL,
    browser_binding_digest bytea,
    browser_binding_digest_key_version integer,
    csrf_digest bytea,
    csrf_digest_key_version integer,
    browser_binding_revision bigint DEFAULT 0 NOT NULL,
    correlation_id uuid NOT NULL,
    created_at timestamp with time zone DEFAULT transaction_timestamp() NOT NULL,
    updated_at timestamp with time zone DEFAULT transaction_timestamp() NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    ready_at timestamp with time zone,
    terminal_at timestamp with time zone,
    CONSTRAINT identity_mutation_intents_bindings_disposition_check CHECK (((bindings_disposition IS NULL) OR (bindings_disposition = 'winner_preferred'::text))),
    CONSTRAINT identity_mutation_intents_browser_binding_revision_check CHECK ((browser_binding_revision >= 0)),
    CONSTRAINT identity_mutation_intents_check CHECK (((expires_at > created_at) AND (expires_at <= (created_at + '00:10:00'::interval)))),
    CONSTRAINT identity_mutation_intents_check1 CHECK ((((browser_binding_digest IS NULL) = (browser_binding_digest_key_version IS NULL)) AND ((csrf_digest IS NULL) = (csrf_digest_key_version IS NULL)) AND ((browser_binding_digest IS NULL) = (csrf_digest IS NULL)) AND ((browser_binding_digest IS NULL) OR ((octet_length(browser_binding_digest) = 32) AND (browser_binding_digest_key_version > 0) AND (octet_length(csrf_digest) = 32) AND (csrf_digest_key_version > 0) AND (browser_binding_revision > 0))))),
    CONSTRAINT identity_mutation_intents_check2 CHECK ((((status = 'pending_proof'::text) AND (ready_at IS NULL) AND (terminal_at IS NULL)) OR ((status = 'ready'::text) AND (ready_at IS NOT NULL) AND (terminal_at IS NULL)) OR ((status = 'completed'::text) AND (ready_at IS NOT NULL) AND (terminal_at IS NOT NULL)) OR ((status = ANY (ARRAY['expired'::text, 'cancelled'::text])) AND (terminal_at IS NOT NULL)))),
    CONSTRAINT identity_mutation_intents_check3 CHECK (((ready_at IS NULL) OR ((ready_at >= created_at) AND (ready_at < expires_at)))),
    CONSTRAINT identity_mutation_intents_check4 CHECK (((terminal_at IS NULL) OR (terminal_at >= created_at))),
    CONSTRAINT identity_mutation_intents_check5 CHECK (((status <> 'completed'::text) OR (terminal_at >= ready_at))),
    CONSTRAINT identity_mutation_intents_check6 CHECK ((((primary_source_disposition = 'provider'::text) AND (primary_provider_identity_id IS NOT NULL) AND (primary_email_identity_id IS NULL) AND (primary_source_identity_revision > 0)) OR ((primary_source_disposition = 'email'::text) AND (primary_provider_identity_id IS NULL) AND (primary_email_identity_id IS NOT NULL) AND (primary_source_identity_revision > 0)) OR ((primary_source_disposition = ANY (ARRAY['preserve'::text, 'clear'::text])) AND (primary_provider_identity_id IS NULL) AND (primary_email_identity_id IS NULL) AND (primary_source_identity_revision IS NULL)))),
    CONSTRAINT identity_mutation_intents_check7 CHECK (((((operation_kind = 'link'::text) AND (destination_user_id IS NOT NULL) AND (destination_user_revision > 0) AND (destination_user_security_revision > 0) AND (identity_owner_user_id IS NULL) AND (identity_owner_user_revision IS NULL) AND (identity_owner_user_security_revision IS NULL) AND (winner_user_id IS NULL) AND (winner_user_revision IS NULL) AND (winner_user_security_revision IS NULL) AND (loser_user_id IS NULL) AND (loser_user_revision IS NULL) AND (loser_user_security_revision IS NULL) AND (primary_source_disposition = 'preserve'::text) AND (sessions_disposition IS NULL) AND (bindings_disposition IS NULL)) OR ((operation_kind = 'unlink'::text) AND (destination_user_id IS NULL) AND (destination_user_revision IS NULL) AND (destination_user_security_revision IS NULL) AND (identity_owner_user_id IS NOT NULL) AND (identity_owner_user_revision > 0) AND (identity_owner_user_security_revision > 0) AND (winner_user_id IS NULL) AND (winner_user_revision IS NULL) AND (winner_user_security_revision IS NULL) AND (loser_user_id IS NULL) AND (loser_user_revision IS NULL) AND (loser_user_security_revision IS NULL) AND (sessions_disposition IS NULL) AND (bindings_disposition IS NULL)) OR ((operation_kind = 'merge'::text) AND (destination_user_id IS NULL) AND (destination_user_revision IS NULL) AND (destination_user_security_revision IS NULL) AND (identity_owner_user_id IS NULL) AND (identity_owner_user_revision IS NULL) AND (identity_owner_user_security_revision IS NULL) AND (winner_user_id IS NOT NULL) AND (winner_user_revision > 0) AND (winner_user_security_revision > 0) AND (loser_user_id IS NOT NULL) AND (loser_user_revision > 0) AND (loser_user_security_revision > 0) AND (winner_user_id <> loser_user_id) AND (primary_source_disposition = ANY (ARRAY['provider'::text, 'email'::text])) AND (sessions_disposition = 'loser_revoked'::text) AND (bindings_disposition = 'winner_preferred'::text))) IS TRUE)),
    CONSTRAINT identity_mutation_intents_hosted_handle_digest_check CHECK ((octet_length(hosted_handle_digest) = 32)),
    CONSTRAINT identity_mutation_intents_hosted_handle_digest_key_versio_check CHECK ((hosted_handle_digest_key_version > 0)),
    CONSTRAINT identity_mutation_intents_intent_revision_check CHECK ((intent_revision > 0)),
    CONSTRAINT identity_mutation_intents_operation_kind_check CHECK ((operation_kind = ANY (ARRAY['link'::text, 'unlink'::text, 'merge'::text]))),
    CONSTRAINT identity_mutation_intents_primary_source_disposition_check CHECK ((primary_source_disposition = ANY (ARRAY['preserve'::text, 'provider'::text, 'email'::text, 'clear'::text]))),
    CONSTRAINT identity_mutation_intents_primary_source_identity_revisio_check CHECK (((primary_source_identity_revision IS NULL) OR (primary_source_identity_revision > 0))),
    CONSTRAINT identity_mutation_intents_project_metadata_revision_check CHECK ((project_metadata_revision > 0)),
    CONSTRAINT identity_mutation_intents_project_security_revision_check CHECK ((project_security_revision > 0)),
    CONSTRAINT identity_mutation_intents_sessions_disposition_check CHECK (((sessions_disposition IS NULL) OR (sessions_disposition = 'loser_revoked'::text))),
    CONSTRAINT identity_mutation_intents_status_check CHECK ((status = ANY (ARRAY['pending_proof'::text, 'ready'::text, 'completed'::text, 'expired'::text, 'cancelled'::text])))
);


--
-- Name: identity_mutation_proof_slots; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.identity_mutation_proof_slots (
    id uuid NOT NULL,
    project_id uuid NOT NULL,
    intent_id uuid NOT NULL,
    slot_ordinal smallint NOT NULL,
    slot_role text NOT NULL,
    purpose text NOT NULL,
    identity_kind text NOT NULL,
    proof_user_id uuid NOT NULL,
    expected_user_revision bigint NOT NULL,
    expected_user_security_revision bigint NOT NULL,
    existing_provider_identity_id uuid,
    existing_email_identity_id uuid,
    expected_identity_revision bigint,
    application_id uuid NOT NULL,
    application_security_revision bigint NOT NULL,
    method_kind text NOT NULL,
    provider_adapter_key text,
    provider_adapter_capability_revision bigint,
    provider_configuration_id uuid,
    provider_revision bigint,
    provider_assignment_security_revision bigint,
    provider_scopes text[],
    callback_url text,
    provider_pkce_required boolean,
    oidc_nonce_required boolean,
    email_assignment_application_id uuid,
    email_policy_revision bigint,
    email_security_revision bigint,
    email_assignment_security_revision bigint,
    state text NOT NULL,
    slot_revision bigint DEFAULT 1 NOT NULL,
    upstream_state_digest bytea,
    upstream_state_digest_key_version integer,
    provider_pkce_ciphertext bytea,
    provider_pkce_key_version integer,
    oidc_nonce_digest bytea,
    oidc_nonce_digest_key_version integer,
    callback_continuation_ciphertext bytea,
    callback_continuation_key_version integer,
    provider_started_at timestamp with time zone,
    exchange_claimed_at timestamp with time zone,
    proved_at timestamp with time zone,
    terminal_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT transaction_timestamp() NOT NULL,
    updated_at timestamp with time zone DEFAULT transaction_timestamp() NOT NULL,
    provider_secret_material_id uuid,
    provider_egress_policy_revision bigint,
    CONSTRAINT identity_mutation_proof_slot_application_security_revisio_check CHECK ((application_security_revision > 0)),
    CONSTRAINT identity_mutation_proof_slot_expected_user_security_revis_check CHECK ((expected_user_security_revision > 0)),
    CONSTRAINT identity_mutation_proof_slots_check CHECK (((((slot_role = 'candidate_identity'::text) AND (existing_provider_identity_id IS NULL) AND (existing_email_identity_id IS NULL) AND (expected_identity_revision IS NULL)) OR ((slot_role <> 'candidate_identity'::text) AND (expected_identity_revision > 0) AND (((identity_kind = 'provider'::text) AND (existing_provider_identity_id IS NOT NULL) AND (existing_email_identity_id IS NULL)) OR ((identity_kind = 'email'::text) AND (existing_provider_identity_id IS NULL) AND (existing_email_identity_id IS NOT NULL))))) IS TRUE)),
    CONSTRAINT identity_mutation_proof_slots_check1 CHECK (((((method_kind = 'provider'::text) AND (identity_kind = 'provider'::text) AND (provider_adapter_key IS NOT NULL) AND ((octet_length(provider_adapter_key) >= 1) AND (octet_length(provider_adapter_key) <= 64)) AND (provider_adapter_capability_revision > 0) AND (provider_configuration_id IS NOT NULL) AND (provider_revision > 0) AND (provider_assignment_security_revision > 0) AND public.owlauth_valid_identity_proof_scopes(provider_scopes) AND (callback_url IS NOT NULL) AND ((char_length(callback_url) >= 8) AND (char_length(callback_url) <= 2048)) AND (provider_pkce_required IS NOT NULL) AND (oidc_nonce_required = true) AND (email_assignment_application_id IS NULL) AND (email_policy_revision IS NULL) AND (email_security_revision IS NULL) AND (email_assignment_security_revision IS NULL)) OR ((method_kind = 'email'::text) AND (identity_kind = 'email'::text) AND (provider_adapter_key IS NULL) AND (provider_adapter_capability_revision IS NULL) AND (provider_configuration_id IS NULL) AND (provider_revision IS NULL) AND (provider_assignment_security_revision IS NULL) AND (provider_scopes IS NULL) AND (callback_url IS NULL) AND (provider_pkce_required IS NULL) AND (oidc_nonce_required IS NULL) AND (email_assignment_application_id = application_id) AND (email_policy_revision > 0) AND (email_security_revision > 0) AND (email_assignment_security_revision > 0))) IS TRUE)),
    CONSTRAINT identity_mutation_proof_slots_check10 CHECK (((state = ANY (ARRAY['provider_exchange_failed'::text, 'expired'::text])) = (terminal_at IS NOT NULL))),
    CONSTRAINT identity_mutation_proof_slots_check2 CHECK ((((upstream_state_digest IS NULL) = (upstream_state_digest_key_version IS NULL)) AND ((upstream_state_digest IS NULL) OR ((octet_length(upstream_state_digest) = 32) AND (upstream_state_digest_key_version > 0))))),
    CONSTRAINT identity_mutation_proof_slots_check3 CHECK ((((provider_pkce_ciphertext IS NULL) = (provider_pkce_key_version IS NULL)) AND ((provider_pkce_ciphertext IS NULL) OR ((state = ANY (ARRAY['provider_authorization_started'::text, 'provider_exchange_in_progress'::text])) AND ((octet_length(provider_pkce_ciphertext) >= 17) AND (octet_length(provider_pkce_ciphertext) <= 4096)) AND (provider_pkce_key_version > 0))))),
    CONSTRAINT identity_mutation_proof_slots_check4 CHECK ((((oidc_nonce_digest IS NULL) = (oidc_nonce_digest_key_version IS NULL)) AND ((oidc_nonce_digest IS NULL) OR ((octet_length(oidc_nonce_digest) = 32) AND (oidc_nonce_digest_key_version > 0))))),
    CONSTRAINT identity_mutation_proof_slots_check5 CHECK ((((callback_continuation_ciphertext IS NULL) = (callback_continuation_key_version IS NULL)) AND ((callback_continuation_ciphertext IS NULL) OR (((octet_length(callback_continuation_ciphertext) >= 41) AND (octet_length(callback_continuation_ciphertext) <= 4096)) AND (callback_continuation_key_version > 0))))),
    CONSTRAINT identity_mutation_proof_slots_check6 CHECK (((state = ANY (ARRAY['provider_authorization_started'::text, 'provider_exchange_in_progress'::text])) = (callback_continuation_ciphertext IS NOT NULL))),
    CONSTRAINT identity_mutation_proof_slots_check7 CHECK (((state <> ALL (ARRAY['provider_authorization_started'::text, 'provider_exchange_in_progress'::text])) OR ((method_kind = 'provider'::text) AND (upstream_state_digest IS NOT NULL) AND (oidc_nonce_digest IS NOT NULL) AND (provider_started_at IS NOT NULL) AND (provider_pkce_required = (provider_pkce_ciphertext IS NOT NULL))))),
    CONSTRAINT identity_mutation_proof_slots_check8 CHECK (((state = 'provider_exchange_in_progress'::text) = (exchange_claimed_at IS NOT NULL))),
    CONSTRAINT identity_mutation_proof_slots_check9 CHECK (((state = 'proved'::text) = (proved_at IS NOT NULL))),
    CONSTRAINT identity_mutation_proof_slots_expected_user_revision_check CHECK ((expected_user_revision > 0)),
    CONSTRAINT identity_mutation_proof_slots_identity_kind_check CHECK ((identity_kind = ANY (ARRAY['provider'::text, 'email'::text]))),
    CONSTRAINT identity_mutation_proof_slots_method_kind_check CHECK ((method_kind = ANY (ARRAY['provider'::text, 'email'::text]))),
    CONSTRAINT identity_mutation_proof_slots_provider_egress_policy_revision_c CHECK (((provider_egress_policy_revision IS NULL) OR (provider_egress_policy_revision > 0))),
    CONSTRAINT identity_mutation_proof_slots_purpose_check CHECK ((purpose = ANY (ARRAY['link.destination_owner'::text, 'link.candidate_identity'::text, 'unlink.identity_owner'::text, 'merge.winner_owner'::text, 'merge.loser_owner'::text]))),
    CONSTRAINT identity_mutation_proof_slots_slot_ordinal_check CHECK (((slot_ordinal >= 1) AND (slot_ordinal <= 2))),
    CONSTRAINT identity_mutation_proof_slots_slot_revision_check CHECK ((slot_revision > 0)),
    CONSTRAINT identity_mutation_proof_slots_slot_role_check CHECK ((slot_role = ANY (ARRAY['destination_owner'::text, 'candidate_identity'::text, 'identity_owner'::text, 'winner_owner'::text, 'loser_owner'::text]))),
    CONSTRAINT identity_mutation_proof_slots_state_check CHECK ((state = ANY (ARRAY['pending'::text, 'provider_authorization_started'::text, 'provider_exchange_in_progress'::text, 'provider_exchange_failed'::text, 'email_address_entry'::text, 'email_challenge_pending'::text, 'proved'::text, 'expired'::text])))
);


--
-- Name: COLUMN identity_mutation_proof_slots.provider_egress_policy_revision; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.identity_mutation_proof_slots.provider_egress_policy_revision IS 'Frozen Project Custom OIDC egress revision; NULL for named providers and email proofs.';


--
-- Name: identity_proof_receipts; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.identity_proof_receipts (
    id uuid NOT NULL,
    project_id uuid NOT NULL,
    intent_id uuid NOT NULL,
    slot_id uuid NOT NULL,
    evidence_kind text NOT NULL,
    identity_kind text NOT NULL,
    provider_identity_id uuid,
    email_identity_id uuid,
    candidate_evidence_id uuid,
    evidence_revision bigint NOT NULL,
    proof_user_id uuid NOT NULL,
    proof_user_revision bigint NOT NULL,
    proof_user_security_revision bigint NOT NULL,
    interaction_browser_binding_digest bytea NOT NULL,
    interaction_browser_binding_digest_key_version integer NOT NULL,
    interaction_browser_binding_revision bigint NOT NULL,
    captured_intent_revision bigint NOT NULL,
    purpose text NOT NULL,
    receipt_digest bytea NOT NULL,
    receipt_digest_key_version integer NOT NULL,
    status text NOT NULL,
    issued_at timestamp with time zone NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    consumed_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT transaction_timestamp() NOT NULL,
    CONSTRAINT identity_proof_receipts_captured_intent_revision_check CHECK ((captured_intent_revision > 0)),
    CONSTRAINT identity_proof_receipts_check CHECK (((expires_at > issued_at) AND (expires_at <= (issued_at + '00:05:00'::interval)))),
    CONSTRAINT identity_proof_receipts_check1 CHECK ((((evidence_kind = 'existing_identity'::text) AND (candidate_evidence_id IS NULL) AND (((identity_kind = 'provider'::text) AND (provider_identity_id IS NOT NULL) AND (email_identity_id IS NULL)) OR ((identity_kind = 'email'::text) AND (provider_identity_id IS NULL) AND (email_identity_id IS NOT NULL)))) OR ((evidence_kind = 'candidate_evidence'::text) AND (provider_identity_id IS NULL) AND (email_identity_id IS NULL) AND (candidate_evidence_id IS NOT NULL)))),
    CONSTRAINT identity_proof_receipts_check2 CHECK (((status = 'consumed'::text) = (consumed_at IS NOT NULL))),
    CONSTRAINT identity_proof_receipts_evidence_kind_check CHECK ((evidence_kind = ANY (ARRAY['existing_identity'::text, 'candidate_evidence'::text]))),
    CONSTRAINT identity_proof_receipts_evidence_revision_check CHECK ((evidence_revision > 0)),
    CONSTRAINT identity_proof_receipts_identity_kind_check CHECK ((identity_kind = ANY (ARRAY['provider'::text, 'email'::text]))),
    CONSTRAINT identity_proof_receipts_interaction_browser_binding_dige_check1 CHECK ((interaction_browser_binding_digest_key_version > 0)),
    CONSTRAINT identity_proof_receipts_interaction_browser_binding_diges_check CHECK ((octet_length(interaction_browser_binding_digest) = 32)),
    CONSTRAINT identity_proof_receipts_interaction_browser_binding_revis_check CHECK ((interaction_browser_binding_revision > 0)),
    CONSTRAINT identity_proof_receipts_proof_user_revision_check CHECK ((proof_user_revision > 0)),
    CONSTRAINT identity_proof_receipts_proof_user_security_revision_check CHECK ((proof_user_security_revision > 0)),
    CONSTRAINT identity_proof_receipts_purpose_check CHECK ((purpose = ANY (ARRAY['link.destination_owner'::text, 'link.candidate_identity'::text, 'unlink.identity_owner'::text, 'merge.winner_owner'::text, 'merge.loser_owner'::text]))),
    CONSTRAINT identity_proof_receipts_receipt_digest_check CHECK ((octet_length(receipt_digest) = 32)),
    CONSTRAINT identity_proof_receipts_receipt_digest_key_version_check CHECK ((receipt_digest_key_version > 0)),
    CONSTRAINT identity_proof_receipts_status_check CHECK ((status = ANY (ARRAY['issued'::text, 'consumed'::text, 'expired'::text])))
);


--
-- Name: key_provisioning_operations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.key_provisioning_operations (
    id uuid NOT NULL,
    project_id uuid NOT NULL,
    ring_id uuid NOT NULL,
    key_id uuid NOT NULL,
    operation_alias text NOT NULL,
    request_digest bytea NOT NULL,
    state text NOT NULL,
    attempt_count integer DEFAULT 0 NOT NULL,
    expected_project_revision bigint NOT NULL,
    expected_ring_revision bigint NOT NULL,
    maintenance_claimed_at timestamp with time zone,
    last_attempt_at timestamp with time zone,
    completed_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT transaction_timestamp() NOT NULL,
    updated_at timestamp with time zone DEFAULT transaction_timestamp() NOT NULL,
    material_id uuid NOT NULL,
    provider_lease_token uuid,
    provider_lease_expires_at timestamp with time zone,
    provider_lease_generation bigint DEFAULT 0 NOT NULL,
    destroy_attempt_count integer DEFAULT 0 NOT NULL,
    next_attempt_at timestamp with time zone,
    last_provider_error_class text,
    last_retry_classification text,
    last_provider_error_code text,
    abandoned_at timestamp with time zone,
    destroyed_at timestamp with time zone,
    CONSTRAINT key_provisioning_operations_attempt_count_check CHECK ((attempt_count >= 0)),
    CONSTRAINT key_provisioning_operations_check CHECK ((((state = 'completed'::text) AND (completed_at IS NOT NULL)) OR (state <> 'completed'::text))),
    CONSTRAINT key_provisioning_operations_destroy_attempt_count_check CHECK ((destroy_attempt_count >= 0)),
    CONSTRAINT key_provisioning_operations_expected_project_revision_check CHECK ((expected_project_revision > 0)),
    CONSTRAINT key_provisioning_operations_expected_ring_revision_check CHECK ((expected_ring_revision > 0)),
    CONSTRAINT key_provisioning_operations_last_provider_error_class_check CHECK (((last_provider_error_class IS NULL) OR (last_provider_error_class = ANY (ARRAY['invalid_request'::text, 'unsupported_algorithm'::text, 'not_found'::text, 'conflict'::text, 'permission_denied'::text, 'unavailable'::text, 'integrity'::text])))),
    CONSTRAINT key_provisioning_operations_last_provider_error_code_check CHECK (((last_provider_error_code IS NULL) OR (((char_length(last_provider_error_code) >= 1) AND (char_length(last_provider_error_code) <= 64)) AND (last_provider_error_code ~ '^[a-z0-9._-]+$'::text)))),
    CONSTRAINT key_provisioning_operations_last_retry_classification_check CHECK (((last_retry_classification IS NULL) OR (last_retry_classification = ANY (ARRAY['never'::text, 'exact_input_safe'::text, 'reconcile'::text])))),
    CONSTRAINT key_provisioning_operations_operation_alias_check CHECK (((char_length(operation_alias) >= 8) AND (char_length(operation_alias) <= 128))),
    CONSTRAINT key_provisioning_operations_provider_lease_generation_check CHECK ((provider_lease_generation >= 0)),
    CONSTRAINT key_provisioning_operations_request_digest_check CHECK ((octet_length(request_digest) = 32)),
    CONSTRAINT key_provisioning_operations_state_check CHECK ((state = ANY (ARRAY['prepared'::text, 'submitted'::text, 'stored'::text, 'completed'::text, 'cleanup_pending'::text, 'cleanup_leased'::text, 'cleanup_blocked'::text, 'failed'::text, 'abandoned'::text]))),
    CONSTRAINT key_provisioning_provider_lease_check CHECK ((((state = 'cleanup_leased'::text) AND (provider_lease_token IS NOT NULL)) OR (state = 'submitted'::text) OR ((state <> ALL (ARRAY['submitted'::text, 'cleanup_leased'::text])) AND (provider_lease_token IS NULL) AND (provider_lease_expires_at IS NULL)))),
    CONSTRAINT key_provisioning_provider_lease_pair_check CHECK (((provider_lease_token IS NULL) = (provider_lease_expires_at IS NULL))),
    CONSTRAINT key_provisioning_terminal_time_check CHECK ((((state = 'abandoned'::text) = (abandoned_at IS NOT NULL)) AND ((destroyed_at IS NULL) OR (state = 'abandoned'::text))))
);


--
-- Name: key_state_events; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.key_state_events (
    id uuid NOT NULL,
    project_id uuid NOT NULL,
    ring_id uuid NOT NULL,
    signing_key_id uuid NOT NULL,
    ring_revision bigint NOT NULL,
    from_state text NOT NULL,
    to_state text NOT NULL,
    actor_kind text NOT NULL,
    occurred_at timestamp with time zone DEFAULT transaction_timestamp() NOT NULL,
    CONSTRAINT key_state_events_actor_kind_check CHECK ((actor_kind = ANY (ARRAY['deployment_operator'::text, 'system'::text]))),
    CONSTRAINT key_state_events_from_state_check CHECK ((from_state = ANY (ARRAY['provisioning'::text, 'published'::text, 'active'::text, 'retiring'::text, 'retired'::text, 'revoked'::text, 'abandoned'::text]))),
    CONSTRAINT key_state_events_ring_revision_check CHECK ((ring_revision > 0)),
    CONSTRAINT key_state_events_to_state_check CHECK ((to_state = ANY (ARRAY['published'::text, 'active'::text, 'retiring'::text, 'retired'::text, 'revoked'::text, 'abandoned'::text])))
);


--
-- Name: linked_identities; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.linked_identities (
    id uuid NOT NULL,
    project_id uuid NOT NULL,
    user_id uuid NOT NULL,
    created_via_provider_configuration_id uuid NOT NULL,
    issuer text NOT NULL,
    subject text NOT NULL,
    status text NOT NULL,
    identity_revision bigint DEFAULT 1 NOT NULL,
    display_name text,
    picture_url text,
    observed_at timestamp with time zone NOT NULL,
    created_at timestamp with time zone DEFAULT transaction_timestamp() NOT NULL,
    updated_at timestamp with time zone DEFAULT transaction_timestamp() NOT NULL,
    source_kind text DEFAULT 'provider'::text NOT NULL,
    source_schema text DEFAULT 'owlauth.provider-profile.v1'::text NOT NULL,
    source_profile_digest bytea NOT NULL,
    locale text,
    CONSTRAINT linked_identities_display_name_check CHECK (((display_name IS NULL) OR ((char_length(display_name) >= 1) AND (char_length(display_name) <= 128)))),
    CONSTRAINT linked_identities_github_numeric_subject_check CHECK (((issuer <> 'https://github.com'::text) OR (subject ~ '^[1-9][0-9]{0,19}$'::text))),
    CONSTRAINT linked_identities_identity_revision_check CHECK ((identity_revision > 0)),
    CONSTRAINT linked_identities_issuer_check CHECK (((char_length(issuer) >= 8) AND (char_length(issuer) <= 2048))),
    CONSTRAINT linked_identities_picture_url_check CHECK (((picture_url IS NULL) OR ((char_length(picture_url) >= 8) AND (char_length(picture_url) <= 2048)))),
    CONSTRAINT linked_identities_status_check CHECK ((status = ANY (ARRAY['active'::text, 'disabled'::text]))),
    CONSTRAINT linked_identities_subject_check CHECK (((char_length(subject) >= 1) AND (char_length(subject) <= 512)))
);


--
-- Name: login_email_method_snapshots; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.login_email_method_snapshots (
    project_id uuid NOT NULL,
    transaction_id uuid NOT NULL,
    application_id uuid NOT NULL,
    method_policy_revision bigint NOT NULL,
    method_security_revision bigint NOT NULL,
    assignment_security_revision bigint NOT NULL,
    otp_enabled boolean NOT NULL,
    magic_link_enabled boolean NOT NULL,
    otp_digits smallint NOT NULL,
    otp_validity_seconds integer NOT NULL,
    otp_max_attempts smallint NOT NULL,
    resend_after_seconds integer NOT NULL,
    max_generations smallint NOT NULL,
    magic_validity_seconds integer NOT NULL,
    signup_enabled boolean NOT NULL,
    transferred_magic_link_enabled boolean NOT NULL,
    smtp_selection_kind text NOT NULL,
    smtp_configuration_id uuid,
    smtp_generation integer NOT NULL,
    smtp_security_eligibility_revision bigint NOT NULL,
    created_at timestamp with time zone DEFAULT transaction_timestamp() NOT NULL,
    CONSTRAINT login_email_method_snapshots_assignment_security_revision_check CHECK ((assignment_security_revision > 0)),
    CONSTRAINT login_email_method_snapshots_check CHECK ((otp_enabled OR magic_link_enabled)),
    CONSTRAINT login_email_method_snapshots_check1 CHECK (((smtp_selection_kind = 'project'::text) = (smtp_configuration_id IS NOT NULL))),
    CONSTRAINT login_email_method_snapshots_magic_validity_seconds_check CHECK (((magic_validity_seconds >= 30) AND (magic_validity_seconds <= 600))),
    CONSTRAINT login_email_method_snapshots_max_generations_check CHECK (((max_generations >= 1) AND (max_generations <= 5))),
    CONSTRAINT login_email_method_snapshots_method_policy_revision_check CHECK ((method_policy_revision > 0)),
    CONSTRAINT login_email_method_snapshots_method_security_revision_check CHECK ((method_security_revision > 0)),
    CONSTRAINT login_email_method_snapshots_otp_digits_check CHECK (((otp_digits >= 6) AND (otp_digits <= 10))),
    CONSTRAINT login_email_method_snapshots_otp_max_attempts_check CHECK (((otp_max_attempts >= 1) AND (otp_max_attempts <= 5))),
    CONSTRAINT login_email_method_snapshots_otp_validity_seconds_check CHECK (((otp_validity_seconds >= 30) AND (otp_validity_seconds <= 600))),
    CONSTRAINT login_email_method_snapshots_resend_after_seconds_check CHECK (((resend_after_seconds >= 30) AND (resend_after_seconds <= 600))),
    CONSTRAINT login_email_method_snapshots_smtp_generation_check CHECK ((smtp_generation > 0)),
    CONSTRAINT login_email_method_snapshots_smtp_security_eligibility_re_check CHECK ((smtp_security_eligibility_revision > 0)),
    CONSTRAINT login_email_method_snapshots_smtp_selection_kind_check CHECK ((smtp_selection_kind = ANY (ARRAY['project'::text, 'deployment_default'::text])))
);


--
-- Name: login_transaction_methods; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.login_transaction_methods (
    project_id uuid NOT NULL,
    transaction_id uuid NOT NULL,
    method_key text NOT NULL,
    method_kind text NOT NULL,
    provider_configuration_id uuid,
    display_name text NOT NULL,
    provider_revision bigint,
    assignment_security_revision bigint,
    created_at timestamp with time zone DEFAULT transaction_timestamp() NOT NULL,
    provider_kind text,
    provider_egress_policy_revision bigint,
    CONSTRAINT login_transaction_methods_check CHECK ((((method_kind = 'provider'::text) AND (provider_configuration_id IS NOT NULL) AND (provider_revision IS NOT NULL) AND (provider_revision > 0) AND (assignment_security_revision IS NOT NULL) AND (assignment_security_revision > 0)) OR ((method_kind = 'email'::text) AND (provider_configuration_id IS NULL) AND (provider_revision IS NULL) AND (assignment_security_revision IS NULL)))),
    CONSTRAINT login_transaction_methods_display_name_check CHECK (((char_length(display_name) >= 1) AND (char_length(display_name) <= 128))),
    CONSTRAINT login_transaction_methods_method_key_check CHECK (((char_length(method_key) >= 1) AND (char_length(method_key) <= 96))),
    CONSTRAINT login_transaction_methods_method_kind_check CHECK ((method_kind = ANY (ARRAY['provider'::text, 'email'::text]))),
    CONSTRAINT login_transaction_methods_provider_egress_policy_revision_check CHECK (((provider_egress_policy_revision IS NULL) OR (provider_egress_policy_revision > 0))),
    CONSTRAINT login_transaction_methods_provider_kind_check CHECK (((provider_kind IS NULL) OR (provider_kind = ANY (ARRAY['oidc'::text, 'google'::text, 'github'::text]))))
);


--
-- Name: login_transactions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.login_transactions (
    id uuid NOT NULL,
    project_id uuid NOT NULL,
    application_id uuid NOT NULL,
    interaction_digest bytea NOT NULL,
    interaction_digest_key_version integer NOT NULL,
    status text NOT NULL,
    transaction_revision bigint DEFAULT 1 NOT NULL,
    redirect_uri text NOT NULL,
    application_pkce_challenge text NOT NULL,
    application_state_ciphertext bytea NOT NULL,
    application_state_key_version integer NOT NULL,
    presentation_hint text,
    browser_binding_digest bytea,
    browser_binding_digest_key_version integer,
    csrf_digest bytea,
    csrf_digest_key_version integer,
    selected_method text,
    provider_configuration_id uuid,
    user_id uuid,
    callback_url text,
    upstream_state_digest bytea,
    upstream_state_digest_key_version integer,
    oidc_nonce_digest bytea,
    oidc_nonce_digest_key_version integer,
    provider_pkce_ciphertext bytea,
    provider_pkce_key_version integer,
    project_metadata_revision bigint NOT NULL,
    project_security_revision bigint NOT NULL,
    application_security_revision bigint NOT NULL,
    provider_revision bigint,
    assignment_security_revision bigint,
    claims_revision bigint NOT NULL,
    session_revision bigint NOT NULL,
    authenticated_at timestamp with time zone,
    expires_at timestamp with time zone NOT NULL,
    terminal_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT transaction_timestamp() NOT NULL,
    updated_at timestamp with time zone DEFAULT transaction_timestamp() NOT NULL,
    CONSTRAINT login_transactions_application_pkce_challenge_check CHECK ((char_length(application_pkce_challenge) = 43)),
    CONSTRAINT login_transactions_application_security_revision_check CHECK ((application_security_revision > 0)),
    CONSTRAINT login_transactions_application_state_ciphertext_check CHECK (((octet_length(application_state_ciphertext) >= 17) AND (octet_length(application_state_ciphertext) <= 4096))),
    CONSTRAINT login_transactions_application_state_key_version_check CHECK ((application_state_key_version > 0)),
    CONSTRAINT login_transactions_browser_material_by_status CHECK ((((status = 'awaiting_browser_binding'::text) AND (browser_binding_digest IS NULL)) OR (status = ANY (ARRAY['provider_exchange_failed'::text, 'completed'::text, 'expired'::text, 'cancelled'::text])) OR (browser_binding_digest IS NOT NULL))),
    CONSTRAINT login_transactions_check CHECK ((expires_at = (created_at + '00:10:00'::interval))),
    CONSTRAINT login_transactions_check1 CHECK ((((browser_binding_digest IS NULL) AND (browser_binding_digest_key_version IS NULL) AND (csrf_digest IS NULL) AND (csrf_digest_key_version IS NULL)) OR ((browser_binding_digest IS NOT NULL) AND (octet_length(browser_binding_digest) = 32) AND (browser_binding_digest_key_version IS NOT NULL) AND (browser_binding_digest_key_version > 0) AND (csrf_digest IS NOT NULL) AND (octet_length(csrf_digest) = 32) AND (csrf_digest_key_version IS NOT NULL) AND (csrf_digest_key_version > 0)))),
    CONSTRAINT login_transactions_check3 CHECK ((((selected_method IS NULL) AND (provider_configuration_id IS NULL)) OR (selected_method = 'email'::text) OR ((selected_method = 'provider'::text) AND (provider_configuration_id IS NOT NULL)))),
    CONSTRAINT login_transactions_check5 CHECK (((status <> ALL (ARRAY['provider_authorization_started'::text, 'provider_exchange_in_progress'::text, 'provider_exchange_failed'::text])) OR ((selected_method = 'provider'::text) AND (provider_configuration_id IS NOT NULL)))),
    CONSTRAINT login_transactions_check6 CHECK (((status <> ALL (ARRAY['email_address_entry'::text, 'email_challenge_pending'::text])) OR (selected_method = 'email'::text))),
    CONSTRAINT login_transactions_check7 CHECK (((status <> ALL (ARRAY['authenticated'::text, 'handoff_issued'::text, 'completed'::text])) OR ((user_id IS NOT NULL) AND (authenticated_at IS NOT NULL)))),
    CONSTRAINT login_transactions_check8 CHECK (((status = ANY (ARRAY['provider_exchange_failed'::text, 'completed'::text, 'expired'::text, 'cancelled'::text])) = (terminal_at IS NOT NULL))),
    CONSTRAINT login_transactions_claims_revision_check CHECK ((claims_revision > 0)),
    CONSTRAINT login_transactions_interaction_digest_check CHECK ((octet_length(interaction_digest) = 32)),
    CONSTRAINT login_transactions_interaction_digest_key_version_check CHECK ((interaction_digest_key_version > 0)),
    CONSTRAINT login_transactions_presentation_hint_check CHECK (((presentation_hint IS NULL) OR ((char_length(presentation_hint) >= 1) AND (char_length(presentation_hint) <= 64)))),
    CONSTRAINT login_transactions_project_metadata_revision_check CHECK ((project_metadata_revision > 0)),
    CONSTRAINT login_transactions_project_security_revision_check CHECK ((project_security_revision > 0)),
    CONSTRAINT login_transactions_provider_material_by_status CHECK (((provider_configuration_id IS NULL) OR ((callback_url IS NOT NULL) AND ((char_length(callback_url) >= 8) AND (char_length(callback_url) <= 2048)) AND (provider_revision IS NOT NULL) AND (provider_revision > 0) AND (assignment_security_revision IS NOT NULL) AND (assignment_security_revision > 0) AND (((status = ANY (ARRAY['provider_exchange_failed'::text, 'completed'::text, 'expired'::text, 'cancelled'::text])) AND (upstream_state_digest IS NULL) AND (upstream_state_digest_key_version IS NULL) AND (oidc_nonce_digest IS NULL) AND (oidc_nonce_digest_key_version IS NULL) AND (provider_pkce_ciphertext IS NULL) AND (provider_pkce_key_version IS NULL)) OR ((upstream_state_digest IS NOT NULL) AND (octet_length(upstream_state_digest) = 32) AND (upstream_state_digest_key_version IS NOT NULL) AND (upstream_state_digest_key_version > 0) AND (oidc_nonce_digest IS NOT NULL) AND (octet_length(oidc_nonce_digest) = 32) AND (oidc_nonce_digest_key_version IS NOT NULL) AND (oidc_nonce_digest_key_version > 0) AND (provider_pkce_ciphertext IS NOT NULL) AND ((octet_length(provider_pkce_ciphertext) >= 17) AND (octet_length(provider_pkce_ciphertext) <= 4096)) AND (provider_pkce_key_version IS NOT NULL) AND (provider_pkce_key_version > 0)))))),
    CONSTRAINT login_transactions_redirect_uri_check CHECK (((char_length(redirect_uri) >= 8) AND (char_length(redirect_uri) <= 2048))),
    CONSTRAINT login_transactions_selected_method_check CHECK ((selected_method = ANY (ARRAY['provider'::text, 'email'::text]))),
    CONSTRAINT login_transactions_session_revision_check CHECK ((session_revision > 0)),
    CONSTRAINT login_transactions_status_check CHECK ((status = ANY (ARRAY['awaiting_browser_binding'::text, 'awaiting_method_selection'::text, 'email_address_entry'::text, 'email_challenge_pending'::text, 'provider_authorization_started'::text, 'provider_exchange_in_progress'::text, 'provider_exchange_failed'::text, 'authenticated'::text, 'handoff_issued'::text, 'completed'::text, 'expired'::text, 'cancelled'::text]))),
    CONSTRAINT login_transactions_transaction_revision_check CHECK ((transaction_revision > 0))
);


--
-- Name: magic_transfer_contexts; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.magic_transfer_contexts (
    id uuid NOT NULL,
    challenge_id uuid NOT NULL,
    context_digest bytea NOT NULL,
    context_digest_key_version integer NOT NULL,
    csrf_digest bytea NOT NULL,
    csrf_digest_key_version integer NOT NULL,
    browser_binding_required boolean NOT NULL,
    status text NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    consumed_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT transaction_timestamp() NOT NULL,
    CONSTRAINT magic_transfer_contexts_check CHECK (((expires_at > created_at) AND (expires_at <= (created_at + '00:05:00'::interval)))),
    CONSTRAINT magic_transfer_contexts_check1 CHECK (((status = 'consumed'::text) = (consumed_at IS NOT NULL))),
    CONSTRAINT magic_transfer_contexts_context_digest_check CHECK ((octet_length(context_digest) = 32)),
    CONSTRAINT magic_transfer_contexts_context_digest_key_version_check CHECK ((context_digest_key_version > 0)),
    CONSTRAINT magic_transfer_contexts_csrf_digest_check CHECK ((octet_length(csrf_digest) = 32)),
    CONSTRAINT magic_transfer_contexts_csrf_digest_key_version_check CHECK ((csrf_digest_key_version > 0)),
    CONSTRAINT magic_transfer_contexts_status_check CHECK ((status = ANY (ARRAY['pending'::text, 'consumed'::text, 'expired'::text])))
);


--
-- Name: mail_outbox; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mail_outbox (
    id uuid NOT NULL,
    project_id uuid NOT NULL,
    transaction_id uuid,
    challenge_id uuid NOT NULL,
    challenge_generation smallint NOT NULL,
    status text NOT NULL,
    smtp_selection_kind text NOT NULL,
    smtp_configuration_id uuid,
    smtp_generation integer NOT NULL,
    smtp_security_eligibility_revision bigint NOT NULL,
    message_id text NOT NULL,
    envelope_ciphertext bytea,
    envelope_key_version integer,
    body_ciphertext bytea,
    body_key_version integer,
    attempts smallint DEFAULT 0 NOT NULL,
    max_attempts smallint DEFAULT 5 NOT NULL,
    next_attempt_at timestamp with time zone NOT NULL,
    lease_owner text,
    lease_expires_at timestamp with time zone,
    safe_outcome text,
    useful_until timestamp with time zone NOT NULL,
    delivered_at timestamp with time zone,
    terminal_at timestamp with time zone,
    redacted_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT transaction_timestamp() NOT NULL,
    updated_at timestamp with time zone DEFAULT transaction_timestamp() NOT NULL,
    CONSTRAINT mail_outbox_attempts_check CHECK (((attempts >= 0) AND (attempts <= 8))),
    CONSTRAINT mail_outbox_body_ciphertext_check CHECK (((body_ciphertext IS NULL) OR ((octet_length(body_ciphertext) >= 41) AND (octet_length(body_ciphertext) <= 65536)))),
    CONSTRAINT mail_outbox_body_key_version_check CHECK (((body_key_version IS NULL) OR (body_key_version > 0))),
    CONSTRAINT mail_outbox_challenge_generation_check CHECK (((challenge_generation >= 1) AND (challenge_generation <= 5))),
    CONSTRAINT mail_outbox_check CHECK (((smtp_selection_kind = 'project'::text) = (smtp_configuration_id IS NOT NULL))),
    CONSTRAINT mail_outbox_check1 CHECK (((status = 'leased'::text) = ((lease_owner IS NOT NULL) AND (lease_expires_at IS NOT NULL)))),
    CONSTRAINT mail_outbox_check2 CHECK (((envelope_ciphertext IS NULL) = (envelope_key_version IS NULL))),
    CONSTRAINT mail_outbox_check3 CHECK (((body_ciphertext IS NULL) = (body_key_version IS NULL))),
    CONSTRAINT mail_outbox_check4 CHECK (((envelope_ciphertext IS NULL) = (body_ciphertext IS NULL))),
    CONSTRAINT mail_outbox_check5 CHECK (((redacted_at IS NULL) = (envelope_ciphertext IS NOT NULL))),
    CONSTRAINT mail_outbox_check6 CHECK ((useful_until > created_at)),
    CONSTRAINT mail_outbox_check7 CHECK ((next_attempt_at <= useful_until)),
    CONSTRAINT mail_outbox_envelope_ciphertext_check CHECK (((envelope_ciphertext IS NULL) OR ((octet_length(envelope_ciphertext) >= 41) AND (octet_length(envelope_ciphertext) <= 8192)))),
    CONSTRAINT mail_outbox_envelope_key_version_check CHECK (((envelope_key_version IS NULL) OR (envelope_key_version > 0))),
    CONSTRAINT mail_outbox_max_attempts_check CHECK (((max_attempts >= 1) AND (max_attempts <= 8))),
    CONSTRAINT mail_outbox_message_id_check CHECK (((char_length(message_id) >= 16) AND (char_length(message_id) <= 255))),
    CONSTRAINT mail_outbox_safe_outcome_check CHECK (((safe_outcome IS NULL) OR (safe_outcome = ANY (ARRAY['delivered'::text, 'transient'::text, 'permanent'::text, 'ambiguous'::text, 'policy_denied'::text, 'expired'::text])))),
    CONSTRAINT mail_outbox_smtp_generation_check CHECK ((smtp_generation > 0)),
    CONSTRAINT mail_outbox_smtp_security_eligibility_revision_check CHECK ((smtp_security_eligibility_revision > 0)),
    CONSTRAINT mail_outbox_smtp_selection_kind_check CHECK ((smtp_selection_kind = ANY (ARRAY['project'::text, 'deployment_default'::text]))),
    CONSTRAINT mail_outbox_status_check CHECK ((status = ANY (ARRAY['pending'::text, 'leased'::text, 'delivered'::text, 'retry'::text, 'permanent_failure'::text, 'ambiguous'::text, 'cancelled'::text, 'expired'::text])))
);


--
-- Name: managed_provider_claim_fairness; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.managed_provider_claim_fairness (
    project_id uuid NOT NULL,
    provider_configuration_id uuid NOT NULL,
    queue_kind text NOT NULL,
    last_claimed_at timestamp with time zone NOT NULL,
    lease_owner uuid,
    lease_expires_at timestamp with time zone,
    CONSTRAINT managed_provider_claim_fairness_check CHECK (((lease_owner IS NULL) = (lease_expires_at IS NULL))),
    CONSTRAINT managed_provider_claim_fairness_check1 CHECK (((lease_expires_at IS NULL) OR (lease_expires_at > last_claimed_at))),
    CONSTRAINT managed_provider_claim_fairness_queue_kind_check CHECK ((queue_kind = 'outbound'::text))
);


--
-- Name: managed_provider_connections; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.managed_provider_connections (
    id uuid NOT NULL,
    project_id uuid NOT NULL,
    provider_configuration_id uuid NOT NULL,
    linked_identity_id uuid NOT NULL,
    user_id uuid NOT NULL,
    state text NOT NULL,
    revision bigint NOT NULL,
    generation bigint NOT NULL,
    credential_generation bigint NOT NULL,
    project_security_revision bigint NOT NULL,
    provider_revision bigint NOT NULL,
    user_security_revision bigint NOT NULL,
    identity_revision bigint NOT NULL,
    managed_profile_revision bigint NOT NULL,
    adapter_key text NOT NULL,
    adapter_capability_revision bigint NOT NULL,
    required_scopes text[] NOT NULL,
    supports_revocation boolean NOT NULL,
    last_safe_outcome text NOT NULL,
    last_synchronized_at timestamp with time zone,
    next_synchronize_at timestamp with time zone,
    next_renewal_at timestamp with time zone,
    revocation_requested_at timestamp with time zone,
    revocation_disposition text,
    revocation_dispatch_started_at timestamp with time zone,
    revocation_attempt_id uuid,
    consecutive_failures integer DEFAULT 0 NOT NULL,
    lease_owner uuid,
    lease_kind text,
    lease_expires_at timestamp with time zone,
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    disconnected_at timestamp with time zone,
    CONSTRAINT managed_provider_connections_adapter_capability_revision_check CHECK ((adapter_capability_revision > 0)),
    CONSTRAINT managed_provider_connections_adapter_key_check CHECK (((char_length(adapter_key) >= 1) AND (char_length(adapter_key) <= 64))),
    CONSTRAINT managed_provider_connections_check CHECK (((lease_owner IS NULL) = (lease_kind IS NULL))),
    CONSTRAINT managed_provider_connections_check1 CHECK (((lease_owner IS NULL) = (lease_expires_at IS NULL))),
    CONSTRAINT managed_provider_connections_check2 CHECK (((revocation_requested_at IS NULL) = (revocation_disposition IS NULL))),
    CONSTRAINT managed_provider_connections_check3 CHECK (((revocation_dispatch_started_at IS NULL) = (revocation_attempt_id IS NULL))),
    CONSTRAINT managed_provider_connections_check4 CHECK (((revocation_dispatch_started_at IS NULL) OR (revocation_requested_at IS NOT NULL))),
    CONSTRAINT managed_provider_connections_check5 CHECK (((state = 'disconnected'::text) = (disconnected_at IS NOT NULL))),
    CONSTRAINT managed_provider_connections_consecutive_failures_check CHECK (((consecutive_failures >= 0) AND (consecutive_failures <= 32))),
    CONSTRAINT managed_provider_connections_credential_generation_check CHECK ((credential_generation > 0)),
    CONSTRAINT managed_provider_connections_generation_check CHECK ((generation > 0)),
    CONSTRAINT managed_provider_connections_identity_revision_check CHECK ((identity_revision > 0)),
    CONSTRAINT managed_provider_connections_last_safe_outcome_check CHECK (((char_length(last_safe_outcome) >= 1) AND (char_length(last_safe_outcome) <= 64))),
    CONSTRAINT managed_provider_connections_lease_kind_check CHECK ((lease_kind = ANY (ARRAY['read'::text, 'renewal'::text, 'revocation'::text, 'rewrap'::text]))),
    CONSTRAINT managed_provider_connections_managed_profile_revision_check CHECK ((managed_profile_revision > 0)),
    CONSTRAINT managed_provider_connections_project_security_revision_check CHECK ((project_security_revision > 0)),
    CONSTRAINT managed_provider_connections_provider_revision_check CHECK ((provider_revision > 0)),
    CONSTRAINT managed_provider_connections_required_scopes_check CHECK (((cardinality(required_scopes) >= 1) AND (cardinality(required_scopes) <= 16))),
    CONSTRAINT managed_provider_connections_revision_check CHECK ((revision > 0)),
    CONSTRAINT managed_provider_connections_revocation_disposition_check CHECK ((revocation_disposition = ANY (ARRAY['revoke'::text, 'disconnect'::text]))),
    CONSTRAINT managed_provider_connections_state_check CHECK ((state = ANY (ARRAY['active'::text, 'reauth_required'::text, 'revoked'::text, 'disconnected'::text]))),
    CONSTRAINT managed_provider_connections_user_security_revision_check CHECK ((user_security_revision > 0))
);


--
-- Name: managed_provider_credentials; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.managed_provider_credentials (
    project_id uuid NOT NULL,
    connection_id uuid NOT NULL,
    connection_generation bigint NOT NULL,
    credential_generation bigint NOT NULL,
    key_version integer NOT NULL,
    ciphertext bytea,
    created_at timestamp with time zone NOT NULL,
    superseded_at timestamp with time zone,
    destroyed_at timestamp with time zone,
    CONSTRAINT managed_provider_credentials_check CHECK (((ciphertext IS NULL) = (destroyed_at IS NOT NULL))),
    CONSTRAINT managed_provider_credentials_check1 CHECK (((superseded_at IS NULL) OR (superseded_at >= created_at))),
    CONSTRAINT managed_provider_credentials_check2 CHECK (((destroyed_at IS NULL) OR (destroyed_at >= created_at))),
    CONSTRAINT managed_provider_credentials_ciphertext_check CHECK (((octet_length(ciphertext) >= 40) AND (octet_length(ciphertext) <= 16384))),
    CONSTRAINT managed_provider_credentials_connection_generation_check CHECK ((connection_generation > 0)),
    CONSTRAINT managed_provider_credentials_credential_generation_check CHECK ((credential_generation > 0)),
    CONSTRAINT managed_provider_credentials_key_version_check CHECK ((key_version > 0))
);


--
-- Name: managed_provider_reauthorization_interactions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.managed_provider_reauthorization_interactions (
    id uuid NOT NULL,
    project_id uuid NOT NULL,
    project_public_id text NOT NULL,
    connection_id uuid NOT NULL,
    linked_identity_id uuid NOT NULL,
    user_id uuid NOT NULL,
    provider_configuration_id uuid NOT NULL,
    provider_key text NOT NULL,
    issuer text NOT NULL,
    subject text NOT NULL,
    client_id text NOT NULL,
    application_id uuid NOT NULL,
    expected_connection_generation bigint NOT NULL,
    expected_credential_generation bigint NOT NULL,
    expected_connection_revision bigint NOT NULL,
    project_security_revision bigint NOT NULL,
    user_security_revision bigint NOT NULL,
    identity_revision bigint NOT NULL,
    provider_revision bigint NOT NULL,
    managed_profile_revision bigint NOT NULL,
    application_revision bigint NOT NULL,
    assignment_security_revision bigint NOT NULL,
    callback_url text NOT NULL,
    adapter_key text NOT NULL,
    adapter_capability_revision bigint NOT NULL,
    supports_revocation boolean NOT NULL,
    required_scopes text[] NOT NULL,
    provider_pkce_required boolean NOT NULL,
    oidc_nonce_required boolean NOT NULL,
    interaction_digest bytea,
    interaction_digest_key_version integer,
    browser_binding_digest bytea,
    browser_binding_key_version integer,
    csrf_digest bytea,
    csrf_key_version integer,
    upstream_state_digest bytea,
    upstream_state_key_version integer,
    provider_pkce_ciphertext bytea,
    provider_pkce_key_version integer,
    oidc_nonce_digest bytea,
    oidc_nonce_key_version integer,
    revision bigint DEFAULT 1 NOT NULL,
    status text NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    created_at timestamp with time zone NOT NULL,
    provider_started_at timestamp with time zone,
    exchange_claimed_at timestamp with time zone,
    terminal_at timestamp with time zone,
    provider_kind text NOT NULL,
    secret_material_id uuid NOT NULL,
    provider_egress_policy_revision bigint,
    provider_display_name text NOT NULL,
    CONSTRAINT managed_provider_reauthoriza_assignment_security_revision_check CHECK ((assignment_security_revision > 0)),
    CONSTRAINT managed_provider_reauthoriza_expected_connection_generati_check CHECK ((expected_connection_generation > 0)),
    CONSTRAINT managed_provider_reauthoriza_expected_connection_revision_check CHECK ((expected_connection_revision > 0)),
    CONSTRAINT managed_provider_reauthoriza_expected_credential_generati_check CHECK ((expected_credential_generation > 0)),
    CONSTRAINT managed_provider_reauthoriza_interaction_digest_key_versi_check CHECK ((interaction_digest_key_version > 0)),
    CONSTRAINT managed_provider_reauthorizat_adapter_capability_revision_check CHECK ((adapter_capability_revision > 0)),
    CONSTRAINT managed_provider_reauthorizatio_project_security_revision_check CHECK ((project_security_revision > 0)),
    CONSTRAINT managed_provider_reauthorization_i_browser_binding_digest_check CHECK ((octet_length(browser_binding_digest) = 32)),
    CONSTRAINT managed_provider_reauthorization_i_user_security_revision_check CHECK ((user_security_revision > 0)),
    CONSTRAINT managed_provider_reauthorization_in_upstream_state_digest_check CHECK ((octet_length(upstream_state_digest) = 32)),
    CONSTRAINT managed_provider_reauthorization_int_application_revision_check CHECK ((application_revision > 0)),
    CONSTRAINT managed_provider_reauthorization_inte_oidc_nonce_required_check CHECK (oidc_nonce_required),
    CONSTRAINT managed_provider_reauthorization_inter_interaction_digest_check CHECK ((octet_length(interaction_digest) = 32)),
    CONSTRAINT managed_provider_reauthorization_intera_identity_revision_check CHECK ((identity_revision > 0)),
    CONSTRAINT managed_provider_reauthorization_intera_oidc_nonce_digest_check CHECK ((octet_length(oidc_nonce_digest) = 32)),
    CONSTRAINT managed_provider_reauthorization_intera_provider_revision_check CHECK ((provider_revision > 0)),
    CONSTRAINT managed_provider_reauthorization_interact_required_scopes_check CHECK (((cardinality(required_scopes) >= 1) AND (cardinality(required_scopes) <= 16))),
    CONSTRAINT managed_provider_reauthorization_interaction_callback_url_check CHECK (((char_length(callback_url) >= 8) AND (char_length(callback_url) <= 2048))),
    CONSTRAINT managed_provider_reauthorization_interactions_adapter_key_check CHECK (((char_length(adapter_key) >= 1) AND (char_length(adapter_key) <= 64))),
    CONSTRAINT managed_provider_reauthorization_interactions_check CHECK (((expires_at > created_at) AND (expires_at <= (created_at + '00:10:00'::interval)))),
    CONSTRAINT managed_provider_reauthorization_interactions_check1 CHECK (((interaction_digest IS NULL) = (interaction_digest_key_version IS NULL))),
    CONSTRAINT managed_provider_reauthorization_interactions_check10 CHECK (((status <> ALL (ARRAY['awaiting_browser_binding'::text, 'awaiting_provider_start'::text])) OR (upstream_state_digest IS NULL))),
    CONSTRAINT managed_provider_reauthorization_interactions_check11 CHECK (((status <> ALL (ARRAY['provider_authorization_started'::text, 'provider_exchange_in_progress'::text])) OR (upstream_state_digest IS NOT NULL))),
    CONSTRAINT managed_provider_reauthorization_interactions_check12 CHECK (((status = ANY (ARRAY['completed'::text, 'provider_exchange_failed'::text, 'expired'::text, 'cancelled'::text])) = (terminal_at IS NOT NULL))),
    CONSTRAINT managed_provider_reauthorization_interactions_check2 CHECK (((browser_binding_digest IS NULL) = (browser_binding_key_version IS NULL))),
    CONSTRAINT managed_provider_reauthorization_interactions_check3 CHECK (((csrf_digest IS NULL) = (csrf_key_version IS NULL))),
    CONSTRAINT managed_provider_reauthorization_interactions_check4 CHECK (((browser_binding_digest IS NULL) = (csrf_digest IS NULL))),
    CONSTRAINT managed_provider_reauthorization_interactions_check5 CHECK (((upstream_state_digest IS NULL) = (upstream_state_key_version IS NULL))),
    CONSTRAINT managed_provider_reauthorization_interactions_check6 CHECK (((provider_pkce_ciphertext IS NULL) = (provider_pkce_key_version IS NULL))),
    CONSTRAINT managed_provider_reauthorization_interactions_check7 CHECK (((oidc_nonce_digest IS NULL) = (oidc_nonce_key_version IS NULL))),
    CONSTRAINT managed_provider_reauthorization_interactions_check8 CHECK (((status <> 'awaiting_browser_binding'::text) OR (browser_binding_digest IS NULL))),
    CONSTRAINT managed_provider_reauthorization_interactions_check9 CHECK (((status <> ALL (ARRAY['awaiting_provider_start'::text, 'provider_authorization_started'::text, 'provider_exchange_in_progress'::text])) OR (browser_binding_digest IS NOT NULL))),
    CONSTRAINT managed_provider_reauthorization_interactions_client_id_check CHECK (((char_length(client_id) >= 1) AND (char_length(client_id) <= 512))),
    CONSTRAINT managed_provider_reauthorization_interactions_csrf_digest_check CHECK ((octet_length(csrf_digest) = 32)),
    CONSTRAINT managed_provider_reauthorization_interactions_issuer_check CHECK (((char_length(issuer) >= 8) AND (char_length(issuer) <= 2048))),
    CONSTRAINT managed_provider_reauthorization_interactions_revision_check CHECK ((revision > 0)),
    CONSTRAINT managed_provider_reauthorization_interactions_status_check CHECK ((status = ANY (ARRAY['awaiting_browser_binding'::text, 'awaiting_provider_start'::text, 'provider_authorization_started'::text, 'provider_exchange_in_progress'::text, 'completed'::text, 'provider_exchange_failed'::text, 'expired'::text, 'cancelled'::text]))),
    CONSTRAINT managed_provider_reauthorization_interactions_subject_check CHECK (((char_length(subject) >= 1) AND (char_length(subject) <= 512))),
    CONSTRAINT managed_provider_reauthorization_managed_profile_revision_check CHECK ((managed_profile_revision > 0)),
    CONSTRAINT managed_provider_reauthorization_provider_egress_policy_revisio CHECK (((provider_egress_policy_revision IS NULL) OR (provider_egress_policy_revision > 0))),
    CONSTRAINT managed_reauthorization_provider_display_name_check CHECK (((provider_display_name IS NULL) OR ((char_length(provider_display_name) >= 1) AND (char_length(provider_display_name) <= 128)))),
    CONSTRAINT managed_reauthorization_provider_kind_check CHECK (((provider_kind IS NULL) OR (provider_kind = ANY (ARRAY['oidc'::text, 'google'::text]))))
);


--
-- Name: COLUMN managed_provider_reauthorization_interactions.provider_egress_policy_revision; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.managed_provider_reauthorization_interactions.provider_egress_policy_revision IS 'Frozen Project Custom OIDC egress revision; NULL for named providers.';


--
-- Name: managed_provider_renewal_operations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.managed_provider_renewal_operations (
    id uuid NOT NULL,
    project_id uuid NOT NULL,
    connection_id uuid NOT NULL,
    expected_connection_generation bigint NOT NULL,
    expected_credential_generation bigint NOT NULL,
    successor_connection_generation bigint NOT NULL,
    successor_credential_generation bigint NOT NULL,
    attempt_id uuid NOT NULL,
    state text NOT NULL,
    adapter_idempotent_replay boolean NOT NULL,
    lease_owner uuid,
    lease_expires_at timestamp with time zone,
    safe_outcome text NOT NULL,
    prepared_at timestamp with time zone NOT NULL,
    submitted_at timestamp with time zone,
    terminal_at timestamp with time zone,
    updated_at timestamp with time zone NOT NULL,
    provider_egress_policy_revision bigint,
    CONSTRAINT managed_provider_renewal_ope_expected_connection_generati_check CHECK ((expected_connection_generation > 0)),
    CONSTRAINT managed_provider_renewal_ope_expected_credential_generati_check CHECK ((expected_credential_generation > 0)),
    CONSTRAINT managed_provider_renewal_ope_successor_connection_generat_check CHECK ((successor_connection_generation > 1)),
    CONSTRAINT managed_provider_renewal_ope_successor_credential_generat_check CHECK ((successor_credential_generation > 1)),
    CONSTRAINT managed_provider_renewal_operations_check CHECK ((successor_connection_generation = (expected_connection_generation + 1))),
    CONSTRAINT managed_provider_renewal_operations_check1 CHECK ((successor_credential_generation = (expected_credential_generation + 1))),
    CONSTRAINT managed_provider_renewal_operations_check2 CHECK (((state = ANY (ARRAY['prepared'::text, 'abandoned'::text, 'reauth_required'::text, 'superseded_by_login'::text])) OR (submitted_at IS NOT NULL))),
    CONSTRAINT managed_provider_renewal_operations_check3 CHECK (((state = ANY (ARRAY['successor_committed'::text, 'reauth_required'::text, 'abandoned'::text, 'superseded_by_login'::text])) = (terminal_at IS NOT NULL))),
    CONSTRAINT managed_provider_renewal_operations_safe_outcome_check CHECK (((char_length(safe_outcome) >= 1) AND (char_length(safe_outcome) <= 64))),
    CONSTRAINT managed_provider_renewal_operations_state_check CHECK ((state = ANY (ARRAY['prepared'::text, 'submitted'::text, 'successor_committed'::text, 'reauth_required'::text, 'abandoned'::text, 'superseded_by_login'::text]))),
    CONSTRAINT managed_provider_renewal_provider_egress_policy_revision_check CHECK (((provider_egress_policy_revision IS NULL) OR (provider_egress_policy_revision > 0)))
);


--
-- Name: COLUMN managed_provider_renewal_operations.provider_egress_policy_revision; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.managed_provider_renewal_operations.provider_egress_policy_revision IS 'Frozen Project Custom OIDC egress revision for a prepared renewal; NULL for named providers.';


--
-- Name: managed_reauthorization_create_results; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.managed_reauthorization_create_results (
    idempotency_key text NOT NULL,
    project_id uuid NOT NULL,
    interaction_id uuid NOT NULL,
    request_digest bytea,
    create_result_key_version integer NOT NULL,
    create_result_ciphertext bytea,
    expires_at timestamp with time zone NOT NULL,
    erased_at timestamp with time zone,
    CONSTRAINT managed_reauthorization_create__create_result_key_version_check CHECK ((create_result_key_version > 0)),
    CONSTRAINT managed_reauthorization_create_r_create_result_ciphertext_check CHECK (((octet_length(create_result_ciphertext) >= 40) AND (octet_length(create_result_ciphertext) <= 4096))),
    CONSTRAINT managed_reauthorization_create_results_check CHECK (((create_result_ciphertext IS NULL) = (erased_at IS NOT NULL))),
    CONSTRAINT managed_reauthorization_create_results_request_digest_check CHECK ((octet_length(request_digest) = 32))
);


--
-- Name: project_browser_logout_interactions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.project_browser_logout_interactions (
    id uuid NOT NULL,
    project_id uuid NOT NULL,
    application_id uuid NOT NULL,
    user_id uuid NOT NULL,
    application_session_id uuid NOT NULL,
    browser_session_id uuid NOT NULL,
    preparation_digest bytea NOT NULL,
    preparation_digest_key_version integer NOT NULL,
    status text NOT NULL,
    interaction_revision bigint DEFAULT 1 NOT NULL,
    csrf_digest bytea,
    csrf_digest_key_version integer,
    application_session_revision bigint NOT NULL,
    browser_session_revision bigint NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    csrf_bound_at timestamp with time zone,
    consumed_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT transaction_timestamp() NOT NULL,
    updated_at timestamp with time zone DEFAULT transaction_timestamp() NOT NULL,
    CONSTRAINT project_browser_logout_inter_application_session_revision_check CHECK ((application_session_revision > 0)),
    CONSTRAINT project_browser_logout_inter_preparation_digest_key_versi_check CHECK ((preparation_digest_key_version > 0)),
    CONSTRAINT project_browser_logout_interacti_browser_session_revision_check CHECK ((browser_session_revision > 0)),
    CONSTRAINT project_browser_logout_interactions_check CHECK ((expires_at > created_at)),
    CONSTRAINT project_browser_logout_interactions_check1 CHECK ((expires_at <= (created_at + '00:01:00'::interval))),
    CONSTRAINT project_browser_logout_interactions_check2 CHECK ((((status = ANY (ARRAY['prepared'::text, 'expired'::text])) AND (csrf_digest IS NULL) AND (csrf_digest_key_version IS NULL) AND (csrf_bound_at IS NULL)) OR ((status = ANY (ARRAY['csrf_bound'::text, 'consumed'::text, 'expired'::text])) AND (csrf_digest IS NOT NULL) AND (octet_length(csrf_digest) = 32) AND (csrf_digest_key_version IS NOT NULL) AND (csrf_digest_key_version > 0) AND (csrf_bound_at IS NOT NULL)))),
    CONSTRAINT project_browser_logout_interactions_check3 CHECK (((status = 'consumed'::text) = (consumed_at IS NOT NULL))),
    CONSTRAINT project_browser_logout_interactions_interaction_revision_check CHECK ((interaction_revision > 0)),
    CONSTRAINT project_browser_logout_interactions_preparation_digest_check CHECK ((octet_length(preparation_digest) = 32)),
    CONSTRAINT project_browser_logout_interactions_status_check CHECK ((status = ANY (ARRAY['prepared'::text, 'csrf_bound'::text, 'consumed'::text, 'expired'::text])))
);


--
-- Name: project_browser_sessions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.project_browser_sessions (
    id uuid NOT NULL,
    project_id uuid NOT NULL,
    user_id uuid NOT NULL,
    credential_digest bytea NOT NULL,
    credential_digest_key_version integer NOT NULL,
    status text NOT NULL,
    session_revision bigint DEFAULT 1 NOT NULL,
    project_security_revision bigint NOT NULL,
    user_security_revision bigint NOT NULL,
    policy_session_revision bigint NOT NULL,
    authenticated_at timestamp with time zone NOT NULL,
    last_activity_at timestamp with time zone NOT NULL,
    idle_expires_at timestamp with time zone NOT NULL,
    absolute_expires_at timestamp with time zone NOT NULL,
    terminated_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT transaction_timestamp() NOT NULL,
    updated_at timestamp with time zone DEFAULT transaction_timestamp() NOT NULL,
    CONSTRAINT project_browser_sessions_check CHECK ((last_activity_at >= authenticated_at)),
    CONSTRAINT project_browser_sessions_check1 CHECK ((absolute_expires_at = (authenticated_at + '24:00:00'::interval))),
    CONSTRAINT project_browser_sessions_check2 CHECK ((idle_expires_at = LEAST((last_activity_at + '08:00:00'::interval), absolute_expires_at))),
    CONSTRAINT project_browser_sessions_check3 CHECK (((status = 'terminated'::text) = (terminated_at IS NOT NULL))),
    CONSTRAINT project_browser_sessions_credential_digest_check CHECK ((octet_length(credential_digest) = 32)),
    CONSTRAINT project_browser_sessions_credential_digest_key_version_check CHECK ((credential_digest_key_version > 0)),
    CONSTRAINT project_browser_sessions_policy_session_revision_check CHECK ((policy_session_revision > 0)),
    CONSTRAINT project_browser_sessions_project_security_revision_check CHECK ((project_security_revision > 0)),
    CONSTRAINT project_browser_sessions_session_revision_check CHECK ((session_revision > 0)),
    CONSTRAINT project_browser_sessions_status_check CHECK ((status = ANY (ARRAY['active'::text, 'terminated'::text, 'expired'::text]))),
    CONSTRAINT project_browser_sessions_user_security_revision_check CHECK ((user_security_revision > 0))
);


--
-- Name: project_client_keys; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.project_client_keys (
    id uuid NOT NULL,
    project_id uuid NOT NULL,
    public_key_id text NOT NULL,
    label text NOT NULL,
    status text NOT NULL,
    digest_key_version integer NOT NULL,
    credential_digest bytea NOT NULL,
    display_prefix text NOT NULL,
    revision bigint NOT NULL,
    created_at timestamp with time zone DEFAULT transaction_timestamp() NOT NULL,
    last_used_at timestamp with time zone,
    revoked_at timestamp with time zone,
    credential_acknowledged_at timestamp with time zone,
    CONSTRAINT project_client_keys_acknowledged_after_create CHECK (((credential_acknowledged_at IS NULL) OR (credential_acknowledged_at >= created_at))),
    CONSTRAINT project_client_keys_check CHECK ((display_prefix = ('owl_client_v1.'::text || public_key_id))),
    CONSTRAINT project_client_keys_check1 CHECK ((((status = 'active'::text) AND (revoked_at IS NULL)) OR ((status = 'revoked'::text) AND (revoked_at IS NOT NULL)))),
    CONSTRAINT project_client_keys_check2 CHECK (((last_used_at IS NULL) OR (last_used_at >= created_at))),
    CONSTRAINT project_client_keys_check3 CHECK (((revoked_at IS NULL) OR (revoked_at >= created_at))),
    CONSTRAINT project_client_keys_credential_digest_check CHECK ((octet_length(credential_digest) = 32)),
    CONSTRAINT project_client_keys_digest_key_version_check CHECK ((digest_key_version > 0)),
    CONSTRAINT project_client_keys_label_check CHECK ((((char_length(label) >= 1) AND (char_length(label) <= 64)) AND (label = btrim(label)) AND (label !~ '[[:cntrl:]]'::text))),
    CONSTRAINT project_client_keys_public_key_id_check CHECK (((public_key_id COLLATE "C") ~ '^[A-Za-z0-9_-]{22}$'::text)),
    CONSTRAINT project_client_keys_revision_check CHECK ((revision > 0)),
    CONSTRAINT project_client_keys_status_check CHECK ((status = ANY (ARRAY['active'::text, 'revoked'::text])))
);


--
-- Name: project_email_policies; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.project_email_policies (
    project_id uuid NOT NULL,
    status text NOT NULL,
    policy_revision bigint DEFAULT 1 NOT NULL,
    security_revision bigint DEFAULT 1 NOT NULL,
    canonicalization_version integer DEFAULT 1 NOT NULL,
    otp_enabled boolean DEFAULT true NOT NULL,
    magic_link_enabled boolean DEFAULT true NOT NULL,
    otp_digits smallint DEFAULT 6 NOT NULL,
    otp_validity_seconds integer DEFAULT 600 NOT NULL,
    otp_max_attempts smallint DEFAULT 5 NOT NULL,
    resend_after_seconds integer DEFAULT 30 NOT NULL,
    max_generations smallint DEFAULT 5 NOT NULL,
    magic_validity_seconds integer DEFAULT 600 NOT NULL,
    signup_enabled boolean DEFAULT true NOT NULL,
    transferred_magic_link_enabled boolean DEFAULT false NOT NULL,
    allow_deployment_default boolean DEFAULT false NOT NULL,
    updated_at timestamp with time zone DEFAULT transaction_timestamp() NOT NULL,
    CONSTRAINT project_email_policies_canonicalization_version_check CHECK ((canonicalization_version = 1)),
    CONSTRAINT project_email_policies_check CHECK ((otp_enabled OR magic_link_enabled)),
    CONSTRAINT project_email_policies_magic_validity_seconds_check CHECK (((magic_validity_seconds >= 30) AND (magic_validity_seconds <= 600))),
    CONSTRAINT project_email_policies_max_generations_check CHECK (((max_generations >= 1) AND (max_generations <= 5))),
    CONSTRAINT project_email_policies_otp_digits_check CHECK (((otp_digits >= 6) AND (otp_digits <= 10))),
    CONSTRAINT project_email_policies_otp_max_attempts_check CHECK (((otp_max_attempts >= 1) AND (otp_max_attempts <= 5))),
    CONSTRAINT project_email_policies_otp_validity_seconds_check CHECK (((otp_validity_seconds >= 30) AND (otp_validity_seconds <= 600))),
    CONSTRAINT project_email_policies_policy_revision_check CHECK ((policy_revision > 0)),
    CONSTRAINT project_email_policies_resend_after_seconds_check CHECK (((resend_after_seconds >= 30) AND (resend_after_seconds <= 600))),
    CONSTRAINT project_email_policies_security_revision_check CHECK ((security_revision > 0)),
    CONSTRAINT project_email_policies_status_check CHECK ((status = ANY (ARRAY['enabled'::text, 'disabled'::text])))
);


--
-- Name: project_key_rings; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.project_key_rings (
    id uuid NOT NULL,
    project_id uuid NOT NULL,
    issuer text NOT NULL,
    purpose text NOT NULL,
    algorithm text NOT NULL,
    revision bigint NOT NULL,
    signing_epoch bigint NOT NULL,
    created_at timestamp with time zone DEFAULT transaction_timestamp() NOT NULL,
    updated_at timestamp with time zone DEFAULT transaction_timestamp() NOT NULL,
    CONSTRAINT project_key_rings_algorithm_check CHECK ((algorithm = 'EdDSA'::text)),
    CONSTRAINT project_key_rings_issuer_check CHECK (((char_length(issuer) >= 8) AND (char_length(issuer) <= 2048))),
    CONSTRAINT project_key_rings_purpose_check CHECK ((purpose = 'application_tokens'::text)),
    CONSTRAINT project_key_rings_revision_check CHECK ((revision > 0)),
    CONSTRAINT project_key_rings_signing_epoch_check CHECK ((signing_epoch > 0))
);


--
-- Name: project_policies; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.project_policies (
    project_id uuid NOT NULL,
    claims_revision bigint DEFAULT 1 NOT NULL,
    session_revision bigint DEFAULT 1 NOT NULL,
    claims_policy jsonb DEFAULT '{"access_token_lifetime_seconds": 900}'::jsonb NOT NULL,
    session_policy jsonb DEFAULT '{"browser_session_reuse": false, "browser_session_reuse_max_age_seconds": 28800}'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT transaction_timestamp() NOT NULL,
    updated_at timestamp with time zone DEFAULT transaction_timestamp() NOT NULL,
    CONSTRAINT project_policies_claims_policy_check CHECK ((jsonb_typeof(claims_policy) = 'object'::text)),
    CONSTRAINT project_policies_claims_policy_check1 CHECK ((octet_length((claims_policy)::text) <= 8192)),
    CONSTRAINT project_policies_claims_policy_check2 CHECK ((((claims_policy - 'access_token_lifetime_seconds'::text) = '{}'::jsonb) AND (jsonb_typeof((claims_policy -> 'access_token_lifetime_seconds'::text)) = 'number'::text) AND ((claims_policy -> 'access_token_lifetime_seconds'::text) = to_jsonb(((claims_policy ->> 'access_token_lifetime_seconds'::text))::integer)) AND ((((claims_policy ->> 'access_token_lifetime_seconds'::text))::integer >= 60) AND (((claims_policy ->> 'access_token_lifetime_seconds'::text))::integer <= 3600)))),
    CONSTRAINT project_policies_claims_revision_check CHECK ((claims_revision > 0)),
    CONSTRAINT project_policies_session_policy_check CHECK ((jsonb_typeof(session_policy) = 'object'::text)),
    CONSTRAINT project_policies_session_policy_check1 CHECK ((octet_length((session_policy)::text) <= 8192)),
    CONSTRAINT project_policies_session_revision_check CHECK ((session_revision > 0)),
    CONSTRAINT project_policies_session_shape_check CHECK ((((session_policy - ARRAY['browser_session_reuse'::text, 'browser_session_reuse_max_age_seconds'::text]) = '{}'::jsonb) AND (jsonb_typeof((session_policy -> 'browser_session_reuse'::text)) = 'boolean'::text) AND (jsonb_typeof((session_policy -> 'browser_session_reuse_max_age_seconds'::text)) = 'number'::text) AND ((session_policy -> 'browser_session_reuse_max_age_seconds'::text) = to_jsonb(((session_policy ->> 'browser_session_reuse_max_age_seconds'::text))::integer)) AND ((((session_policy ->> 'browser_session_reuse_max_age_seconds'::text))::integer >= 0) AND (((session_policy ->> 'browser_session_reuse_max_age_seconds'::text))::integer <= 86400))))
);


--
-- Name: project_provider_egress_policies; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.project_provider_egress_policies (
    project_id uuid NOT NULL,
    mode text NOT NULL,
    exact_origins jsonb DEFAULT '[]'::jsonb NOT NULL,
    revision bigint DEFAULT 1 NOT NULL,
    created_at timestamp with time zone DEFAULT transaction_timestamp() NOT NULL,
    updated_at timestamp with time zone DEFAULT transaction_timestamp() NOT NULL,
    CONSTRAINT project_provider_egress_policies_mode_check CHECK ((mode = ANY (ARRAY['allow_all'::text, 'exact_origins'::text]))),
    CONSTRAINT project_provider_egress_policies_revision_check CHECK ((revision > 0)),
    CONSTRAINT project_provider_egress_policy_origins_check CHECK (((jsonb_typeof(exact_origins) = 'array'::text) AND (((mode = 'allow_all'::text) AND (jsonb_array_length(exact_origins) = 0)) OR ((mode = 'exact_origins'::text) AND ((jsonb_array_length(exact_origins) >= 1) AND (jsonb_array_length(exact_origins) <= 1024))))))
);


--
-- Name: TABLE project_provider_egress_policies; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.project_provider_egress_policies IS 'Project authority for Custom OIDC origins. allow_all stores []; exact_origins stores 1-1024 sorted unique canonical origins.';


--
-- Name: project_signing_keys; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.project_signing_keys (
    id uuid NOT NULL,
    project_id uuid NOT NULL,
    ring_id uuid NOT NULL,
    kid text NOT NULL,
    public_jwk jsonb NOT NULL,
    state text NOT NULL,
    ring_revision bigint NOT NULL,
    provisioned_at timestamp with time zone,
    published_at timestamp with time zone,
    activated_at timestamp with time zone,
    retiring_at timestamp with time zone,
    retired_at timestamp with time zone,
    revoked_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT transaction_timestamp() NOT NULL,
    updated_at timestamp with time zone DEFAULT transaction_timestamp() NOT NULL,
    sign_not_before timestamp with time zone,
    verify_not_after timestamp with time zone,
    maintenance_claimed_at timestamp with time zone,
    signer_material_id uuid NOT NULL,
    signer_material_generation bigint DEFAULT 1 NOT NULL,
    CONSTRAINT project_signing_keys_active_sign_time_check CHECK (((state <> ALL (ARRAY['active'::text, 'retiring'::text, 'retired'::text])) OR (sign_not_before IS NOT NULL))),
    CONSTRAINT project_signing_keys_kid_check CHECK (((char_length(kid) >= 8) AND (char_length(kid) <= 128))),
    CONSTRAINT project_signing_keys_kid_shape_check CHECK ((kid ~ '^[A-Za-z0-9_-]+$'::text)),
    CONSTRAINT project_signing_keys_public_jwk_check CHECK ((jsonb_typeof(public_jwk) = 'object'::text)),
    CONSTRAINT project_signing_keys_public_jwk_shape_check CHECK ((((state = ANY (ARRAY['provisioning'::text, 'abandoned'::text])) AND (public_jwk = '{}'::jsonb)) OR ((jsonb_typeof(public_jwk) = 'object'::text) AND ((public_jwk - ARRAY['kty'::text, 'crv'::text, 'alg'::text, 'use'::text, 'kid'::text, 'x'::text]) = '{}'::jsonb) AND (public_jwk ?& ARRAY['kty'::text, 'crv'::text, 'alg'::text, 'use'::text, 'kid'::text, 'x'::text]) AND ((public_jwk ->> 'kty'::text) = 'OKP'::text) AND ((public_jwk ->> 'crv'::text) = 'Ed25519'::text) AND ((public_jwk ->> 'alg'::text) = 'EdDSA'::text) AND ((public_jwk ->> 'use'::text) = 'sig'::text) AND ((public_jwk ->> 'kid'::text) = kid) AND (jsonb_typeof((public_jwk -> 'x'::text)) = 'string'::text) AND ((public_jwk ->> 'x'::text) ~ '^[A-Za-z0-9_-]{43}$'::text) AND (octet_length(decode((translate((public_jwk ->> 'x'::text), '-_'::text, '+/'::text) || '='::text), 'base64'::text)) = 32) AND (octet_length((public_jwk)::text) <= 512)))),
    CONSTRAINT project_signing_keys_retirement_cutoff_check CHECK (((state <> ALL (ARRAY['retiring'::text, 'retired'::text])) OR (verify_not_after IS NOT NULL))),
    CONSTRAINT project_signing_keys_ring_revision_check CHECK ((ring_revision > 0)),
    CONSTRAINT project_signing_keys_sign_window_check CHECK (((verify_not_after IS NULL) OR (sign_not_before IS NULL) OR (verify_not_after > sign_not_before))),
    CONSTRAINT project_signing_keys_signer_material_generation_check CHECK ((signer_material_generation > 0)),
    CONSTRAINT project_signing_keys_state_check CHECK ((state = ANY (ARRAY['provisioning'::text, 'published'::text, 'active'::text, 'retiring'::text, 'retired'::text, 'revoked'::text, 'abandoned'::text])))
);


--
-- Name: project_smtp_configurations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.project_smtp_configurations (
    id uuid NOT NULL,
    project_id uuid NOT NULL,
    status text NOT NULL,
    generation integer NOT NULL,
    revision bigint DEFAULT 1 NOT NULL,
    security_eligibility_revision bigint DEFAULT 1 NOT NULL,
    host text NOT NULL,
    port integer NOT NULL,
    tls_mode text NOT NULL,
    sender_address text NOT NULL,
    sender_name text,
    reply_to text,
    safe_fingerprint bytea,
    retained_until timestamp with time zone,
    created_at timestamp with time zone DEFAULT transaction_timestamp() NOT NULL,
    updated_at timestamp with time zone DEFAULT transaction_timestamp() NOT NULL,
    credential_material_id uuid NOT NULL,
    CONSTRAINT project_smtp_configurations_check CHECK (((status = 'retained'::text) = (retained_until IS NOT NULL))),
    CONSTRAINT project_smtp_configurations_check1 CHECK (((tls_mode <> 'development_loopback_plaintext'::text) OR (host = ANY (ARRAY['127.0.0.1'::text, '::1'::text, 'localhost'::text])))),
    CONSTRAINT project_smtp_configurations_generation_check CHECK ((generation > 0)),
    CONSTRAINT project_smtp_configurations_host_check CHECK (((char_length(host) >= 1) AND (char_length(host) <= 253))),
    CONSTRAINT project_smtp_configurations_port_check CHECK (((port >= 1) AND (port <= 65535))),
    CONSTRAINT project_smtp_configurations_reply_to_check CHECK (((reply_to IS NULL) OR ((char_length(reply_to) >= 3) AND (char_length(reply_to) <= 254)))),
    CONSTRAINT project_smtp_configurations_revision_check CHECK ((revision > 0)),
    CONSTRAINT project_smtp_configurations_safe_fingerprint_check CHECK ((octet_length(safe_fingerprint) = 32)),
    CONSTRAINT project_smtp_configurations_security_eligibility_revision_check CHECK ((security_eligibility_revision > 0)),
    CONSTRAINT project_smtp_configurations_sender_address_check CHECK (((char_length(sender_address) >= 3) AND (char_length(sender_address) <= 254))),
    CONSTRAINT project_smtp_configurations_sender_name_check CHECK (((sender_name IS NULL) OR ((char_length(sender_name) >= 1) AND (char_length(sender_name) <= 128)))),
    CONSTRAINT project_smtp_configurations_status_check CHECK ((status = ANY (ARRAY['pending'::text, 'active'::text, 'retained'::text, 'disabled'::text, 'compromised'::text, 'retired'::text]))),
    CONSTRAINT project_smtp_configurations_tls_mode_check CHECK ((tls_mode = ANY (ARRAY['implicit_tls'::text, 'starttls_required'::text, 'development_loopback_plaintext'::text])))
);


--
-- Name: project_smtp_runtime_readiness; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.project_smtp_runtime_readiness (
    project_id uuid NOT NULL,
    configuration_id uuid NOT NULL,
    generation integer NOT NULL,
    process_id text NOT NULL,
    process_incarnation uuid NOT NULL,
    state text NOT NULL,
    checked_at timestamp with time zone NOT NULL,
    lease_expires_at timestamp with time zone NOT NULL,
    CONSTRAINT project_smtp_runtime_readiness_check CHECK ((lease_expires_at > checked_at)),
    CONSTRAINT project_smtp_runtime_readiness_generation_check CHECK ((generation > 0)),
    CONSTRAINT project_smtp_runtime_readiness_process_id_check CHECK ((process_id ~ '^[a-zA-Z0-9._:-]{1,128}$'::text)),
    CONSTRAINT project_smtp_runtime_readiness_state_check CHECK ((state = ANY (ARRAY['ready'::text, 'unavailable'::text])))
);


--
-- Name: project_smtp_secret_operations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.project_smtp_secret_operations (
    project_id uuid NOT NULL,
    operation_alias text NOT NULL,
    configuration_id uuid NOT NULL,
    request_digest bytea NOT NULL,
    state text NOT NULL,
    provisioning_token uuid,
    created_at timestamp with time zone DEFAULT transaction_timestamp() NOT NULL,
    completed_at timestamp with time zone,
    material_id uuid NOT NULL,
    CONSTRAINT project_smtp_secret_operations_check CHECK (((state = 'completed'::text) = (completed_at IS NOT NULL))),
    CONSTRAINT project_smtp_secret_operations_check1 CHECK (((state = 'provisioning'::text) = (provisioning_token IS NOT NULL))),
    CONSTRAINT project_smtp_secret_operations_operation_alias_check CHECK (((char_length(operation_alias) >= 8) AND (char_length(operation_alias) <= 128))),
    CONSTRAINT project_smtp_secret_operations_request_digest_check CHECK ((octet_length(request_digest) = 32)),
    CONSTRAINT project_smtp_secret_operations_state_check CHECK ((state = ANY (ARRAY['prepared'::text, 'provisioning'::text, 'completed'::text])))
);


--
-- Name: project_smtp_test_operations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.project_smtp_test_operations (
    id uuid NOT NULL,
    project_id uuid NOT NULL,
    idempotency_key text NOT NULL,
    configuration_id uuid NOT NULL,
    configuration_generation integer NOT NULL,
    configuration_revision bigint NOT NULL,
    configuration_security_eligibility_revision bigint NOT NULL,
    host text NOT NULL,
    port integer NOT NULL,
    tls_mode text NOT NULL,
    sender_address text NOT NULL,
    request_digest bytea NOT NULL,
    message_id text NOT NULL,
    provisioning_token uuid,
    recipient_erased_at timestamp with time zone,
    cleanup_lease_owner text,
    cleanup_lease_expires_at timestamp with time zone,
    state text NOT NULL,
    safe_outcome text,
    lease_owner text,
    lease_expires_at timestamp with time zone,
    attempts smallint DEFAULT 0 NOT NULL,
    correlation_id uuid NOT NULL,
    created_at timestamp with time zone DEFAULT transaction_timestamp() NOT NULL,
    expires_at timestamp with time zone DEFAULT (transaction_timestamp() + '00:10:00'::interval) NOT NULL,
    completed_at timestamp with time zone,
    credential_material_id uuid NOT NULL,
    recipient_material_id uuid NOT NULL,
    CONSTRAINT project_smtp_test_operations_attempts_check CHECK (((attempts >= 0) AND (attempts <= 1))),
    CONSTRAINT project_smtp_test_operations_check CHECK ((expires_at = (created_at + '00:10:00'::interval))),
    CONSTRAINT project_smtp_test_operations_check1 CHECK (((state = ANY (ARRAY['preparing'::text, 'pending'::text, 'submitting'::text])) = (completed_at IS NULL))),
    CONSTRAINT project_smtp_test_operations_check2 CHECK (((state = ANY (ARRAY['preparing'::text, 'pending'::text, 'submitting'::text])) = (safe_outcome IS NULL))),
    CONSTRAINT project_smtp_test_operations_check3 CHECK (((state = 'preparing'::text) = (provisioning_token IS NOT NULL))),
    CONSTRAINT project_smtp_test_operations_check4 CHECK (((state = 'submitting'::text) = ((lease_owner IS NOT NULL) AND (lease_expires_at IS NOT NULL)))),
    CONSTRAINT project_smtp_test_operations_check5 CHECK (((cleanup_lease_owner IS NULL) = (cleanup_lease_expires_at IS NULL))),
    CONSTRAINT project_smtp_test_operations_check6 CHECK (((recipient_erased_at IS NULL) OR (state = ANY (ARRAY['delivered'::text, 'failed'::text, 'ambiguous'::text])))),
    CONSTRAINT project_smtp_test_operations_configuration_generation_check CHECK ((configuration_generation > 0)),
    CONSTRAINT project_smtp_test_operations_configuration_revision_check CHECK ((configuration_revision > 0)),
    CONSTRAINT project_smtp_test_operations_configuration_security_eligi_check CHECK ((configuration_security_eligibility_revision > 0)),
    CONSTRAINT project_smtp_test_operations_host_check CHECK (((char_length(host) >= 1) AND (char_length(host) <= 253))),
    CONSTRAINT project_smtp_test_operations_idempotency_key_check CHECK (((char_length(idempotency_key) >= 8) AND (char_length(idempotency_key) <= 128))),
    CONSTRAINT project_smtp_test_operations_message_id_check CHECK (((char_length(message_id) >= 16) AND (char_length(message_id) <= 255))),
    CONSTRAINT project_smtp_test_operations_port_check CHECK (((port >= 1) AND (port <= 65535))),
    CONSTRAINT project_smtp_test_operations_request_digest_check CHECK ((octet_length(request_digest) = 32)),
    CONSTRAINT project_smtp_test_operations_safe_outcome_check CHECK (((safe_outcome IS NULL) OR (safe_outcome = ANY (ARRAY['delivered'::text, 'transient'::text, 'permanent'::text, 'ambiguous'::text, 'policy_denied'::text])))),
    CONSTRAINT project_smtp_test_operations_sender_address_check CHECK (((char_length(sender_address) >= 3) AND (char_length(sender_address) <= 254))),
    CONSTRAINT project_smtp_test_operations_state_check CHECK ((state = ANY (ARRAY['preparing'::text, 'pending'::text, 'submitting'::text, 'delivered'::text, 'failed'::text, 'ambiguous'::text]))),
    CONSTRAINT project_smtp_test_operations_tls_mode_check CHECK ((tls_mode = ANY (ARRAY['implicit_tls'::text, 'starttls_required'::text])))
);


--
-- Name: project_user_merge_tombstones; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.project_user_merge_tombstones (
    project_id uuid NOT NULL,
    loser_user_id uuid NOT NULL,
    winner_user_id uuid NOT NULL,
    loser_user_revision bigint NOT NULL,
    winner_user_revision bigint NOT NULL,
    primary_source_kind text NOT NULL,
    primary_provider_identity_id uuid,
    sessions_disposition text NOT NULL,
    bindings_disposition text NOT NULL,
    merged_at timestamp with time zone NOT NULL,
    correlation_id uuid NOT NULL,
    identity_mutation_intent_id uuid NOT NULL,
    primary_email_identity_id uuid,
    CONSTRAINT project_user_merge_tombstones_bindings_disposition_check CHECK ((bindings_disposition = 'winner_preferred'::text)),
    CONSTRAINT project_user_merge_tombstones_check CHECK ((loser_user_id <> winner_user_id)),
    CONSTRAINT project_user_merge_tombstones_loser_user_revision_check CHECK ((loser_user_revision > 0)),
    CONSTRAINT project_user_merge_tombstones_primary_shape_check CHECK ((((primary_source_kind = 'provider'::text) AND (primary_provider_identity_id IS NOT NULL) AND (primary_email_identity_id IS NULL)) OR ((primary_source_kind = 'email'::text) AND (primary_provider_identity_id IS NULL) AND (primary_email_identity_id IS NOT NULL)))),
    CONSTRAINT project_user_merge_tombstones_primary_source_kind_check CHECK ((primary_source_kind = ANY (ARRAY['provider'::text, 'email'::text]))),
    CONSTRAINT project_user_merge_tombstones_sessions_disposition_check CHECK ((sessions_disposition = 'loser_revoked'::text)),
    CONSTRAINT project_user_merge_tombstones_winner_user_revision_check CHECK ((winner_user_revision > 0))
);


--
-- Name: project_users; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.project_users (
    id uuid NOT NULL,
    project_id uuid NOT NULL,
    public_id text NOT NULL,
    status text NOT NULL,
    user_revision bigint DEFAULT 1 NOT NULL,
    security_revision bigint DEFAULT 1 NOT NULL,
    primary_profile_identity_id uuid,
    base_profile_digest bytea NOT NULL,
    display_name text,
    picture_url text,
    created_at timestamp with time zone DEFAULT transaction_timestamp() NOT NULL,
    updated_at timestamp with time zone DEFAULT transaction_timestamp() NOT NULL,
    primary_source_kind text DEFAULT 'provider'::text NOT NULL,
    local_display_name_set boolean DEFAULT false NOT NULL,
    local_display_name text,
    local_picture_url_set boolean DEFAULT false NOT NULL,
    local_picture_url text,
    local_locale_set boolean DEFAULT false NOT NULL,
    local_locale text,
    locale text,
    primary_email_identity_id uuid,
    merged_into_user_id uuid,
    CONSTRAINT project_users_base_profile_digest_check CHECK ((octet_length(base_profile_digest) = 32)),
    CONSTRAINT project_users_display_name_check CHECK (((display_name IS NULL) OR ((char_length(display_name) >= 1) AND (char_length(display_name) <= 128)))),
    CONSTRAINT project_users_merged_shape_check CHECK ((((status = 'merged'::text) AND (merged_into_user_id IS NOT NULL) AND (merged_into_user_id <> id) AND (primary_profile_identity_id IS NULL) AND (primary_email_identity_id IS NULL)) OR ((status = ANY (ARRAY['active'::text, 'disabled'::text])) AND (merged_into_user_id IS NULL) AND (((primary_source_kind = 'provider'::text) AND (primary_email_identity_id IS NULL)) OR ((primary_source_kind = 'email'::text) AND (primary_profile_identity_id IS NULL)))))),
    CONSTRAINT project_users_picture_url_check CHECK (((picture_url IS NULL) OR ((char_length(picture_url) >= 8) AND (char_length(picture_url) <= 2048)))),
    CONSTRAINT project_users_public_id_check CHECK (((char_length(public_id) >= 8) AND (char_length(public_id) <= 96))),
    CONSTRAINT project_users_security_revision_check CHECK ((security_revision > 0)),
    CONSTRAINT project_users_status_check CHECK ((status = ANY (ARRAY['active'::text, 'disabled'::text, 'merged'::text]))),
    CONSTRAINT project_users_user_revision_check CHECK ((user_revision > 0))
);


--
-- Name: projection_email_key_authority; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.projection_email_key_authority (
    singleton boolean DEFAULT true NOT NULL,
    authority_revision bigint NOT NULL,
    write_version integer NOT NULL,
    accepted_versions integer[] NOT NULL,
    target_version integer,
    target_staged_at timestamp with time zone,
    retirement_version integer,
    retirement_authorized_at timestamp with time zone,
    updated_at timestamp with time zone NOT NULL,
    CONSTRAINT projection_email_key_authority_accepted_check CHECK ((public.owlauth_positive_unique_key_versions(accepted_versions) AND (accepted_versions @> ARRAY[write_version]))),
    CONSTRAINT projection_email_key_authority_authority_revision_check CHECK ((authority_revision > 0)),
    CONSTRAINT projection_email_key_authority_retirement_check CHECK ((((retirement_version IS NULL) AND (retirement_authorized_at IS NULL)) OR ((retirement_version IS NOT NULL) AND (retirement_version > 0) AND (retirement_version <> write_version) AND (accepted_versions @> ARRAY[retirement_version]) AND (retirement_authorized_at IS NOT NULL)))),
    CONSTRAINT projection_email_key_authority_singleton_check CHECK (singleton),
    CONSTRAINT projection_email_key_authority_target_check CHECK ((((target_version IS NULL) AND (target_staged_at IS NULL)) OR ((target_version IS NOT NULL) AND (target_version > 0) AND (target_version <> write_version) AND (target_staged_at IS NOT NULL) AND (accepted_versions @> ARRAY[target_version])))),
    CONSTRAINT projection_email_key_authority_write_version_check CHECK ((write_version > 0))
);


--
-- Name: projection_email_runtime_observations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.projection_email_runtime_observations (
    process_id text NOT NULL,
    process_incarnation uuid NOT NULL,
    authority_revision bigint NOT NULL,
    readable_versions integer[] NOT NULL,
    observed_at timestamp with time zone NOT NULL,
    lease_expires_at timestamp with time zone NOT NULL,
    CONSTRAINT projection_email_runtime_observations_authority_revision_check CHECK ((authority_revision > 0)),
    CONSTRAINT projection_email_runtime_observations_lease_check CHECK ((lease_expires_at > observed_at)),
    CONSTRAINT projection_email_runtime_observations_process_id_check CHECK (((process_id <> ''::text) AND (length(process_id) <= 128))),
    CONSTRAINT projection_email_runtime_observations_versions_check CHECK (public.owlauth_positive_unique_key_versions(readable_versions))
);


--
-- Name: projects; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.projects (
    id uuid NOT NULL,
    public_id text NOT NULL,
    belongs_to text,
    status text NOT NULL,
    metadata_revision bigint NOT NULL,
    security_revision bigint NOT NULL,
    created_at timestamp with time zone DEFAULT transaction_timestamp() NOT NULL,
    updated_at timestamp with time zone DEFAULT transaction_timestamp() NOT NULL,
    display_name text DEFAULT 'Untitled project'::text NOT NULL,
    CONSTRAINT projects_belongs_to_length CHECK (((belongs_to IS NULL) OR ((char_length(belongs_to) >= 1) AND (char_length(belongs_to) <= 256)))),
    CONSTRAINT projects_display_name_length CHECK (((char_length(display_name) >= 1) AND (char_length(display_name) <= 128))),
    CONSTRAINT projects_metadata_revision_check CHECK ((metadata_revision > 0)),
    CONSTRAINT projects_public_id_length CHECK (((char_length(public_id) >= 8) AND (char_length(public_id) <= 96))),
    CONSTRAINT projects_public_id_shape_check CHECK ((public_id ~ '^[A-Za-z0-9_-]+$'::text)),
    CONSTRAINT projects_security_revision_check CHECK ((security_revision > 0)),
    CONSTRAINT projects_status_check CHECK ((status = ANY (ARRAY['active'::text, 'disabled'::text])))
);


--
-- Name: protected_material_inventory_authority; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.protected_material_inventory_authority (
    singleton boolean DEFAULT true NOT NULL,
    revision bigint DEFAULT 1 NOT NULL,
    updated_at timestamp with time zone DEFAULT transaction_timestamp() NOT NULL,
    CONSTRAINT protected_material_inventory_authority_revision_check CHECK ((revision > 0)),
    CONSTRAINT protected_material_inventory_authority_singleton_check CHECK (singleton)
);


--
-- Name: protected_materials; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.protected_materials (
    id uuid NOT NULL,
    scope_kind text NOT NULL,
    project_id uuid,
    owner_kind text NOT NULL,
    owner_id uuid NOT NULL,
    generation bigint NOT NULL,
    material_kind text NOT NULL,
    provider_id text NOT NULL,
    provider_format_version integer NOT NULL,
    context_version integer NOT NULL,
    context_digest bytea NOT NULL,
    opaque_value bytea,
    safe_fingerprint bytea,
    state text NOT NULL,
    created_at timestamp with time zone DEFAULT transaction_timestamp() NOT NULL,
    updated_at timestamp with time zone DEFAULT transaction_timestamp() NOT NULL,
    erased_at timestamp with time zone,
    CONSTRAINT protected_material_fingerprint_check CHECK ((((material_kind = 'signing_key'::text) AND (safe_fingerprint IS NULL)) OR ((material_kind = 'configuration_secret'::text) AND (((state = 'pending'::text) AND (safe_fingerprint IS NULL)) OR ((state = 'live'::text) AND (safe_fingerprint IS NOT NULL)) OR (state = 'erased'::text))))),
    CONSTRAINT protected_material_kind_owner_check CHECK ((((material_kind = 'signing_key'::text) AND (owner_kind = 'signing_key'::text)) OR ((material_kind = 'configuration_secret'::text) AND (owner_kind <> 'signing_key'::text)))),
    CONSTRAINT protected_material_scope_check CHECK ((((scope_kind = 'deployment'::text) AND (project_id IS NULL)) OR ((scope_kind = 'project'::text) AND (project_id IS NOT NULL)))),
    CONSTRAINT protected_material_state_check CHECK ((((state = 'pending'::text) AND (opaque_value IS NULL) AND (erased_at IS NULL)) OR ((state = 'live'::text) AND (opaque_value IS NOT NULL) AND (erased_at IS NULL)) OR ((state = 'erased'::text) AND (opaque_value IS NULL) AND (erased_at IS NOT NULL)))),
    CONSTRAINT protected_materials_context_digest_check CHECK ((octet_length(context_digest) = 32)),
    CONSTRAINT protected_materials_context_version_check CHECK (((context_version >= 1) AND (context_version <= 65535))),
    CONSTRAINT protected_materials_generation_check CHECK ((generation > 0)),
    CONSTRAINT protected_materials_material_kind_check CHECK ((material_kind = ANY (ARRAY['signing_key'::text, 'configuration_secret'::text]))),
    CONSTRAINT protected_materials_opaque_value_check CHECK (((opaque_value IS NULL) OR ((octet_length(opaque_value) >= 1) AND (octet_length(opaque_value) <= 65536)))),
    CONSTRAINT protected_materials_owner_kind_check CHECK ((owner_kind = ANY (ARRAY['signing_key'::text, 'provider_secret'::text, 'project_smtp'::text, 'deployment_smtp'::text, 'smtp_test_recipient'::text, 'webhook_secret'::text]))),
    CONSTRAINT protected_materials_provider_format_version_check CHECK (((provider_format_version >= 1) AND (provider_format_version <= 65535))),
    CONSTRAINT protected_materials_provider_id_check CHECK ((((char_length(provider_id) >= 1) AND (char_length(provider_id) <= 64)) AND (provider_id ~ '^[a-z][a-z0-9_-]*$'::text))),
    CONSTRAINT protected_materials_safe_fingerprint_check CHECK (((safe_fingerprint IS NULL) OR (octet_length(safe_fingerprint) = 32))),
    CONSTRAINT protected_materials_scope_kind_check CHECK ((scope_kind = ANY (ARRAY['deployment'::text, 'project'::text]))),
    CONSTRAINT protected_materials_state_check CHECK ((state = ANY (ARRAY['pending'::text, 'live'::text, 'erased'::text])))
);


--
-- Name: provider_callback_owners; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.provider_callback_owners (
    state_id uuid NOT NULL,
    project_id uuid NOT NULL,
    provider_configuration_id uuid NOT NULL,
    owner_kind text NOT NULL,
    login_transaction_id uuid,
    identity_mutation_intent_id uuid,
    identity_mutation_proof_slot_id uuid,
    managed_reauthorization_interaction_id uuid,
    created_at timestamp with time zone DEFAULT transaction_timestamp() NOT NULL,
    CONSTRAINT provider_callback_owners_check CHECK ((((owner_kind = 'login'::text) AND (login_transaction_id IS NOT NULL) AND (state_id = login_transaction_id) AND (identity_mutation_intent_id IS NULL) AND (identity_mutation_proof_slot_id IS NULL) AND (managed_reauthorization_interaction_id IS NULL)) OR ((owner_kind = 'identity_mutation'::text) AND (login_transaction_id IS NULL) AND (identity_mutation_intent_id IS NOT NULL) AND (identity_mutation_proof_slot_id IS NOT NULL) AND (state_id = identity_mutation_proof_slot_id) AND (managed_reauthorization_interaction_id IS NULL)) OR ((owner_kind = 'managed_reauthorization'::text) AND (login_transaction_id IS NULL) AND (identity_mutation_intent_id IS NULL) AND (identity_mutation_proof_slot_id IS NULL) AND (managed_reauthorization_interaction_id IS NOT NULL) AND (state_id = managed_reauthorization_interaction_id)))),
    CONSTRAINT provider_callback_owners_owner_kind_check CHECK ((owner_kind = ANY (ARRAY['login'::text, 'identity_mutation'::text, 'managed_reauthorization'::text])))
);


--
-- Name: provider_configurations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.provider_configurations (
    id uuid NOT NULL,
    project_id uuid NOT NULL,
    provider_key text NOT NULL,
    kind text NOT NULL,
    display_name text NOT NULL,
    issuer text NOT NULL,
    client_id text NOT NULL,
    callback_url text NOT NULL,
    status text NOT NULL,
    revision bigint NOT NULL,
    created_at timestamp with time zone DEFAULT transaction_timestamp() NOT NULL,
    updated_at timestamp with time zone DEFAULT transaction_timestamp() NOT NULL,
    managed_profile_enabled boolean DEFAULT false NOT NULL,
    managed_profile_revision bigint DEFAULT 1 NOT NULL,
    secret_material_id uuid NOT NULL,
    secret_generation bigint DEFAULT 1 NOT NULL,
    onboarding_policy_revision bigint,
    CONSTRAINT provider_configurations_callback_url_check CHECK (((char_length(callback_url) >= 8) AND (char_length(callback_url) <= 2048))),
    CONSTRAINT provider_configurations_client_id_check CHECK (((char_length(client_id) >= 1) AND (char_length(client_id) <= 512))),
    CONSTRAINT provider_configurations_display_name_check CHECK (((char_length(display_name) >= 1) AND (char_length(display_name) <= 128))),
    CONSTRAINT provider_configurations_issuer_check CHECK (((char_length(issuer) >= 8) AND (char_length(issuer) <= 2048))),
    CONSTRAINT provider_configurations_kind_check CHECK ((kind = ANY (ARRAY['oidc'::text, 'google'::text, 'github'::text]))),
    CONSTRAINT provider_configurations_kind_issuer_check CHECK ((((kind = 'oidc'::text) AND (issuer <> ALL (ARRAY['https://accounts.google.com'::text, 'https://github.com'::text]))) OR ((kind = 'google'::text) AND (issuer = 'https://accounts.google.com'::text)) OR ((kind = 'github'::text) AND (issuer = 'https://github.com'::text) AND (NOT managed_profile_enabled)))),
    CONSTRAINT provider_configurations_managed_profile_revision_check CHECK ((managed_profile_revision > 0)),
    CONSTRAINT provider_configurations_onboarding_policy_revision_check CHECK (((onboarding_policy_revision IS NULL) OR (onboarding_policy_revision > 0))),
    CONSTRAINT provider_configurations_provider_key_check CHECK (((char_length(provider_key) >= 1) AND (char_length(provider_key) <= 64))),
    CONSTRAINT provider_configurations_provider_key_check1 CHECK ((provider_key ~ '^[a-z][a-z0-9_-]*$'::text)),
    CONSTRAINT provider_configurations_revision_check CHECK ((revision > 0)),
    CONSTRAINT provider_configurations_secret_generation_check CHECK ((secret_generation > 0)),
    CONSTRAINT provider_configurations_status_check CHECK ((status = ANY (ARRAY['provisioning'::text, 'active'::text, 'disabled'::text])))
);


--
-- Name: provider_secret_operations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.provider_secret_operations (
    id uuid NOT NULL,
    project_id uuid NOT NULL,
    provider_id uuid NOT NULL,
    operation_alias text NOT NULL,
    request_digest bytea NOT NULL,
    state text NOT NULL,
    attempt_count integer DEFAULT 0 NOT NULL,
    expected_project_revision bigint NOT NULL,
    expected_provider_revision bigint NOT NULL,
    last_attempt_at timestamp with time zone,
    completed_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT transaction_timestamp() NOT NULL,
    updated_at timestamp with time zone DEFAULT transaction_timestamp() NOT NULL,
    material_id uuid NOT NULL,
    egress_policy_revision bigint,
    CONSTRAINT provider_secret_operations_attempt_count_check CHECK ((attempt_count >= 0)),
    CONSTRAINT provider_secret_operations_check CHECK ((((state = 'completed'::text) AND (completed_at IS NOT NULL)) OR (state <> 'completed'::text))),
    CONSTRAINT provider_secret_operations_egress_policy_revision_check CHECK (((egress_policy_revision IS NULL) OR (egress_policy_revision > 0))),
    CONSTRAINT provider_secret_operations_expected_project_revision_check CHECK ((expected_project_revision > 0)),
    CONSTRAINT provider_secret_operations_expected_provider_revision_check CHECK ((expected_provider_revision > 0)),
    CONSTRAINT provider_secret_operations_operation_alias_check CHECK (((char_length(operation_alias) >= 8) AND (char_length(operation_alias) <= 128))),
    CONSTRAINT provider_secret_operations_request_digest_check CHECK ((octet_length(request_digest) = 32)),
    CONSTRAINT provider_secret_operations_state_check CHECK ((state = ANY (ARRAY['prepared'::text, 'stored'::text, 'completed'::text, 'failed'::text, 'abandoned'::text])))
);


--
-- Name: refresh_families; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.refresh_families (
    id uuid NOT NULL,
    project_id uuid NOT NULL,
    application_id uuid NOT NULL,
    user_id uuid NOT NULL,
    application_session_id uuid NOT NULL,
    status text NOT NULL,
    family_revision bigint DEFAULT 1 NOT NULL,
    current_generation bigint DEFAULT 1 NOT NULL,
    allowed_clock_skew_seconds integer NOT NULL,
    absolute_expires_at timestamp with time zone NOT NULL,
    revoked_at timestamp with time zone,
    revocation_reason text,
    created_at timestamp with time zone DEFAULT transaction_timestamp() NOT NULL,
    updated_at timestamp with time zone DEFAULT transaction_timestamp() NOT NULL,
    CONSTRAINT refresh_families_allowed_clock_skew_seconds_check CHECK (((allowed_clock_skew_seconds >= 0) AND (allowed_clock_skew_seconds <= 300))),
    CONSTRAINT refresh_families_check CHECK ((absolute_expires_at = (created_at + '30 days'::interval))),
    CONSTRAINT refresh_families_check1 CHECK ((((status = 'revoked'::text) AND (revoked_at IS NOT NULL) AND (revocation_reason IS NOT NULL)) OR ((status <> 'revoked'::text) AND (revoked_at IS NULL) AND (revocation_reason IS NULL)))),
    CONSTRAINT refresh_families_current_generation_check CHECK ((current_generation > 0)),
    CONSTRAINT refresh_families_family_revision_check CHECK ((family_revision > 0)),
    CONSTRAINT refresh_families_revocation_reason_check CHECK ((revocation_reason = ANY (ARRAY['logout'::text, 'replay'::text, 'control'::text, 'owner_invalidated'::text]))),
    CONSTRAINT refresh_families_status_check CHECK ((status = ANY (ARRAY['active'::text, 'revoked'::text, 'expired'::text])))
);


--
-- Name: refresh_token_generations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.refresh_token_generations (
    id uuid NOT NULL,
    project_id uuid NOT NULL,
    family_id uuid NOT NULL,
    application_id uuid NOT NULL,
    user_id uuid NOT NULL,
    generation bigint NOT NULL,
    token_digest bytea NOT NULL,
    token_digest_key_version integer NOT NULL,
    status text NOT NULL,
    consumed_at timestamp with time zone,
    replay_detected_at timestamp with time zone,
    retain_until timestamp with time zone NOT NULL,
    created_at timestamp with time zone DEFAULT transaction_timestamp() NOT NULL,
    CONSTRAINT refresh_token_generations_check CHECK ((retain_until > created_at)),
    CONSTRAINT refresh_token_generations_check1 CHECK (((status = 'consumed'::text) = (consumed_at IS NOT NULL))),
    CONSTRAINT refresh_token_generations_check2 CHECK (((replay_detected_at IS NULL) OR (consumed_at IS NOT NULL))),
    CONSTRAINT refresh_token_generations_generation_check CHECK ((generation > 0)),
    CONSTRAINT refresh_token_generations_status_check CHECK ((status = ANY (ARRAY['current'::text, 'consumed'::text]))),
    CONSTRAINT refresh_token_generations_token_digest_check CHECK ((octet_length(token_digest) = 32)),
    CONSTRAINT refresh_token_generations_token_digest_key_version_check CHECK ((token_digest_key_version > 0))
);


--
-- Name: runtime_process_incarnations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.runtime_process_incarnations (
    process_id text NOT NULL,
    process_incarnation uuid NOT NULL,
    started_at timestamp with time zone NOT NULL,
    CONSTRAINT runtime_process_incarnations_process_id_check CHECK ((process_id ~ '^[a-zA-Z0-9._:-]{1,128}$'::text))
);


--
-- Name: runtime_publication_leases; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.runtime_publication_leases (
    project_id uuid NOT NULL,
    ring_id uuid NOT NULL,
    process_id text NOT NULL,
    loaded_revision bigint NOT NULL,
    first_observed_at timestamp with time zone NOT NULL,
    last_observed_at timestamp with time zone NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    process_incarnation uuid NOT NULL,
    CONSTRAINT runtime_publication_leases_check CHECK ((last_observed_at >= first_observed_at)),
    CONSTRAINT runtime_publication_leases_check1 CHECK ((expires_at > last_observed_at)),
    CONSTRAINT runtime_publication_leases_loaded_revision_check CHECK ((loaded_revision > 0)),
    CONSTRAINT runtime_publication_leases_process_id_check CHECK (((char_length(process_id) >= 1) AND (char_length(process_id) <= 128)))
);


--
-- Name: smtp_credential_cleanup_operations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.smtp_credential_cleanup_operations (
    id uuid NOT NULL,
    scope text NOT NULL,
    project_id uuid,
    generation integer NOT NULL,
    state text NOT NULL,
    lease_owner text,
    lease_expires_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT transaction_timestamp() NOT NULL,
    erased_at timestamp with time zone,
    material_id uuid NOT NULL,
    CONSTRAINT smtp_credential_cleanup_operations_check CHECK (((scope = 'project'::text) = (project_id IS NOT NULL))),
    CONSTRAINT smtp_credential_cleanup_operations_check1 CHECK (((state = 'leased'::text) = ((lease_owner IS NOT NULL) AND (lease_expires_at IS NOT NULL)))),
    CONSTRAINT smtp_credential_cleanup_operations_check2 CHECK (((state = 'erased'::text) = (erased_at IS NOT NULL))),
    CONSTRAINT smtp_credential_cleanup_operations_generation_check CHECK ((generation > 0)),
    CONSTRAINT smtp_credential_cleanup_operations_scope_check CHECK ((scope = ANY (ARRAY['project'::text, 'deployment_default'::text]))),
    CONSTRAINT smtp_credential_cleanup_operations_state_check CHECK ((state = ANY (ARRAY['pending'::text, 'leased'::text, 'erased'::text])))
);


--
-- Name: webhook_application_dispatch_state; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.webhook_application_dispatch_state (
    project_id uuid NOT NULL,
    application_id uuid NOT NULL,
    last_claim_sequence bigint DEFAULT 0 NOT NULL,
    CONSTRAINT webhook_application_dispatch_state_last_claim_sequence_check CHECK ((last_claim_sequence >= 0))
);


--
-- Name: webhook_deliveries; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.webhook_deliveries (
    id uuid NOT NULL,
    project_id uuid NOT NULL,
    application_id uuid NOT NULL,
    endpoint_id uuid NOT NULL,
    event_id uuid NOT NULL,
    replay_sequence integer DEFAULT 0 NOT NULL,
    replay_of_delivery_id uuid,
    state text NOT NULL,
    attempt_count integer DEFAULT 0 NOT NULL,
    next_attempt_at timestamp with time zone NOT NULL,
    lease_owner text,
    lease_incarnation uuid,
    lease_generation bigint DEFAULT 0 NOT NULL,
    lease_expires_at timestamp with time zone,
    claimed_secret_generation integer,
    claimed_overlap_generation integer,
    last_outcome_class text,
    last_http_status integer,
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    delivered_at timestamp with time zone,
    terminal_at timestamp with time zone,
    claimed_secret_material_id uuid,
    claimed_overlap_material_id uuid,
    CONSTRAINT webhook_deliveries_attempt_count_check CHECK ((attempt_count >= 0)),
    CONSTRAINT webhook_deliveries_last_http_status_check CHECK (((last_http_status >= 100) AND (last_http_status <= 599))),
    CONSTRAINT webhook_deliveries_lease_generation_check CHECK ((lease_generation >= 0)),
    CONSTRAINT webhook_deliveries_replay_sequence_check CHECK ((replay_sequence >= 0)),
    CONSTRAINT webhook_deliveries_state_check CHECK ((state = ANY (ARRAY['pending'::text, 'leased'::text, 'delivered'::text, 'terminal'::text, 'cancelled'::text]))),
    CONSTRAINT webhook_delivery_lease_check CHECK ((((state = 'leased'::text) AND (lease_owner IS NOT NULL) AND (lease_incarnation IS NOT NULL) AND (lease_expires_at IS NOT NULL) AND (claimed_secret_generation IS NOT NULL) AND (claimed_secret_material_id IS NOT NULL) AND (((claimed_overlap_generation IS NULL) AND (claimed_overlap_material_id IS NULL)) OR ((claimed_overlap_generation IS NOT NULL) AND (claimed_overlap_material_id IS NOT NULL)))) OR ((state <> 'leased'::text) AND (lease_owner IS NULL) AND (lease_incarnation IS NULL) AND (lease_expires_at IS NULL) AND (claimed_secret_generation IS NULL) AND (claimed_secret_material_id IS NULL) AND (claimed_overlap_generation IS NULL) AND (claimed_overlap_material_id IS NULL)))),
    CONSTRAINT webhook_delivery_replay_check CHECK ((((replay_sequence = 0) AND (replay_of_delivery_id IS NULL)) OR ((replay_sequence > 0) AND (replay_of_delivery_id IS NOT NULL)))),
    CONSTRAINT webhook_delivery_terminal_check CHECK ((((state = 'delivered'::text) AND (delivered_at IS NOT NULL) AND (terminal_at IS NULL)) OR ((state = ANY (ARRAY['terminal'::text, 'cancelled'::text])) AND (terminal_at IS NOT NULL) AND (delivered_at IS NULL)) OR ((state = ANY (ARRAY['pending'::text, 'leased'::text])) AND (delivered_at IS NULL) AND (terminal_at IS NULL))))
);


--
-- Name: TABLE webhook_deliveries; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.webhook_deliveries IS 'At-least-once per-endpoint delivery state. Replay creates a new row referencing an existing immutable event and original delivery.';


--
-- Name: webhook_delivery_attempts; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.webhook_delivery_attempts (
    delivery_id uuid NOT NULL,
    attempt_number integer NOT NULL,
    lease_generation bigint NOT NULL,
    attempted_at timestamp with time zone NOT NULL,
    attempt_timestamp bigint NOT NULL,
    outcome_class text NOT NULL,
    http_status integer,
    duration_millis integer NOT NULL,
    correlation_id uuid NOT NULL,
    CONSTRAINT webhook_delivery_attempts_attempt_number_check CHECK ((attempt_number > 0)),
    CONSTRAINT webhook_delivery_attempts_attempt_timestamp_check CHECK ((attempt_timestamp > 0)),
    CONSTRAINT webhook_delivery_attempts_duration_millis_check CHECK ((duration_millis >= 0)),
    CONSTRAINT webhook_delivery_attempts_http_status_check CHECK (((http_status >= 100) AND (http_status <= 599))),
    CONSTRAINT webhook_delivery_attempts_lease_generation_check CHECK ((lease_generation > 0))
);


--
-- Name: TABLE webhook_delivery_attempts; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.webhook_delivery_attempts IS 'Append-only safe attempt metadata; response bodies and credentials are never retained.';


--
-- Name: webhook_dispatch_claim_sequence; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.webhook_dispatch_claim_sequence
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: webhook_endpoints; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.webhook_endpoints (
    id uuid NOT NULL,
    project_id uuid NOT NULL,
    application_id uuid NOT NULL,
    public_id text NOT NULL,
    idempotency_key text NOT NULL,
    secret_request_fingerprint bytea NOT NULL,
    url text NOT NULL,
    subscribed_event_types text[] NOT NULL,
    status text NOT NULL,
    revision bigint NOT NULL,
    current_secret_generation integer,
    overlap_secret_generation integer,
    overlap_expires_at timestamp with time zone,
    consecutive_failure_count integer DEFAULT 0 NOT NULL,
    last_delivery_at timestamp with time zone,
    last_success_at timestamp with time zone,
    last_failure_class text,
    last_tested_at timestamp with time zone,
    last_test_succeeded_at timestamp with time zone,
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    disabled_at timestamp with time zone,
    CONSTRAINT webhook_endpoint_activation_test_check CHECK (((status <> 'active'::text) OR (last_test_succeeded_at IS NOT NULL))),
    CONSTRAINT webhook_endpoint_disabled_check CHECK ((((status = 'disabled'::text) AND (disabled_at IS NOT NULL)) OR ((status <> 'disabled'::text) AND (disabled_at IS NULL)))),
    CONSTRAINT webhook_endpoint_overlap_check CHECK ((((overlap_secret_generation IS NULL) AND (overlap_expires_at IS NULL)) OR ((overlap_secret_generation IS NOT NULL) AND (overlap_expires_at IS NOT NULL) AND (overlap_secret_generation <> current_secret_generation)))),
    CONSTRAINT webhook_endpoint_secret_state_check CHECK ((((status = 'pending'::text) AND (current_secret_generation IS NULL)) OR ((status = 'active'::text) AND (current_secret_generation IS NOT NULL)) OR (status = 'disabled'::text))),
    CONSTRAINT webhook_endpoint_subscriptions_check CHECK ((((cardinality(subscribed_event_types) >= 1) AND (cardinality(subscribed_event_types) <= 3)) AND (subscribed_event_types <@ ARRAY['user.projection.created'::text, 'user.projection.updated'::text, 'user.projection.disabled'::text]))),
    CONSTRAINT webhook_endpoint_test_check CHECK ((((last_test_succeeded_at IS NULL) AND (last_tested_at IS NULL)) OR ((last_test_succeeded_at IS NOT NULL) AND (last_tested_at IS NOT NULL) AND (last_test_succeeded_at = last_tested_at)))),
    CONSTRAINT webhook_endpoints_consecutive_failure_count_check CHECK ((consecutive_failure_count >= 0)),
    CONSTRAINT webhook_endpoints_current_secret_generation_check CHECK ((current_secret_generation > 0)),
    CONSTRAINT webhook_endpoints_overlap_secret_generation_check CHECK ((overlap_secret_generation > 0)),
    CONSTRAINT webhook_endpoints_revision_check CHECK ((revision > 0)),
    CONSTRAINT webhook_endpoints_secret_request_fingerprint_check CHECK ((octet_length(secret_request_fingerprint) = 32)),
    CONSTRAINT webhook_endpoints_status_check CHECK ((status = ANY (ARRAY['pending'::text, 'active'::text, 'disabled'::text])))
);


--
-- Name: webhook_secret_cleanup_operations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.webhook_secret_cleanup_operations (
    id uuid NOT NULL,
    endpoint_id uuid NOT NULL,
    generation integer NOT NULL,
    state text NOT NULL,
    lease_owner text,
    lease_incarnation uuid,
    lease_generation bigint DEFAULT 0 NOT NULL,
    lease_expires_at timestamp with time zone,
    not_before timestamp with time zone DEFAULT transaction_timestamp() NOT NULL,
    created_at timestamp with time zone DEFAULT transaction_timestamp() NOT NULL,
    updated_at timestamp with time zone DEFAULT transaction_timestamp() NOT NULL,
    erased_at timestamp with time zone,
    material_id uuid NOT NULL,
    CONSTRAINT webhook_secret_cleanup_erased_check CHECK (((state = 'erased'::text) = (erased_at IS NOT NULL))),
    CONSTRAINT webhook_secret_cleanup_lease_check CHECK ((((state = 'leased'::text) AND (lease_owner IS NOT NULL) AND (lease_incarnation IS NOT NULL) AND (lease_expires_at IS NOT NULL)) OR ((state <> 'leased'::text) AND (lease_owner IS NULL) AND (lease_incarnation IS NULL) AND (lease_expires_at IS NULL)))),
    CONSTRAINT webhook_secret_cleanup_operations_generation_check CHECK ((generation > 0)),
    CONSTRAINT webhook_secret_cleanup_operations_lease_generation_check CHECK ((lease_generation >= 0)),
    CONSTRAINT webhook_secret_cleanup_operations_state_check CHECK ((state = ANY (ARRAY['pending'::text, 'leased'::text, 'erased'::text])))
);


--
-- Name: TABLE webhook_secret_cleanup_operations; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.webhook_secret_cleanup_operations IS 'Restart-safe Runtime authority for permanent webhook secret alias erasure.';


--
-- Name: webhook_secret_generations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.webhook_secret_generations (
    endpoint_id uuid NOT NULL,
    generation integer NOT NULL,
    idempotency_key text NOT NULL,
    request_fingerprint bytea NOT NULL,
    safe_fingerprint text,
    state text NOT NULL,
    created_at timestamp with time zone NOT NULL,
    provisioned_at timestamp with time zone,
    activated_at timestamp with time zone,
    retired_at timestamp with time zone,
    material_id uuid NOT NULL,
    CONSTRAINT webhook_secret_activation_check CHECK ((((state = 'pending'::text) AND (activated_at IS NULL) AND (retired_at IS NULL)) OR ((state = ANY (ARRAY['active'::text, 'overlap'::text])) AND (activated_at IS NOT NULL) AND (retired_at IS NULL)) OR ((state = ANY (ARRAY['retired'::text, 'compromised'::text])) AND (retired_at IS NOT NULL)))),
    CONSTRAINT webhook_secret_generations_generation_check CHECK ((generation > 0)),
    CONSTRAINT webhook_secret_generations_request_fingerprint_check CHECK ((octet_length(request_fingerprint) = 32)),
    CONSTRAINT webhook_secret_generations_state_check CHECK ((state = ANY (ARRAY['pending'::text, 'active'::text, 'overlap'::text, 'retired'::text, 'compromised'::text]))),
    CONSTRAINT webhook_secret_provisioning_check CHECK (((state = ANY (ARRAY['pending'::text, 'retired'::text])) OR (provisioned_at IS NOT NULL)))
);


--
-- Name: email_identity_alias_authority_events id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.email_identity_alias_authority_events ALTER COLUMN id SET DEFAULT nextval('public.email_identity_alias_authority_events_id_seq'::regclass);

-- Restore the default path before SQLx records this migration in public._sqlx_migrations.
SELECT pg_catalog.set_config('search_path', '"$user", public', false);
