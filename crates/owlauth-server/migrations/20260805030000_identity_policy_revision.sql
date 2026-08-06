-- Add identity-mutation provider authority in its own bounded expansion transaction.

ALTER TABLE identity_mutation_proof_slots
    ADD COLUMN provider_egress_policy_revision BIGINT,
    ADD CONSTRAINT identity_mutation_proof_slots_provider_egress_policy_revision_check CHECK (
        provider_egress_policy_revision IS NULL OR provider_egress_policy_revision > 0
    ) NOT VALID;
