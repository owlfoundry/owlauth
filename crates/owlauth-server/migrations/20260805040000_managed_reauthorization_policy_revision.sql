-- Add managed-reauthorization provider authority in its own bounded expansion transaction.

ALTER TABLE managed_provider_reauthorization_interactions
    ADD COLUMN provider_egress_policy_revision BIGINT,
    ADD CONSTRAINT managed_provider_reauthorization_provider_egress_policy_revision_check CHECK (
        provider_egress_policy_revision IS NULL OR provider_egress_policy_revision > 0
    ) NOT VALID;
