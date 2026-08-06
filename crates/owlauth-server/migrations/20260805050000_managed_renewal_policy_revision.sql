-- Add managed-renewal provider authority in its own bounded expansion transaction.

ALTER TABLE managed_provider_renewal_operations
    ADD COLUMN provider_egress_policy_revision BIGINT,
    ADD CONSTRAINT managed_provider_renewal_provider_egress_policy_revision_check CHECK (
        provider_egress_policy_revision IS NULL OR provider_egress_policy_revision > 0
    ) NOT VALID;
