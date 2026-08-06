-- Add provider-secret preparation authority in its own bounded expansion transaction.

ALTER TABLE provider_secret_operations
    ADD COLUMN egress_policy_revision BIGINT,
    ADD CONSTRAINT provider_secret_operations_egress_policy_revision_check CHECK (
        egress_policy_revision IS NULL OR egress_policy_revision > 0
    ) NOT VALID;
