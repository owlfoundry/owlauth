-- Add provider onboarding authority without validating a populated table under the metadata lock.

ALTER TABLE provider_configurations
    ADD COLUMN onboarding_policy_revision BIGINT,
    ADD CONSTRAINT provider_configurations_onboarding_policy_revision_check CHECK (
        onboarding_policy_revision IS NULL OR onboarding_policy_revision > 0
    ) NOT VALID;
