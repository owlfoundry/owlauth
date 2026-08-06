-- Build the populated provider policy index in its own transactional, timeout-bounded step.

CREATE INDEX provider_configurations_custom_policy_idx
    ON provider_configurations (project_id, onboarding_policy_revision, id)
    WHERE adapter_kind = 'oidc';
