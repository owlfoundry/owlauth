-- Keep each populated-table index build in its own transactional, statement-timeout-bounded step.

CREATE INDEX key_provisioning_provider_recovery_idx
    ON key_provisioning_operations (state, next_attempt_at, provider_lease_expires_at, id)
    WHERE state IN ('submitted', 'cleanup_pending', 'cleanup_leased');
