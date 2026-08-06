-- Expand signing-key custody and recovery state without validating populated-table constraints while
-- holding the metadata lock. NOT VALID constraints protect every new write and are validated later.

ALTER TABLE project_signing_keys
    ADD COLUMN signer_material_id UUID,
    ADD COLUMN signer_material_generation BIGINT NOT NULL DEFAULT 1,
    ADD CONSTRAINT project_signing_keys_signer_material_id_fkey
        FOREIGN KEY (signer_material_id) REFERENCES protected_materials (id)
        DEFERRABLE INITIALLY DEFERRED NOT VALID,
    ADD CONSTRAINT project_signing_keys_signer_material_generation_check
        CHECK (signer_material_generation > 0) NOT VALID;

ALTER TABLE key_provisioning_operations
    ADD COLUMN material_id UUID,
    ADD COLUMN provider_lease_token UUID,
    ADD COLUMN provider_lease_expires_at TIMESTAMPTZ,
    ADD COLUMN provider_lease_generation BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN destroy_attempt_count INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN next_attempt_at TIMESTAMPTZ,
    ADD COLUMN last_provider_error_class TEXT,
    ADD COLUMN last_retry_classification TEXT,
    ADD COLUMN last_provider_error_code TEXT,
    ADD COLUMN abandoned_at TIMESTAMPTZ,
    ADD COLUMN destroyed_at TIMESTAMPTZ,
    ADD CONSTRAINT key_provisioning_operations_material_id_fkey
        FOREIGN KEY (material_id) REFERENCES protected_materials (id)
        DEFERRABLE INITIALLY DEFERRED NOT VALID,
    ADD CONSTRAINT key_provisioning_operations_provider_lease_generation_check
        CHECK (provider_lease_generation >= 0) NOT VALID,
    ADD CONSTRAINT key_provisioning_operations_destroy_attempt_count_check
        CHECK (destroy_attempt_count >= 0) NOT VALID,
    ADD CONSTRAINT key_provisioning_operations_last_provider_error_class_check
        CHECK (
            last_provider_error_class IS NULL OR last_provider_error_class IN (
                'invalid_request', 'unsupported_algorithm', 'not_found', 'conflict',
                'permission_denied', 'unavailable', 'integrity'
            )
        ) NOT VALID,
    ADD CONSTRAINT key_provisioning_operations_last_retry_classification_check
        CHECK (
            last_retry_classification IS NULL OR last_retry_classification IN (
                'never', 'exact_input_safe', 'reconcile'
            )
        ) NOT VALID,
    ADD CONSTRAINT key_provisioning_operations_last_provider_error_code_check
        CHECK (
            last_provider_error_code IS NULL OR (
                char_length(last_provider_error_code) BETWEEN 1 AND 64
                AND last_provider_error_code ~ '^[a-z0-9._-]+$'
            )
        ) NOT VALID,
    ADD CONSTRAINT key_provisioning_operations_state_check_v2 CHECK (state IN (
        'prepared', 'submitted', 'stored', 'completed', 'cleanup_pending',
        'cleanup_leased', 'cleanup_blocked', 'failed', 'abandoned'
    )) NOT VALID,
    ADD CONSTRAINT key_provisioning_provider_lease_check CHECK (
        (state = 'cleanup_leased' AND provider_lease_token IS NOT NULL)
        OR state = 'submitted'
        OR (
            state NOT IN ('submitted', 'cleanup_leased')
            AND provider_lease_token IS NULL
            AND provider_lease_expires_at IS NULL
        )
    ) NOT VALID,
    ADD CONSTRAINT key_provisioning_provider_lease_pair_check CHECK (
        (provider_lease_token IS NULL) = (provider_lease_expires_at IS NULL)
    ) NOT VALID,
    ADD CONSTRAINT key_provisioning_terminal_time_check CHECK (
        (state = 'abandoned') = (abandoned_at IS NOT NULL)
        AND (destroyed_at IS NULL OR state = 'abandoned')
    ) NOT VALID,
    DROP CONSTRAINT key_provisioning_operations_state_check;

ALTER TABLE key_provisioning_operations
    RENAME CONSTRAINT key_provisioning_operations_state_check_v2
        TO key_provisioning_operations_state_check;
