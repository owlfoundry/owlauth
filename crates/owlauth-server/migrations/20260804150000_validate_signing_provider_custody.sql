-- Validate signing and provider custody constraints without retaining ACCESS EXCLUSIVE expansion
-- locks. NOT VALID already protected every write since expansion.

ALTER TABLE project_signing_keys
    VALIDATE CONSTRAINT project_signing_keys_signer_material_id_fkey;
ALTER TABLE project_signing_keys
    VALIDATE CONSTRAINT project_signing_keys_signer_material_generation_check;

ALTER TABLE key_provisioning_operations
    VALIDATE CONSTRAINT key_provisioning_operations_material_id_fkey;
ALTER TABLE key_provisioning_operations
    VALIDATE CONSTRAINT key_provisioning_operations_provider_lease_generation_check;
ALTER TABLE key_provisioning_operations
    VALIDATE CONSTRAINT key_provisioning_operations_destroy_attempt_count_check;
ALTER TABLE key_provisioning_operations
    VALIDATE CONSTRAINT key_provisioning_operations_last_provider_error_class_check;
ALTER TABLE key_provisioning_operations
    VALIDATE CONSTRAINT key_provisioning_operations_last_retry_classification_check;
ALTER TABLE key_provisioning_operations
    VALIDATE CONSTRAINT key_provisioning_operations_last_provider_error_code_check;
ALTER TABLE key_provisioning_operations
    VALIDATE CONSTRAINT key_provisioning_operations_state_check;
ALTER TABLE key_provisioning_operations
    VALIDATE CONSTRAINT key_provisioning_provider_lease_check;
ALTER TABLE key_provisioning_operations
    VALIDATE CONSTRAINT key_provisioning_provider_lease_pair_check;
ALTER TABLE key_provisioning_operations
    VALIDATE CONSTRAINT key_provisioning_terminal_time_check;

ALTER TABLE provider_configurations
    VALIDATE CONSTRAINT provider_configurations_secret_material_id_fkey;
ALTER TABLE provider_configurations
    VALIDATE CONSTRAINT provider_configurations_secret_generation_check;
ALTER TABLE provider_configurations
    VALIDATE CONSTRAINT provider_configuration_secret_authority_check;
ALTER TABLE provider_secret_operations
    VALIDATE CONSTRAINT provider_secret_operations_material_id_fkey;
ALTER TABLE identity_mutation_proof_slots
    VALIDATE CONSTRAINT identity_mutation_proof_slots_provider_secret_material_id_fkey;
ALTER TABLE managed_provider_reauthorization_interactions
    VALIDATE CONSTRAINT managed_provider_reauthorization_interactions_secret_material_id_fkey;
ALTER TABLE managed_provider_reauthorization_interactions
    VALIDATE CONSTRAINT managed_reauthorization_secret_snapshot_check;
