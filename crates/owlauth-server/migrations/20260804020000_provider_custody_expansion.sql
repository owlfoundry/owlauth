-- Expand provider credential snapshots without combining metadata locks with backfills or
-- populated-table validation.

ALTER TABLE provider_configurations
    ADD COLUMN secret_material_id UUID,
    ADD COLUMN secret_generation BIGINT NOT NULL DEFAULT 1,
    ADD CONSTRAINT provider_configurations_secret_material_id_fkey
        FOREIGN KEY (secret_material_id) REFERENCES protected_materials (id)
        DEFERRABLE INITIALLY DEFERRED NOT VALID,
    ADD CONSTRAINT provider_configurations_secret_generation_check
        CHECK (secret_generation > 0) NOT VALID,
    ADD CONSTRAINT provider_configuration_secret_authority_check CHECK (
        (status = 'provisioning' AND secret_ref IS NULL AND secret_material_id IS NULL)
        OR (
            status <> 'provisioning'
            AND num_nonnulls(secret_ref, secret_material_id) = 1
        )
    ) NOT VALID,
    DROP CONSTRAINT provider_configurations_check;

ALTER TABLE provider_secret_operations
    ADD COLUMN material_id UUID,
    ADD CONSTRAINT provider_secret_operations_material_id_fkey
        FOREIGN KEY (material_id) REFERENCES protected_materials (id)
        DEFERRABLE INITIALLY DEFERRED NOT VALID;

-- Long-lived Runtime interactions snapshot the exact protected provider generation. They must not
-- resolve through the provider's current row after a later rotation.
ALTER TABLE identity_mutation_proof_slots
    ADD COLUMN provider_secret_material_id UUID,
    ADD CONSTRAINT identity_mutation_proof_slots_provider_secret_material_id_fkey
        FOREIGN KEY (provider_secret_material_id) REFERENCES protected_materials (id)
        DEFERRABLE INITIALLY DEFERRED NOT VALID;

ALTER TABLE managed_provider_reauthorization_interactions
    ADD COLUMN secret_material_id UUID,
    ALTER COLUMN secret_ref DROP NOT NULL,
    ADD CONSTRAINT managed_provider_reauthorization_interactions_secret_material_id_fkey
        FOREIGN KEY (secret_material_id) REFERENCES protected_materials (id)
        DEFERRABLE INITIALLY DEFERRED NOT VALID,
    ADD CONSTRAINT managed_reauthorization_secret_snapshot_check CHECK (
        num_nonnulls(secret_ref, secret_material_id) = 1
    ) NOT VALID;
