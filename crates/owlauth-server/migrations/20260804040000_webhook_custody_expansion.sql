-- Expand webhook protected-material snapshots without combining metadata locks with index builds or
-- populated-table validation.

ALTER TABLE webhook_secret_generations
    ADD COLUMN material_id UUID,
    ALTER COLUMN safe_fingerprint DROP NOT NULL,
    ADD CONSTRAINT webhook_secret_generations_material_id_fkey
        FOREIGN KEY (material_id) REFERENCES protected_materials (id)
        DEFERRABLE INITIALLY DEFERRED NOT VALID;

ALTER TABLE webhook_deliveries
    ADD COLUMN claimed_secret_material_id UUID,
    ADD COLUMN claimed_overlap_material_id UUID,
    ADD CONSTRAINT webhook_deliveries_claimed_secret_material_id_fkey
        FOREIGN KEY (claimed_secret_material_id) REFERENCES protected_materials (id)
        DEFERRABLE INITIALLY DEFERRED NOT VALID,
    ADD CONSTRAINT webhook_deliveries_claimed_overlap_material_id_fkey
        FOREIGN KEY (claimed_overlap_material_id) REFERENCES protected_materials (id)
        DEFERRABLE INITIALLY DEFERRED NOT VALID,
    ADD CONSTRAINT webhook_delivery_lease_check_v2 CHECK (
        (
            state = 'leased'
            AND lease_owner IS NOT NULL
            AND lease_incarnation IS NOT NULL
            AND lease_expires_at IS NOT NULL
            AND claimed_secret_generation IS NOT NULL
            AND (claimed_secret_material_id IS NULL OR claimed_secret_generation IS NOT NULL)
            AND (claimed_overlap_material_id IS NULL OR claimed_overlap_generation IS NOT NULL)
        )
        OR (
            state <> 'leased'
            AND lease_owner IS NULL
            AND lease_incarnation IS NULL
            AND lease_expires_at IS NULL
            AND claimed_secret_generation IS NULL
            AND claimed_overlap_generation IS NULL
            AND claimed_secret_material_id IS NULL
            AND claimed_overlap_material_id IS NULL
        )
    ) NOT VALID,
    DROP CONSTRAINT webhook_delivery_lease_check;

ALTER TABLE webhook_deliveries
    RENAME CONSTRAINT webhook_delivery_lease_check_v2 TO webhook_delivery_lease_check;

ALTER TABLE webhook_secret_cleanup_operations
    ADD COLUMN material_id UUID,
    ADD CONSTRAINT webhook_secret_cleanup_operations_material_id_fkey
        FOREIGN KEY (material_id) REFERENCES protected_materials (id)
        DEFERRABLE INITIALLY DEFERRED NOT VALID;

ALTER TABLE webhook_secret_reference_reservations
    ADD COLUMN material_id UUID,
    ADD CONSTRAINT webhook_secret_reference_reservations_material_id_fkey
        FOREIGN KEY (material_id) REFERENCES protected_materials (id)
        DEFERRABLE INITIALLY DEFERRED NOT VALID;
