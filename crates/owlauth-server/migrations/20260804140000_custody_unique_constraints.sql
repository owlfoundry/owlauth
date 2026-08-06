-- Attach already-built unique indexes with brief metadata locks, then add composite webhook
-- generation/material references as NOT VALID constraints for later online validation.

ALTER TABLE deployment_smtp_generations
    ADD CONSTRAINT deployment_smtp_material_owner_uq
        UNIQUE USING INDEX deployment_smtp_material_owner_uq_index;

ALTER TABLE webhook_secret_generations
    ADD CONSTRAINT webhook_secret_generation_material_uq
        UNIQUE USING INDEX webhook_secret_generation_material_uq_index;

ALTER TABLE webhook_deliveries
    ADD CONSTRAINT webhook_delivery_claimed_secret_material_fk
        FOREIGN KEY (endpoint_id, claimed_secret_generation, claimed_secret_material_id)
        REFERENCES webhook_secret_generations (endpoint_id, generation, material_id)
        DEFERRABLE INITIALLY DEFERRED NOT VALID,
    ADD CONSTRAINT webhook_delivery_claimed_overlap_material_fk
        FOREIGN KEY (endpoint_id, claimed_overlap_generation, claimed_overlap_material_id)
        REFERENCES webhook_secret_generations (endpoint_id, generation, material_id)
        DEFERRABLE INITIALLY DEFERRED NOT VALID;

ALTER TABLE webhook_secret_cleanup_operations
    ADD CONSTRAINT webhook_secret_cleanup_material_generation_fk
        FOREIGN KEY (endpoint_id, generation, material_id)
        REFERENCES webhook_secret_generations (endpoint_id, generation, material_id)
        DEFERRABLE INITIALLY DEFERRED NOT VALID;
