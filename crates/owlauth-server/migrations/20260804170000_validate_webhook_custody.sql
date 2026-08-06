-- Validate webhook material references and the replacement lease invariant after unique-key
-- attachment, without repeating index construction.

ALTER TABLE webhook_secret_generations
    VALIDATE CONSTRAINT webhook_secret_generations_material_id_fkey;
ALTER TABLE webhook_deliveries
    VALIDATE CONSTRAINT webhook_deliveries_claimed_secret_material_id_fkey;
ALTER TABLE webhook_deliveries
    VALIDATE CONSTRAINT webhook_deliveries_claimed_overlap_material_id_fkey;
ALTER TABLE webhook_deliveries
    VALIDATE CONSTRAINT webhook_delivery_claimed_secret_material_fk;
ALTER TABLE webhook_deliveries
    VALIDATE CONSTRAINT webhook_delivery_claimed_overlap_material_fk;
ALTER TABLE webhook_deliveries
    VALIDATE CONSTRAINT webhook_delivery_lease_check;
ALTER TABLE webhook_secret_cleanup_operations
    VALIDATE CONSTRAINT webhook_secret_cleanup_operations_material_id_fkey;
ALTER TABLE webhook_secret_cleanup_operations
    VALIDATE CONSTRAINT webhook_secret_cleanup_material_generation_fk;
ALTER TABLE webhook_secret_reference_reservations
    VALIDATE CONSTRAINT webhook_secret_reference_reservations_material_id_fkey;
