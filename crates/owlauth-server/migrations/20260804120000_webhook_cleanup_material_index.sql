-- Build the cleanup material identity index in an isolated transactional step.

CREATE UNIQUE INDEX webhook_secret_cleanup_material_uq
    ON webhook_secret_cleanup_operations (material_id)
    WHERE material_id IS NOT NULL;
