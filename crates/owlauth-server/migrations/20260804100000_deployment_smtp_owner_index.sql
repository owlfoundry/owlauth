-- Build the deployment-owner unique index in an isolated transactional step.

CREATE UNIQUE INDEX deployment_smtp_material_owner_uq_index
    ON deployment_smtp_generations (material_owner_id);
