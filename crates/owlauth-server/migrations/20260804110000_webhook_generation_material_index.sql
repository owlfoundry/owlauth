-- Build the material-aware webhook generation key in an isolated transactional step.

CREATE UNIQUE INDEX webhook_secret_generation_material_uq_index
    ON webhook_secret_generations (endpoint_id, generation, material_id)
    NULLS NOT DISTINCT;
