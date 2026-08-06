-- The validated helper check lets PostgreSQL install the physical NOT NULL attribute without a new
-- populated-table scan.

ALTER TABLE deployment_smtp_generations
    ALTER COLUMN material_owner_id SET NOT NULL,
    DROP CONSTRAINT deployment_smtp_material_owner_not_null_check;
