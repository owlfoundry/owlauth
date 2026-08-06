-- Expand SMTP credential and recipient custody. Nullable foreign keys are enforced for new writes
-- immediately and validated after bounded backfills.

ALTER TABLE project_smtp_configurations
    ALTER COLUMN safe_fingerprint DROP NOT NULL,
    ADD COLUMN credential_material_id UUID,
    ADD CONSTRAINT project_smtp_configurations_credential_material_id_fkey
        FOREIGN KEY (credential_material_id) REFERENCES protected_materials (id)
        DEFERRABLE INITIALLY DEFERRED NOT VALID;

ALTER TABLE project_smtp_secret_operations
    ADD COLUMN material_id UUID,
    ADD CONSTRAINT project_smtp_secret_operations_material_id_fkey
        FOREIGN KEY (material_id) REFERENCES protected_materials (id)
        DEFERRABLE INITIALLY DEFERRED NOT VALID;

ALTER TABLE project_smtp_test_operations
    ADD COLUMN credential_material_id UUID,
    ADD COLUMN recipient_material_id UUID,
    ADD CONSTRAINT project_smtp_test_operations_credential_material_id_fkey
        FOREIGN KEY (credential_material_id) REFERENCES protected_materials (id)
        DEFERRABLE INITIALLY DEFERRED NOT VALID,
    ADD CONSTRAINT project_smtp_test_operations_recipient_material_id_fkey
        FOREIGN KEY (recipient_material_id) REFERENCES protected_materials (id)
        DEFERRABLE INITIALLY DEFERRED NOT VALID;

ALTER TABLE deployment_smtp_generations
    ADD COLUMN material_owner_id UUID,
    ALTER COLUMN safe_fingerprint DROP NOT NULL,
    ADD COLUMN credential_material_id UUID,
    ADD CONSTRAINT deployment_smtp_generations_credential_material_id_fkey
        FOREIGN KEY (credential_material_id) REFERENCES protected_materials (id)
        DEFERRABLE INITIALLY DEFERRED NOT VALID,
    ADD CONSTRAINT deployment_smtp_material_owner_not_null_check
        CHECK (material_owner_id IS NOT NULL) NOT VALID;

CREATE TABLE deployment_smtp_secret_operations (
    id UUID PRIMARY KEY,
    idempotency_key TEXT NOT NULL UNIQUE
        CHECK (char_length(idempotency_key) BETWEEN 8 AND 128),
    generation INTEGER NOT NULL UNIQUE
        REFERENCES deployment_smtp_generations (generation) ON DELETE RESTRICT,
    material_id UUID NOT NULL UNIQUE
        REFERENCES protected_materials (id) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    request_digest BYTEA NOT NULL CHECK (octet_length(request_digest) = 32),
    secret_fingerprint BYTEA CHECK (
        secret_fingerprint IS NULL OR octet_length(secret_fingerprint) = 32
    ),
    state TEXT NOT NULL CHECK (state IN ('prepared', 'completed')),
    correlation_id UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    completed_at TIMESTAMPTZ,
    CHECK ((state = 'completed') = (completed_at IS NOT NULL)),
    CHECK ((state = 'completed') = (secret_fingerprint IS NOT NULL))
);

ALTER TABLE smtp_credential_cleanup_operations
    ADD COLUMN material_id UUID,
    ADD CONSTRAINT smtp_credential_cleanup_operations_material_id_fkey
        FOREIGN KEY (material_id) REFERENCES protected_materials (id)
        DEFERRABLE INITIALLY DEFERRED NOT VALID;

ALTER TABLE smtp_credential_reference_reservations
    ADD COLUMN material_id UUID,
    ADD CONSTRAINT smtp_credential_reference_reservations_material_id_fkey
        FOREIGN KEY (material_id) REFERENCES protected_materials (id)
        DEFERRABLE INITIALLY DEFERRED NOT VALID;

ALTER TABLE smtp_test_recipient_reference_reservations
    ADD COLUMN material_id UUID,
    ADD CONSTRAINT smtp_test_recipient_reference_reservations_material_id_fkey
        FOREIGN KEY (material_id) REFERENCES protected_materials (id)
        DEFERRABLE INITIALLY DEFERRED NOT VALID;
