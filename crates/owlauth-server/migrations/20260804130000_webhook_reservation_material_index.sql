-- Build the reservation material identity index in an isolated transactional step.

CREATE UNIQUE INDEX webhook_secret_reservation_material_uq
    ON webhook_secret_reference_reservations (material_id)
    WHERE material_id IS NOT NULL;
