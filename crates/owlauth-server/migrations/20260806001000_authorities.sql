-- Required singleton authorities for the initial model.

INSERT INTO public.projection_email_key_authority (
    singleton, authority_revision, write_version, accepted_versions, updated_at
) VALUES (
    TRUE, 1, 1, ARRAY[1]::INTEGER[], transaction_timestamp()
);

INSERT INTO public.protected_material_inventory_authority (singleton, revision)
VALUES (TRUE, 1);
