-- Backfill managed-reauthorization material snapshots independently from metadata locks.

UPDATE managed_provider_reauthorization_interactions AS interaction
SET secret_material_id = provider.secret_material_id
FROM provider_configurations AS provider
WHERE interaction.project_id = provider.project_id
  AND interaction.provider_configuration_id = provider.id
  AND provider.secret_material_id IS NOT NULL
  AND interaction.secret_material_id IS DISTINCT FROM provider.secret_material_id;
