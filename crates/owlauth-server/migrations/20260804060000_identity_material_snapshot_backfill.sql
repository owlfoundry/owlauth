-- Backfill exact provider material snapshots without rewriting rows whose target is already equal.

UPDATE identity_mutation_proof_slots AS slot
SET provider_secret_material_id = provider.secret_material_id
FROM provider_configurations AS provider
WHERE slot.project_id = provider.project_id
  AND slot.provider_configuration_id = provider.id
  AND slot.method_kind = 'provider'
  AND slot.provider_secret_material_id IS DISTINCT FROM provider.secret_material_id;
