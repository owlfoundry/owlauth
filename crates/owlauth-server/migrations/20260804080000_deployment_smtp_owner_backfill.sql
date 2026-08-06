-- Backfill deterministic deployment SMTP owner identity before validating the final invariant.

UPDATE deployment_smtp_generations
SET material_owner_id = md5('owlauth-deployment-smtp-owner-v1:' || generation::TEXT)::UUID
WHERE material_owner_id IS NULL;
