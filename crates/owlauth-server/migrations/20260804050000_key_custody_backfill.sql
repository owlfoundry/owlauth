-- Backfill terminal timing independently from table expansion and index construction.

UPDATE key_provisioning_operations
SET abandoned_at = COALESCE(last_attempt_at, created_at)
WHERE state = 'abandoned'
  AND abandoned_at IS NULL;
