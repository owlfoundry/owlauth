-- Expand signing and configuration-secret custody into PostgreSQL protected material.
--
-- This migration is intentionally compatible with the pre-TS-003 source-deployment bridge binary:
-- existing legacy references remain readable/writable while custody mode is `legacy`. Operators must
-- drain every process that cannot honor the cutover authority before entering `importing`.

CREATE TABLE protected_materials (
    id UUID PRIMARY KEY,
    scope_kind TEXT NOT NULL CHECK (scope_kind IN ('deployment', 'project')),
    project_id UUID REFERENCES projects (id) ON DELETE RESTRICT,
    owner_kind TEXT NOT NULL CHECK (owner_kind IN (
        'signing_key',
        'provider_secret',
        'project_smtp',
        'deployment_smtp',
        'smtp_test_recipient',
        'webhook_secret'
    )),
    owner_id UUID NOT NULL,
    generation BIGINT NOT NULL CHECK (generation > 0),
    material_kind TEXT NOT NULL CHECK (material_kind IN ('signing_key', 'configuration_secret')),
    provider_id TEXT NOT NULL CHECK (
        char_length(provider_id) BETWEEN 1 AND 64
        AND provider_id ~ '^[a-z][a-z0-9_-]*$'
    ),
    provider_format_version INTEGER NOT NULL CHECK (provider_format_version BETWEEN 1 AND 65535),
    context_version INTEGER NOT NULL CHECK (context_version BETWEEN 1 AND 65535),
    context_digest BYTEA NOT NULL CHECK (octet_length(context_digest) = 32),
    custody_mode TEXT NOT NULL CHECK (custody_mode IN ('importing', 'protected')),
    custody_revision BIGINT NOT NULL CHECK (custody_revision > 0),
    opaque_value BYTEA CHECK (opaque_value IS NULL OR octet_length(opaque_value) BETWEEN 1 AND 65536),
    safe_fingerprint BYTEA CHECK (
        safe_fingerprint IS NULL OR octet_length(safe_fingerprint) = 32
    ),
    state TEXT NOT NULL CHECK (state IN ('pending', 'live', 'erased')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    erased_at TIMESTAMPTZ,
    CONSTRAINT protected_material_scope_check CHECK (
        (scope_kind = 'deployment' AND project_id IS NULL)
        OR (scope_kind = 'project' AND project_id IS NOT NULL)
    ),
    CONSTRAINT protected_material_kind_owner_check CHECK (
        (material_kind = 'signing_key' AND owner_kind = 'signing_key')
        OR (material_kind = 'configuration_secret' AND owner_kind <> 'signing_key')
    ),
    CONSTRAINT protected_material_fingerprint_check CHECK (
        (material_kind = 'signing_key' AND safe_fingerprint IS NULL)
        OR (
            material_kind = 'configuration_secret'
            AND (
                (state = 'pending' AND safe_fingerprint IS NULL)
                OR (state = 'live' AND safe_fingerprint IS NOT NULL)
                OR state = 'erased'
            )
        )
    ),
    CONSTRAINT protected_material_state_check CHECK (
        (state = 'pending' AND opaque_value IS NULL AND erased_at IS NULL)
        OR (state = 'live' AND opaque_value IS NOT NULL AND erased_at IS NULL)
        OR (state = 'erased' AND opaque_value IS NULL AND erased_at IS NOT NULL)
    ),
    UNIQUE NULLS NOT DISTINCT (scope_kind, project_id, owner_kind, owner_id, generation),
    UNIQUE (id, owner_kind, owner_id, generation)
);

CREATE INDEX protected_material_project_owner_idx
    ON protected_materials (project_id, owner_kind, owner_id, generation);
CREATE INDEX protected_material_provider_state_idx
    ON protected_materials (provider_id, provider_format_version, state, id);
CREATE INDEX protected_material_pending_idx
    ON protected_materials (created_at, id)
    WHERE state = 'pending';

CREATE TABLE custody_cutover_authority (
    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    mode TEXT NOT NULL CHECK (mode IN ('legacy', 'importing', 'protected')),
    revision BIGINT NOT NULL CHECK (revision > 0),
    material_inventory_revision BIGINT NOT NULL DEFAULT 1 CHECK (material_inventory_revision > 0),
    legacy_inventory_completed_at TIMESTAMPTZ,
    protected_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    CONSTRAINT custody_cutover_state_check CHECK (
        (mode = 'legacy' AND legacy_inventory_completed_at IS NULL AND protected_at IS NULL)
        OR (mode = 'importing' AND protected_at IS NULL)
        OR (
            mode = 'protected'
            AND legacy_inventory_completed_at IS NOT NULL
            AND protected_at IS NOT NULL
        )
    )
);

-- A new database has no legacy owner and starts directly in protected mode. Any authoritative legacy
-- reference makes this an upgrade and keeps legacy authority until the listenerless importer proves
-- complete inventory and performs the guarded switch. The short write fence makes classification a
-- single authoritative snapshot; operators must still drain pre-TS-003 writers before migration.
LOCK TABLE
    project_signing_keys,
    provider_configurations,
    provider_secret_operations,
    project_smtp_configurations,
    deployment_smtp_generations,
    project_smtp_test_operations,
    webhook_secret_generations
IN SHARE ROW EXCLUSIVE MODE;

INSERT INTO custody_cutover_authority (
    singleton,
    mode,
    revision,
    legacy_inventory_completed_at,
    protected_at
)
SELECT
    TRUE,
    CASE WHEN legacy.has_reference THEN 'legacy' ELSE 'protected' END,
    1,
    CASE WHEN legacy.has_reference THEN NULL ELSE transaction_timestamp() END,
    CASE WHEN legacy.has_reference THEN NULL ELSE transaction_timestamp() END
FROM (
    SELECT
        EXISTS (SELECT 1 FROM project_signing_keys)
        OR EXISTS (SELECT 1 FROM provider_configurations WHERE secret_ref IS NOT NULL)
        OR EXISTS (
            SELECT 1
              FROM provider_secret_operations operation
              JOIN provider_configurations provider
                ON provider.project_id=operation.project_id AND provider.id=operation.provider_id
             WHERE operation.state='prepared'
               AND provider.status='provisioning'
               AND provider.secret_ref IS NULL
        )
        OR EXISTS (SELECT 1 FROM project_smtp_configurations)
        OR EXISTS (SELECT 1 FROM deployment_smtp_generations)
        OR EXISTS (SELECT 1 FROM project_smtp_test_operations WHERE recipient_erased_at IS NULL)
        OR EXISTS (SELECT 1 FROM webhook_secret_generations)
        AS has_reference
) AS legacy;

CREATE FUNCTION owlauth_bump_material_inventory_revision()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    UPDATE custody_cutover_authority
       SET material_inventory_revision=material_inventory_revision+1,
           updated_at=transaction_timestamp()
     WHERE singleton;
    RETURN NULL;
END;
$$;

CREATE TRIGGER protected_material_inventory_revision_trigger
AFTER INSERT OR UPDATE OR DELETE ON protected_materials
FOR EACH STATEMENT
EXECUTE FUNCTION owlauth_bump_material_inventory_revision();

CREATE TABLE custody_import_operations (
    id UUID PRIMARY KEY,
    material_id UUID NOT NULL REFERENCES protected_materials (id) ON DELETE RESTRICT,
    owner_kind TEXT NOT NULL,
    owner_id UUID NOT NULL,
    generation BIGINT NOT NULL CHECK (generation > 0),
    legacy_reference TEXT NOT NULL CHECK (char_length(legacy_reference) BETWEEN 1 AND 512),
    cutover_revision BIGINT NOT NULL CHECK (cutover_revision > 0),
    state TEXT NOT NULL CHECK (state IN ('reserved', 'importing', 'verified', 'failed')),
    attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    failure_class TEXT CHECK (
        failure_class IS NULL OR failure_class IN ('missing', 'unreadable', 'mismatch', 'unavailable')
    ),
    created_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    verified_at TIMESTAMPTZ,
    CONSTRAINT custody_import_material_owner_fk
        FOREIGN KEY (material_id, owner_kind, owner_id, generation)
        REFERENCES protected_materials (id, owner_kind, owner_id, generation)
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT custody_import_state_check CHECK (
        (state = 'verified' AND verified_at IS NOT NULL AND failure_class IS NULL)
        OR (state = 'failed' AND verified_at IS NULL AND failure_class IS NOT NULL)
        OR (state IN ('reserved', 'importing') AND verified_at IS NULL AND failure_class IS NULL)
    ),
    UNIQUE (owner_kind, owner_id, generation),
    UNIQUE (legacy_reference)
);

CREATE INDEX custody_import_state_idx
    ON custody_import_operations (state, updated_at, id)
    WHERE state <> 'verified';

-- Every earlier server build was pre-alpha. Once any post-initial migration commits, only the
-- current rewritten migration series may restart; partial prefixes remain available solely for
-- operator remediation and retry by this binary.
UPDATE schema_compatibility
SET minimum_binary_schema_level = 20260805100000
WHERE singleton
  AND minimum_binary_schema_level < 20260805100000;
