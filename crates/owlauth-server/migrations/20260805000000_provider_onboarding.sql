-- Project-owned Custom OIDC egress authority and onboarding fences.
-- Existing deployments are bridged by bounded application code using the validated legacy origin
-- list as migration input. New Projects receive the target allow-all default transactionally.

CREATE TABLE project_provider_egress_policies (
    project_id UUID PRIMARY KEY REFERENCES projects (id) ON DELETE CASCADE,
    mode TEXT NOT NULL CHECK (mode IN ('allow_all', 'exact_origins')),
    exact_origins JSONB NOT NULL DEFAULT '[]'::jsonb,
    revision BIGINT NOT NULL DEFAULT 1 CHECK (revision > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    CONSTRAINT project_provider_egress_policy_origins_check CHECK (
        jsonb_typeof(exact_origins) = 'array'
        AND (
            (mode = 'allow_all' AND jsonb_array_length(exact_origins) = 0)
            OR (
                mode = 'exact_origins'
                AND jsonb_array_length(exact_origins) BETWEEN 1 AND 1024
            )
        )
    )
);

CREATE TABLE provider_egress_policy_bridge_authority (
    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    state TEXT NOT NULL CHECK (state IN ('pending', 'completed')),
    revision BIGINT NOT NULL DEFAULT 1 CHECK (revision > 0),
    completed_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    CONSTRAINT provider_egress_policy_bridge_state_check CHECK (
        (state = 'pending' AND completed_at IS NULL)
        OR (state = 'completed' AND completed_at IS NOT NULL)
    )
);

-- Fence Project writers across the bridge snapshot and trigger installation so no Project can fall
-- between migration input and the transactional default initializer.
LOCK TABLE projects IN SHARE ROW EXCLUSIVE MODE;

INSERT INTO provider_egress_policy_bridge_authority (
    singleton,
    state,
    completed_at
)
SELECT
    TRUE,
    CASE WHEN EXISTS (SELECT 1 FROM projects) THEN 'pending' ELSE 'completed' END,
    CASE
        WHEN EXISTS (SELECT 1 FROM projects) THEN NULL
        ELSE transaction_timestamp()
    END;

CREATE FUNCTION owlauth_initialize_project_provider_egress_policy()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    INSERT INTO project_provider_egress_policies (
        project_id,
        mode,
        exact_origins
    ) VALUES (
        NEW.id,
        'allow_all',
        '[]'::jsonb
    );
    RETURN NEW;
END;
$$;

CREATE TRIGGER projects_initialize_provider_egress_policy
AFTER INSERT ON projects
FOR EACH ROW
EXECUTE FUNCTION owlauth_initialize_project_provider_egress_policy();
