-- Expand login-method snapshots without installing the drained-writer contract trigger yet.

ALTER TABLE login_transaction_methods
    ADD COLUMN provider_kind TEXT,
    ADD COLUMN provider_egress_policy_revision BIGINT,
    ADD CONSTRAINT login_transaction_methods_provider_kind_check CHECK (
        provider_kind IS NULL OR provider_kind IN ('oidc', 'google', 'github')
    ) NOT VALID,
    ADD CONSTRAINT login_transaction_methods_provider_egress_policy_revision_check CHECK (
        provider_egress_policy_revision IS NULL OR provider_egress_policy_revision > 0
    ) NOT VALID;
