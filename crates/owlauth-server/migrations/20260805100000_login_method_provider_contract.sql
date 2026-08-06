-- Install the strict admitted-method authority contract after expansion and validation.

CREATE FUNCTION owlauth_validate_provider_method_snapshot()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.method_kind = 'email' THEN
        IF NEW.provider_kind IS NOT NULL OR NEW.provider_egress_policy_revision IS NOT NULL THEN
            RAISE EXCEPTION 'email method cannot carry provider authority'
                USING ERRCODE = '23514';
        END IF;
    ELSIF NEW.provider_kind IS NULL THEN
        RAISE EXCEPTION 'provider method requires a closed provider kind'
            USING ERRCODE = '23514';
    ELSIF NEW.provider_kind = 'oidc' AND NEW.provider_egress_policy_revision IS NULL THEN
        RAISE EXCEPTION 'Custom OIDC method requires Project egress authority'
            USING ERRCODE = '23514';
    ELSIF NEW.provider_kind <> 'oidc' AND NEW.provider_egress_policy_revision IS NOT NULL THEN
        RAISE EXCEPTION 'named provider method cannot carry Custom OIDC authority'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER login_transaction_methods_validate_provider_snapshot
BEFORE INSERT OR UPDATE OF method_kind, provider_kind, provider_egress_policy_revision
ON login_transaction_methods
FOR EACH ROW
EXECUTE FUNCTION owlauth_validate_provider_method_snapshot();
