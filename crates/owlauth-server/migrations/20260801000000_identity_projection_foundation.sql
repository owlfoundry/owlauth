-- Bounded identity-source provenance, local field ownership, proof receipts, and merge history.

ALTER TABLE project_users
    ADD COLUMN primary_source_kind TEXT NOT NULL DEFAULT 'provider',
    ADD COLUMN local_display_name_set BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN local_display_name TEXT,
    ADD COLUMN local_picture_url_set BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN local_picture_url TEXT,
    ADD COLUMN local_locale_set BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN local_locale TEXT,
    ADD COLUMN locale TEXT,
    ADD CONSTRAINT project_users_local_profile_shape_check CHECK (
        (local_display_name_set OR local_display_name IS NULL)
        AND (local_picture_url_set OR local_picture_url IS NULL)
        AND (local_locale_set OR local_locale IS NULL)
        AND (local_display_name IS NULL OR char_length(local_display_name) BETWEEN 1 AND 128)
        AND (local_picture_url IS NULL OR char_length(local_picture_url) BETWEEN 8 AND 2048)
        AND (local_locale IS NULL OR char_length(local_locale) BETWEEN 2 AND 35)
        AND (locale IS NULL OR char_length(locale) BETWEEN 2 AND 35)
    ) NOT VALID,
    ADD CONSTRAINT project_users_primary_source_kind_check CHECK (
        primary_source_kind IN ('provider', 'email')
    ) NOT VALID,
    ADD CONSTRAINT project_users_primary_source_shape_check CHECK (
        primary_source_kind = 'provider'
        OR (primary_source_kind = 'email' AND primary_profile_identity_id IS NULL)
    ) NOT VALID;

-- Compatibility defaults remain through the N/N-1 overlap. A later contract migration may
-- remove them only after every supported writer supplies the fields explicitly.

ALTER TABLE linked_identities
    ADD COLUMN source_kind TEXT NOT NULL DEFAULT 'provider',
    ADD COLUMN source_schema TEXT NOT NULL DEFAULT 'owlauth.provider-profile.v1',
    ADD COLUMN source_profile_digest BYTEA,
    ADD COLUMN locale TEXT,
    ADD CONSTRAINT linked_identities_source_kind_check CHECK (
        source_kind = 'provider'
    ) NOT VALID,
    ADD CONSTRAINT linked_identities_source_schema_check CHECK (
        source_schema = 'owlauth.provider-profile.v1'
    ) NOT VALID,
    ADD CONSTRAINT linked_identities_source_profile_shape_check CHECK (
        octet_length(source_profile_digest) = 32
        AND (locale IS NULL OR char_length(locale) BETWEEN 2 AND 35)
    ) NOT VALID;

CREATE FUNCTION owlauth_provider_source_profile_digest(
    profile_display_name TEXT,
    profile_picture_url TEXT,
    profile_locale TEXT
) RETURNS BYTEA
LANGUAGE SQL
IMMUTABLE
PARALLEL SAFE
RETURN sha256(convert_to(
    '{"display_name":' || COALESCE(to_json(profile_display_name)::TEXT, 'null')
        || CASE WHEN profile_locale IS NULL THEN ''
            ELSE ',"locale":' || to_json(profile_locale)::TEXT END
        || ',"picture_url":' || COALESCE(to_json(profile_picture_url)::TEXT, 'null')
        || '}',
    'UTF8'
));

CREATE FUNCTION owlauth_fill_provider_source_profile_digest()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.source_profile_digest IS NULL
        OR (TG_OP = 'UPDATE'
            AND (NEW.display_name, NEW.picture_url, NEW.locale)
                IS DISTINCT FROM (OLD.display_name, OLD.picture_url, OLD.locale)
            AND NEW.source_profile_digest IS NOT DISTINCT FROM OLD.source_profile_digest)
    THEN
        NEW.source_profile_digest := owlauth_provider_source_profile_digest(
            NEW.display_name,
            NEW.picture_url,
            NEW.locale
        );
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER linked_identities_source_profile_digest_fill
BEFORE INSERT OR UPDATE OF display_name, picture_url, locale, source_profile_digest
ON linked_identities
FOR EACH ROW
EXECUTE FUNCTION owlauth_fill_provider_source_profile_digest();

-- Existing rows remain nullable during the expand phase. New and N-1 writes are filled by
-- the trigger; current N reads repair legacy rows without semantic revision churn. A later
-- contract migration may add NOT NULL only after bounded inventory/backfill proves closure.

CREATE TABLE identity_proof_receipts (
    id UUID PRIMARY KEY,
    project_id UUID NOT NULL,
    user_id UUID NOT NULL,
    provider_identity_id UUID NOT NULL,
    identity_kind TEXT NOT NULL CHECK (identity_kind = 'provider'),
    purpose TEXT NOT NULL CHECK (purpose IN ('link', 'unlink', 'merge')),
    browser_session_id UUID NOT NULL,
    receipt_digest BYTEA NOT NULL CHECK (octet_length(receipt_digest) = 32),
    receipt_digest_key_version INTEGER NOT NULL CHECK (receipt_digest_key_version > 0),
    user_revision BIGINT NOT NULL CHECK (user_revision > 0),
    identity_revision BIGINT NOT NULL CHECK (identity_revision > 0),
    status TEXT NOT NULL CHECK (status IN ('issued', 'consumed', 'expired')),
    issued_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    FOREIGN KEY (project_id, user_id)
        REFERENCES project_users (project_id, id) ON DELETE CASCADE,
    FOREIGN KEY (project_id, provider_identity_id, user_id)
        REFERENCES linked_identities (project_id, id, user_id) ON DELETE CASCADE,
    FOREIGN KEY (project_id, browser_session_id, user_id)
        REFERENCES project_browser_sessions (project_id, id, user_id) ON DELETE CASCADE,
    UNIQUE (project_id, id),
    UNIQUE (receipt_digest_key_version, receipt_digest),
    CHECK (expires_at > issued_at AND expires_at <= issued_at + INTERVAL '5 minutes'),
    CHECK ((status = 'consumed') = (consumed_at IS NOT NULL))
);

CREATE INDEX identity_proof_receipts_lookup_idx
    ON identity_proof_receipts
        (project_id, user_id, purpose, status, expires_at, id);

CREATE TABLE project_user_merge_tombstones (
    project_id UUID NOT NULL,
    loser_user_id UUID NOT NULL,
    winner_user_id UUID NOT NULL,
    loser_user_revision BIGINT NOT NULL CHECK (loser_user_revision > 0),
    winner_user_revision BIGINT NOT NULL CHECK (winner_user_revision > 0),
    primary_source_kind TEXT NOT NULL CHECK (primary_source_kind IN ('provider', 'email')),
    primary_provider_identity_id UUID,
    sessions_disposition TEXT NOT NULL CHECK (sessions_disposition = 'loser_revoked'),
    bindings_disposition TEXT NOT NULL CHECK (bindings_disposition = 'winner_preferred'),
    merged_at TIMESTAMPTZ NOT NULL,
    correlation_id UUID NOT NULL,
    PRIMARY KEY (project_id, loser_user_id),
    FOREIGN KEY (project_id, loser_user_id)
        REFERENCES project_users (project_id, id),
    FOREIGN KEY (project_id, winner_user_id)
        REFERENCES project_users (project_id, id),
    FOREIGN KEY (project_id, primary_provider_identity_id, winner_user_id)
        REFERENCES linked_identities (project_id, id, user_id),
    CHECK (loser_user_id <> winner_user_id),
    CHECK (
        (primary_source_kind = 'provider' AND primary_provider_identity_id IS NOT NULL)
        OR (primary_source_kind = 'email' AND primary_provider_identity_id IS NULL)
    )
);

CREATE INDEX project_user_merge_winner_idx
    ON project_user_merge_tombstones (project_id, winner_user_id, merged_at);

ALTER TABLE application_user_projections
    ADD COLUMN source_base_profile_digest BYTEA;

CREATE FUNCTION owlauth_fill_projection_source_base_digest()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    current_base_profile_digest BYTEA;
BEGIN
    IF NEW.source_base_profile_digest IS NULL
        OR (TG_OP = 'UPDATE'
            AND NEW.source_user_revision IS DISTINCT FROM OLD.source_user_revision
            AND NEW.source_base_profile_digest
                IS NOT DISTINCT FROM OLD.source_base_profile_digest)
    THEN
        SELECT project_user.base_profile_digest
        INTO STRICT current_base_profile_digest
        FROM project_users AS project_user
        WHERE project_user.project_id = NEW.project_id
          AND project_user.id = NEW.user_id;
        NEW.source_base_profile_digest := current_base_profile_digest;
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER application_user_projections_source_base_digest_fill
BEFORE INSERT OR UPDATE OF source_user_revision, source_base_profile_digest
ON application_user_projections
FOR EACH ROW
EXECUTE FUNCTION owlauth_fill_projection_source_base_digest();

-- As above, legacy projections are repaired lazily and by later bounded inventory/backfill;
-- startup migration does not scan or rewrite the user directory under one global deadline.
ALTER TABLE application_user_projections
    ADD CONSTRAINT application_user_projections_source_digest_check
        CHECK (octet_length(source_base_profile_digest) = 32) NOT VALID;

-- The existing application_bindings_user_idx covers the bounded fan-out predicate. Do not
-- build a redundant ordinary index during startup; any future index change must use the
-- reviewed online migration path.
