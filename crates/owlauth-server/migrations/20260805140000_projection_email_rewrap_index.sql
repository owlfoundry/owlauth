DROP INDEX application_user_projections_email_key_version_idx;

CREATE INDEX application_user_projections_email_rewrap_idx
    ON application_user_projections (verified_email_key_version, id)
    WHERE verified_email_key_version IS NOT NULL;
