use time::OffsetDateTime;

use super::{
    DomainError, ProfileDisplayName, ProfilePictureUrl, ProjectUserStatus, PublicId, UserRevision,
};

pub(crate) const USER_PROJECTION_SCHEMA_V1: &str = "owlauth.user.v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ProjectionRevision(i64);

impl ProjectionRevision {
    pub(crate) const fn initial() -> Self {
        Self(1)
    }

    pub(crate) fn parse(value: i64) -> Result<Self, DomainError> {
        if value < 1 {
            return Err(DomainError::InvalidTransition);
        }
        Ok(Self(value))
    }

    pub(crate) const fn value(self) -> i64 {
        self.0
    }

    pub(crate) fn advance(&mut self) -> Result<(), DomainError> {
        self.0 = self
            .0
            .checked_add(1)
            .ok_or(DomainError::InvalidTransition)?;
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct UserProjectionSource {
    pub(crate) user_id: PublicId,
    pub(crate) status: ProjectUserStatus,
    pub(crate) display_name: Option<ProfileDisplayName>,
    pub(crate) picture_url: Option<ProfilePictureUrl>,
    pub(crate) created_at: OffsetDateTime,
    pub(crate) updated_at: OffsetDateTime,
    pub(crate) user_revision: UserRevision,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct UserProjection {
    pub(crate) schema: &'static str,
    pub(crate) user_id: String,
    pub(crate) status: ProjectUserStatus,
    pub(crate) display_name: Option<String>,
    pub(crate) picture_url: Option<String>,
    pub(crate) created_at: OffsetDateTime,
    pub(crate) updated_at: OffsetDateTime,
    pub(crate) user_revision: i64,
    pub(crate) projection_revision: i64,
}

impl UserProjection {
    pub(crate) fn materialize(
        source: UserProjectionSource,
        projection_revision: ProjectionRevision,
    ) -> Result<Self, DomainError> {
        if source.updated_at < source.created_at {
            return Err(DomainError::InvalidTransition);
        }
        Ok(Self {
            schema: USER_PROJECTION_SCHEMA_V1,
            user_id: source.user_id.to_string(),
            status: source.status,
            display_name: source.display_name.map(ProfileDisplayName::into_inner),
            picture_url: source.picture_url.map(ProfilePictureUrl::into_inner),
            created_at: source.created_at,
            updated_at: source.updated_at,
            user_revision: source.user_revision.value(),
            projection_revision: projection_revision.value(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source() -> UserProjectionSource {
        let created_at = OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();
        UserProjectionSource {
            user_id: PublicId::parse("usr_12345678".to_owned()).unwrap(),
            status: ProjectUserStatus::Active,
            display_name: Some(ProfileDisplayName::parse("Ada".to_owned()).unwrap()),
            picture_url: Some(
                ProfilePictureUrl::parse("https://cdn.example/ada.png".to_owned()).unwrap(),
            ),
            created_at,
            updated_at: created_at,
            user_revision: UserRevision::initial(),
        }
    }

    #[test]
    fn initial_projection_has_a_deterministic_bounded_shape() {
        let first = UserProjection::materialize(source(), ProjectionRevision::initial()).unwrap();
        let second = UserProjection::materialize(source(), ProjectionRevision::initial()).unwrap();

        assert_eq!(first, second);
        assert_eq!(first.schema, USER_PROJECTION_SCHEMA_V1);
        assert_eq!(first.user_id, "usr_12345678");
        assert_eq!(first.status.as_str(), "active");
        assert_eq!(first.display_name.as_deref(), Some("Ada"));
        assert_eq!(first.user_revision, 1);
        assert_eq!(first.projection_revision, 1);
    }

    #[test]
    fn projection_revisions_are_positive_and_monotonic() {
        let mut revision = ProjectionRevision::initial();
        revision.advance().unwrap();
        assert_eq!(revision.value(), 2);
        assert_eq!(
            ProjectionRevision::parse(0),
            Err(DomainError::InvalidTransition)
        );
    }

    #[test]
    fn projection_rejects_time_traveling_source_state() {
        let mut invalid = source();
        invalid.updated_at = invalid.created_at - time::Duration::SECOND;
        assert_eq!(
            UserProjection::materialize(invalid, ProjectionRevision::initial()),
            Err(DomainError::InvalidTransition)
        );
    }
}
