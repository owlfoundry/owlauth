use async_trait::async_trait;
use sea_orm::{ConnectionTrait, DatabaseConnection, DbBackend, QueryResult, Statement};
use uuid::Uuid;

use crate::application::{
    ApplicationError, ControlOverviewPort, ProjectOverviewApplicationCounts,
    ProjectOverviewProviderCounts, ProjectOverviewServerKeyCounts, ProjectOverviewSummary,
    ProjectOverviewUserCounts,
};

use super::authentication::persistence;

const PROJECT_OVERVIEW_QUERY: &str = r"
SELECT
    project.id AS project_id,
    (SELECT COUNT(*) FROM applications application
      WHERE application.project_id = project.id) AS applications,
    (SELECT COUNT(*) FROM applications application
      WHERE application.project_id = project.id
        AND application.status = 'active') AS active_applications,
    (SELECT COUNT(*) FROM applications application
      WHERE application.project_id = project.id
        AND application.status = 'active'
        AND EXISTS (
            SELECT 1 FROM application_redirects redirect
             WHERE redirect.project_id = application.project_id
               AND redirect.application_id = application.id
        )) AS configured_applications,
    (SELECT COUNT(*) FROM provider_configurations provider
      WHERE provider.project_id = project.id) AS providers,
    (SELECT COUNT(*) FROM provider_configurations provider
      WHERE provider.project_id = project.id
        AND provider.status = 'active') AS active_providers,
    (SELECT COUNT(*)
       FROM application_provider_assignments assignment
       JOIN applications application
         ON application.project_id = assignment.project_id
        AND application.id = assignment.application_id
       JOIN provider_configurations provider
         ON provider.project_id = assignment.project_id
        AND provider.id = assignment.provider_id
      WHERE assignment.project_id = project.id
        AND assignment.status = 'active'
        AND application.status = 'active'
        AND provider.status = 'active') AS provider_assignments,
    (SELECT COUNT(*) FROM project_users project_user
      WHERE project_user.project_id = project.id) AS users,
    (SELECT COUNT(*) FROM project_users project_user
      WHERE project_user.project_id = project.id
        AND project_user.status = 'active') AS active_users,
    (SELECT COUNT(*) FROM project_users project_user
      WHERE project_user.project_id = project.id
        AND project_user.status = 'disabled') AS disabled_users,
    (SELECT COUNT(*) FROM project_users project_user
      WHERE project_user.project_id = project.id
        AND project_user.status = 'merged') AS merged_users,
    (SELECT COUNT(*) FROM project_server_keys server_key
      WHERE server_key.project_id = project.id) AS project_server_keys,
    (SELECT COUNT(*) FROM project_server_keys server_key
      WHERE server_key.project_id = project.id
        AND server_key.status = 'active') AS active_project_server_keys,
    (SELECT COUNT(*) FROM project_server_keys server_key
      WHERE server_key.project_id = project.id
        AND server_key.status = 'revoked') AS revoked_project_server_keys
FROM projects project
WHERE project.id = $1
";

#[derive(Clone)]
pub(crate) struct PostgresControlOverviewRepository {
    database: DatabaseConnection,
}

impl PostgresControlOverviewRepository {
    pub(crate) fn new(database: DatabaseConnection) -> Self {
        Self { database }
    }
}

#[async_trait]
impl ControlOverviewPort for PostgresControlOverviewRepository {
    async fn get_project_overview(
        &self,
        project_id: Uuid,
    ) -> Result<ProjectOverviewSummary, ApplicationError> {
        let row = self
            .database
            .query_one_raw(Statement::from_sql_and_values(
                DbBackend::Postgres,
                PROJECT_OVERVIEW_QUERY,
                [project_id.into()],
            ))
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        let returned_project_id = row.try_get::<Uuid>("", "project_id").map_err(persistence)?;
        if returned_project_id != project_id {
            return Err(ApplicationError::Integrity);
        }
        Ok(ProjectOverviewSummary {
            project_id: returned_project_id,
            applications: ProjectOverviewApplicationCounts {
                total: count(&row, "applications")?,
                active: count(&row, "active_applications")?,
                configured: count(&row, "configured_applications")?,
            },
            providers: ProjectOverviewProviderCounts {
                total: count(&row, "providers")?,
                active: count(&row, "active_providers")?,
                active_assignments: count(&row, "provider_assignments")?,
            },
            users: ProjectOverviewUserCounts {
                total: count(&row, "users")?,
                active: count(&row, "active_users")?,
                disabled: count(&row, "disabled_users")?,
                merged: count(&row, "merged_users")?,
            },
            project_server_keys: ProjectOverviewServerKeyCounts {
                total: count(&row, "project_server_keys")?,
                active: count(&row, "active_project_server_keys")?,
                revoked: count(&row, "revoked_project_server_keys")?,
            },
        })
    }
}

fn count(row: &QueryResult, column: &str) -> Result<u64, ApplicationError> {
    let value = row.try_get::<i64>("", column).map_err(persistence)?;
    u64::try_from(value).map_err(|_| ApplicationError::Integrity)
}
