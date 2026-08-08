use std::sync::Arc;

use async_trait::async_trait;
use uuid::Uuid;

use super::ApplicationError;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ProjectOverviewSummary {
    pub project_id: Uuid,
    pub applications: ProjectOverviewApplicationCounts,
    pub providers: ProjectOverviewProviderCounts,
    pub users: ProjectOverviewUserCounts,
    pub project_server_keys: ProjectOverviewServerKeyCounts,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ProjectOverviewApplicationCounts {
    pub total: u64,
    pub active: u64,
    pub configured: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ProjectOverviewProviderCounts {
    pub total: u64,
    pub active: u64,
    pub active_assignments: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ProjectOverviewUserCounts {
    pub total: u64,
    pub active: u64,
    pub disabled: u64,
    pub merged: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ProjectOverviewServerKeyCounts {
    pub total: u64,
    pub active: u64,
    pub revoked: u64,
}

#[async_trait]
pub(crate) trait ControlOverviewPort: Send + Sync {
    async fn get_project_overview(
        &self,
        project_id: Uuid,
    ) -> Result<ProjectOverviewSummary, ApplicationError>;
}

#[derive(Clone)]
pub(crate) struct ControlOverviewService {
    port: Arc<dyn ControlOverviewPort>,
}

impl ControlOverviewService {
    pub(crate) fn new(port: Arc<dyn ControlOverviewPort>) -> Self {
        Self { port }
    }

    pub(crate) async fn get_project_overview(
        &self,
        project_id: Uuid,
    ) -> Result<ProjectOverviewSummary, ApplicationError> {
        self.port.get_project_overview(project_id).await
    }
}

#[cfg(test)]
mod tests {
    use async_trait::async_trait;

    use super::*;

    struct RecordingPort {
        expected_project_id: Uuid,
        summary: ProjectOverviewSummary,
    }

    #[async_trait]
    impl ControlOverviewPort for RecordingPort {
        async fn get_project_overview(
            &self,
            project_id: Uuid,
        ) -> Result<ProjectOverviewSummary, ApplicationError> {
            assert_eq!(project_id, self.expected_project_id);
            Ok(self.summary)
        }
    }

    #[tokio::test]
    async fn project_overview_delegates_one_project_scoped_read() {
        let project_id = Uuid::new_v4();
        let summary = ProjectOverviewSummary {
            project_id,
            applications: ProjectOverviewApplicationCounts {
                total: 3,
                active: 2,
                configured: 1,
            },
            providers: ProjectOverviewProviderCounts {
                total: 2,
                active: 1,
                active_assignments: 1,
            },
            users: ProjectOverviewUserCounts {
                total: 7,
                active: 5,
                disabled: 1,
                merged: 1,
            },
            project_server_keys: ProjectOverviewServerKeyCounts {
                total: 2,
                active: 1,
                revoked: 1,
            },
        };
        let service = ControlOverviewService::new(Arc::new(RecordingPort {
            expected_project_id: project_id,
            summary,
        }));

        assert_eq!(service.get_project_overview(project_id).await, Ok(summary));
    }
}
