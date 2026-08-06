import { Link, useNavigate, useParams } from "react-router";

import { EmptyState, PageHeader } from "../../shared/layout/Layout";
import { useControl, useProject } from "../app/ControlContext";
import { UserManagement } from "../features/UserManagement";
import styles from "./pages.module.css";

export function UsersPage() {
  const { projectId } = useParams();
  const project = useProject(projectId);
  const { session, handleError, setMessage } = useControl();
  const navigate = useNavigate();

  if (project === null) {
    return (
      <EmptyState
        level={1}
        title="Project not found"
        description="Select an existing Project before reviewing users."
        action={<Link to="/">Return to Projects</Link>}
      />
    );
  }

  return (
    <div className={styles["page"]}>
      <PageHeader
        title="Users"
        description="Select a bounded Project user to inspect on its dedicated authority page."
      />
      <UserManagement
        session={session}
        project={project}
        onUserSelected={(selectedUserId) => {
          void navigate(`/projects/${project.id}/users/${selectedUserId}`);
        }}
        onError={handleError}
        setMessage={(message) => {
          setMessage(message, "success");
        }}
      />
    </div>
  );
}
