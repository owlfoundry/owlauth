import { Link, useParams } from "react-router";

import { EmptyState, PageHeader } from "../../shared/layout/Layout";
import { useControl, useProject } from "../app/ControlContext";
import { EmailSettings } from "../features/EmailSettings";
import styles from "./pages.module.css";

export function EmailPage() {
  const { projectId } = useParams();
  const project = useProject(projectId);
  const { session, refreshProjects, handleError, setMessage } = useControl();

  if (project === null) {
    return (
      <EmptyState
        level={1}
        title="Project not found"
        description="Select an existing Project before configuring passwordless email."
        action={<Link to="/">Return to Projects</Link>}
      />
    );
  }

  return (
    <div className={styles["page"]}>
      <PageHeader
        title="Passwordless email"
        description="Configure proof modes and SMTP delivery for the Project. Assign this method from each Application."
      />
      <EmailSettings
        session={session}
        project={project}
        onProjectChanged={async () => {
          await refreshProjects();
        }}
        onError={handleError}
        setMessage={(message) => {
          setMessage(message, "success");
        }}
      />
    </div>
  );
}
