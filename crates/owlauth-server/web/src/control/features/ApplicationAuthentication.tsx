import { useCallback, useEffect, useMemo, useState } from "react";

import { DataTable, EmptyState, LoadingState, Section } from "../../shared/layout/Layout";
import { Button } from "../../shared/primitives/Button";
import { InlineAlert, StatusBadge } from "../../shared/primitives/Feedback";
import { useControlConfirmation } from "../app/Confirmation";
import {
  type Application,
  type DisposableControlClient,
  type EmailAssignment,
  type EmailMethodPolicy,
  type Provider,
  requireData,
} from "../client";
import styles from "./features.module.css";

interface ApplicationAuthenticationProps {
  readonly session: DisposableControlClient;
  readonly application: Application;
  readonly editable: boolean;
  readonly onApplicationChanged: () => Promise<void>;
  readonly onError: (error: unknown, refreshConflict?: () => Promise<void>) => Promise<void>;
  readonly setMessage: (message: string) => void;
}

export function ApplicationAuthentication({
  session,
  application,
  editable,
  onApplicationChanged,
  onError,
  setMessage,
}: ApplicationAuthenticationProps) {
  const confirm = useControlConfirmation();
  const [providers, setProviders] = useState<Provider[]>([]);
  const [emailPolicy, setEmailPolicy] = useState<EmailMethodPolicy | null>(null);
  const [emailAssignments, setEmailAssignments] = useState<EmailAssignment[]>([]);
  const [loadState, setLoadState] = useState<"loading" | "ready" | "failed">("loading");
  const [submittingMethod, setSubmittingMethod] = useState<string | null>(null);

  const refresh = useCallback(
    async (signal?: AbortSignal) => {
      const [providerResult, emailPolicyResult, emailAssignmentResult] = await Promise.all([
        session.client.GET("/v1/projects/{project_id}/providers", {
          params: { path: { project_id: application.project_id } },
          signal: signal ?? null,
        }),
        session.client.GET("/v1/projects/{project_id}/email-method", {
          params: { path: { project_id: application.project_id } },
          signal: signal ?? null,
        }),
        session.client.GET("/v1/projects/{project_id}/email-method/assignments", {
          params: { path: { project_id: application.project_id } },
          signal: signal ?? null,
        }),
      ]);
      if (signal?.aborted === true) return;
      setProviders(
        requireData(providerResult.data, providerResult.error, providerResult.response).items,
      );
      setEmailPolicy(
        requireData(emailPolicyResult.data, emailPolicyResult.error, emailPolicyResult.response),
      );
      setEmailAssignments(
        requireData(
          emailAssignmentResult.data,
          emailAssignmentResult.error,
          emailAssignmentResult.response,
        ).items,
      );
    },
    [application.project_id, session],
  );

  const load = useCallback(
    async (signal?: AbortSignal) => {
      setLoadState("loading");
      try {
        await refresh(signal);
        if (signal?.aborted !== true) setLoadState("ready");
      } catch (error) {
        if (signal?.aborted !== true) setLoadState("failed");
        throw error;
      }
    },
    [refresh],
  );

  useEffect(() => {
    const controller = new AbortController();
    const timer = window.setTimeout(() => {
      void load(controller.signal).catch((error: unknown) => {
        if (!controller.signal.aborted) void onError(error);
      });
    }, 0);
    return () => {
      window.clearTimeout(timer);
      controller.abort();
    };
  }, [load, onError]);

  const emailAssigned = useMemo(
    () =>
      emailAssignments.some(
        (assignment) => assignment.application_id === application.id && assignment.enabled,
      ),
    [application.id, emailAssignments],
  );

  async function setProviderAssignment(provider: Provider, assigned: boolean) {
    if (
      !assigned &&
      !(await confirm({
        title: "Remove authentication provider",
        message: `Remove ${provider.display_name} from ${application.display_name}? New sign-in attempts for this Application will no longer offer this provider.`,
        actionLabel: "Remove provider",
        destructive: true,
      }))
    ) {
      return;
    }
    setSubmittingMethod(provider.id);
    try {
      const request = {
        params: {
          path: {
            project_id: application.project_id,
            provider_id: provider.id,
            application_id: application.id,
          },
        },
        body: { expected_application_revision: application.security_revision },
      };
      const result = assigned
        ? await session.client.PUT(
            "/v1/projects/{project_id}/providers/{provider_id}/assignments/{application_id}",
            request,
          )
        : await session.client.POST(
            "/v1/projects/{project_id}/providers/{provider_id}/assignments/{application_id}/unassign",
            request,
          );
      requireData(result.data, result.error, result.response);
      await Promise.all([onApplicationChanged(), refresh()]);
      setMessage(
        `${provider.display_name} ${assigned ? "assigned to" : "removed from"} this Application.`,
      );
    } catch (error) {
      await onError(error, async () => {
        await Promise.all([onApplicationChanged(), refresh()]);
      });
    } finally {
      setSubmittingMethod(null);
    }
  }

  async function setEmailAssignment(assigned: boolean) {
    if (
      !assigned &&
      !(await confirm({
        title: "Remove passwordless email",
        message: `Remove passwordless email from ${application.display_name}? New sign-in attempts for this Application will no longer offer this method.`,
        actionLabel: "Remove email method",
        destructive: true,
      }))
    ) {
      return;
    }
    setSubmittingMethod("email");
    try {
      const result = await session.client.PUT(
        "/v1/projects/{project_id}/applications/{application_id}/email-method",
        {
          params: {
            path: { project_id: application.project_id, application_id: application.id },
          },
          body: {
            enabled: assigned,
            expected_application_security_revision: application.security_revision,
          },
        },
      );
      requireData(result.data, result.error, result.response);
      await Promise.all([onApplicationChanged(), refresh()]);
      setMessage(
        `Passwordless email ${assigned ? "assigned to" : "removed from"} this Application.`,
      );
    } catch (error) {
      await onError(error, async () => {
        await Promise.all([onApplicationChanged(), refresh()]);
      });
    } finally {
      setSubmittingMethod(null);
    }
  }

  if (loadState === "loading") return <LoadingState>Loading authentication methods</LoadingState>;
  if (loadState === "failed" || emailPolicy === null) {
    return (
      <InlineAlert tone="danger" role="alert">
        <p>Authentication methods could not be loaded.</p>
        <Button type="button" onClick={() => void load().catch(onError)}>
          Retry authentication methods
        </Button>
      </InlineAlert>
    );
  }

  const methods = [
    ...providers.map((provider) => ({
      id: provider.id,
      name: provider.display_name,
      detail: provider.provider_key,
      kind: provider.kind,
      available: provider.status === "active" && provider.login_supported,
      assigned: provider.assigned_application_ids.includes(application.id),
      provider,
    })),
    {
      id: "email",
      name: "Passwordless email",
      detail: "One-time code and magic link",
      kind: "email",
      available: emailPolicy.enabled,
      assigned: emailAssigned,
      provider: null,
    },
  ];

  return (
    <Section
      title="Authentication methods"
      description="Choose the Project sign-in methods available to this Application."
    >
      {methods.length === 1 && !emailPolicy.enabled ? (
        <EmptyState
          level={3}
          title="No available authentication methods"
          description="Configure a provider or enable the Project passwordless email policy first."
        />
      ) : (
        <DataTable
          caption="Application authentication methods"
          headings={["Method", "Kind", "Project status", "Application", "Action"]}
        >
          {methods.map((method) => (
            <tr key={method.id}>
              <td>
                <strong>{method.name}</strong>
                <span className={styles["machineValue"]}>{method.detail}</span>
              </td>
              <td>{method.kind}</td>
              <td>
                <StatusBadge
                  status={method.available ? "available" : "unavailable"}
                  family={method.available ? "active" : "disabled"}
                />
              </td>
              <td>
                <StatusBadge
                  status={method.assigned ? "assigned" : "not assigned"}
                  family={method.assigned ? "active" : "disabled"}
                />
              </td>
              <td>
                <Button
                  type="button"
                  variant={method.assigned ? "quiet" : "secondary"}
                  busy={submittingMethod === method.id}
                  disabled={
                    !editable ||
                    submittingMethod !== null ||
                    (!method.assigned && !method.available)
                  }
                  onClick={() => {
                    if (method.provider === null) void setEmailAssignment(!method.assigned);
                    else void setProviderAssignment(method.provider, !method.assigned);
                  }}
                >
                  {method.assigned ? "Remove" : "Assign"}
                </Button>
              </td>
            </tr>
          ))}
        </DataTable>
      )}
    </Section>
  );
}
