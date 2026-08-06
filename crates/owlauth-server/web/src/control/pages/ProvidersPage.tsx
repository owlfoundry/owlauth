import { useCallback, useEffect, useRef, useState } from "react";
import type { RefObject, SyntheticEvent } from "react";
import { Link, useParams } from "react-router";

import {
  DataTable,
  DescriptionList,
  EmptyState,
  PageHeader,
  Section,
} from "../../shared/layout/Layout";
import { Button } from "../../shared/primitives/Button";
import { InlineAlert, StatusBadge } from "../../shared/primitives/Feedback";
import { Checkbox, Field, Input, Select, Textarea } from "../../shared/primitives/Field";
import { Dialog } from "../../shared/primitives/Overlay";
import { useControl, useProject } from "../app/ControlContext";
import {
  type Application,
  IdempotencyAttempt,
  type OidcPreflightResult,
  type Provider,
  type ProviderEgressPolicy,
  requireData,
} from "../client";
import styles from "./pages.module.css";

type OnboardingKind = "google" | "oidc" | "github";
type Confirmation =
  | { kind: "disable"; provider: Provider }
  | { kind: "unassign"; provider: Provider; application: Application }
  | null;

export function ProvidersPage() {
  const { projectId } = useParams();
  const project = useProject(projectId);
  const { session, refreshProjects, handleError, setMessage } = useControl();
  const [providers, setProviders] = useState<Provider[]>([]);
  const [applications, setApplications] = useState<Application[]>([]);
  const [policy, setPolicy] = useState<ProviderEgressPolicy | null>(null);
  const [loadState, setLoadState] = useState<"loading" | "ready" | "failed">("loading");
  const [selectedProviderId, setSelectedProviderId] = useState<string | null>(null);
  const [onboarding, setOnboarding] = useState<OnboardingKind | null>(null);
  const [preflight, setPreflight] = useState<OidcPreflightResult | null>(null);
  const [preflightIssuer, setPreflightIssuer] = useState("");
  const [editingEgressPolicy, setEditingEgressPolicy] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [reconcileProvider, setReconcileProvider] = useState<Provider | null>(null);
  const [confirmation, setConfirmation] = useState<Confirmation>(null);
  const createAttempt = useRef(new IdempotencyAttempt());
  const onboardingSecretInput = useRef<HTMLInputElement>(null);

  const clearOnboardingSecret = useCallback(() => {
    if (onboardingSecretInput.current !== null) onboardingSecretInput.current.value = "";
  }, []);

  const refresh = useCallback(async () => {
    if (project === null) return;
    setLoadState("loading");
    try {
      const [providerResult, applicationResult, policyResult] = await Promise.all([
        session.client.GET("/v1/projects/{project_id}/providers", {
          params: { path: { project_id: project.id } },
        }),
        session.client.GET("/v1/projects/{project_id}/applications", {
          params: { path: { project_id: project.id } },
        }),
        session.client.GET("/v1/projects/{project_id}/provider-egress-policy", {
          params: { path: { project_id: project.id } },
        }),
      ]);
      const nextProviders = requireData(
        providerResult.data,
        providerResult.error,
        providerResult.response,
      ).items;
      const nextApplications = requireData(
        applicationResult.data,
        applicationResult.error,
        applicationResult.response,
      ).items;
      const nextPolicy = requireData(policyResult.data, policyResult.error, policyResult.response);
      setProviders(nextProviders);
      setApplications(nextApplications);
      setPolicy(nextPolicy);
      setSelectedProviderId((current) =>
        current !== null && nextProviders.some((provider) => provider.id === current)
          ? current
          : (nextProviders[0]?.id ?? null),
      );
      setLoadState("ready");
    } catch (error) {
      setLoadState("failed");
      throw error;
    }
  }, [project, session]);

  useEffect(() => {
    const timer = window.setTimeout(() => {
      void refresh().catch(handleError);
    }, 0);
    return () => {
      window.clearTimeout(timer);
    };
  }, [handleError, refresh]);

  function closeOnboarding() {
    if (submitting) return;
    clearOnboardingSecret();
    createAttempt.current.abandon();
    setPreflight(null);
    setPreflightIssuer("");
    setOnboarding(null);
  }

  async function runPreflight(event: SyntheticEvent<HTMLFormElement, SubmitEvent>) {
    event.preventDefault();
    if (project === null) return;
    const fields = new FormData(event.currentTarget);
    const issuer = text(fields, "issuer").trim();
    clearOnboardingSecret();
    setSubmitting(true);
    setPreflight(null);
    try {
      const result = await session.client.POST(
        "/v1/projects/{project_id}/providers/oidc/preflight",
        {
          params: { path: { project_id: project.id } },
          body: { issuer },
        },
      );
      const checked = requireData(result.data, result.error, result.response);
      setPreflight(checked);
      setPreflightIssuer(issuer);
      setMessage("Custom OIDC metadata passed preflight review.", "success");
    } catch (error) {
      await handleError(error, async () => {
        setPreflight(null);
        setPreflightIssuer("");
        await Promise.all([refresh(), refreshProjects()]);
      });
    } finally {
      setSubmitting(false);
    }
  }

  async function updateEgressPolicy(event: SyntheticEvent<HTMLFormElement, SubmitEvent>) {
    event.preventDefault();
    if (project === null || policy === null) return;
    const fields = new FormData(event.currentTarget);
    const mode = text(fields, "mode") === "exact_origins" ? "exact_origins" : "allow_all";
    clearOnboardingSecret();
    setSubmitting(true);
    try {
      const result = await session.client.PUT("/v1/projects/{project_id}/provider-egress-policy", {
        params: { path: { project_id: project.id } },
        body: {
          mode,
          exact_origins: mode === "exact_origins" ? lines(fields, "exact_origins") : [],
          expected_revision: policy.revision,
        },
      });
      setPolicy(requireData(result.data, result.error, result.response));
      setPreflight(null);
      setPreflightIssuer("");
      setEditingEgressPolicy(false);
      setMessage("Provider egress policy updated.", "success");
    } catch (error) {
      setPreflight(null);
      setPreflightIssuer("");
      await handleError(error, async () => {
        await refresh();
        setEditingEgressPolicy(false);
      });
    } finally {
      setSubmitting(false);
    }
  }

  async function adoptPreflightOrigins() {
    if (project === null || policy === null || preflight === null) return;
    clearOnboardingSecret();
    setSubmitting(true);
    try {
      const result = await session.client.PUT("/v1/projects/{project_id}/provider-egress-policy", {
        params: { path: { project_id: project.id } },
        body: {
          mode: "exact_origins",
          exact_origins: preflight.admitted_endpoint_origins,
          expected_revision: policy.revision,
        },
      });
      setPolicy(requireData(result.data, result.error, result.response));
      setPreflight(null);
      setPreflightIssuer("");
      setMessage("Reviewed preflight origins adopted as the exact egress policy.", "success");
    } catch (error) {
      setPreflight(null);
      setPreflightIssuer("");
      await handleError(error, refresh);
    } finally {
      setSubmitting(false);
    }
  }

  async function createProvider(event: SyntheticEvent<HTMLFormElement, SubmitEvent>) {
    event.preventDefault();
    if (project === null || onboarding === null) return;
    const form = event.currentTarget;
    const fields = new FormData(form);
    const secretInput = form.elements.namedItem("client_secret");
    const clientSecret = text(fields, "client_secret");
    if (secretInput instanceof HTMLInputElement) secretInput.value = "";
    const idempotencyKey = createAttempt.current.begin();
    if (idempotencyKey === null) return;
    if (onboarding === "oidc" && preflight === null) {
      createAttempt.current.abandon();
      setMessage(
        "Run Custom OIDC preflight and review its result before creating the provider.",
        "warning",
      );
      return;
    }
    const body = {
      kind: onboarding,
      provider_key: text(fields, "provider_key"),
      display_name: text(fields, "display_name"),
      ...(onboarding === "oidc" && preflight !== null
        ? { issuer: preflight.canonical_issuer }
        : {}),
      client_id: text(fields, "client_id"),
      client_secret: clientSecret,
      managed_profile_enabled:
        onboarding !== "github" && fields.get("managed_profile_enabled") === "on",
      expected_project_revision: project.metadata_revision,
    };
    setSubmitting(true);
    try {
      const result = await (async () => {
        try {
          return await session.client.POST("/v1/projects/{project_id}/providers", {
            params: {
              path: { project_id: project.id },
              header: { "Idempotency-Key": idempotencyKey },
            },
            body,
          });
        } finally {
          body.client_secret = "";
        }
      })();
      const created = requireData(result.data, result.error, result.response);
      createAttempt.current.settle();
      await Promise.all([refresh(), refreshProjects()]);
      setSelectedProviderId(created.id);
      closeOnboardingAfterSuccess();
      setMessage("Provider configured. Its client secret was discarded from the page.", "success");
    } catch (error) {
      body.client_secret = "";
      createAttempt.current.settle(error);
      setPreflight(null);
      setPreflightIssuer("");
      if (!createAttempt.current.retainsKey) form.reset();
      await handleError(error, async () => {
        await Promise.all([refresh(), refreshProjects()]);
      });
    } finally {
      setSubmitting(false);
    }
  }

  function closeOnboardingAfterSuccess() {
    createAttempt.current.abandon();
    setPreflight(null);
    setPreflightIssuer("");
    setOnboarding(null);
  }

  async function reconcile(event: SyntheticEvent<HTMLFormElement, SubmitEvent>) {
    event.preventDefault();
    if (project === null || reconcileProvider === null) return;
    const form = event.currentTarget;
    const fields = new FormData(form);
    const secretInput = form.elements.namedItem("client_secret");
    const body = {
      client_secret: text(fields, "client_secret"),
      expected_project_revision: project.metadata_revision,
    };
    if (secretInput instanceof HTMLInputElement) secretInput.value = "";
    setSubmitting(true);
    try {
      const result = await (async () => {
        try {
          return await session.client.POST(
            "/v1/projects/{project_id}/providers/{provider_id}/reconcile",
            {
              params: { path: { project_id: project.id, provider_id: reconcileProvider.id } },
              body,
            },
          );
        } finally {
          body.client_secret = "";
        }
      })();
      requireData(result.data, result.error, result.response);
      await Promise.all([refresh(), refreshProjects()]);
      setReconcileProvider(null);
      setMessage("Provider provisioning reconciled.", "success");
    } catch (error) {
      body.client_secret = "";
      await handleError(error, refresh);
    } finally {
      setSubmitting(false);
    }
  }

  async function assign(provider: Provider, event: SyntheticEvent<HTMLFormElement, SubmitEvent>) {
    event.preventDefault();
    if (project === null) return;
    const fields = new FormData(event.currentTarget);
    const application = applications.find(
      (candidate) => candidate.id === text(fields, "application_id"),
    );
    if (application === undefined) return;
    try {
      const result = await session.client.PUT(
        "/v1/projects/{project_id}/providers/{provider_id}/assignments/{application_id}",
        {
          params: {
            path: {
              project_id: project.id,
              provider_id: provider.id,
              application_id: application.id,
            },
          },
          body: { expected_application_revision: application.security_revision },
        },
      );
      requireData(result.data, result.error, result.response);
      await refresh();
      setMessage("Provider assigned to Application.", "success");
    } catch (error) {
      await handleError(error, refresh);
    }
  }

  async function confirmAction() {
    if (project === null || confirmation === null) return;
    setSubmitting(true);
    try {
      if (confirmation.kind === "disable") {
        const result = await session.client.POST(
          "/v1/projects/{project_id}/providers/{provider_id}/disable",
          {
            params: { path: { project_id: project.id, provider_id: confirmation.provider.id } },
            body: { expected_provider_revision: confirmation.provider.revision },
          },
        );
        requireData(result.data, result.error, result.response);
        setMessage("Provider disabled.", "success");
      } else {
        const result = await session.client.DELETE(
          "/v1/projects/{project_id}/providers/{provider_id}/assignments/{application_id}",
          {
            params: {
              path: {
                project_id: project.id,
                provider_id: confirmation.provider.id,
                application_id: confirmation.application.id,
              },
            },
            body: { expected_application_revision: confirmation.application.security_revision },
          },
        );
        requireData(result.data, result.error, result.response);
        setMessage("Provider unassigned.", "success");
      }
      await refresh();
      setConfirmation(null);
    } catch (error) {
      await handleError(error, refresh);
    } finally {
      setSubmitting(false);
    }
  }

  if (project === null) {
    return (
      <EmptyState
        level={1}
        title="Project not found"
        description="Select an existing Project before configuring identity providers."
        action={<Link to="/">Return to Projects</Link>}
      />
    );
  }

  if (loadState !== "ready") {
    return (
      <div className={styles["page"]}>
        <PageHeader
          title="Authentication providers"
          description="Configure closed provider profiles, exact egress policy, and Application assignments."
        />
        {loadState === "loading" ? <p role="status">Loading authentication providers</p> : null}
        {loadState === "failed" ? (
          <InlineAlert tone="danger" role="alert">
            <p>Provider configuration could not be loaded.</p>
            <Button type="button" onClick={() => void refresh().catch(handleError)}>
              Retry provider configuration
            </Button>
          </InlineAlert>
        ) : null}
      </div>
    );
  }

  const selectedProvider = providers.find((provider) => provider.id === selectedProviderId) ?? null;
  return (
    <div className={styles["page"]}>
      <PageHeader
        title="Authentication providers"
        description="Configure closed provider profiles, exact egress policy, and Application assignments."
        actions={
          project.status === "active" ? (
            <div className={styles["actions"]}>
              <Button
                type="button"
                variant="primary"
                onClick={() => {
                  setOnboarding("google");
                }}
              >
                Add Google
              </Button>
              <Button
                type="button"
                variant="secondary"
                onClick={() => {
                  setOnboarding("oidc");
                }}
              >
                Add Custom OIDC
              </Button>
              <Button
                type="button"
                variant="quiet"
                onClick={() => {
                  setOnboarding("github");
                }}
              >
                Add GitHub
              </Button>
            </div>
          ) : undefined
        }
      />
      <Section
        title="Provider egress policy"
        description="Preflight and provider traffic are fenced by this Project policy."
        action={
          policy !== null && project.status === "active" && !editingEgressPolicy ? (
            <Button
              type="button"
              onClick={() => {
                setEditingEgressPolicy(true);
              }}
            >
              Edit egress policy
            </Button>
          ) : undefined
        }
      >
        {policy === null ? (
          <p role="status">Loading egress policy</p>
        ) : editingEgressPolicy ? (
          <form className={styles["form"]} onSubmit={(event) => void updateEgressPolicy(event)}>
            <Field label="Policy mode" htmlFor="egress-mode">
              <Select
                id="egress-mode"
                name="mode"
                defaultValue={policy.mode}
                data-owl-initial-focus
              >
                <option value="allow_all">Allow all safe discovered origins</option>
                <option value="exact_origins">Allow only exact origins</option>
              </Select>
            </Field>
            <Field
              label="Exact origins"
              htmlFor="egress-origins"
              optional
              description="One normalized HTTPS origin per line; ignored in allow-all mode."
            >
              <Textarea
                id="egress-origins"
                name="exact_origins"
                rows={4}
                defaultValue={policy.exact_origins.join("\n")}
              />
            </Field>
            <div className={styles["formActions"]}>
              <Button
                type="button"
                variant="quiet"
                disabled={submitting}
                onClick={() => {
                  setEditingEgressPolicy(false);
                }}
              >
                Cancel
              </Button>
              <Button type="submit" variant="primary" busy={submitting}>
                Save egress policy
              </Button>
            </div>
          </form>
        ) : (
          <DescriptionList
            items={[
              {
                term: "Mode",
                detail:
                  policy.mode === "allow_all"
                    ? "Allow all safe discovered origins"
                    : "Allow exact origins only",
              },
              {
                term: "Exact origins",
                detail:
                  policy.exact_origins.length === 0
                    ? "None configured"
                    : policy.exact_origins.map((origin) => (
                        <span className={styles["machineValue"]} key={origin}>
                          {origin}
                        </span>
                      )),
              },
              { term: "Revision", detail: String(policy.revision) },
            ]}
          />
        )}
      </Section>
      <Section title="Configured providers">
        {providers.length === 0 ? (
          <EmptyState
            level={3}
            title="No identity providers"
            description="Add Google, Custom OIDC, or GitHub using a reviewed onboarding workflow."
          />
        ) : (
          <DataTable
            caption="Configured identity providers"
            headings={["Provider", "Kind", "Status", "Assignments", "Action"]}
          >
            {providers.map((provider) => (
              <tr key={provider.id}>
                <td>
                  <button
                    className={styles["resourceLink"]}
                    type="button"
                    onClick={() => {
                      setSelectedProviderId(provider.id);
                    }}
                  >
                    {provider.display_name}
                  </button>
                  <span className={styles["machineValue"]}>{provider.provider_key}</span>
                </td>
                <td>{provider.kind}</td>
                <td>
                  <StatusBadge status={provider.status} />
                </td>
                <td>{String(provider.assigned_application_ids.length)}</td>
                <td>
                  <Button
                    type="button"
                    variant="quiet"
                    onClick={() => {
                      setSelectedProviderId(provider.id);
                    }}
                  >
                    Review
                  </Button>
                </td>
              </tr>
            ))}
          </DataTable>
        )}
      </Section>
      {selectedProvider === null ? null : (
        <ProviderDetail
          provider={selectedProvider}
          applications={applications}
          onAssign={assign}
          onReconcile={() => {
            setReconcileProvider(selectedProvider);
          }}
          onDisable={() => {
            setConfirmation({ kind: "disable", provider: selectedProvider });
          }}
          onUnassign={(application) => {
            setConfirmation({ kind: "unassign", provider: selectedProvider, application });
          }}
        />
      )}
      <ProviderOnboardingDialog
        kind={onboarding}
        preflight={preflight}
        preflightIssuer={preflightIssuer}
        policy={policy}
        submitting={submitting}
        onClose={closeOnboarding}
        secretInputRef={onboardingSecretInput}
        onIssuerChanged={() => {
          clearOnboardingSecret();
          setPreflight(null);
          setPreflightIssuer("");
        }}
        onPreflight={runPreflight}
        onCreate={createProvider}
        onAdoptOrigins={() => void adoptPreflightOrigins()}
      />
      <Dialog
        open={reconcileProvider !== null}
        title="Resume provider provisioning"
        onClose={() => {
          if (!submitting) setReconcileProvider(null);
        }}
        actions={
          <>
            <Button
              type="button"
              variant="quiet"
              disabled={submitting}
              onClick={() => {
                setReconcileProvider(null);
              }}
            >
              Cancel
            </Button>
            <Button type="submit" variant="primary" form="reconcile-provider" busy={submitting}>
              Resume provisioning
            </Button>
          </>
        }
      >
        <form
          id="reconcile-provider"
          className={styles["form"]}
          onSubmit={(event) => void reconcile(event)}
        >
          <p>Re-enter the write-only client secret for {reconcileProvider?.display_name}.</p>
          <Field label="Client secret" htmlFor="reconcile-secret">
            <Input
              id="reconcile-secret"
              name="client_secret"
              type="password"
              autoComplete="new-password"
              required
              maxLength={4096}
            />
          </Field>
        </form>
      </Dialog>
      <Dialog
        open={confirmation !== null}
        title={confirmation?.kind === "disable" ? "Disable provider" : "Remove provider assignment"}
        onClose={() => {
          if (!submitting) setConfirmation(null);
        }}
        actions={
          <>
            <Button
              type="button"
              variant="quiet"
              disabled={submitting}
              onClick={() => {
                setConfirmation(null);
              }}
            >
              Cancel
            </Button>
            <Button
              type="button"
              variant="danger"
              busy={submitting}
              onClick={() => void confirmAction()}
            >
              {confirmation?.kind === "disable" ? "Disable provider" : "Remove assignment"}
            </Button>
          </>
        }
      >
        {confirmation?.kind === "disable" ? (
          <p>
            Disable <strong>{confirmation.provider.display_name}</strong> and prevent all of its
            current assignments from being used?
          </p>
        ) : confirmation?.kind === "unassign" ? (
          <p>
            Remove <strong>{confirmation.provider.display_name}</strong> from{" "}
            <strong>{confirmation.application.display_name}</strong>?
          </p>
        ) : null}
      </Dialog>
    </div>
  );
}

function ProviderDetail({
  provider,
  applications,
  onAssign,
  onReconcile,
  onDisable,
  onUnassign,
}: {
  readonly provider: Provider;
  readonly applications: Application[];
  readonly onAssign: (
    provider: Provider,
    event: SyntheticEvent<HTMLFormElement, SubmitEvent>,
  ) => Promise<void>;
  readonly onReconcile: () => void;
  readonly onDisable: () => void;
  readonly onUnassign: (application: Application) => void;
}) {
  const assigned = applications.filter((application) =>
    provider.assigned_application_ids.includes(application.id),
  );
  const available = applications.filter(
    (application) =>
      application.status === "active" &&
      !provider.assigned_application_ids.includes(application.id),
  );
  return (
    <Section
      title={provider.display_name}
      description="Committed provider state and Application assignments."
    >
      <div className={styles["detailSurface"]}>
        <DescriptionList
          items={[
            {
              term: "Provider key",
              detail: <span className={styles["machineValue"]}>{provider.provider_key}</span>,
            },
            { term: "Kind", detail: provider.kind },
            { term: "Status", detail: <StatusBadge status={provider.status} /> },
            {
              term: "Callback URL",
              detail: <span className={styles["machineValue"]}>{provider.callback_url}</span>,
            },
            {
              term: "Managed profile",
              detail: provider.managed_profile.enabled ? "Enabled" : "Disabled",
            },
            {
              term: "Fixed scopes",
              detail: provider.managed_profile.exact_scopes.join(" ") || "None",
            },
          ]}
        />
        {provider.status === "provisioning" ? (
          <div className={styles["formActions"]}>
            <Button type="button" variant="primary" onClick={onReconcile}>
              Resume provisioning
            </Button>
          </div>
        ) : null}
        {provider.status === "active" && available.length > 0 ? (
          <form className={styles["form"]} onSubmit={(event) => void onAssign(provider, event)}>
            <Field label="Assign to Application" htmlFor={`provider-assignment-${provider.id}`}>
              <Select id={`provider-assignment-${provider.id}`} name="application_id">
                {available.map((application) => (
                  <option key={application.id} value={application.id}>
                    {application.display_name}
                  </option>
                ))}
              </Select>
            </Field>
            <div className={styles["formActions"]}>
              <Button type="submit" variant="secondary">
                Assign provider
              </Button>
            </div>
          </form>
        ) : null}
        <h3>Assigned Applications</h3>
        {assigned.length === 0 ? (
          <p className={styles["muted"]}>No assignments.</p>
        ) : (
          <ul>
            {assigned.map((application) => (
              <li key={application.id}>
                {application.display_name}{" "}
                <Button
                  type="button"
                  variant="quiet"
                  onClick={() => {
                    onUnassign(application);
                  }}
                >
                  Remove
                </Button>
              </li>
            ))}
          </ul>
        )}
        {provider.status === "active" ? (
          <div className={styles["dangerZone"]}>
            <h3>Disable provider</h3>
            <p>Disabling removes this provider from active sign-in methods.</p>
            <Button type="button" variant="danger" onClick={onDisable}>
              Disable provider
            </Button>
          </div>
        ) : null}
      </div>
    </Section>
  );
}

function ProviderOnboardingDialog({
  kind,
  preflight,
  preflightIssuer,
  policy,
  submitting,
  secretInputRef,
  onClose,
  onIssuerChanged,
  onPreflight,
  onCreate,
  onAdoptOrigins,
}: {
  readonly kind: OnboardingKind | null;
  readonly preflight: OidcPreflightResult | null;
  readonly preflightIssuer: string;
  readonly policy: ProviderEgressPolicy | null;
  readonly submitting: boolean;
  readonly secretInputRef: RefObject<HTMLInputElement | null>;
  readonly onClose: () => void;
  readonly onIssuerChanged: () => void;
  readonly onPreflight: (event: SyntheticEvent<HTMLFormElement, SubmitEvent>) => Promise<void>;
  readonly onCreate: (event: SyntheticEvent<HTMLFormElement, SubmitEvent>) => Promise<void>;
  readonly onAdoptOrigins: () => void;
}) {
  const title =
    kind === "google" ? "Add Google" : kind === "github" ? "Add GitHub" : "Add Custom OIDC";
  const formId = "provider-onboarding";
  return (
    <Dialog
      open={kind !== null}
      title={title}
      onClose={onClose}
      actions={
        <>
          <Button type="button" variant="quiet" disabled={submitting} onClick={onClose}>
            Cancel
          </Button>
          <Button
            type="submit"
            variant="primary"
            form={formId}
            busy={submitting}
            disabled={kind === "oidc" && preflight === null}
          >
            Add provider
          </Button>
        </>
      }
    >
      {kind === "oidc" ? (
        <form className={styles["form"]} onSubmit={(event) => void onPreflight(event)}>
          <Field label="Canonical HTTPS issuer" htmlFor="provider-preflight-issuer">
            <Input
              id="provider-preflight-issuer"
              name="issuer"
              type="url"
              required
              onChange={onIssuerChanged}
              defaultValue={preflightIssuer}
            />
          </Field>
          <Button type="submit" variant="secondary" busy={submitting}>
            Run preflight
          </Button>
        </form>
      ) : (
        <InlineAlert tone="info">
          {kind === "google"
            ? "Google uses OwlAuth's fixed issuer and adapter profile."
            : "GitHub uses OwlAuth's fixed login-only profile; managed sync is unavailable."}
        </InlineAlert>
      )}
      {preflight === null ? null : (
        <div className={styles["detailSurface"]}>
          <h3>Preflight result</h3>
          <DescriptionList
            items={[
              {
                term: "Canonical issuer",
                detail: (
                  <span className={styles["machineValue"]}>{preflight.canonical_issuer}</span>
                ),
              },
              {
                term: "Policy",
                detail: `${preflight.policy_mode}, revision ${String(preflight.policy_revision)}`,
              },
              {
                term: "PKCE S256",
                detail: preflight.pkce_s256_supported ? "Supported" : "Unsupported",
              },
              {
                term: "Authorization code",
                detail: preflight.authorization_code_supported ? "Supported" : "Unsupported",
              },
              {
                term: "RS256 ID tokens",
                detail: preflight.rs256_id_tokens_supported ? "Supported" : "Unsupported",
              },
              {
                term: "Managed profile",
                detail: preflight.managed_profile_supported ? "Supported" : "Unsupported",
              },
              { term: "Exact scopes", detail: preflight.exact_scopes.join(" ") },
              {
                term: "Endpoint origins",
                detail: preflight.admitted_endpoint_origins.map((origin) => (
                  <span className={styles["machineValue"]} key={origin}>
                    {origin}
                  </span>
                )),
              },
            ]}
          />
          {policy !== null &&
          (policy.mode !== "exact_origins" ||
            preflight.admitted_endpoint_origins.some(
              (origin) => !policy.exact_origins.includes(origin),
            )) ? (
            <Button type="button" variant="secondary" onClick={onAdoptOrigins}>
              Adopt reviewed origins as exact policy
            </Button>
          ) : null}
        </div>
      )}
      <form id={formId} className={styles["form"]} onSubmit={(event) => void onCreate(event)}>
        <Field
          label="Provider key"
          htmlFor="provider-key"
          description="A stable lowercase identifier."
        >
          <Input
            id="provider-key"
            name="provider_key"
            required
            pattern="[a-z][a-z0-9_-]*"
            maxLength={64}
          />
        </Field>
        <Field label="Display name" htmlFor="provider-name">
          <Input id="provider-name" name="display_name" required maxLength={128} />
        </Field>
        <Field label="Client ID" htmlFor="provider-client-id">
          <Input id="provider-client-id" name="client_id" required maxLength={512} />
        </Field>
        <Field
          label="Client secret"
          htmlFor="provider-client-secret"
          description="Write-only. It is cleared on every submission and transition."
        >
          <Input
            ref={secretInputRef}
            id="provider-client-secret"
            name="client_secret"
            type="password"
            required
            autoComplete="new-password"
            maxLength={4096}
          />
        </Field>
        {kind === "github" ? null : (
          <Checkbox name="managed_profile_enabled">
            Enable bounded managed profile synchronization
          </Checkbox>
        )}
      </form>
    </Dialog>
  );
}

function text(fields: FormData, name: string): string {
  const value = fields.get(name);
  return typeof value === "string" ? value : "";
}

function lines(fields: FormData, name: string): string[] {
  return text(fields, name)
    .split(/\r?\n/u)
    .map((value) => value.trim())
    .filter(Boolean);
}
