import { Fragment, useCallback, useEffect, useRef, useState } from "react";
import type { RefObject, SyntheticEvent } from "react";
import { Link, useParams } from "react-router";

import { CopyValue } from "../../shared/compositions/CopyValue";
import {
  compactStringList,
  isValidStringList,
  StringListField,
} from "../../shared/compositions/StringListField";
import { ChevronDownIcon, ProviderIcon } from "../../shared/icons/Icons";
import {
  DataTable,
  DescriptionList,
  EmptyState,
  LoadingState,
  PageHeader,
  Section,
} from "../../shared/layout/Layout";
import { Button } from "../../shared/primitives/Button";
import { InlineAlert, StatusBadge } from "../../shared/primitives/Feedback";
import { Checkbox, Field, Input, Select } from "../../shared/primitives/Field";
import { Dialog, SideSheet } from "../../shared/primitives/Overlay";
import { useControl, useProject } from "../app/ControlContext";
import { UnsavedChangesGuard } from "../app/UnsavedChangesGuard";
import {
  ControlRequestError,
  IdempotencyAttempt,
  type NamedProviderPreflightResult,
  type OidcPreflightResult,
  type Provider,
  type ProviderEgressPolicy,
  requireData,
} from "../client";
import styles from "./pages.module.css";

type OnboardingKind = "google" | "oidc" | "github";
type Confirmation =
  | { kind: "disable"; provider: Provider }
  | { kind: "abandon-secret-replacement"; provider: Provider }
  | null;

export function ProvidersPage() {
  const { projectId } = useParams();
  const project = useProject(projectId);
  const { session, refreshProjects, handleError, setMessage } = useControl();
  const [providers, setProviders] = useState<Provider[]>([]);
  const [policy, setPolicy] = useState<ProviderEgressPolicy | null>(null);
  const [loadState, setLoadState] = useState<"loading" | "ready" | "failed">("loading");
  const [expandedProviderId, setExpandedProviderId] = useState<string | null>(null);
  const [editingProvider, setEditingProvider] = useState<Provider | null>(null);
  const [choosingProvider, setChoosingProvider] = useState(false);
  const [onboarding, setOnboarding] = useState<OnboardingKind | null>(null);
  const [preflight, setPreflight] = useState<OidcPreflightResult | null>(null);
  const [preflightIssuer, setPreflightIssuer] = useState("");
  const [namedPreflight, setNamedPreflight] = useState<NamedProviderPreflightResult | null>(null);
  const [providerKey, setProviderKey] = useState("");
  const [editingEgressPolicy, setEditingEgressPolicy] = useState(false);
  const [egressMode, setEgressMode] = useState<"allow_all" | "exact_origins">("allow_all");
  const [egressOrigins, setEgressOrigins] = useState<string[]>([""]);
  const [egressError, setEgressError] = useState<string | null>(null);
  const [overlayError, setOverlayError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [reconcileProvider, setReconcileProvider] = useState<Provider | null>(null);
  const [resolvingSecretReplacement, setResolvingSecretReplacement] = useState<Provider | null>(
    null,
  );
  const [confirmation, setConfirmation] = useState<Confirmation>(null);
  const createAttempt = useRef(new IdempotencyAttempt());
  const updateAttempt = useRef(new IdempotencyAttempt());
  const onboardingSecretInput = useRef<HTMLInputElement>(null);
  const editSecretInput = useRef<HTMLInputElement>(null);
  const replacementRecoverySecretInput = useRef<HTMLInputElement>(null);

  const clearOnboardingSecret = useCallback(() => {
    if (onboardingSecretInput.current !== null) onboardingSecretInput.current.value = "";
  }, []);

  const refresh = useCallback(
    async (signal?: AbortSignal) => {
      if (project === null) return;
      setLoadState("loading");
      try {
        const [providerResult, policyResult] = await Promise.all([
          session.client.GET("/v1/projects/{project_id}/providers", {
            params: { path: { project_id: project.id } },
            signal: signal ?? null,
          }),
          session.client.GET("/v1/projects/{project_id}/provider-egress-policy", {
            params: { path: { project_id: project.id } },
            signal: signal ?? null,
          }),
        ]);
        const nextProviders = requireData(
          providerResult.data,
          providerResult.error,
          providerResult.response,
        ).items;
        const nextPolicy = requireData(
          policyResult.data,
          policyResult.error,
          policyResult.response,
        );
        if (signal?.aborted !== true) {
          setProviders(nextProviders);
          setPolicy(nextPolicy);
          setExpandedProviderId((current) =>
            current !== null && nextProviders.some((provider) => provider.id === current)
              ? current
              : null,
          );
          setEditingProvider((current) =>
            current === null
              ? null
              : (nextProviders.find((provider) => provider.id === current.id) ?? null),
          );
          setResolvingSecretReplacement((current) =>
            current === null
              ? null
              : (nextProviders.find((provider) => provider.id === current.id) ?? null),
          );
          setLoadState("ready");
        }
      } catch (error) {
        if (signal?.aborted !== true) setLoadState("failed");
        throw error;
      }
    },
    [project, session],
  );

  useEffect(() => {
    const controller = new AbortController();
    const timer = window.setTimeout(() => {
      void refresh(controller.signal).catch((error: unknown) => {
        if (!controller.signal.aborted) void handleError(error);
      });
    }, 0);
    return () => {
      window.clearTimeout(timer);
      controller.abort();
    };
  }, [handleError, refresh]);

  function closeOnboarding() {
    if (submitting) return;
    clearOnboardingSecret();
    createAttempt.current.abandon();
    setPreflight(null);
    setPreflightIssuer("");
    setNamedPreflight(null);
    setProviderKey("");
    setOverlayError(null);
    setOnboarding(null);
  }

  function closeProviderEditor() {
    if (submitting) return;
    const refreshReplacementState = updateAttempt.current.retainsKey;
    updateAttempt.current.abandon();
    if (editSecretInput.current !== null) editSecretInput.current.value = "";
    setEditingProvider(null);
    setOverlayError(null);
    if (refreshReplacementState) {
      void refresh().catch((error: unknown) => void handleError(error));
    }
  }

  async function runPreflight(event: SyntheticEvent<HTMLFormElement, SubmitEvent>) {
    event.preventDefault();
    if (project === null) return;
    const fields = new FormData(event.currentTarget);
    const issuer = text(fields, "issuer").trim();
    if (!/^[a-z][a-z0-9_-]{0,63}$/u.test(providerKey)) return;
    clearOnboardingSecret();
    setOverlayError(null);
    setSubmitting(true);
    setPreflight(null);
    try {
      const result = await session.client.POST(
        "/v1/projects/{project_id}/providers/oidc/preflight",
        {
          params: { path: { project_id: project.id } },
          body: { provider_key: providerKey, issuer },
        },
      );
      const checked = requireData(result.data, result.error, result.response);
      setPreflight(checked);
      setPreflightIssuer(issuer);
      setMessage("Custom OIDC metadata passed preflight review.", "success");
    } catch (error) {
      setOverlayError(errorMessage(error, "Custom OIDC preflight could not be completed."));
      await handleError(error, async () => {
        setPreflight(null);
        setPreflightIssuer("");
        await Promise.all([refresh(), refreshProjects()]);
      });
    } finally {
      setSubmitting(false);
    }
  }

  async function runNamedPreflight() {
    if (
      project === null ||
      onboarding === null ||
      onboarding === "oidc" ||
      !/^[a-z][a-z0-9_-]{0,63}$/u.test(providerKey)
    )
      return;
    clearOnboardingSecret();
    setOverlayError(null);
    setSubmitting(true);
    setNamedPreflight(null);
    try {
      const result = await session.client.POST(
        "/v1/projects/{project_id}/providers/named/preflight",
        {
          params: { path: { project_id: project.id } },
          body: { kind: onboarding, provider_key: providerKey },
        },
      );
      setNamedPreflight(requireData(result.data, result.error, result.response));
      setMessage("Provider registration settings are ready for review.", "success");
    } catch (error) {
      setOverlayError(errorMessage(error, "Provider registration settings could not be loaded."));
      await handleError(error, async () => {
        setNamedPreflight(null);
        await Promise.all([refresh(), refreshProjects()]);
      });
    } finally {
      setSubmitting(false);
    }
  }

  async function updateEgressPolicy(event: SyntheticEvent<HTMLFormElement, SubmitEvent>) {
    event.preventDefault();
    if (
      project === null ||
      policy === null ||
      (egressMode === "exact_origins" && !isValidStringList(egressOrigins, true))
    )
      return;
    clearOnboardingSecret();
    setEgressError(null);
    setSubmitting(true);
    try {
      const result = await session.client.PUT("/v1/projects/{project_id}/provider-egress-policy", {
        params: { path: { project_id: project.id } },
        body: {
          mode: egressMode,
          exact_origins: egressMode === "exact_origins" ? compactStringList(egressOrigins) : [],
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
      setEgressError("Provider destination policy could not be updated.");
      await handleError(error, async () => {
        await refresh();
        setEditingEgressPolicy(false);
      });
    } finally {
      setSubmitting(false);
    }
  }

  async function adoptPreflightOrigins() {
    if (project === null || policy?.mode !== "exact_origins" || preflight === null) {
      return;
    }
    clearOnboardingSecret();
    setOverlayError(null);
    setSubmitting(true);
    const proposedOrigins = [
      ...new Set([...policy.exact_origins, ...preflight.admitted_endpoint_origins]),
    ].sort();
    try {
      const result = await session.client.PUT("/v1/projects/{project_id}/provider-egress-policy", {
        params: { path: { project_id: project.id } },
        body: {
          mode: "exact_origins",
          exact_origins: proposedOrigins,
          expected_revision: policy.revision,
        },
      });
      setPolicy(requireData(result.data, result.error, result.response));
      setPreflight(null);
      setPreflightIssuer("");
      setMessage(
        "Reviewed origins added without removing existing destinations. Run preflight again against the updated policy.",
        "success",
      );
    } catch (error) {
      clearOnboardingSecret();
      setPreflight(null);
      setPreflightIssuer("");
      setOverlayError(
        errorMessage(error, "The reviewed origins could not be added. Run preflight again."),
      );
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
    if (
      (onboarding === "oidc" && preflight === null) ||
      (onboarding !== "oidc" && namedPreflight === null)
    ) {
      createAttempt.current.abandon();
      setOverlayError(
        onboarding === "oidc"
          ? "Run Custom OIDC preflight and review its result before creating the provider."
          : "Review the provider registration settings before creating the provider.",
      );
      return;
    }
    const body = {
      kind: onboarding,
      provider_key: providerKey,
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
    setOverlayError(null);
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
      setExpandedProviderId(created.id);
      closeOnboardingAfterSuccess();
      setMessage("Provider configured. Its client secret was discarded from the page.", "success");
    } catch (error) {
      body.client_secret = "";
      createAttempt.current.settle(error);
      setPreflight(null);
      setPreflightIssuer("");
      setNamedPreflight(null);
      setOverlayError(errorMessage(error, "Provider setup could not be completed."));
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
    setNamedPreflight(null);
    setProviderKey("");
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
    setOverlayError(null);
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
      setOverlayError(errorMessage(error, "Provider provisioning could not be resumed."));
      await handleError(error, refresh);
    } finally {
      setSubmitting(false);
    }
  }

  async function updateProvider(event: SyntheticEvent<HTMLFormElement, SubmitEvent>) {
    event.preventDefault();
    if (project === null || editingProvider === null) return;
    const form = event.currentTarget;
    const fields = new FormData(form);
    const clientSecret = text(fields, "client_secret");
    const secretInput = form.elements.namedItem("client_secret");
    if (secretInput instanceof HTMLInputElement) secretInput.value = "";
    if (clientSecret === "" && updateAttempt.current.retainsKey) {
      setOverlayError(
        "Re-enter the client secret to retry the unresolved replacement, or cancel this editor before making a metadata-only update.",
      );
      return;
    }
    const metadata = {
      display_name: text(fields, "display_name"),
      client_id: text(fields, "client_id"),
      expected_provider_revision: editingProvider.revision,
    };
    const idempotencyKey = clientSecret === "" ? null : updateAttempt.current.begin();
    if (clientSecret !== "" && idempotencyKey === null) return;
    setOverlayError(null);
    setSubmitting(true);
    try {
      if (clientSecret === "") {
        const result = await session.client.PATCH(
          "/v1/projects/{project_id}/providers/{provider_id}",
          {
            params: { path: { project_id: project.id, provider_id: editingProvider.id } },
            body: metadata,
          },
        );
        requireData(result.data, result.error, result.response);
      } else {
        if (idempotencyKey === null) return;
        const body = { ...metadata, client_secret: clientSecret };
        const result = await (async () => {
          try {
            return await session.client.POST(
              "/v1/projects/{project_id}/providers/{provider_id}/replace-secret",
              {
                params: {
                  path: { project_id: project.id, provider_id: editingProvider.id },
                  header: { "Idempotency-Key": idempotencyKey },
                },
                body,
              },
            );
          } finally {
            body.client_secret = "";
          }
        })();
        requireData(result.data, result.error, result.response);
        updateAttempt.current.settle();
      }
      await refresh();
      setEditingProvider(null);
      setMessage(
        clientSecret === ""
          ? "Provider configuration updated."
          : "Provider configuration and client secret updated. The secret was discarded from the page.",
        "success",
      );
    } catch (error) {
      if (clientSecret !== "") updateAttempt.current.settle(error);
      if (updateAttempt.current.retainsKey) {
        try {
          await refresh();
        } catch (refreshError) {
          await handleError(refreshError);
        }
      }
      setOverlayError(
        updateAttempt.current.retainsKey
          ? "The replacement result is unresolved. Re-enter the same client secret to retry safely with the retained operation key."
          : errorMessage(error, "Provider configuration could not be updated."),
      );
      await handleError(error, async () => {
        updateAttempt.current.abandon();
        await refresh();
        setEditingProvider(null);
      });
    } finally {
      setSubmitting(false);
    }
  }

  async function reconcileSecretReplacement(event: SyntheticEvent<HTMLFormElement, SubmitEvent>) {
    event.preventDefault();
    if (project === null || resolvingSecretReplacement === null) return;
    const form = event.currentTarget;
    const fields = new FormData(form);
    const body = {
      client_secret: text(fields, "client_secret"),
      expected_provider_revision: resolvingSecretReplacement.revision,
    };
    const secretInput = form.elements.namedItem("client_secret");
    if (secretInput instanceof HTMLInputElement) secretInput.value = "";
    setOverlayError(null);
    setSubmitting(true);
    try {
      const result = await (async () => {
        try {
          return await session.client.POST(
            "/v1/projects/{project_id}/providers/{provider_id}/replace-secret/reconcile",
            {
              params: {
                path: {
                  project_id: project.id,
                  provider_id: resolvingSecretReplacement.id,
                },
              },
              body,
            },
          );
        } finally {
          body.client_secret = "";
        }
      })();
      requireData(result.data, result.error, result.response);
      await refresh();
      setResolvingSecretReplacement(null);
      setMessage(
        "Provider client secret replacement reconciled. The secret was discarded from the page.",
        "success",
      );
    } catch (error) {
      body.client_secret = "";
      setOverlayError(errorMessage(error, "The client secret replacement could not be resumed."));
      await handleError(error, async () => {
        await refresh();
        setResolvingSecretReplacement(null);
      });
    } finally {
      setSubmitting(false);
    }
  }

  async function confirmAction() {
    if (project === null || confirmation === null) return;
    setOverlayError(null);
    setSubmitting(true);
    try {
      const path =
        confirmation.kind === "disable"
          ? ("/v1/projects/{project_id}/providers/{provider_id}/disable" as const)
          : ("/v1/projects/{project_id}/providers/{provider_id}/replace-secret/abandon" as const);
      const result = await session.client.POST(path, {
        params: { path: { project_id: project.id, provider_id: confirmation.provider.id } },
        body: { expected_provider_revision: confirmation.provider.revision },
      });
      requireData(result.data, result.error, result.response);
      setMessage(
        confirmation.kind === "disable"
          ? "Provider disabled."
          : "Pending client secret replacement abandoned.",
        "success",
      );
      await refresh();
      setResolvingSecretReplacement(null);
      setConfirmation(null);
    } catch (error) {
      if (
        error instanceof ControlRequestError &&
        error.status === 409 &&
        error.code === "revision_conflict"
      )
        setConfirmation(null);
      else setOverlayError(errorMessage(error, "The provider action could not be completed."));
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
          description="Configure the upstream identity providers available to Applications."
        />
        {loadState === "loading" ? (
          <LoadingState>Loading authentication providers</LoadingState>
        ) : null}
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

  return (
    <div className={styles["page"]}>
      <UnsavedChangesGuard
        dirty={
          editingEgressPolicy ||
          onboarding !== null ||
          reconcileProvider !== null ||
          resolvingSecretReplacement !== null ||
          editingProvider !== null
        }
        submitting={submitting}
        onDiscard={() => {
          clearOnboardingSecret();
          createAttempt.current.abandon();
          updateAttempt.current.abandon();
          setEditingEgressPolicy(false);
          setEditingProvider(null);
          setOnboarding(null);
          setReconcileProvider(null);
          setResolvingSecretReplacement(null);
          setPreflight(null);
          setPreflightIssuer("");
          setNamedPreflight(null);
          setProviderKey("");
          setEgressError(null);
          setOverlayError(null);
        }}
      />
      <PageHeader
        title="Authentication providers"
        description="Configure the upstream identity providers available to Applications."
        actions={
          project.status === "active" ? (
            <Button
              type="button"
              variant="primary"
              onClick={() => {
                setChoosingProvider(true);
              }}
            >
              Add provider
            </Button>
          ) : undefined
        }
      />
      <Section
        title="Allowed provider destinations"
        description="Control which HTTPS origins providers may contact during sign-in."
        action={
          policy !== null && project.status === "active" ? (
            <Button
              type="button"
              variant="secondary"
              onClick={() => {
                setEgressMode(policy.mode);
                setEgressOrigins(
                  policy.exact_origins.length === 0 ? [""] : [...policy.exact_origins],
                );
                setEgressError(null);
                setEditingEgressPolicy(true);
              }}
            >
              Edit destinations
            </Button>
          ) : undefined
        }
      >
        {policy === null ? (
          <LoadingState>Loading allowed destinations</LoadingState>
        ) : (
          <DescriptionList
            items={[
              {
                term: "Mode",
                detail:
                  policy.mode === "allow_all"
                    ? "Trust operator-selected provider origins"
                    : "Allow exact reviewed origins only",
              },
              ...(policy.mode === "exact_origins"
                ? [
                    {
                      term: "Allowed origins",
                      detail:
                        policy.exact_origins.length === 0
                          ? "None configured"
                          : policy.exact_origins.map((origin) => (
                              <CopyValue
                                key={origin}
                                value={origin}
                                label="provider origin"
                                block
                              />
                            )),
                    },
                  ]
                : []),
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
            headings={["Provider", "Kind", "Status", "Action", "Details"]}
          >
            {providers.map((provider) => {
              const expanded = expandedProviderId === provider.id;
              return (
                <Fragment key={provider.id}>
                  <tr>
                    <td>
                      <strong title={provider.display_name}>{provider.display_name}</strong>
                      <span className={styles["machineValue"]}>{provider.provider_key}</span>
                    </td>
                    <td>{provider.kind}</td>
                    <td>
                      <StatusBadge status={provider.status} />
                      {provider.secret_replacement_pending ? (
                        <StatusBadge status="secret replacement pending" family="pending" />
                      ) : null}
                    </td>
                    <td>
                      <Button
                        type="button"
                        variant="quiet"
                        disabled={provider.status !== "active" || project.status !== "active"}
                        onClick={() => {
                          updateAttempt.current.abandon();
                          if (editSecretInput.current !== null) editSecretInput.current.value = "";
                          if (replacementRecoverySecretInput.current !== null) {
                            replacementRecoverySecretInput.current.value = "";
                          }
                          setOverlayError(null);
                          if (provider.secret_replacement_pending) {
                            setResolvingSecretReplacement(provider);
                          } else {
                            setEditingProvider(provider);
                          }
                        }}
                      >
                        {provider.secret_replacement_pending ? "Resolve replacement" : "Edit"}
                      </Button>
                    </td>
                    <td>
                      <Button
                        type="button"
                        variant="quiet"
                        iconOnly
                        aria-label={`${expanded ? "Collapse" : "Expand"} ${provider.display_name} details`}
                        aria-expanded={expanded}
                        aria-controls={`provider-details-${provider.id}`}
                        onClick={() => {
                          setExpandedProviderId((current) =>
                            current === provider.id ? null : provider.id,
                          );
                        }}
                      >
                        <ChevronDownIcon
                          className={
                            expanded ? styles["disclosureIconExpanded"] : styles["disclosureIcon"]
                          }
                        />
                      </Button>
                    </td>
                  </tr>
                  {expanded ? (
                    <tr id={`provider-details-${provider.id}`}>
                      <td colSpan={5} className={styles["expandedDetailCell"]}>
                        <ProviderDetail
                          provider={provider}
                          onReconcile={() => {
                            setOverlayError(null);
                            setReconcileProvider(provider);
                          }}
                          onDisable={() => {
                            setOverlayError(null);
                            setConfirmation({ kind: "disable", provider });
                          }}
                        />
                      </td>
                    </tr>
                  ) : null}
                </Fragment>
              );
            })}
          </DataTable>
        )}
      </Section>
      <Dialog
        open={choosingProvider}
        title="Choose a provider"
        onClose={() => {
          setChoosingProvider(false);
        }}
      >
        <p className={styles["muted"]}>
          Select the provider profile that matches your identity service.
        </p>
        <div className={styles["providerChoices"]}>
          {(
            [
              ["google", "Google", "Google sign-in with optional managed profile sync."],
              ["github", "GitHub", "GitHub sign-in using OwlAuth’s fixed login profile."],
              ["oidc", "Custom OIDC", "Any compatible OIDC provider, verified before setup."],
            ] as const
          ).map(([kind, title, description]) => (
            <button
              key={kind}
              type="button"
              className={styles["providerChoice"]}
              onClick={() => {
                setChoosingProvider(false);
                clearOnboardingSecret();
                setPreflight(null);
                setPreflightIssuer("");
                setNamedPreflight(null);
                setProviderKey("");
                setOverlayError(null);
                setOnboarding(kind);
              }}
            >
              <ProviderIcon kind={kind} />
              <span>
                <strong>{title}</strong>
                <small>{description}</small>
              </span>
            </button>
          ))}
        </div>
      </Dialog>
      <Dialog
        open={editingEgressPolicy && policy !== null}
        title="Edit allowed provider destinations"
        onClose={() => {
          if (!submitting) setEditingEgressPolicy(false);
        }}
        actions={
          <>
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
            <Button type="submit" form="provider-egress-form" variant="primary" busy={submitting}>
              Save destinations
            </Button>
          </>
        }
      >
        <form
          id="provider-egress-form"
          className={styles["form"]}
          onSubmit={(event) => void updateEgressPolicy(event)}
        >
          {egressError === null ? null : (
            <InlineAlert tone="danger" role="alert">
              {egressError}
            </InlineAlert>
          )}
          <Field label="Destination policy" htmlFor="egress-mode">
            <Select
              id="egress-mode"
              value={egressMode}
              data-owl-initial-focus
              onChange={(event) => {
                setEgressMode(
                  event.target.value === "exact_origins" ? "exact_origins" : "allow_all",
                );
              }}
            >
              <option value="allow_all">
                Allow safe origins discovered from provider metadata
              </option>
              <option value="exact_origins">Allow only the origins listed below</option>
            </Select>
          </Field>
          {egressMode === "exact_origins" ? (
            <StringListField
              label="Allowed origins"
              description="Add each normalized HTTPS origin providers may contact."
              itemLabel="Origin"
              placeholder={`https://identity.example.com`}
              values={egressOrigins}
              onChange={setEgressOrigins}
              required
            />
          ) : (
            <InlineAlert tone="info">
              OwlAuth will use the safe HTTPS origins discovered during provider preflight.
            </InlineAlert>
          )}
        </form>
      </Dialog>
      <ProviderOnboardingDialog
        kind={onboarding}
        preflight={preflight}
        preflightIssuer={preflightIssuer}
        namedPreflight={namedPreflight}
        providerKey={providerKey}
        policy={policy}
        submitting={submitting}
        error={overlayError}
        onClose={closeOnboarding}
        secretInputRef={onboardingSecretInput}
        onIssuerChanged={() => {
          clearOnboardingSecret();
          setPreflight(null);
          setPreflightIssuer("");
        }}
        onPreflight={runPreflight}
        onNamedPreflight={() => void runNamedPreflight()}
        onProviderKeyChanged={(value) => {
          clearOnboardingSecret();
          setPreflight(null);
          setNamedPreflight(null);
          setProviderKey(value);
        }}
        onCreate={createProvider}
        onAdoptOrigins={() => void adoptPreflightOrigins()}
      />
      <SideSheet
        open={editingProvider !== null}
        side="right"
        title="Edit provider"
        closeLabel="Close provider editor"
        onClose={closeProviderEditor}
        actions={
          <>
            <Button
              type="button"
              variant="quiet"
              disabled={submitting}
              onClick={closeProviderEditor}
            >
              Cancel
            </Button>
            <Button type="submit" form="provider-edit-form" variant="primary" busy={submitting}>
              Save provider
            </Button>
          </>
        }
      >
        {editingProvider === null ? null : (
          <form
            id="provider-edit-form"
            className={styles["form"]}
            onSubmit={(event) => void updateProvider(event)}
          >
            {overlayError === null ? null : (
              <InlineAlert tone="danger" role="alert">
                {overlayError}
              </InlineAlert>
            )}
            <DescriptionList
              items={[
                {
                  term: "Provider key",
                  detail: (
                    <span className={styles["machineValue"]}>{editingProvider.provider_key}</span>
                  ),
                },
                { term: "Kind", detail: editingProvider.kind },
                {
                  term: "Issuer",
                  detail: <span className={styles["machineValue"]}>{editingProvider.issuer}</span>,
                },
              ]}
            />
            <Field label="Display name" htmlFor="provider-edit-name">
              <Input
                id="provider-edit-name"
                name="display_name"
                defaultValue={editingProvider.display_name}
                required
                maxLength={128}
                data-owl-initial-focus
              />
            </Field>
            <Field label="Client ID" htmlFor="provider-edit-client-id">
              <Input
                id="provider-edit-client-id"
                name="client_id"
                defaultValue={editingProvider.client_id}
                required
                maxLength={512}
              />
            </Field>
            <Field
              label="New client secret"
              htmlFor="provider-edit-client-secret"
              optional
              description="Leave blank to keep the current write-only secret. Enter a value to replace it."
            >
              <Input
                ref={editSecretInput}
                id="provider-edit-client-secret"
                name="client_secret"
                type="password"
                autoComplete="new-password"
                maxLength={4096}
              />
            </Field>
          </form>
        )}
      </SideSheet>
      <Dialog
        open={resolvingSecretReplacement !== null}
        title="Resolve client secret replacement"
        onClose={() => {
          if (submitting) return;
          if (replacementRecoverySecretInput.current !== null) {
            replacementRecoverySecretInput.current.value = "";
          }
          setResolvingSecretReplacement(null);
          setOverlayError(null);
        }}
        actions={
          <>
            <Button
              type="button"
              variant="quiet"
              disabled={submitting}
              onClick={() => {
                if (replacementRecoverySecretInput.current !== null) {
                  replacementRecoverySecretInput.current.value = "";
                }
                setResolvingSecretReplacement(null);
                setOverlayError(null);
              }}
            >
              Cancel
            </Button>
            <Button
              type="button"
              variant="danger"
              disabled={submitting}
              onClick={() => {
                if (resolvingSecretReplacement !== null) {
                  if (replacementRecoverySecretInput.current !== null) {
                    replacementRecoverySecretInput.current.value = "";
                  }
                  setConfirmation({
                    kind: "abandon-secret-replacement",
                    provider: resolvingSecretReplacement,
                  });
                  setResolvingSecretReplacement(null);
                }
              }}
            >
              Abandon replacement
            </Button>
            <Button
              type="submit"
              variant="primary"
              form="reconcile-secret-replacement"
              busy={submitting}
            >
              Resume replacement
            </Button>
          </>
        }
      >
        <form
          id="reconcile-secret-replacement"
          className={styles["form"]}
          onSubmit={(event) => void reconcileSecretReplacement(event)}
        >
          {overlayError === null ? null : (
            <InlineAlert tone="danger" role="alert">
              {overlayError}
            </InlineAlert>
          )}
          <p>
            The protected replacement was prepared but not confirmed. Re-enter the intended client
            secret to resume it, or explicitly abandon the pending generation before editing this
            provider again.
          </p>
          <Field label="Replacement client secret" htmlFor="replacement-recovery-secret">
            <Input
              ref={replacementRecoverySecretInput}
              id="replacement-recovery-secret"
              name="client_secret"
              type="password"
              autoComplete="new-password"
              required
              maxLength={4096}
              data-owl-initial-focus
            />
          </Field>
        </form>
      </Dialog>
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
          {overlayError === null ? null : (
            <InlineAlert tone="danger" role="alert">
              {overlayError}
            </InlineAlert>
          )}
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
        title={
          confirmation?.kind === "abandon-secret-replacement"
            ? "Abandon client secret replacement"
            : "Disable provider"
        }
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
              {confirmation?.kind === "abandon-secret-replacement"
                ? "Abandon replacement"
                : "Disable provider"}
            </Button>
          </>
        }
      >
        {overlayError === null ? null : (
          <InlineAlert tone="danger" role="alert">
            {overlayError}
          </InlineAlert>
        )}
        {confirmation === null ? null : confirmation.kind === "disable" ? (
          <p>
            Disable <strong>{confirmation.provider.display_name}</strong> and remove it from every
            Application’s active sign-in methods?
          </p>
        ) : (
          <p>
            Abandon the pending protected client secret generation for{" "}
            <strong>{confirmation.provider.display_name}</strong>? The unpublished material will be
            erased, and the current active client secret will remain unchanged.
          </p>
        )}
      </Dialog>
    </div>
  );
}

function ProviderDetail({
  provider,
  onReconcile,
  onDisable,
}: {
  readonly provider: Provider;
  readonly onReconcile: () => void;
  readonly onDisable: () => void;
}) {
  return (
    <div className={styles["inlineDetail"]}>
      <p className={styles["muted"]}>
        Register the callback URL below as an exact redirect URI in this provider’s console.
      </p>
      <DescriptionList
        items={[
          {
            term: "Provider key",
            detail: <span className={styles["machineValue"]}>{provider.provider_key}</span>,
          },
          {
            term: "Issuer",
            detail: <span className={styles["machineValue"]}>{provider.issuer}</span>,
          },
          {
            term: "Client ID",
            detail: <span className={styles["machineValue"]}>{provider.client_id}</span>,
          },
          {
            term: "Callback URL",
            detail: <CopyValue value={provider.callback_url} label="provider callback URL" block />,
          },
          {
            term: "Callback registration",
            detail:
              "Copy this URL to the provider’s authorized redirect URI or callback URL setting.",
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
      {provider.secret_replacement_pending ? (
        <InlineAlert tone="warning">
          A protected client secret replacement is pending. Resume or abandon it from the table
          action before changing or disabling this provider.
        </InlineAlert>
      ) : null}
      {provider.status === "provisioning" ? (
        <div className={styles["formActions"]}>
          <Button type="button" variant="primary" onClick={onReconcile}>
            Resume provisioning
          </Button>
        </div>
      ) : null}
      {provider.status === "active" && !provider.secret_replacement_pending ? (
        <div className={styles["inlineDangerZone"]}>
          <div>
            <h3>Disable provider</h3>
            <p>Disabling removes this provider from every Application’s active sign-in methods.</p>
          </div>
          <Button type="button" variant="danger" onClick={onDisable}>
            Disable provider
          </Button>
        </div>
      ) : null}
    </div>
  );
}

function ProviderOnboardingDialog({
  kind,
  preflight,
  preflightIssuer,
  namedPreflight,
  providerKey,
  policy,
  submitting,
  error,
  secretInputRef,
  onClose,
  onIssuerChanged,
  onPreflight,
  onNamedPreflight,
  onProviderKeyChanged,
  onCreate,
  onAdoptOrigins,
}: {
  readonly kind: OnboardingKind | null;
  readonly preflight: OidcPreflightResult | null;
  readonly preflightIssuer: string;
  readonly namedPreflight: NamedProviderPreflightResult | null;
  readonly providerKey: string;
  readonly policy: ProviderEgressPolicy | null;
  readonly submitting: boolean;
  readonly error: string | null;
  readonly secretInputRef: RefObject<HTMLInputElement | null>;
  readonly onClose: () => void;
  readonly onIssuerChanged: () => void;
  readonly onPreflight: (event: SyntheticEvent<HTMLFormElement, SubmitEvent>) => Promise<void>;
  readonly onNamedPreflight: () => void;
  readonly onProviderKeyChanged: (value: string) => void;
  readonly onCreate: (event: SyntheticEvent<HTMLFormElement, SubmitEvent>) => Promise<void>;
  readonly onAdoptOrigins: () => void;
}) {
  const title =
    kind === "google" ? "Add Google" : kind === "github" ? "Add GitHub" : "Add Custom OIDC";
  const formId = "provider-onboarding";
  const registrationReady = kind === "oidc" ? preflight !== null : namedPreflight !== null;
  return (
    <SideSheet
      open={kind !== null}
      side="right"
      title={title}
      closeLabel="Close provider setup"
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
            disabled={!registrationReady}
          >
            Add provider
          </Button>
        </>
      }
    >
      {error === null ? null : (
        <InlineAlert tone="danger" role="alert">
          {error}
        </InlineAlert>
      )}
      {kind === "oidc" ? (
        <>
          <InlineAlert tone="info">
            Choose the stable provider key and issuer first. OwlAuth will validate discovery and
            generate the exact callback URL to register before you create upstream credentials.
          </InlineAlert>
          <form className={styles["form"]} onSubmit={(event) => void onPreflight(event)}>
            <Field
              label="Provider key"
              htmlFor="provider-preflight-key"
              description="A stable lowercase identifier used in the callback URL."
            >
              <Input
                id="provider-preflight-key"
                name="provider_key"
                required
                pattern="[a-z][a-z0-9_-]*"
                maxLength={64}
                value={providerKey}
                disabled={submitting}
                onChange={(event) => {
                  onProviderKeyChanged(event.currentTarget.value);
                }}
              />
            </Field>
            <Field label="Canonical HTTPS issuer" htmlFor="provider-preflight-issuer">
              <Input
                id="provider-preflight-issuer"
                name="issuer"
                type="url"
                required
                disabled={submitting}
                onChange={onIssuerChanged}
                defaultValue={preflightIssuer}
              />
            </Field>
            <Button type="submit" variant="secondary" busy={submitting}>
              Review registration settings
            </Button>
          </form>
        </>
      ) : (
        <InlineAlert tone="info">
          Enter a stable provider key, then review the exact registration settings generated by
          OwlAuth before creating credentials with {kind === "google" ? "Google" : "GitHub"}.
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
                term: "Callback URL",
                detail: (
                  <CopyValue value={preflight.callback_url} label="provider callback URL" block />
                ),
              },
              {
                term: "Callback registration",
                detail: "Register the callback URL above as an exact redirect URI.",
              },
              {
                term: "Policy",
                detail:
                  preflight.policy_mode === "exact_origins"
                    ? "Allowed origins match the Project destination policy"
                    : "Operator-selected discovered origins are trusted",
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
          {policy?.mode === "exact_origins" &&
          preflight.admitted_endpoint_origins.some(
            (origin) => !policy.exact_origins.includes(origin),
          ) ? (
            <Button type="button" variant="secondary" onClick={onAdoptOrigins}>
              Add reviewed origins to exact policy
            </Button>
          ) : null}
        </div>
      )}
      <form id={formId} className={styles["form"]} onSubmit={(event) => void onCreate(event)}>
        {kind === "oidc" ? null : (
          <>
            <Field
              label="Provider key"
              htmlFor="provider-key"
              description="A stable lowercase identifier used in the callback URL."
            >
              <Input
                id="provider-key"
                name="provider_key"
                required
                pattern="[a-z][a-z0-9_-]*"
                maxLength={64}
                value={providerKey}
                disabled={submitting}
                onChange={(event) => {
                  onProviderKeyChanged(event.currentTarget.value);
                }}
              />
            </Field>
            <Button
              type="button"
              variant="secondary"
              busy={submitting}
              disabled={!/^[a-z][a-z0-9_-]{0,63}$/u.test(providerKey)}
              onClick={onNamedPreflight}
            >
              Review registration settings
            </Button>
          </>
        )}
        {namedPreflight === null ? null : (
          <div className={styles["detailSurface"]}>
            <h3>Registration settings</h3>
            <DescriptionList
              items={[
                {
                  term: "Exact issuer",
                  detail: <span className={styles["machineValue"]}>{namedPreflight.issuer}</span>,
                },
                {
                  term: "Callback URL",
                  detail: (
                    <CopyValue
                      value={namedPreflight.callback_url}
                      label="provider callback URL"
                      block
                    />
                  ),
                },
                {
                  term: "Callback registration",
                  detail: "Register the callback URL above as an exact redirect URI.",
                },
                {
                  term: "Login scopes",
                  detail: namedPreflight.login.exact_scopes.join(" "),
                },
                {
                  term: "Login consent",
                  detail: consentDescription(namedPreflight.login.consent_behavior),
                },
                {
                  term: "Managed profile",
                  detail:
                    namedPreflight.managed_profile === null ||
                    namedPreflight.managed_profile === undefined
                      ? "Unavailable; this provider uses a fixed login-only profile."
                      : `${namedPreflight.managed_profile.exact_scopes.join(" ")}; ${consentDescription(namedPreflight.managed_profile.consent_behavior)}`,
                },
              ]}
            />
          </div>
        )}
        <Field label="Display name" htmlFor="provider-name">
          <Input id="provider-name" name="display_name" required maxLength={128} />
        </Field>
        <Field label="Client ID" htmlFor="provider-client-id">
          <Input
            id="provider-client-id"
            name="client_id"
            required
            maxLength={512}
            disabled={!registrationReady}
          />
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
            disabled={!registrationReady}
          />
        </Field>
        {kind === "github" ? null : (
          <Checkbox name="managed_profile_enabled" disabled={!registrationReady}>
            Enable bounded managed profile synchronization
          </Checkbox>
        )}
      </form>
    </SideSheet>
  );
}

function consentDescription(
  behavior: NamedProviderPreflightResult["login"]["consent_behavior"],
): string {
  return behavior === "explicit_offline_consent"
    ? "OwlAuth requests explicit consent and offline access."
    : "OwlAuth adds no forced consent or offline-access parameters.";
}

function errorMessage(error: unknown, fallback: string): string {
  return error instanceof ControlRequestError ? error.message : fallback;
}

function text(fields: FormData, name: string): string {
  const value = fields.get(name);
  return typeof value === "string" ? value : "";
}
