import { useEffect, useMemo, useRef, useState } from "react";
import type { SyntheticEvent } from "react";

import { Timestamp } from "../../shared/compositions/Timestamp";
import { Button } from "../../shared/primitives/Button";
import { Input, Select } from "../../shared/primitives/Field";
import { useControlConfirmation } from "../app/Confirmation";
import { safeHostedTarget } from "../safe-target";
import styles from "./features.module.css";
import {
  type Application,
  type ConfirmIdentityMutationIntentRequest,
  ControlRequestError,
  type CreateIdentityMutationIntentRequest,
  type DisposableControlClient,
  type IdentityMutationIntent,
  type IdentityMutationProofAuthority,
  IdempotencyAttempt,
  type Project,
  type ProjectUser,
  type ProjectUserIdentity,
  type Provider,
  requireData,
} from "../client";

interface IdentityOperationsProps {
  readonly session: DisposableControlClient;
  readonly project: Project;
  readonly selectedUser: ProjectUser;
  readonly users: ProjectUser[];
  readonly identities: ProjectUserIdentity[];
  readonly applications: Application[];
  readonly providers: Provider[];
  readonly hasMoreUsers: boolean;
  readonly loadingMoreUsers: boolean;
  readonly loadMoreUsers: () => Promise<void>;
  readonly reloadSelectedUser: () => Promise<void>;
  readonly onError: (error: unknown) => Promise<void>;
  readonly setMessage: (message: string | null) => void;
}

type Operation = "link" | "unlink" | "merge";
type IdentityKind = "provider" | "email";
type PrimaryDisposition = "preserve" | "clear" | "provider" | "email";
interface AuthorityDraft {
  applicationId: string;
  providerId: string;
}
type AuthorityKey = "destination" | "candidate" | "owner" | "winner" | "loser";
interface IntentWithPlan {
  intent: IdentityMutationIntent;
  plan: CreateIdentityMutationIntentRequest | null;
}

function emptyAuthorities(): Record<AuthorityKey, AuthorityDraft> {
  return {
    destination: { applicationId: "", providerId: "" },
    candidate: { applicationId: "", providerId: "" },
    owner: { applicationId: "", providerId: "" },
    winner: { applicationId: "", providerId: "" },
    loser: { applicationId: "", providerId: "" },
  };
}
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const CONFIRMATION: Record<
  Operation,
  { phrase: string; value: "link_identity" | "unlink_identity" | "merge_users" }
> = {
  link: { phrase: "LINK IDENTITY", value: "link_identity" },
  unlink: { phrase: "UNLINK IDENTITY", value: "unlink_identity" },
  merge: { phrase: "MERGE USERS", value: "merge_users" },
};

/** Drops malformed, over-cap, or non-redacted inventory rather than rendering it. */
export function validateSafeIdentityInventory(value: unknown): value is ProjectUserIdentity[] {
  if (!Array.isArray(value) || value.length > 100) return false;
  const ids = new Set<string>();
  const commonKeys = [
    "created_at",
    "id",
    "identity_kind",
    "identity_revision",
    "is_primary_source",
    "project_id",
    "status",
    "updated_at",
    "user_id",
    "verified_or_observed_at",
  ];
  for (const item of value) {
    if (typeof item !== "object" || item === null) return false;
    const identity = item as Record<string, unknown>;
    if (
      typeof identity["id"] !== "string" ||
      !UUID.test(identity["id"]) ||
      ids.has(identity["id"]) ||
      typeof identity["user_id"] !== "string" ||
      typeof identity["project_id"] !== "string" ||
      (identity["status"] !== "active" && identity["status"] !== "disabled") ||
      typeof identity["identity_revision"] !== "number" ||
      !Number.isSafeInteger(identity["identity_revision"]) ||
      identity["identity_revision"] < 1 ||
      typeof identity["is_primary_source"] !== "boolean"
    ) {
      return false;
    }
    if (identity["identity_kind"] === "provider") {
      if (
        !exactInventoryKeys(identity, [...commonKeys, "provider_key"]) ||
        typeof identity["provider_key"] !== "string" ||
        identity["provider_key"].length < 1 ||
        identity["provider_key"].length > 64 ||
        "address" in identity
      ) {
        return false;
      }
    } else if (
      identity["identity_kind"] !== "email" ||
      !exactInventoryKeys(identity, [...commonKeys, "address"]) ||
      identity["address"] !== "redacted" ||
      "provider_key" in identity
    ) {
      return false;
    }
    ids.add(identity["id"]);
  }
  return true;
}

function exactInventoryKeys(value: Record<string, unknown>, expected: string[]): boolean {
  const keys = Object.keys(value).sort();
  const sortedExpected = expected.sort();
  return (
    keys.length === sortedExpected.length &&
    keys.every((key, index) => key === sortedExpected[index])
  );
}

function identityLabel(identity: ProjectUserIdentity): string {
  const presentation =
    identity.identity_kind === "provider"
      ? `provider (${identity.provider_key} provenance label)`
      : "email (address redacted)";
  return `${presentation}; revision ${String(identity.identity_revision)}${identity.is_primary_source ? "; primary source" : ""}`;
}

function identityReference(identity: ProjectUserIdentity) {
  return {
    identity_kind: identity.identity_kind,
    identity_id: identity.id,
    expected_identity_revision: identity.identity_revision,
  } as const;
}

function userTarget(user: ProjectUser) {
  return {
    user_id: user.id,
    expected_user_revision: user.user_revision,
    expected_user_security_revision: user.security_revision,
  };
}

function snapshotPlan(
  plan: CreateIdentityMutationIntentRequest,
): CreateIdentityMutationIntentRequest {
  const copyUser = (target: {
    user_id: string;
    expected_user_revision: number;
    expected_user_security_revision: number;
  }) => Object.freeze({ ...target });
  const copyIdentity = (identity: {
    identity_kind: IdentityKind;
    identity_id: string;
    expected_identity_revision: number;
  }) => Object.freeze({ ...identity });
  const copyAuthority = (authority: IdentityMutationProofAuthority) =>
    authority.method_kind === "provider"
      ? Object.freeze({
          method_kind: "provider" as const,
          application_id: authority.application_id,
          provider_id: authority.provider_id,
        })
      : Object.freeze({
          method_kind: "email" as const,
          application_id: authority.application_id,
        });

  switch (plan.operation_kind) {
    case "link":
      return Object.freeze({
        operation_kind: "link" as const,
        destination: copyUser(plan.destination),
        destination_identity: copyIdentity(plan.destination_identity),
        candidate_identity_kind: plan.candidate_identity_kind,
        destination_proof_authority: copyAuthority(plan.destination_proof_authority),
        candidate_proof_authority: copyAuthority(plan.candidate_proof_authority),
      });
    case "unlink": {
      const disposition = plan.primary_source_disposition;
      return Object.freeze({
        operation_kind: "unlink" as const,
        owner: copyUser(plan.owner),
        identity: copyIdentity(plan.identity),
        proof_authority: copyAuthority(plan.proof_authority),
        primary_source_disposition:
          disposition.disposition === "preserve" || disposition.disposition === "clear"
            ? Object.freeze({ disposition: disposition.disposition })
            : Object.freeze({
                disposition: disposition.disposition,
                identity_id: disposition.identity_id,
                expected_identity_revision: disposition.expected_identity_revision,
              }),
      });
    }
    case "merge":
      return Object.freeze({
        operation_kind: "merge" as const,
        winner: copyUser(plan.winner),
        winner_identity: copyIdentity(plan.winner_identity),
        winner_proof_authority: copyAuthority(plan.winner_proof_authority),
        loser: copyUser(plan.loser),
        loser_identity: copyIdentity(plan.loser_identity),
        loser_proof_authority: copyAuthority(plan.loser_proof_authority),
        primary_source: copyIdentity(plan.primary_source),
        sessions_disposition: plan.sessions_disposition,
        bindings_disposition: plan.bindings_disposition,
      });
  }
}

export function IdentityOperations({
  session,
  project,
  selectedUser,
  users,
  identities,
  applications,
  providers,
  hasMoreUsers,
  loadingMoreUsers,
  loadMoreUsers,
  reloadSelectedUser,
  onError,
  setMessage,
}: IdentityOperationsProps) {
  const confirm = useControlConfirmation();
  const [operation, setOperation] = useState<Operation | "">("");
  const [selectedIdentityId, setSelectedIdentityId] = useState("");
  const [candidateKind, setCandidateKind] = useState<IdentityKind | "">("");
  const [counterpartUserId, setCounterpartUserId] = useState("");
  const [counterpartIdentities, setCounterpartIdentities] = useState<ProjectUserIdentity[]>([]);
  const [counterpartIdentityId, setCounterpartIdentityId] = useState("");
  const [loadingCounterpart, setLoadingCounterpart] = useState(false);
  const [primaryDisposition, setPrimaryDisposition] = useState<PrimaryDisposition | "">("");
  const [primaryIdentityId, setPrimaryIdentityId] = useState("");
  const [authorities, setAuthorities] =
    useState<Record<AuthorityKey, AuthorityDraft>>(emptyAuthorities);
  const [active, setActive] = useState<IntentWithPlan | null>(null);
  const [readIntentId, setReadIntentId] = useState("");
  const [confirmation, setConfirmation] = useState("");
  const [pending, setPending] = useState(false);
  const [popupFallback, setPopupFallback] = useState<string | null>(null);
  const [localNotice, setLocalNotice] = useState<string | null>(null);
  const createAttempt = useRef(new IdempotencyAttempt());
  const createOwner = useRef<string | null>(null);
  const counterpartInventoryRequest = useRef<AbortController | null>(null);
  const counterpartUserIdRef = useRef("");

  useEffect(
    () => () => {
      counterpartInventoryRequest.current?.abort();
    },
    [],
  );

  const activeIdentities = useMemo(
    () => identities.filter((identity) => identity.status === "active"),
    [identities],
  );
  const selectedIdentity =
    activeIdentities.find((identity) => identity.id === selectedIdentityId) ?? null;
  const counterpartUser = users.find((user) => user.id === counterpartUserId) ?? null;
  const counterpartIdentity =
    counterpartIdentities.find((identity) => identity.id === counterpartIdentityId) ?? null;

  async function loadCounterpartInventory() {
    if (counterpartUser === null) return;
    counterpartInventoryRequest.current?.abort();
    const controller = new AbortController();
    counterpartInventoryRequest.current = controller;
    const requestedUserId = counterpartUser.id;
    setLoadingCounterpart(true);
    setLocalNotice(null);
    try {
      const result = await session.client.GET(
        "/v1/projects/{project_id}/users/{user_id}/identities",
        {
          params: { path: { project_id: project.id, user_id: requestedUserId } },
          signal: controller.signal,
        },
      );
      if (controller.signal.aborted || counterpartUserIdRef.current !== requestedUserId) return;
      const loaded = requireData(result.data, result.error, result.response).items;
      if (!validateSafeIdentityInventory(loaded)) {
        throw new Error("Unsafe identity inventory response");
      }
      setCounterpartIdentities(loaded.filter((identity) => identity.status === "active"));
      setCounterpartIdentityId("");
      setPrimaryIdentityId("");
      clearAuthority("loser");
      setLocalNotice("Loaded the bounded, redacted identity inventory for the losing user.");
    } catch (error) {
      if (!controller.signal.aborted) await onError(error);
    } finally {
      if (counterpartInventoryRequest.current === controller) {
        counterpartInventoryRequest.current = null;
        setLoadingCounterpart(false);
      }
    }
  }

  function setAuthority(key: AuthorityKey, change: Partial<AuthorityDraft>) {
    setAuthorities((current) => ({
      ...current,
      [key]: { ...current[key], ...change },
    }));
  }

  function clearAuthority(key: AuthorityKey) {
    setAuthorities((current) => ({
      ...current,
      [key]: { applicationId: "", providerId: "" },
    }));
  }

  function authority(kind: IdentityKind, key: AuthorityKey): IdentityMutationProofAuthority | null {
    const draft = authorities[key];
    if (draft.applicationId === "") return null;
    if (kind === "email") return { method_kind: "email", application_id: draft.applicationId };
    if (draft.providerId === "") return null;
    return {
      method_kind: "provider",
      application_id: draft.applicationId,
      provider_id: draft.providerId,
    };
  }

  function buildPlan(): CreateIdentityMutationIntentRequest | null {
    if (operation === "" || selectedIdentity === null) return null;
    if (operation === "link") {
      if (candidateKind === "") return null;
      const destinationAuthority = authority(selectedIdentity.identity_kind, "destination");
      const candidateAuthority = authority(candidateKind, "candidate");
      if (destinationAuthority === null || candidateAuthority === null) return null;
      return {
        operation_kind: "link",
        destination: userTarget(selectedUser),
        destination_identity: identityReference(selectedIdentity),
        candidate_identity_kind: candidateKind,
        destination_proof_authority: destinationAuthority,
        candidate_proof_authority: candidateAuthority,
      };
    }
    if (operation === "unlink") {
      const proofAuthority = authority(selectedIdentity.identity_kind, "owner");
      if (proofAuthority === null) return null;
      const replacement = activeIdentities.find((identity) => identity.id === primaryIdentityId);
      const disposition =
        primaryDisposition === "preserve" || primaryDisposition === "clear"
          ? { disposition: primaryDisposition }
          : replacement?.identity_kind === primaryDisposition
            ? {
                disposition: primaryDisposition,
                identity_id: replacement.id,
                expected_identity_revision: replacement.identity_revision,
              }
            : null;
      if (disposition === null) return null;
      return {
        operation_kind: "unlink",
        owner: userTarget(selectedUser),
        identity: identityReference(selectedIdentity),
        proof_authority: proofAuthority,
        primary_source_disposition: disposition,
      };
    }
    if (counterpartUser === null || counterpartIdentity === null) return null;
    const winnerAuthority = authority(selectedIdentity.identity_kind, "winner");
    const loserAuthority = authority(counterpartIdentity.identity_kind, "loser");
    const primary = [...activeIdentities, ...counterpartIdentities].find(
      (identity) => identity.id === primaryIdentityId,
    );
    if (winnerAuthority === null || loserAuthority === null || primary === undefined) return null;
    return {
      operation_kind: "merge",
      winner: userTarget(selectedUser),
      winner_identity: identityReference(selectedIdentity),
      winner_proof_authority: winnerAuthority,
      loser: userTarget(counterpartUser),
      loser_identity: identityReference(counterpartIdentity),
      loser_proof_authority: loserAuthority,
      primary_source: identityReference(primary),
      sessions_disposition: "loser_revoked",
      bindings_disposition: "winner_preferred",
    };
  }

  async function createIntent(event: SyntheticEvent<HTMLFormElement, SubmitEvent>) {
    event.preventDefault();
    const plan = buildPlan();
    if (plan === null) {
      setLocalNotice("Choose every exact identity and proof authority before creating the intent.");
      return;
    }
    const exactPlan = snapshotPlan(plan);
    const owner = JSON.stringify(exactPlan);
    if (createOwner.current !== null && createOwner.current !== owner)
      createAttempt.current.abandon();
    createOwner.current = owner;
    const idempotencyKey = createAttempt.current.begin();
    if (idempotencyKey === null) return;

    // Reserve the browsing context while this trusted submit still has user activation.
    const popup = window.open("about:blank", "_blank");
    if (popup !== null) popup.opener = null;
    setPending(true);
    setLocalNotice(null);
    setPopupFallback(null);
    try {
      const result = await session.client.POST(
        "/v1/projects/{project_id}/identity-mutation-intents",
        {
          params: {
            path: { project_id: project.id },
            header: { "Idempotency-Key": idempotencyKey },
          },
          body: exactPlan,
        },
      );
      const created = requireData(result.data, result.error, result.response);
      if (created.operation_kind !== exactPlan.operation_kind) {
        throw new Error("Identity mutation create response did not match the exact plan");
      }
      createAttempt.current.settle();
      createOwner.current = null;
      const target = safeHostedTarget(created.hosted_target);
      if (
        created.hosted_target !== null &&
        created.hosted_target !== undefined &&
        target === null
      ) {
        popup?.close();
        setLocalNotice("The server returned an unsafe Hosted target. It was not opened.");
      } else if (target === null) {
        popup?.close();
      } else if (popup === null) {
        setPopupFallback(target);
      } else {
        try {
          popup.location.replace(target);
        } catch {
          popup.close();
          setPopupFallback(target);
        }
      }
      setActive({ intent: created, plan: exactPlan });
      setReadIntentId(created.id);
      setConfirmation("");
      setMessage("Identity proof intent created. Ownership has not changed.");
    } catch (error) {
      popup?.close();
      createAttempt.current.settle(error);
      if (!createAttempt.current.retainsKey) createOwner.current = null;
      if (error instanceof ControlRequestError && error.status === 409) {
        setLocalNotice(
          "The create plan conflicted with current authority. Reload inventories before creating a new plan.",
        );
        await reloadSelectedUser();
      }
      await onError(error);
    } finally {
      setPending(false);
    }
  }

  async function readIntent(id = readIntentId) {
    const normalized = id.trim();
    if (!UUID.test(normalized)) {
      setLocalNotice("Enter a valid intent ID.");
      return;
    }
    setPending(true);
    setLocalNotice(null);
    try {
      const result = await session.client.GET(
        "/v1/projects/{project_id}/identity-mutation-intents/{intent_id}",
        { params: { path: { project_id: project.id, intent_id: normalized } } },
      );
      const intent = requireData(result.data, result.error, result.response);
      setActive((current) => ({
        intent,
        plan: current?.intent.id === intent.id ? current.plan : null,
      }));
      setReadIntentId(intent.id);
      setConfirmation("");
      setLocalNotice(
        active?.intent.id === intent.id
          ? "Intent status refreshed."
          : "Orphan intent loaded. GET omits the immutable original plan, so only read and cancel are available.",
      );
    } catch (error) {
      await onError(error);
    } finally {
      setPending(false);
    }
  }

  async function cancelIntent() {
    if (
      active === null ||
      !(await confirm({
        title: "Cancel identity operation",
        message:
          "Cancel this exact identity proof intent? Completed proofs will not mutate identity.",
        actionLabel: "Cancel intent",
        destructive: true,
      }))
    )
      return;
    setPending(true);
    try {
      const result = await session.client.POST(
        "/v1/projects/{project_id}/identity-mutation-intents/{intent_id}/cancel",
        {
          params: { path: { project_id: project.id, intent_id: active.intent.id } },
          body: { expected_revision: active.intent.revision },
        },
      );
      const intent = requireData(result.data, result.error, result.response);
      setActive((current) => (current === null ? null : { ...current, intent }));
      setConfirmation("");
      setMessage("Identity proof intent cancelled. Ownership was not changed.");
    } catch (error) {
      if (error instanceof ControlRequestError && error.status === 409)
        await readIntent(active.intent.id);
      await onError(error);
    } finally {
      setPending(false);
    }
  }

  async function confirmIntent() {
    if (
      active?.plan === undefined ||
      active.plan === null ||
      active.intent.status !== "ready" ||
      active.intent.operation_kind !== active.plan.operation_kind
    ) {
      return;
    }
    const operationKind = active.plan.operation_kind;
    const required = CONFIRMATION[operationKind];
    if (confirmation !== required.phrase) return;
    setPending(true);
    try {
      const body: ConfirmIdentityMutationIntentRequest =
        operationKind === "link"
          ? {
              operation_kind: "link",
              expected_revision: active.intent.revision,
              confirmation: "link_identity",
            }
          : operationKind === "unlink"
            ? {
                operation_kind: "unlink",
                expected_revision: active.intent.revision,
                confirmation: "unlink_identity",
              }
            : {
                operation_kind: "merge",
                expected_revision: active.intent.revision,
                confirmation: "merge_users",
              };
      const result = await session.client.POST(
        "/v1/projects/{project_id}/identity-mutation-intents/{intent_id}/confirm",
        {
          params: { path: { project_id: project.id, intent_id: active.intent.id } },
          body,
        },
      );
      const intent = requireData(result.data, result.error, result.response);
      setActive((current) => (current === null ? null : { ...current, intent }));
      setConfirmation("");
      setMessage("Identity mutation completed under the exact ready revision.");
      await reloadSelectedUser();
    } catch (error) {
      if (error instanceof ControlRequestError && error.status === 409) {
        setLocalNotice("Final confirmation conflicted. The intent was refreshed; review it again.");
        await readIntent(active.intent.id);
      }
      await onError(error);
    } finally {
      setPending(false);
    }
  }

  return (
    <section
      aria-labelledby="identity-mutation-console-heading"
      className={styles["identityMutation"]}
    >
      <h4 id="identity-mutation-console-heading">Identity link, unlink, and merge</h4>
      <p>
        Inventory is bounded and redacted. A provider key shown on an identity is creation
        provenance only; it never selects current proof authority.
      </p>
      <ul className={styles["cards"]} aria-label="Safe identity inventory">
        {identities.map((identity) => (
          <li key={identity.id}>
            <span>{identityLabel(identity)}</span>
            <span>Status: {identity.status}</span>
            <code>{identity.id}</code>
          </li>
        ))}
      </ul>
      {identities.length === 0 ? (
        <p className={styles["emptyNote"]}>No identities are available for this user.</p>
      ) : null}

      <form className={styles["form"]} onSubmit={(event) => void createIntent(event)}>
        <h5>Create an immutable proof plan</h5>
        <label htmlFor="identity-operation">Operation</label>
        <Select
          id="identity-operation"
          value={operation}
          onChange={(event) => {
            setOperation(event.target.value as Operation | "");
            setSelectedIdentityId("");
            setCandidateKind("");
            counterpartInventoryRequest.current?.abort();
            counterpartInventoryRequest.current = null;
            counterpartUserIdRef.current = "";
            setLoadingCounterpart(false);
            setCounterpartUserId("");
            setCounterpartIdentities([]);
            setCounterpartIdentityId("");
            setPrimaryDisposition("");
            setPrimaryIdentityId("");
            setAuthorities(emptyAuthorities());
          }}
        >
          <option value="">Choose an exact operation…</option>
          <option value="link">Link a new identity</option>
          <option value="unlink">Unlink an existing identity</option>
          <option value="merge">Merge another user into this winning user</option>
        </Select>

        {operation === "" ? null : (
          <IdentitySelect
            id="identity-selected"
            label={
              operation === "merge"
                ? "Exact winning-user proof identity"
                : "Exact existing identity"
            }
            identities={activeIdentities}
            value={selectedIdentityId}
            onChange={(value) => {
              setSelectedIdentityId(value);
              setPrimaryDisposition("");
              setPrimaryIdentityId("");
              setAuthorities(emptyAuthorities());
            }}
          />
        )}

        {operation === "link" ? (
          <>
            <AuthorityFields
              fieldKey="destination"
              label="Destination-owner proof authority"
              kind={selectedIdentity?.identity_kind ?? null}
              draft={authorities.destination}
              applications={applications}
              providers={providers}
              onChange={setAuthority}
            />
            <label htmlFor="identity-candidate-kind">New candidate identity kind</label>
            <Select
              id="identity-candidate-kind"
              value={candidateKind}
              onChange={(event) => {
                setCandidateKind(event.target.value as IdentityKind | "");
                clearAuthority("candidate");
              }}
            >
              <option value="">Choose candidate identity kind…</option>
              <option value="provider">Provider identity</option>
              <option value="email">Email identity</option>
            </Select>
            <AuthorityFields
              fieldKey="candidate"
              label="Candidate proof authority"
              kind={candidateKind === "" ? null : candidateKind}
              draft={authorities.candidate}
              applications={applications}
              providers={providers}
              onChange={setAuthority}
            />
          </>
        ) : operation === "unlink" ? (
          <>
            <AuthorityFields
              fieldKey="owner"
              label="Identity-owner proof authority"
              kind={selectedIdentity?.identity_kind ?? null}
              draft={authorities.owner}
              applications={applications}
              providers={providers}
              onChange={setAuthority}
            />
            <label htmlFor="unlink-primary-disposition">Primary-source disposition</label>
            <Select
              id="unlink-primary-disposition"
              value={primaryDisposition}
              onChange={(event) => {
                setPrimaryDisposition(event.target.value as PrimaryDisposition | "");
                setPrimaryIdentityId("");
              }}
            >
              <option value="">Choose exact primary-source disposition…</option>
              <option value="preserve">
                Preserve current primary source (only if still valid)
              </option>
              <option value="clear">Clear primary source</option>
              <option value="provider">Replace with exact provider identity</option>
              <option value="email">Replace with exact email identity</option>
            </Select>
            {primaryDisposition === "provider" || primaryDisposition === "email" ? (
              <IdentitySelect
                id="unlink-primary-identity"
                label="Exact replacement primary identity"
                identities={activeIdentities.filter(
                  (identity) =>
                    identity.identity_kind === primaryDisposition &&
                    identity.id !== selectedIdentityId,
                )}
                value={primaryIdentityId}
                onChange={setPrimaryIdentityId}
              />
            ) : null}
          </>
        ) : operation === "merge" ? (
          <>
            <AuthorityFields
              fieldKey="winner"
              label="Winning-user proof authority"
              kind={selectedIdentity?.identity_kind ?? null}
              draft={authorities.winner}
              applications={applications}
              providers={providers}
              onChange={setAuthority}
            />
            <label htmlFor="merge-loser-user">Exact losing user</label>
            <Select
              id="merge-loser-user"
              value={counterpartUserId}
              disabled={pending}
              onChange={(event) => {
                counterpartInventoryRequest.current?.abort();
                counterpartInventoryRequest.current = null;
                counterpartUserIdRef.current = event.target.value;
                setLoadingCounterpart(false);
                setCounterpartUserId(event.target.value);
                setCounterpartIdentities([]);
                setCounterpartIdentityId("");
                setPrimaryIdentityId("");
                clearAuthority("loser");
              }}
            >
              <option value="">Choose losing user…</option>
              {users
                .filter((user) => user.id !== selectedUser.id && user.status === "active")
                .map((user) => (
                  <option key={user.id} value={user.id}>
                    {user.display_name ?? user.public_id} ({user.public_id})
                  </option>
                ))}
            </Select>
            {hasMoreUsers ? (
              <Button
                type="button"
                disabled={pending || loadingCounterpart || loadingMoreUsers}
                onClick={() => void loadMoreUsers()}
              >
                {loadingMoreUsers ? "Loading more merge candidates" : "Load more merge candidates"}
              </Button>
            ) : null}
            <Button
              type="button"
              disabled={counterpartUser === null || pending || loadingCounterpart}
              onClick={() => void loadCounterpartInventory()}
            >
              {loadingCounterpart
                ? "Loading losing user’s identities"
                : "Load losing user’s redacted identities"}
            </Button>
            <IdentitySelect
              id="merge-loser-identity"
              label="Exact losing-user proof identity"
              identities={counterpartIdentities}
              value={counterpartIdentityId}
              onChange={(value) => {
                setCounterpartIdentityId(value);
                setPrimaryIdentityId("");
                clearAuthority("loser");
              }}
            />
            <AuthorityFields
              fieldKey="loser"
              label="Losing-user proof authority"
              kind={counterpartIdentity?.identity_kind ?? null}
              draft={authorities.loser}
              applications={applications}
              providers={providers}
              onChange={setAuthority}
            />
            <IdentitySelect
              id="merge-primary-source"
              label="Exact primary source after merge"
              identities={[...activeIdentities, ...counterpartIdentities]}
              value={primaryIdentityId}
              onChange={setPrimaryIdentityId}
            />
            <p>
              Fixed dispositions: losing user sessions <strong>revoked</strong>; Application
              bindings <strong>winner preferred</strong>.
            </p>
          </>
        ) : null}
        <Button
          type="submit"
          variant="primary"
          disabled={pending || selectedUser.status !== "active"}
        >
          Create proof intent and open Hosted verification
        </Button>
      </form>

      {popupFallback === null ? null : (
        <p role="status">
          The verification window was blocked.{" "}
          <a href={popupFallback} target="_blank" rel="noopener noreferrer">
            Continue Hosted identity verification
          </a>
        </p>
      )}
      {localNotice === null ? null : <p role="status">{localNotice}</p>}

      <form
        className={styles["inlineForm"]}
        onSubmit={(event) => {
          event.preventDefault();
          void readIntent();
        }}
      >
        <label htmlFor="identity-intent-id">Read an existing intent by ID</label>
        <Input
          id="identity-intent-id"
          value={readIntentId}
          onChange={(event) => {
            setReadIntentId(event.target.value);
          }}
          placeholder="UUID"
        />
        <Button type="submit" disabled={pending}>
          Read intent
        </Button>
      </form>

      {active === null ? null : (
        <article className={styles["panel"]} aria-labelledby="active-identity-intent">
          <h5 id="active-identity-intent">Identity mutation intent</h5>
          <p>
            Operation: {active.intent.operation_kind}; status:{" "}
            <strong>{active.intent.status}</strong>; revision {String(active.intent.revision)}.
          </p>
          <p>
            Effective expiry: <Timestamp value={active.intent.effective_expires_at} />
          </p>
          {active.plan === null ? (
            <p role="status">
              Original immutable plan unavailable after reload. This orphan view intentionally
              permits read and cancel only; it will not reconstruct high-risk confirmation.
            </p>
          ) : active.intent.operation_kind !== active.plan.operation_kind ? (
            <p role="alert">
              The intent operation no longer matches the create-time snapshot. Final confirmation is
              disabled.
            </p>
          ) : (
            <ExactPlanReview plan={active.plan} />
          )}
          <ul className={styles["cards"]}>
            {active.intent.slots.map((slot) => (
              <li key={slot.id}>
                <span>
                  {slot.role}: fixed {slot.identity_kind}/{slot.method_kind} proof
                </span>
                <strong>{slot.proved ? "proved" : "pending"}</strong>
              </li>
            ))}
          </ul>
          <div className={styles["actions"]}>
            <Button
              type="button"
              disabled={pending}
              onClick={() => void readIntent(active.intent.id)}
            >
              Refresh status
            </Button>
            {active.intent.status === "pending_proof" || active.intent.status === "ready" ? (
              <Button
                variant="danger"
                type="button"
                disabled={pending}
                onClick={() => void cancelIntent()}
              >
                Cancel intent
              </Button>
            ) : null}
          </div>
          {active.intent.status === "ready" &&
          active.plan !== null &&
          active.intent.operation_kind === active.plan.operation_kind ? (
            <section
              className={styles["confirmation"]}
              aria-labelledby="final-identity-confirmation"
            >
              <h5 id="final-identity-confirmation">Final ownership confirmation</h5>
              <p>
                Review the exact plan and current ready revision. Type{" "}
                <strong>{CONFIRMATION[active.plan.operation_kind].phrase}</strong> exactly.
              </p>
              <label htmlFor="identity-confirmation-phrase">Typed confirmation phrase</label>
              <Input
                id="identity-confirmation-phrase"
                autoComplete="off"
                value={confirmation}
                onChange={(event) => {
                  setConfirmation(event.target.value);
                }}
              />
              <Button
                variant="danger"
                type="button"
                disabled={
                  pending || confirmation !== CONFIRMATION[active.plan.operation_kind].phrase
                }
                onClick={() => void confirmIntent()}
              >
                Confirm exact {active.plan.operation_kind} at revision{" "}
                {String(active.intent.revision)}
              </Button>
            </section>
          ) : null}
        </article>
      )}
    </section>
  );
}

function ExactPlanReview({ plan }: { readonly plan: CreateIdentityMutationIntentRequest }) {
  return (
    <section aria-labelledby="exact-plan-review" className={styles["planReview"]}>
      <h5 id="exact-plan-review">Exact immutable create-time plan</h5>
      <p>
        This read-only snapshot is the exact request sent when the intent was created. Form changes
        do not alter it.
      </p>
      <PlanValue label="Operation" value={plan.operation_kind} />
      {plan.operation_kind === "link" ? (
        <>
          <PlanUser label="Destination user" target={plan.destination} />
          <PlanIdentity label="Destination identity" identity={plan.destination_identity} />
          <PlanAuthority
            label="Destination proof authority"
            authority={plan.destination_proof_authority}
          />
          <PlanValue label="Candidate identity kind" value={plan.candidate_identity_kind} />
          <PlanAuthority
            label="Candidate proof authority"
            authority={plan.candidate_proof_authority}
          />
        </>
      ) : plan.operation_kind === "unlink" ? (
        <>
          <PlanUser label="Owner user" target={plan.owner} />
          <PlanIdentity label="Identity to unlink" identity={plan.identity} />
          <PlanAuthority label="Owner proof authority" authority={plan.proof_authority} />
          <PlanValue
            label="Primary-source disposition"
            value={plan.primary_source_disposition.disposition}
          />
          {plan.primary_source_disposition.disposition === "provider" ||
          plan.primary_source_disposition.disposition === "email" ? (
            <PlanIdentity
              label="Replacement primary identity"
              identity={{
                identity_kind: plan.primary_source_disposition.disposition,
                identity_id: plan.primary_source_disposition.identity_id,
                expected_identity_revision:
                  plan.primary_source_disposition.expected_identity_revision,
              }}
            />
          ) : null}
        </>
      ) : (
        <>
          <PlanUser label="Winning user" target={plan.winner} />
          <PlanIdentity label="Winning-user proof identity" identity={plan.winner_identity} />
          <PlanAuthority
            label="Winning-user proof authority"
            authority={plan.winner_proof_authority}
          />
          <PlanUser label="Losing user" target={plan.loser} />
          <PlanIdentity label="Losing-user proof identity" identity={plan.loser_identity} />
          <PlanAuthority
            label="Losing-user proof authority"
            authority={plan.loser_proof_authority}
          />
          <PlanIdentity label="Primary source after merge" identity={plan.primary_source} />
          <PlanValue label="Losing sessions disposition" value={plan.sessions_disposition} />
          <PlanValue label="Application bindings disposition" value={plan.bindings_disposition} />
        </>
      )}
    </section>
  );
}

function PlanUser({
  label,
  target,
}: {
  readonly label: string;
  readonly target: {
    user_id: string;
    expected_user_revision: number;
    expected_user_security_revision: number;
  };
}) {
  return (
    <div className={styles["planGroup"]}>
      <strong>{label}</strong>
      <PlanValue label="User ID" value={target.user_id} code />
      <PlanValue label="Expected user revision" value={String(target.expected_user_revision)} />
      <PlanValue
        label="Expected user security revision"
        value={String(target.expected_user_security_revision)}
      />
    </div>
  );
}

function PlanIdentity({
  label,
  identity,
}: {
  readonly label: string;
  readonly identity: {
    identity_kind: IdentityKind;
    identity_id: string;
    expected_identity_revision: number;
  };
}) {
  return (
    <div className={styles["planGroup"]}>
      <strong>{label}</strong>
      <PlanValue label="Identity kind" value={identity.identity_kind} />
      <PlanValue label="Identity ID" value={identity.identity_id} code />
      <PlanValue
        label="Expected identity revision"
        value={String(identity.expected_identity_revision)}
      />
    </div>
  );
}

function PlanAuthority({
  label,
  authority,
}: {
  readonly label: string;
  readonly authority: IdentityMutationProofAuthority;
}) {
  return (
    <div className={styles["planGroup"]}>
      <strong>{label}</strong>
      <PlanValue label="Proof method" value={authority.method_kind} />
      <PlanValue label="Proof Application ID" value={authority.application_id} code />
      {authority.method_kind === "provider" ? (
        <PlanValue label="Proof provider authority ID" value={authority.provider_id} code />
      ) : null}
    </div>
  );
}

function PlanValue({
  label,
  value,
  code = false,
}: {
  readonly label: string;
  readonly value: string;
  readonly code?: boolean;
}) {
  return (
    <p>
      {label}: {code ? <code>{value}</code> : <strong>{value}</strong>}
    </p>
  );
}

function IdentitySelect({
  id,
  label,
  identities,
  value,
  onChange,
}: {
  readonly id: string;
  readonly label: string;
  readonly identities: ProjectUserIdentity[];
  readonly value: string;
  readonly onChange: (value: string) => void;
}) {
  return (
    <>
      <label htmlFor={id}>{label}</label>
      <Select
        id={id}
        value={value}
        onChange={(event) => {
          onChange(event.target.value);
        }}
      >
        <option value="">Choose exact identity…</option>
        {identities.map((identity) => (
          <option key={identity.id} value={identity.id}>
            {identityLabel(identity)}
          </option>
        ))}
      </Select>
    </>
  );
}

function AuthorityFields({
  fieldKey,
  label,
  kind,
  draft,
  applications,
  providers,
  onChange,
}: {
  readonly fieldKey: AuthorityKey;
  readonly label: string;
  readonly kind: IdentityKind | null;
  readonly draft: AuthorityDraft;
  readonly applications: Application[];
  readonly providers: Provider[];
  readonly onChange: (key: AuthorityKey, change: Partial<AuthorityDraft>) => void;
}) {
  const eligibleProviders = providers.filter(
    (provider) =>
      provider.status === "active" &&
      provider.identity_proof_supported &&
      draft.applicationId !== "" &&
      provider.assigned_application_ids.includes(draft.applicationId),
  );
  return (
    <fieldset className={styles["authority"]}>
      <legend>{label}</legend>
      {kind === null ? (
        <p>Choose the exact identity first.</p>
      ) : (
        <>
          <p>
            Explicit method: <strong>{kind}</strong>. Eligibility and captured revisions are
            revalidated by the server.
          </p>
          <label htmlFor={`${fieldKey}-application`}>Proof-policy Application</label>
          <Select
            id={`${fieldKey}-application`}
            value={draft.applicationId}
            onChange={(event) => {
              onChange(fieldKey, { applicationId: event.target.value, providerId: "" });
            }}
          >
            <option value="">Choose exact Application…</option>
            {applications
              .filter((application) => application.status === "active")
              .map((application) => (
                <option key={application.id} value={application.id}>
                  {application.display_name}
                </option>
              ))}
          </Select>
          {kind === "provider" ? (
            <>
              <label htmlFor={`${fieldKey}-provider`}>Current assigned provider authority</label>
              <Select
                id={`${fieldKey}-provider`}
                value={draft.providerId}
                onChange={(event) => {
                  onChange(fieldKey, { providerId: event.target.value });
                }}
              >
                <option value="">Choose current provider authority…</option>
                {eligibleProviders.map((provider) => (
                  <option key={provider.id} value={provider.id}>
                    {provider.display_name} ({provider.provider_key})
                  </option>
                ))}
              </Select>
              <p>Provider creation provenance is never used to preselect this authority.</p>
            </>
          ) : (
            <p>
              Choose an Application with an active email-method assignment; no assignment is
              inferred.
            </p>
          )}
        </>
      )}
    </fieldset>
  );
}
