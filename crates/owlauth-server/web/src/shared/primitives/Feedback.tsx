import type { ReactNode } from "react";

import { CheckIcon, CloseIcon, ErrorIcon, InfoIcon, WarningIcon } from "../icons/Icons";
import { Button, classes } from "./Button";
import styles from "./primitives.module.css";

export type AlertTone = "info" | "success" | "warning" | "danger";

interface InlineAlertProps {
  readonly tone?: AlertTone;
  readonly children: ReactNode;
  readonly role?: "alert" | "status";
}

export function InlineAlert({ tone = "info", children, role }: InlineAlertProps) {
  return (
    <div
      className={classes(styles["alert"], toneClass(tone))}
      role={role ?? (tone === "danger" ? "alert" : "status")}
    >
      <span className={styles["alertIcon"]}>{toneIcon(tone)}</span>
      <div>{children}</div>
    </div>
  );
}

export type StatusFamily = "active" | "pending" | "attention" | "disabled" | "danger";

interface StatusBadgeProps {
  readonly status: string;
  readonly family?: StatusFamily;
}

export function StatusBadge({ status, family = classifyStatus(status) }: StatusBadgeProps) {
  return (
    <span className={classes(styles["badge"], badgeClass(family))}>
      <span className={styles["srOnly"]}>Status: </span>
      {status}
    </span>
  );
}

interface NotificationRegionProps {
  readonly message: string | null;
  readonly tone?: AlertTone;
}

export function NotificationRegion({ message, tone = "info" }: NotificationRegionProps) {
  return message === null ? null : (
    <div className={styles["notificationRegion"]}>
      <InlineAlert tone={tone}>{message}</InlineAlert>
    </div>
  );
}

export interface ToastMessage {
  readonly id: number;
  readonly message: string;
  readonly tone: "info" | "success";
}

export function ToastRegion({
  toasts,
  onDismiss,
}: {
  readonly toasts: readonly ToastMessage[];
  readonly onDismiss: (id: number) => void;
}) {
  return (
    <div className={styles["toastRegion"]} aria-live="polite" aria-atomic="true">
      {toasts.map((toast) => (
        <div
          className={classes(styles["toast"], toneClass(toast.tone))}
          key={toast.id}
          role="status"
        >
          <span className={styles["alertIcon"]}>{toneIcon(toast.tone)}</span>
          <span>{toast.message}</span>
          <Button
            type="button"
            variant="quiet"
            iconOnly
            aria-label="Dismiss notification"
            onClick={() => {
              onDismiss(toast.id);
            }}
          >
            <CloseIcon />
          </Button>
        </div>
      ))}
    </div>
  );
}

function classifyStatus(status: string): StatusFamily {
  const normalized = status.toLowerCase();
  if (["active", "ready", "published", "complete", "completed"].includes(normalized)) {
    return "active";
  }
  if (["pending", "provisioning", "reconciling", "queued", "prepared"].includes(normalized)) {
    return "pending";
  }
  if (["failed", "rejected", "compromised", "error"].includes(normalized)) return "danger";
  if (["unavailable", "partial", "expiring", "attention"].includes(normalized)) {
    return "attention";
  }
  return "disabled";
}

function badgeClass(family: StatusFamily): string | undefined {
  switch (family) {
    case "active":
      return styles["badgeActive"];
    case "pending":
      return styles["badgePending"];
    case "attention":
      return styles["badgeAttention"];
    case "danger":
      return styles["badgeDanger"];
    case "disabled":
      return undefined;
  }
}

function toneClass(tone: AlertTone): string {
  switch (tone) {
    case "info":
      return styles["info"] ?? "";
    case "success":
      return styles["success"] ?? "";
    case "warning":
      return styles["warning"] ?? "";
    case "danger":
      return styles["alertDanger"] ?? "";
  }
}

function toneIcon(tone: AlertTone): ReactNode {
  switch (tone) {
    case "success":
      return <CheckIcon />;
    case "warning":
      return <WarningIcon />;
    case "danger":
      return <ErrorIcon />;
    case "info":
      return <InfoIcon />;
  }
}
