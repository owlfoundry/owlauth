import type { ReactNode } from "react";

import { classes } from "./Button";
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
      <span aria-hidden="true">{toneSymbol(tone)}</span>
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
  return (
    <div className={styles["notificationRegion"]} aria-live="polite" aria-atomic="true">
      {message === null ? null : <InlineAlert tone={tone}>{message}</InlineAlert>}
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

function toneSymbol(tone: AlertTone): string {
  switch (tone) {
    case "success":
      return "ok";
    case "warning":
      return "!";
    case "danger":
      return "x";
    case "info":
      return "i";
  }
}
