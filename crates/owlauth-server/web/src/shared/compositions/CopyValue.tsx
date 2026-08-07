import { useState, type ReactNode } from "react";

import { CheckIcon, CopyIcon } from "../icons/Icons";
import { Button } from "../primitives/Button";
import styles from "./compositions.module.css";

interface CopyButtonProps {
  readonly value: string;
  readonly label: string;
  readonly onCopied?: (message: string) => void;
  readonly unavailableMessage?: string;
  readonly children?: ReactNode;
}

export function CopyButton({
  value,
  label,
  onCopied,
  unavailableMessage = "Copy unavailable.",
  children,
}: CopyButtonProps) {
  const [copyState, setCopyState] = useState<"idle" | "copied" | "failed">("idle");

  async function copy() {
    try {
      await navigator.clipboard.writeText(value);
      setCopyState("copied");
      onCopied?.(`${label} copied.`);
      window.setTimeout(() => {
        setCopyState("idle");
      }, 2000);
    } catch {
      setCopyState("failed");
    }
  }

  return (
    <>
      <Button
        type="button"
        variant="quiet"
        {...(children === undefined ? { iconOnly: true } : {})}
        aria-label={copyState === "failed" ? `Copy ${label} unavailable` : `Copy ${label}`}
        title={copyState === "failed" ? unavailableMessage : `Copy ${label}`}
        onClick={() => void copy()}
      >
        {copyState === "copied" ? <CheckIcon /> : <CopyIcon />}
        {children}
      </Button>
      <span className="visually-hidden" role="status" aria-live="polite">
        {copyState === "copied" && onCopied === undefined
          ? `${label} copied.`
          : copyState === "failed"
            ? unavailableMessage
            : ""}
      </span>
    </>
  );
}

interface CopyValueProps {
  readonly value: string;
  readonly label: string;
  readonly onCopied?: (message: string) => void;
  readonly block?: boolean;
}

export function CopyValue({ value, label, onCopied, block = false }: CopyValueProps) {
  return (
    <span className={block ? styles["copyValueBlock"] : styles["copyValue"]}>
      <code>{value}</code>
      <CopyButton
        value={value}
        label={label}
        unavailableMessage="Copy unavailable. Select the value and copy it manually."
        {...(onCopied === undefined ? {} : { onCopied })}
      />
    </span>
  );
}

export function formatDuration(seconds: number): string {
  if (seconds % 3600 === 0) {
    const hours = seconds / 3600;
    return `${String(hours)} ${hours === 1 ? "hour" : "hours"}`;
  }
  if (seconds % 60 === 0) {
    const minutes = seconds / 60;
    return `${String(minutes)} ${minutes === 1 ? "minute" : "minutes"}`;
  }
  return `${String(seconds)} ${seconds === 1 ? "second" : "seconds"}`;
}
