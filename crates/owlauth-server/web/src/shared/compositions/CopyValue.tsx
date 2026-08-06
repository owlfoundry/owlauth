import { useState } from "react";

import { CheckIcon, CopyIcon } from "../icons/Icons";
import { Button } from "../primitives/Button";
import styles from "./compositions.module.css";

interface CopyValueProps {
  readonly value: string;
  readonly label: string;
  readonly onCopied?: (message: string) => void;
  readonly block?: boolean;
}

export function CopyValue({ value, label, onCopied, block = false }: CopyValueProps) {
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
    <span className={block ? styles["copyValueBlock"] : styles["copyValue"]}>
      <code>{value}</code>
      <Button
        type="button"
        variant="quiet"
        iconOnly
        aria-label={copyState === "failed" ? `Copy ${label} unavailable` : `Copy ${label}`}
        title={
          copyState === "failed" ? "Copy unavailable; select the value manually" : `Copy ${label}`
        }
        onClick={() => void copy()}
      >
        {copyState === "copied" ? <CheckIcon /> : <CopyIcon />}
      </Button>
      <span className="visually-hidden" role="status" aria-live="polite">
        {copyState === "failed" ? "Copy unavailable. Select the value and copy it manually." : ""}
      </span>
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
