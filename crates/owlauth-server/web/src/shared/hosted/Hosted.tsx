import { useEffect, useRef } from "react";
import type { ButtonHTMLAttributes, ReactNode } from "react";

import { OwlAuthMark } from "../brand/OwlAuthMark";
import { classes } from "../primitives/Button";
import styles from "./hosted.module.css";

interface HostedCardProps {
  readonly title: string;
  readonly projectName?: string;
  readonly description?: ReactNode;
  readonly children: ReactNode;
  readonly wide?: boolean;
}

export function HostedCard({
  title,
  projectName,
  description,
  children,
  wide = false,
}: HostedCardProps) {
  return (
    <main className={styles["canvas"]}>
      <section className={classes(styles["card"], wide ? styles["wide"] : undefined)}>
        <header className={styles["header"]}>
          {projectName === undefined ? null : <p className={styles["context"]}>{projectName}</p>}
          <h1>{title}</h1>
          {description === undefined ? null : (
            <p className={styles["description"]}>{description}</p>
          )}
        </header>
        <div className={styles["content"]}>{children}</div>
        <p className={styles["attribution"]}>
          <OwlAuthMark size={18} />
          <span>Secured by OwlAuth</span>
        </p>
      </section>
    </main>
  );
}

interface MethodButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  readonly kind: string;
  readonly children: ReactNode;
}

export function MethodButton({ kind, children, ...props }: MethodButtonProps) {
  return (
    <button {...props} className={styles["method"]} type={props.type ?? "button"}>
      <span className={styles["providerIcon"]} aria-hidden="true">
        <ProviderIcon kind={kind} />
      </span>
      <span>{children}</span>
    </button>
  );
}

export function MethodDivider({ children = "or" }: { readonly children?: ReactNode }) {
  return <div className={styles["divider"]}>{children}</div>;
}

interface TerminalStateProps {
  readonly title: string;
  readonly children: ReactNode;
  readonly action?: ReactNode;
  readonly announce?: boolean;
}

export function TerminalState({ title, children, action, announce = true }: TerminalStateProps) {
  const heading = useRef<HTMLHeadingElement | null>(null);
  useEffect(() => {
    heading.current?.focus();
  }, [title]);
  return (
    <section className={styles["terminal"]} aria-live={announce ? "polite" : undefined}>
      <h2 ref={heading} tabIndex={-1}>
        {title}
      </h2>
      <div>{children}</div>
      {action}
    </section>
  );
}

function ProviderIcon({ kind }: { readonly kind: string }) {
  switch (kind) {
    case "google":
      return (
        <svg width="22" height="22" viewBox="0 0 24 24" fill="none">
          <circle cx="12" cy="12" r="9" stroke="currentColor" strokeWidth="1.8" />
          <path d="M12 8.2h6.2v4.2H12" stroke="currentColor" strokeWidth="1.8" />
        </svg>
      );
    case "github":
      return (
        <svg width="22" height="22" viewBox="0 0 24 24" fill="none">
          <path
            d="M8.2 19.2c-4.2 1.3-4.2-2.1-5.9-2.6m11.8 5v-3.3c0-1 .1-1.5-.5-2.1 3.1-.3 6.4-1.5 6.4-6.9 0-1.5-.5-2.8-1.4-3.8.1-.4.6-1.8-.2-3.7 0 0-1.2-.4-3.9 1.4a13.4 13.4 0 0 0-7 0C4.8 1.4 3.6 1.8 3.6 1.8c-.8 1.9-.3 3.3-.2 3.7A5.5 5.5 0 0 0 2 9.3c0 5.4 3.3 6.6 6.4 6.9-.5.5-.6 1-.6 2.1v3.3"
            stroke="currentColor"
            strokeWidth="1.6"
            strokeLinecap="round"
          />
        </svg>
      );
    case "email":
      return (
        <svg width="22" height="22" viewBox="0 0 24 24" fill="none">
          <rect x="3" y="5" width="18" height="14" rx="2" stroke="currentColor" strokeWidth="1.8" />
          <path d="m4 7 8 6 8-6" stroke="currentColor" strokeWidth="1.8" />
        </svg>
      );
    default:
      return (
        <svg width="22" height="22" viewBox="0 0 24 24" fill="none">
          <circle cx="12" cy="12" r="9" stroke="currentColor" strokeWidth="1.8" />
          <path
            d="M3.5 12h17M12 3c2.2 2.4 3.3 5.4 3.3 9S14.2 18.6 12 21c-2.2-2.4-3.3-5.4-3.3-9S9.8 5.4 12 3Z"
            stroke="currentColor"
            strokeWidth="1.5"
          />
        </svg>
      );
  }
}
