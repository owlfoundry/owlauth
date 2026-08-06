import type { ButtonHTMLAttributes, ReactNode } from "react";

import styles from "./primitives.module.css";

export type ButtonVariant = "primary" | "secondary" | "quiet" | "danger";

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  readonly variant?: ButtonVariant;
  readonly fullWidth?: boolean;
  readonly iconOnly?: boolean;
  readonly busy?: boolean;
  readonly children: ReactNode;
}

export function Button({
  variant = "secondary",
  fullWidth = false,
  iconOnly = false,
  busy = false,
  disabled,
  className,
  children,
  ...props
}: ButtonProps) {
  return (
    <button
      {...props}
      className={classes(
        styles["button"],
        styles[variant],
        fullWidth ? styles["fullWidth"] : undefined,
        iconOnly ? styles["iconOnly"] : undefined,
        className,
      )}
      disabled={disabled === true || busy}
      aria-busy={busy || undefined}
    >
      {children}
    </button>
  );
}

export function buttonClassName(
  variant: ButtonVariant = "secondary",
  options: { readonly fullWidth?: boolean } = {},
): string {
  return classes(
    styles["button"],
    styles[variant],
    options.fullWidth === true ? styles["fullWidth"] : undefined,
  );
}

export function classes(...values: (string | undefined | false)[]): string {
  return values.filter(Boolean).join(" ");
}
