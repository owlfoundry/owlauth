import { useId, useLayoutEffect, useRef } from "react";
import type { ReactNode } from "react";
import { createPortal } from "react-dom";

import { CloseIcon } from "../icons/Icons";
import { Button } from "./Button";
import styles from "./primitives.module.css";

const modalStack: symbol[] = [];

interface DialogProps {
  readonly open: boolean;
  readonly title: string;
  readonly children: ReactNode;
  readonly actions?: ReactNode;
  readonly closeLabel?: string;
  readonly dismissible?: boolean;
  readonly onClose: () => void;
}

export function Dialog({
  open,
  title,
  children,
  actions,
  closeLabel = "Close dialog",
  dismissible = true,
  onClose,
}: DialogProps) {
  const titleId = useId();
  const surface = useRef<HTMLDivElement | null>(null);
  useModalFocus(open, surface, dismissible ? onClose : null);

  if (!open) return null;
  return createPortal(
    <div className={styles["backdrop"]}>
      <div
        ref={surface}
        className={styles["dialog"]}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        tabIndex={-1}
      >
        <div className={styles["dialogHeader"]}>
          <h2 id={titleId}>{title}</h2>
          {dismissible ? (
            <Button
              type="button"
              variant="quiet"
              iconOnly
              aria-label={closeLabel}
              onClick={onClose}
            >
              <CloseIcon />
            </Button>
          ) : null}
        </div>
        <div className={styles["dialogBody"]}>{children}</div>
        {actions === undefined ? null : <div className={styles["dialogActions"]}>{actions}</div>}
      </div>
    </div>,
    document.body,
  );
}

interface SideSheetProps {
  readonly open: boolean;
  readonly title: string;
  readonly children: ReactNode;
  readonly actions?: ReactNode;
  readonly side?: "left" | "right";
  readonly closeLabel?: string;
  readonly onClose: () => void;
}

export function SideSheet({
  open,
  title,
  children,
  actions,
  side = "left",
  closeLabel = "Close panel",
  onClose,
}: SideSheetProps) {
  const titleId = useId();
  const surface = useRef<HTMLDivElement | null>(null);
  useModalFocus(open, surface, onClose);

  if (!open) return null;
  return createPortal(
    <div className={styles["sheetBackdrop"]}>
      <div
        ref={surface}
        className={`${styles["sheet"] ?? ""} ${side === "right" ? (styles["sheetRight"] ?? "") : ""}`}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        tabIndex={-1}
      >
        <div className={styles["dialogHeader"]}>
          <h2 id={titleId}>{title}</h2>
          <Button type="button" variant="quiet" iconOnly aria-label={closeLabel} onClick={onClose}>
            <CloseIcon />
          </Button>
        </div>
        <div className={styles["dialogBody"]}>{children}</div>
        {actions === undefined ? null : <div className={styles["dialogActions"]}>{actions}</div>}
      </div>
    </div>,
    document.body,
  );
}

function useModalFocus(
  open: boolean,
  surface: React.RefObject<HTMLDivElement | null>,
  onClose: (() => void) | null,
) {
  const onCloseRef = useRef(onClose);
  useLayoutEffect(() => {
    onCloseRef.current = onClose;
  }, [onClose]);

  useLayoutEffect(() => {
    if (!open || surface.current === null) return;
    const token = Symbol("modal");
    modalStack.push(token);
    const previous = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    const modal = surface.current;
    const focusables = getFocusable(modal);
    const preferred = modal.querySelector<HTMLElement>("[data-owl-initial-focus]");
    (preferred ?? focusables[0] ?? modal).focus();
    const isTopmost = () => modalStack.at(-1) === token;
    const focusBoundary = (reverse: boolean) => {
      const current = getFocusable(modal);
      (reverse ? current.at(-1) : current[0])?.focus();
      if (current.length === 0) modal.focus();
    };
    const handleKey = (event: KeyboardEvent) => {
      if (!isTopmost()) return;
      if (event.key === "Escape" && onCloseRef.current !== null) {
        event.preventDefault();
        event.stopImmediatePropagation();
        onCloseRef.current();
        return;
      }
      if (event.key !== "Tab") return;
      const current = getFocusable(modal);
      const active = document.activeElement;
      if (!(active instanceof Node) || !modal.contains(active) || current.length === 0) {
        event.preventDefault();
        focusBoundary(event.shiftKey);
        return;
      }
      const first = current[0];
      const last = current.at(-1);
      if (event.shiftKey && active === first) {
        event.preventDefault();
        last?.focus();
      } else if (!event.shiftKey && active === last) {
        event.preventDefault();
        first?.focus();
      }
    };
    const containFocus = (event: FocusEvent) => {
      if (!isTopmost() || !(event.target instanceof Node) || modal.contains(event.target)) return;
      focusBoundary(false);
    };
    document.addEventListener("keydown", handleKey);
    document.addEventListener("focusin", containFocus);
    return () => {
      document.removeEventListener("keydown", handleKey);
      document.removeEventListener("focusin", containFocus);
      const index = modalStack.lastIndexOf(token);
      if (index >= 0) modalStack.splice(index, 1);
      previous?.focus();
    };
  }, [open, surface]);
}

function getFocusable(root: HTMLElement): HTMLElement[] {
  return Array.from(
    root.querySelectorAll<HTMLElement>(
      'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])',
    ),
  ).filter((element) => !element.hidden);
}
