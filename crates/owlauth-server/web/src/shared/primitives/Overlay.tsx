import { useEffect, useId, useRef } from "react";
import type { ReactNode } from "react";
import { createPortal } from "react-dom";

import { Button } from "./Button";
import styles from "./primitives.module.css";

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
  readonly onClose: () => void;
}

export function SideSheet({ open, title, children, onClose }: SideSheetProps) {
  const titleId = useId();
  const surface = useRef<HTMLDivElement | null>(null);
  useModalFocus(open, surface, onClose);

  if (!open) return null;
  return createPortal(
    <div className={styles["sheetBackdrop"]}>
      <div
        ref={surface}
        className={styles["sheet"]}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        tabIndex={-1}
      >
        <div className={styles["dialogHeader"]}>
          <h2 id={titleId}>{title}</h2>
          <Button
            type="button"
            variant="quiet"
            iconOnly
            aria-label="Close navigation"
            onClick={onClose}
          >
            <CloseIcon />
          </Button>
        </div>
        <div className={styles["dialogBody"]}>{children}</div>
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
  useEffect(() => {
    onCloseRef.current = onClose;
  }, [onClose]);

  useEffect(() => {
    if (!open || surface.current === null) return;
    const previous = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    const modal = surface.current;
    const focusables = getFocusable(modal);
    const preferred = modal.querySelector<HTMLElement>("[data-owl-initial-focus]");
    (preferred ?? focusables[0] ?? modal).focus();
    const handleKey = (event: KeyboardEvent) => {
      if (event.key === "Escape" && onCloseRef.current !== null) {
        event.preventDefault();
        onCloseRef.current();
        return;
      }
      if (event.key !== "Tab") return;
      const current = getFocusable(modal);
      if (current.length === 0) {
        event.preventDefault();
        modal.focus();
        return;
      }
      const first = current[0];
      const last = current.at(-1);
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last?.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first?.focus();
      }
    };
    document.addEventListener("keydown", handleKey);
    return () => {
      document.removeEventListener("keydown", handleKey);
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

function CloseIcon() {
  return (
    <svg aria-hidden="true" width="18" height="18" viewBox="0 0 18 18" fill="none">
      <path d="M4 4l10 10M14 4L4 14" stroke="currentColor" strokeWidth="2" />
    </svg>
  );
}
