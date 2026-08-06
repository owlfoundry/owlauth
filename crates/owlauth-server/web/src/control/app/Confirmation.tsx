import { createContext, useCallback, useContext, useRef, useState } from "react";
import type { ReactNode } from "react";

import { Button } from "../../shared/primitives/Button";
import { Dialog } from "../../shared/primitives/Overlay";

interface ConfirmationRequest {
  readonly title: string;
  readonly message: ReactNode;
  readonly actionLabel: string;
  readonly destructive?: boolean;
}

type Confirm = (request: ConfirmationRequest) => Promise<boolean>;

const ConfirmationContext = createContext<Confirm | null>(null);

export function ControlConfirmationProvider({ children }: { readonly children: ReactNode }) {
  const [request, setRequest] = useState<ConfirmationRequest | null>(null);
  const resolver = useRef<((confirmed: boolean) => void) | null>(null);

  const settle = useCallback((confirmed: boolean) => {
    resolver.current?.(confirmed);
    resolver.current = null;
    setRequest(null);
  }, []);

  const confirm = useCallback<Confirm>((next) => {
    resolver.current?.(false);
    setRequest(next);
    return new Promise<boolean>((resolve) => {
      resolver.current = resolve;
    });
  }, []);

  return (
    <ConfirmationContext.Provider value={confirm}>
      {children}
      <Dialog
        open={request !== null}
        title={request?.title ?? "Confirm action"}
        onClose={() => {
          settle(false);
        }}
        actions={
          <>
            <Button
              type="button"
              variant="quiet"
              onClick={() => {
                settle(false);
              }}
            >
              Cancel
            </Button>
            <Button
              type="button"
              variant={request?.destructive === true ? "danger" : "primary"}
              onClick={() => {
                settle(true);
              }}
            >
              {request?.actionLabel ?? "Confirm"}
            </Button>
          </>
        }
      >
        <div>{request?.message}</div>
      </Dialog>
    </ConfirmationContext.Provider>
  );
}

export function useControlConfirmation(): Confirm {
  const value = useContext(ConfirmationContext);
  if (value === null) throw new Error("Control confirmation context is unavailable");
  return value;
}
