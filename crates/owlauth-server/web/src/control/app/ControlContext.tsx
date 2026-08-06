import { createContext, useCallback, useContext, useMemo, useState } from "react";
import type { ReactNode } from "react";

import {
  ControlRequestError,
  type DisposableControlClient,
  type Project,
  requireData,
} from "../client";

interface ControlContextValue {
  readonly session: DisposableControlClient;
  readonly projects: readonly Project[];
  readonly loadingProjects: boolean;
  readonly message: string | null;
  readonly messageTone: "info" | "success" | "warning" | "danger";
  readonly refreshProjects: () => Promise<Project[]>;
  readonly setMessage: (
    message: string | null,
    tone?: "info" | "success" | "warning" | "danger",
  ) => void;
  readonly handleError: (error: unknown, refreshConflict?: () => Promise<void>) => Promise<void>;
  readonly lock: () => void;
}

const ControlContext = createContext<ControlContextValue | null>(null);

interface ControlProviderProps {
  readonly session: DisposableControlClient;
  readonly initialProjects: readonly Project[];
  readonly lock: () => void;
  readonly children: ReactNode;
}

export function ControlProvider({
  session,
  initialProjects,
  lock,
  children,
}: ControlProviderProps) {
  const [projects, setProjects] = useState<readonly Project[]>(initialProjects);
  const [loadingProjects, setLoadingProjects] = useState(false);
  const [message, setCurrentMessage] = useState<string | null>(null);
  const [messageTone, setMessageTone] = useState<ControlContextValue["messageTone"]>("info");

  const setMessage = useCallback<ControlContextValue["setMessage"]>((next, tone = "info") => {
    setCurrentMessage(next);
    setMessageTone(tone);
  }, []);

  const refreshProjects = useCallback(async () => {
    setLoadingProjects(true);
    try {
      const result = await session.client.GET("/v1/projects");
      const next = requireData(result.data, result.error, result.response).items;
      setProjects(next);
      return next;
    } finally {
      setLoadingProjects(false);
    }
  }, [session]);

  const handleError = useCallback<ControlContextValue["handleError"]>(
    async (error, refreshConflict) => {
      if (error instanceof ControlRequestError && error.status === 401) {
        lock();
        return;
      }
      if (
        error instanceof ControlRequestError &&
        error.status === 409 &&
        error.code === "revision_conflict"
      ) {
        try {
          if (refreshConflict === undefined) await refreshProjects();
          else await refreshConflict();
          setMessage(
            "The resource changed. Current state was refreshed; review it before submitting again.",
            "warning",
          );
        } catch (refreshError) {
          if (refreshError instanceof ControlRequestError && refreshError.status === 401) {
            lock();
            return;
          }
          setMessage("The current state could not be refreshed.", "danger");
        }
        return;
      }
      setMessage(
        error instanceof ControlRequestError
          ? error.message
          : "The request could not be completed.",
        "danger",
      );
    },
    [lock, refreshProjects, setMessage],
  );

  const value = useMemo<ControlContextValue>(
    () => ({
      session,
      projects,
      loadingProjects,
      message,
      messageTone,
      refreshProjects,
      setMessage,
      handleError,
      lock,
    }),
    [
      handleError,
      loadingProjects,
      lock,
      message,
      messageTone,
      projects,
      refreshProjects,
      session,
      setMessage,
    ],
  );

  return <ControlContext.Provider value={value}>{children}</ControlContext.Provider>;
}

export function useControl(): ControlContextValue {
  const value = useContext(ControlContext);
  if (value === null) throw new Error("Control context is unavailable");
  return value;
}

export function useProject(projectId: string | undefined): Project | null {
  const { projects } = useControl();
  if (projectId === undefined) return null;
  return projects.find((project) => project.id === projectId) ?? null;
}
