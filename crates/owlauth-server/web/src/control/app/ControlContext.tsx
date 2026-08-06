import {
  createContext,
  useCallback,
  useContext,
  useLayoutEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import { useLocation } from "react-router";
import type { ReactNode } from "react";

import type { ToastMessage } from "../../shared/primitives/Feedback";
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
  readonly messageTone: "warning" | "danger";
  readonly toasts: readonly ToastMessage[];
  readonly dismissToast: (id: number) => void;
  readonly clearFeedback: () => void;
  readonly upsertProject: (project: Project) => void;
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
  const [messageTone, setMessageTone] = useState<ControlContextValue["messageTone"]>("warning");
  const [toasts, setToasts] = useState<readonly ToastMessage[]>([]);
  const nextToastId = useRef(1);
  const location = useLocation();
  const previousRouteKey = useRef(location.key);
  const activeRouteGeneration = useRef(0);
  const [routeGeneration, setRouteGeneration] = useState(0);

  useLayoutEffect(() => {
    if (previousRouteKey.current === location.key) return;
    previousRouteKey.current = location.key;
    activeRouteGeneration.current += 1;
    setRouteGeneration(activeRouteGeneration.current);
  }, [location.key]);

  const dismissToast = useCallback((id: number) => {
    setToasts((current) => current.filter((toast) => toast.id !== id));
  }, []);

  const clearFeedback = useCallback(() => {
    setCurrentMessage(null);
    setToasts([]);
  }, []);

  const upsertProject = useCallback((project: Project) => {
    setProjects((current) => [
      ...current.filter((candidate) => candidate.id !== project.id),
      project,
    ]);
  }, []);

  const setMessage = useCallback<ControlContextValue["setMessage"]>(
    (next, tone = "info") => {
      if (activeRouteGeneration.current !== routeGeneration) return;
      if (next === null) {
        setCurrentMessage(null);
        return;
      }
      if (tone === "success" || tone === "info") {
        setCurrentMessage(null);
        const id = nextToastId.current++;
        setToasts((current) => [...current.slice(-2), { id, message: next, tone }]);
        window.setTimeout(() => {
          dismissToast(id);
        }, 5000);
        return;
      }
      setToasts([]);
      setCurrentMessage(next);
      setMessageTone(tone);
    },
    [dismissToast, routeGeneration],
  );

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
      toasts,
      dismissToast,
      clearFeedback,
      upsertProject,
      refreshProjects,
      setMessage,
      handleError,
      lock,
    }),
    [
      clearFeedback,
      dismissToast,
      handleError,
      loadingProjects,
      lock,
      message,
      messageTone,
      projects,
      refreshProjects,
      session,
      setMessage,
      toasts,
      upsertProject,
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
