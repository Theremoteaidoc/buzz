import * as React from "react";

import { router } from "@/app/router";
import {
  createOnboardingHistoryState,
  onboardingRoutePath,
  readOnboardingHistoryEntry,
  type OnboardingHistoryEntry,
  type OnboardingRouteStep,
} from "./onboardingRoute";

const ONBOARDING_HISTORY_SESSION_ID = crypto.randomUUID();

type HistoryAction = "initial" | "PUSH" | "REPLACE" | "BACK" | "FORWARD" | "GO";

type OnboardingHistorySnapshot = {
  action: HistoryAction;
  depth: number;
  direction: "backward" | "forward";
  step: OnboardingRouteStep | null;
};

type OnboardingHistoryContextValue = OnboardingHistorySnapshot & {
  back: (fallback: OnboardingRouteStep) => void;
  backBy: (steps: number, fallback: OnboardingRouteStep) => void;
  exit: (path: string) => void;
  push: (step: OnboardingRouteStep) => void;
  replace: (step: OnboardingRouteStep) => void;
};

const OnboardingHistoryContext =
  React.createContext<OnboardingHistoryContextValue | null>(null);

function currentEntry(): OnboardingHistoryEntry | null {
  return readOnboardingHistoryEntry(
    router.history.location.pathname,
    router.history.location.state,
    ONBOARDING_HISTORY_SESSION_ID,
  );
}

function readSnapshot(
  action: HistoryAction,
  goIndex?: number,
): OnboardingHistorySnapshot {
  const entry = currentEntry();
  const direction =
    action === "BACK" || (action === "GO" && (goIndex ?? 0) < 0)
      ? "backward"
      : "forward";
  return {
    action,
    depth: entry?.depth ?? 0,
    direction,
    step: entry?.step ?? null,
  };
}

export function OnboardingHistoryProvider({
  children,
}: {
  children: React.ReactNode;
}) {
  const [snapshot, setSnapshot] = React.useState(() => readSnapshot("initial"));

  React.useEffect(
    () =>
      router.history.subscribe(({ action }) => {
        setSnapshot(
          readSnapshot(
            action.type,
            action.type === "GO" ? action.index : undefined,
          ),
        );
      }),
    [],
  );

  const replace = React.useCallback((step: OnboardingRouteStep) => {
    const entry = currentEntry();
    router.history.replace(
      onboardingRoutePath(step),
      createOnboardingHistoryState(
        ONBOARDING_HISTORY_SESSION_ID,
        entry?.depth ?? 0,
      ),
    );
  }, []);

  const push = React.useCallback((step: OnboardingRouteStep) => {
    const entry = currentEntry();
    router.history.push(
      onboardingRoutePath(step),
      createOnboardingHistoryState(
        ONBOARDING_HISTORY_SESSION_ID,
        (entry?.depth ?? 0) + 1,
      ),
    );
  }, []);

  const backBy = React.useCallback(
    (steps: number, fallback: OnboardingRouteStep) => {
      if (snapshot.step && steps > 0 && snapshot.depth >= steps) {
        router.history.go(-steps);
        return;
      }
      replace(fallback);
    },
    [replace, snapshot.depth, snapshot.step],
  );

  const back = React.useCallback(
    (fallback: OnboardingRouteStep) => backBy(1, fallback),
    [backBy],
  );

  const exit = React.useCallback((path: string) => {
    router.history.replace(path, {});
  }, []);

  const value = React.useMemo<OnboardingHistoryContextValue>(
    () => ({
      ...snapshot,
      back,
      backBy,
      exit,
      push,
      replace,
    }),
    [back, backBy, exit, push, replace, snapshot],
  );

  return (
    <OnboardingHistoryContext.Provider value={value}>
      {children}
    </OnboardingHistoryContext.Provider>
  );
}

export function useOnboardingHistory() {
  const value = React.useContext(OnboardingHistoryContext);
  if (!value) {
    throw new Error(
      "useOnboardingHistory must be used within OnboardingHistoryProvider",
    );
  }
  return value;
}
