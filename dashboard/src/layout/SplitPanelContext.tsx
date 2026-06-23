import { createContext, useContext } from 'react';

export interface SplitPanelState {
  /** Header shown at the top of the SplitPanel. */
  header: string;
  /** SplitPanel body content. */
  content: React.ReactNode;
}

export interface SplitPanelController {
  /** Open the SplitPanel with the given header + content. */
  openSplitPanel: (state: SplitPanelState) => void;
  /** Close (collapse) the SplitPanel. */
  closeSplitPanel: () => void;
}

// Pages call openSplitPanel(...) to show per-asset detail in the AppLayout's
// splitPanel slot, which is owned by AppShell. Default is a no-op so a page
// rendered outside the shell (e.g. in isolation) does not crash.
export const SplitPanelContext = createContext<SplitPanelController>({
  openSplitPanel: () => {},
  closeSplitPanel: () => {},
});

export function useSplitPanel(): SplitPanelController {
  return useContext(SplitPanelContext);
}
