import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import AppLayout from '@cloudscape-design/components/app-layout';
import SideNavigation from '@cloudscape-design/components/side-navigation';
import type { SideNavigationProps } from '@cloudscape-design/components/side-navigation';
import TopNavigation from '@cloudscape-design/components/top-navigation';
import SplitPanel from '@cloudscape-design/components/split-panel';
import Flashbar from '@cloudscape-design/components/flashbar';
import { SplitPanelContext } from './SplitPanelContext';
import type { SplitPanelState } from './SplitPanelContext';
import { getRuntimeConfig, fetchLatestCBOM } from '../services/api';
import { scanProvenance, isDemoData } from '../hooks/useScanData';

interface Props {
  children: React.ReactNode;
}

const NAV_ITEMS: SideNavigationProps.Item[] = [
  { type: 'link', text: 'Overview', href: '/' },
  { type: 'link', text: 'Crypto Assets', href: '/assets' },
  { type: 'link', text: 'PQC Roadmap', href: '/roadmap' },
  { type: 'link', text: 'Reports', href: '/reports' },
  { type: 'link', text: 'Learn', href: '/learn' },
  {
    type: 'section',
    text: 'Compliance',
    items: [
      { type: 'link', text: 'CERT-In (national)', href: '/compliance/certin' },
      { type: 'link', text: 'SEBI CSCRF', href: '/compliance/sebi' },
      { type: 'link', text: 'RBI', href: '/compliance/rbi' },
      { type: 'link', text: 'IRDAI', href: '/compliance/irdai' },
    ],
  },
  { type: 'divider' },
  { type: 'link', text: 'Settings', href: '/settings' },
];

// activeHref maps the current location to the best-matching nav href so the
// SideNavigation highlight tracks react-router rather than maintaining its own
// source of truth.
function activeHref(pathname: string): string {
  if (pathname === '/') return '/';
  const hrefs = ['/assets', '/roadmap', '/reports', '/learn', '/compliance/certin', '/compliance/sebi', '/compliance/rbi', '/compliance/irdai', '/settings'];
  const match = hrefs
    .filter((h) => pathname === h || pathname.startsWith(h + '/'))
    .sort((a, b) => b.length - a.length)[0];
  return match ?? pathname;
}

const SPLIT_PANEL_I18N = {
  closeButtonAriaLabel: 'Close panel',
  openButtonAriaLabel: 'Open panel',
  preferencesTitle: 'Split panel preferences',
  preferencesPositionLabel: 'Split panel position',
  preferencesPositionDescription: 'Choose the default split panel position for the service.',
  preferencesPositionSide: 'Side',
  preferencesPositionBottom: 'Bottom',
  preferencesConfirm: 'Confirm',
  preferencesCancel: 'Cancel',
  resizeHandleAriaLabel: 'Resize split panel',
};

export default function AppShell({ children }: Props) {
  const location = useLocation();
  const navigate = useNavigate();
  const [navOpen, setNavOpen] = useState(true);
  // Data-authenticity label. The signal is the DATA's own provenance
  // (cryptamap:mode in the loaded CBOM's metadata), NOT config.json's mockMode
  // (which is only a transport flag: static-file vs live-API). This is why a
  // customer's real `cryptamap serve` scan — served over the static-file
  // transport (mockMode:true) but carrying mode=live/merged in the CBOM — is
  // correctly labeled a real scan, never "Mock mode". `dataMode`:
  //   'mock'   → synthetic demo data (NOT a real scan)
  //   'live'   → real single-account AWS scan
  //   'merged' → real org-wide merged scan
  //   ''       → unknown (CBOM had no mode); fall back to the transport flag
  const [dataMode, setDataMode] = useState<string | null>(null);
  const [demo, setDemo] = useState<boolean | null>(null);
  const [bannerDismissed, setBannerDismissed] = useState(false);
  useEffect(() => {
    let cancelled = false;
    (async () => {
      const cfg = await getRuntimeConfig();
      const transportMock = !!cfg?.mockMode || !cfg?.apiBase;
      const cbom = await fetchLatestCBOM().catch(() => null);
      if (cancelled) return;
      setDataMode(scanProvenance(cbom)?.mode ?? '');
      setDemo(isDemoData(cbom, transportMock));
    })();
    return () => { cancelled = true; };
  }, []);

  // Three-state authenticity chip text/icon, driven by the data's own mode.
  const chip =
    demo === null
      ? { text: '', icon: 'status-info' as const }
      : demo
        ? { text: 'Demo data', icon: 'status-warning' as const }
        : dataMode === 'merged'
          ? { text: 'Live org scan', icon: 'status-positive' as const }
          : { text: 'Live scan', icon: 'status-positive' as const };

  // SplitPanel state owned here so any page can push per-asset detail into the
  // AppLayout splitPanel slot via the SplitPanelContext. We stamp the route the
  // panel was opened on so the route-change reset (below) can tell a freshly
  // (re)opened panel from a stale one left over from the previous page.
  const [panel, setPanel] = useState<(SplitPanelState & { path: string }) | null>(null);
  const [panelOpen, setPanelOpen] = useState(false);

  const openSplitPanel = useCallback(
    (state: SplitPanelState) => {
      setPanel({ ...state, path: location.pathname });
      setPanelOpen(true);
    },
    [location.pathname],
  );
  // Collapse AND clear the panel content. Clearing `panel` is essential:
  // AppShell lives above <Routes>, so without nulling the content a later
  // re-open (or a re-mount of the AppLayout splitPanel) would resurrect the
  // previous asset's detail.
  const closeSplitPanel = useCallback(() => {
    setPanelOpen(false);
    setPanel(null);
  }, []);

  // Reset the split panel whenever the route's base path changes. Selection is
  // driven by per-route URL params, so navigating away (e.g. Roadmap -> item
  // -> Back to Overview) must not leave a stale detail panel open on a page
  // that never opened one. We key on pathname only (not the query string), and
  // skip the very first render plus any transition the destination page itself
  // handles: the reset runs in a layout effect that fires AFTER the destination
  // page's open effect for the same commit, so we record the path the page
  // opened on and never clear a panel that was (re)opened for the current path.
  const prevPathRef = useRef(location.pathname);
  useEffect(() => {
    if (prevPathRef.current !== location.pathname) {
      // The page that owns the new path runs its own open effect (a child
      // effect) before this parent effect. If it opened a panel, `panel` now
      // belongs to the current path and we must NOT clear it; otherwise we
      // clear the stale panel left over from the previous route.
      if (!panel || panel.path !== location.pathname) {
        setPanelOpen(false);
        setPanel(null);
      }
      prevPathRef.current = location.pathname;
    }
  }, [location.pathname, panel]);

  const controller = useMemo(
    () => ({ openSplitPanel, closeSplitPanel }),
    [openSplitPanel, closeSplitPanel],
  );

  return (
    <SplitPanelContext.Provider value={controller}>
      <div id="app-top-nav">
        <TopNavigation
          identity={{
            href: '/',
            title: 'CryptaMap',
            onFollow: (e) => {
              e.preventDefault();
              navigate('/');
            },
          }}
          utilities={[
            {
              type: 'button',
              text: chip.text,
              iconName: chip.icon,
            },
            { type: 'button', text: 'v1.0.0' },
          ]}
        />
      </div>
      <AppLayout
        headerSelector="#app-top-nav"
        navigationOpen={navOpen}
        onNavigationChange={({ detail }) => setNavOpen(detail.open)}
        toolsHide
        navigation={
          <SideNavigation
            header={{ href: '/', text: 'CryptaMap' }}
            activeHref={activeHref(location.pathname)}
            items={NAV_ITEMS}
            onFollow={(e) => {
              if (!e.detail.external) {
                e.preventDefault();
                navigate(e.detail.href);
              }
            }}
          />
        }
        splitPanelOpen={panelOpen}
        onSplitPanelToggle={({ detail }) => setPanelOpen(detail.open)}
        splitPanel={
          panel ? (
            <SplitPanel header={panel.header} i18nStrings={SPLIT_PANEL_I18N} closeBehavior="hide">
              {panel.content}
            </SplitPanel>
          ) : undefined
        }
        // Prominent, dismissible warning whenever the loaded data is synthetic
        // demo data — so a real customer (especially a regulator/auditor) can
        // never mistake illustrative findings for a real AWS scan. Shown only for
        // demo data; real live/merged scans render no nag.
        notifications={
          demo && !bannerDismissed ? (
            <Flashbar
              items={[
                {
                  type: 'warning',
                  dismissible: true,
                  onDismiss: () => setBannerDismissed(true),
                  header: 'Demo data — not a real AWS scan',
                  content:
                    'This dashboard is showing synthetic sample data for demonstration. Findings, accounts, and postures are illustrative only. To see your own environment, run a CryptaMap scan and open it with `cryptamap serve ./out`.',
                  id: 'demo-data-warning',
                },
              ]}
            />
          ) : undefined
        }
        content={children}
      />
    </SplitPanelContext.Provider>
  );
}
