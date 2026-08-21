// Maps one AgentAction returned by the AI Agent backend onto a react-router
// navigation, reusing the dashboard's EXISTING URL contracts unmodified:
//   - filter_assets -> AssetsView.tsx's ?q= PropertyFilter query param
//     (see parseQueryParam / QUERY_PARAM there — this must produce exactly
//     that shape, which PropertyFilterQuery mirrors field-for-field).
//   - select_asset  -> AssetsView.tsx's ?asset=<bomRef> selection param,
//     which already drives the SplitPanel open/close effect.
//   - view_roadmap  -> RoadmapView.tsx's ?service=<raw id> filter param.
// A pure function (no React) so it is trivially testable and keeps
// AgentChatPanel.tsx free of navigation-format details.
import type { NavigateFunction } from 'react-router-dom';
import type { AgentAction } from '../services/agentApi';

export function dispatchAgentAction(action: AgentAction, navigate: NavigateFunction): void {
  switch (action.type) {
    case 'filter_assets': {
      const q = action.query ? `?q=${encodeURIComponent(JSON.stringify(action.query))}` : '';
      navigate(`/assets${q}`);
      return;
    }
    case 'select_asset': {
      if (!action.assetBomRef) return;
      const params = new URLSearchParams();
      if (action.query) params.set('q', JSON.stringify(action.query));
      params.set('asset', action.assetBomRef);
      navigate(`/assets?${params.toString()}`);
      return;
    }
    case 'view_roadmap': {
      navigate(action.service ? `/roadmap?service=${encodeURIComponent(action.service)}` : '/roadmap');
      return;
    }
    default:
      return;
  }
}
