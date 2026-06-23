import { Routes, Route } from 'react-router-dom';
import AppShell from './layout/AppShell';
import Overview from './pages/Overview';
import AssetsView from './pages/AssetsView';
import RoadmapView from './pages/RoadmapView';
import ReportsView from './pages/ReportsView';
import LearnView from './pages/LearnView';
import CERTInView from './pages/CERTInView';
import SEBIView from './pages/SEBIView';
import RBIView from './pages/RBIView';
import IRDAIView from './pages/IRDAIView';
import SettingsView from './pages/SettingsView';
import NotFound from './pages/NotFound';

export default function App() {
  return (
    <AppShell>
      <Routes>
        <Route path="/" element={<Overview />} />
        <Route path="/assets" element={<AssetsView />} />
        <Route path="/roadmap" element={<RoadmapView />} />
        <Route path="/reports" element={<ReportsView />} />
        <Route path="/learn" element={<LearnView />} />
        <Route path="/compliance/certin" element={<CERTInView />} />
        <Route path="/compliance/sebi" element={<SEBIView />} />
        <Route path="/compliance/rbi" element={<RBIView />} />
        <Route path="/compliance/irdai" element={<IRDAIView />} />
        <Route path="/settings" element={<SettingsView />} />
        <Route path="*" element={<NotFound />} />
      </Routes>
    </AppShell>
  );
}
