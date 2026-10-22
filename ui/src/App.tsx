import React from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { Layout } from './components/layout/Layout';
// Load only the requested route's feature graph. This avoids bundling every
// report/graph/visualization dependency into the authentication entrypoint.
const Overview = React.lazy(() => import('./pages/Overview').then(m => ({ default: m.Overview })));
const MissionControl = React.lazy(() => import('./pages/MissionControl').then(m => ({ default: m.MissionControl })));
const ResearchIntelligence = React.lazy(() => import('./pages/ResearchIntelligence').then(m => ({ default: m.ResearchIntelligence })));
const KnowledgeGraphs = React.lazy(() => import('./pages/KnowledgeGraphs').then(m => ({ default: m.KnowledgeGraphs })));
const FindingsVerification = React.lazy(() => import('./pages/FindingsVerification').then(m => ({ default: m.FindingsVerification })));
const LearningAnalytics = React.lazy(() => import('./pages/LearningAnalytics').then(m => ({ default: m.LearningAnalytics })));
const DifferentialAuth = React.lazy(() => import('./pages/DifferentialAuth').then(m => ({ default: m.DifferentialAuth })));
const VisualContext = React.lazy(() => import('./pages/VisualContext').then(m => ({ default: m.VisualContext })));
const UncertaintyEngine = React.lazy(() => import('./pages/UncertaintyEngine').then(m => ({ default: m.UncertaintyEngine })));
const RealityVerificationCenter = React.lazy(() => import('./pages/RealityVerificationCenter').then(m => ({ default: m.RealityVerificationCenter })));
const Administration = React.lazy(() => import('./pages/Administration').then(m => ({ default: m.Administration })));
const SkillIntelligence = React.lazy(() => import('./pages/SkillIntelligence').then(m => ({ default: m.SkillIntelligence })));
const AuthAudit = React.lazy(() => import('./pages/AuthAudit').then(m => ({ default: m.AuthAudit })));
const MissionTimeline = React.lazy(() => import('./pages/MissionTimeline').then(m => ({ default: m.MissionTimeline })));
const MissionReport = React.lazy(() => import('./pages/MissionReport').then(m => ({ default: m.MissionReport })));
const FlowOperations = React.lazy(() => import('./pages/FlowOperations').then(m => ({ default: m.FlowOperations })));
const UserLibrary = React.lazy(() => import('./pages/UserLibrary').then(m => ({ default: m.UserLibrary })));

class ErrorBoundary extends React.Component<{children: React.ReactNode}, {hasError: boolean, error: any}> {
  constructor(props: any) {
    super(props);
    this.state = { hasError: false, error: null };
  }
  static getDerivedStateFromError(error: any) { return { hasError: true, error }; }
  render() {
    if (this.state.hasError) {
      return (
        <div className="h-screen w-full bg-black text-error p-10 font-code-sm">
          <h1 className="text-[24px] mb-4">CRITICAL_RENDER_FAILURE</h1>
          <pre className="bg-surface-container p-4 border border-error/50 whitespace-pre-wrap">
            {this.state.error?.toString()}
          </pre>
          <button onClick={() => window.location.reload()} className="mt-6 px-6 py-2 bg-error text-white font-label-caps">RELOAD RUNTIME</button>
        </div>
      );
    }
    return this.props.children;
  }
}

export default function App() {
  return (
    <ErrorBoundary>
      <BrowserRouter>
        <React.Suspense fallback={<div role="status" className="p-8 font-code-sm text-on-surface-variant">Loading the requested view...</div>}>
        <Routes>
          <Route path="/" element={<Layout />}>
            <Route index element={<Overview />} />
            <Route path="mission-control" element={<MissionControl />} />
            <Route path="flows" element={<FlowOperations />} />
            <Route path="intelligence" element={<ResearchIntelligence />} />
            <Route path="knowledge-graphs" element={<KnowledgeGraphs />} />
            <Route path="user-library" element={<UserLibrary />} />
            <Route path="findings" element={<FindingsVerification />} />
            <Route path="verification" element={<RealityVerificationCenter />} />
            <Route path="uncertainty" element={<UncertaintyEngine />} />
            <Route path="skills" element={<SkillIntelligence />} />
            <Route path="auth-audit" element={<AuthAudit />} />
            <Route path="timeline" element={<MissionTimeline />} />
            <Route path="learning" element={<LearningAnalytics />} />
            <Route path="differential-auth" element={<DifferentialAuth />} />
            <Route path="visual-context" element={<VisualContext />} />
            <Route path="admin" element={<Administration />} />
            <Route path="report/:sessionId" element={<MissionReport />} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Route>
        </Routes>
        </React.Suspense>
      </BrowserRouter>
    </ErrorBoundary>
  );
}
