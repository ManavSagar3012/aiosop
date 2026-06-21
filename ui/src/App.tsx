import React from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { Layout } from './components/layout/Layout';
import { Overview } from './pages/Overview';
import { MissionControl } from './pages/MissionControl';
import { ResearchIntelligence } from './pages/ResearchIntelligence';
import { KnowledgeGraphs } from './pages/KnowledgeGraphs';
import { FindingsVerification } from './pages/FindingsVerification';
import { LearningAnalytics } from './pages/LearningAnalytics';
import { DifferentialAuth } from './pages/DifferentialAuth';
import { VisualContext } from './pages/VisualContext';
import { UncertaintyEngine } from './pages/UncertaintyEngine';
import { RealityVerificationCenter } from './pages/RealityVerificationCenter';
import { Administration } from './pages/Administration';
import { SkillIntelligence } from './pages/SkillIntelligence';
import { AuthAudit } from './pages/AuthAudit';
import { MissionTimeline } from './pages/MissionTimeline';
import { MissionReport } from './pages/MissionReport';

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
        <Routes>
          <Route path="/" element={<Layout />}>
            <Route index element={<Overview />} />
            <Route path="mission-control" element={<MissionControl />} />
            <Route path="intelligence" element={<ResearchIntelligence />} />
            <Route path="knowledge-graphs" element={<KnowledgeGraphs />} />
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
      </BrowserRouter>
    </ErrorBoundary>
  );
}
