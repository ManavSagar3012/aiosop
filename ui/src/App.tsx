import React from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { ThemeProvider } from './contexts/ThemeContext';
import { ToastProvider } from './contexts/ToastContext';
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

class ErrorBoundary extends React.Component<
  { children: React.ReactNode },
  { hasError: boolean; error: any }
> {
  constructor(props: any) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error: any) {
    return { hasError: true, error };
  }

  render() {
    if (this.state.hasError) {
      return (
        <div
          className="h-screen w-full flex flex-col items-center justify-center p-10"
          style={{ background: 'var(--bg-app)', color: 'var(--danger)' }}
        >
          <div
            className="mb-6"
            style={{
              fontFamily: "'Space Grotesk', sans-serif",
              fontSize: 24,
              fontWeight: 700,
            }}
          >
            CRITICAL RENDER FAILURE
          </div>
          <pre
            className="mb-6 p-6 max-w-2xl w-full overflow-auto"
            style={{
              background: 'var(--surface-1)',
              border: '1px solid var(--danger-border)',
              borderRadius: 'var(--radius-lg)',
              fontFamily: "'JetBrains Mono', monospace",
              fontSize: 12,
              lineHeight: 1.6,
              color: 'var(--text-primary)',
              whiteSpace: 'pre-wrap',
            }}
          >
            {this.state.error?.toString()}
          </pre>
          <button
            onClick={() => window.location.reload()}
            className="btn btn-danger"
          >
            RELOAD RUNTIME
          </button>
        </div>
      );
    }
    return this.props.children;
  }
}

export default function App() {
  return (
    <ErrorBoundary>
      <ThemeProvider>
        <ToastProvider>
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
        </ToastProvider>
      </ThemeProvider>
    </ErrorBoundary>
  );
}
