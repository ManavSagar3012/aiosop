import React, { Suspense } from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { ThemeProvider } from './contexts/ThemeContext';
import { ToastProvider } from './contexts/ToastContext';
import { Layout } from './components/layout/Layout';

// Lazy-loaded page chunks — each route is its own bundle
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

// Loading fallback for lazy chunks
function PageLoader() {
  return (
    <div
      style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        height: '100vh',
        background: 'var(--bg-app)',
        color: 'var(--text-secondary)',
        fontFamily: "'Space Grotesk', sans-serif",
        fontSize: 14,
        gap: 12,
      }}
    >
      <div
        style={{
          width: 20,
          height: 20,
          border: '2px solid var(--border)',
          borderTopColor: 'var(--accent)',
          borderRadius: '50%',
          animation: 'spin 0.8s linear infinite',
        }}
      />
      Loading module…
    </div>
  );
}

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
          style={{
            height: '100vh',
            width: '100%',
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'center',
            justifyContent: 'center',
            padding: 40,
            background: 'var(--bg-app)',
            color: 'var(--danger)',
          }}
        >
          <div
            style={{
              fontFamily: "'Space Grotesk', sans-serif",
              fontSize: 24,
              fontWeight: 700,
              marginBottom: 24,
            }}
          >
            CRITICAL RENDER FAILURE
          </div>
          <pre
            style={{
              marginBottom: 24,
              padding: 24,
              maxWidth: 640,
              width: '100%',
              overflow: 'auto',
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
            <Suspense fallback={<PageLoader />}>
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
            </Suspense>
          </BrowserRouter>
        </ToastProvider>
      </ThemeProvider>
    </ErrorBoundary>
  );
}
