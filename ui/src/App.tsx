import React, { Suspense, lazy } from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { Layout } from './components/layout/Layout';
import { AlertTriangle } from 'lucide-react';
import { PageErrorBoundary } from './components/shared/PageErrorBoundary';
import { Skeleton } from './components/shared/Skeleton';

const Overview = lazy(() => import('./pages/Overview').then((m) => ({ default: m.Overview })));
const MissionControl = lazy(() => import('./pages/MissionControl').then((m) => ({ default: m.MissionControl })));
const ResearchIntelligence = lazy(() => import('./pages/ResearchIntelligence').then((m) => ({ default: m.ResearchIntelligence })));
const KnowledgeGraphs = lazy(() => import('./pages/KnowledgeGraphs').then((m) => ({ default: m.KnowledgeGraphs })));
const FindingsVerification = lazy(() => import('./pages/FindingsVerification').then((m) => ({ default: m.FindingsVerification })));
const LearningAnalytics = lazy(() => import('./pages/LearningAnalytics').then((m) => ({ default: m.LearningAnalytics })));
const DifferentialAuth = lazy(() => import('./pages/DifferentialAuth').then((m) => ({ default: m.DifferentialAuth })));
const VisualContext = lazy(() => import('./pages/VisualContext').then((m) => ({ default: m.VisualContext })));
const UncertaintyEngine = lazy(() => import('./pages/UncertaintyEngine').then((m) => ({ default: m.UncertaintyEngine })));
const RealityVerificationCenter = lazy(() => import('./pages/RealityVerificationCenter').then((m) => ({ default: m.RealityVerificationCenter })));
const Administration = lazy(() => import('./pages/Administration').then((m) => ({ default: m.Administration })));
const SkillIntelligence = lazy(() => import('./pages/SkillIntelligence').then((m) => ({ default: m.SkillIntelligence })));
const AuthAudit = lazy(() => import('./pages/AuthAudit').then((m) => ({ default: m.AuthAudit })));
const MissionTimeline = lazy(() => import('./pages/MissionTimeline').then((m) => ({ default: m.MissionTimeline })));
const MissionReport = lazy(() => import('./pages/MissionReport').then((m) => ({ default: m.MissionReport })));
const ReasoningTrace = lazy(() => import('./pages/ReasoningTrace').then((m) => ({ default: m.ReasoningTrace })));
const CognitionDashboard = lazy(() => import('./pages/CognitionDashboard').then((m) => ({ default: m.CognitionDashboard })));
const Hypotheses = lazy(() => import('./pages/Hypotheses').then((m) => ({ default: m.Hypotheses })));
const AttackChains = lazy(() => import('./pages/AttackChains').then((m) => ({ default: m.AttackChains })));

class ErrorBoundary extends React.Component<{children: React.ReactNode}, {hasError: boolean, error: any}> {
  constructor(props: any) {
    super(props);
    this.state = { hasError: false, error: null };
  }
  static getDerivedStateFromError(error: any) { return { hasError: true, error }; }
  handleReset = () => {
    this.setState({ hasError: false, error: null });
  };
  render() {
    if (this.state.hasError) {
      return (
        <div className="h-screen w-full bg-black text-error p-10 font-code-sm flex flex-col items-center justify-center">
          <AlertTriangle size={48} className="text-error mb-6 opacity-70" />
          <h1 className="text-[24px] mb-4 tracking-wider">CRITICAL_RENDER_FAILURE</h1>
          <pre className="bg-surface-container p-4 border border-error/50 whitespace-pre-wrap max-w-2xl w-full max-h-40 overflow-y-auto mb-6">
            {this.state.error?.toString()}
          </pre>
          <div className="flex gap-4">
            <button onClick={this.handleReset} className="px-6 py-2.5 bg-error text-white font-label-caps hover:brightness-110 transition-all">
              RETRY RENDER
            </button>
            <button onClick={() => { this.handleReset(); window.location.href = '/'; }} className="px-6 py-2.5 border border-outline text-on-surface font-label-caps hover:bg-surface-container-high transition-all">
              GO TO DASHBOARD
            </button>
          </div>
        </div>
      );
    }
    return this.props.children;
  }
}

const PageFallback: React.FC = () => (
  <div className="flex flex-col gap-4 p-2">
    <Skeleton className="h-8 w-64" />
    <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
      {Array.from({ length: 4 }).map((_, i) => (
        <Skeleton key={i} className="h-24" />
      ))}
    </div>
    <Skeleton className="h-64 w-full" />
  </div>
);

export default function App() {
  return (
    <ErrorBoundary>
      <BrowserRouter>
        <Routes>
          <Route path="/" element={<Layout />}>
            <Route index element={<PageErrorBoundary pageName="Overview"><Suspense fallback={<PageFallback />}><Overview /></Suspense></PageErrorBoundary>} />
            <Route path="mission-control" element={<PageErrorBoundary pageName="MissionControl"><Suspense fallback={<PageFallback />}><MissionControl /></Suspense></PageErrorBoundary>} />
            <Route path="intelligence" element={<PageErrorBoundary pageName="ResearchIntelligence"><Suspense fallback={<PageFallback />}><ResearchIntelligence /></Suspense></PageErrorBoundary>} />
            <Route path="knowledge-graphs" element={<PageErrorBoundary pageName="KnowledgeGraphs"><Suspense fallback={<PageFallback />}><KnowledgeGraphs /></Suspense></PageErrorBoundary>} />
            <Route path="findings" element={<PageErrorBoundary pageName="FindingsVerification"><Suspense fallback={<PageFallback />}><FindingsVerification /></Suspense></PageErrorBoundary>} />
            <Route path="verification" element={<PageErrorBoundary pageName="RealityVerificationCenter"><Suspense fallback={<PageFallback />}><RealityVerificationCenter /></Suspense></PageErrorBoundary>} />
            <Route path="uncertainty" element={<PageErrorBoundary pageName="UncertaintyEngine"><Suspense fallback={<PageFallback />}><UncertaintyEngine /></Suspense></PageErrorBoundary>} />
            <Route path="skills" element={<PageErrorBoundary pageName="SkillIntelligence"><Suspense fallback={<PageFallback />}><SkillIntelligence /></Suspense></PageErrorBoundary>} />
            <Route path="auth-audit" element={<PageErrorBoundary pageName="AuthAudit"><Suspense fallback={<PageFallback />}><AuthAudit /></Suspense></PageErrorBoundary>} />
            <Route path="timeline" element={<PageErrorBoundary pageName="MissionTimeline"><Suspense fallback={<PageFallback />}><MissionTimeline /></Suspense></PageErrorBoundary>} />
            <Route path="learning" element={<PageErrorBoundary pageName="LearningAnalytics"><Suspense fallback={<PageFallback />}><LearningAnalytics /></Suspense></PageErrorBoundary>} />
            <Route path="differential-auth" element={<PageErrorBoundary pageName="DifferentialAuth"><Suspense fallback={<PageFallback />}><DifferentialAuth /></Suspense></PageErrorBoundary>} />
            <Route path="visual-context" element={<PageErrorBoundary pageName="VisualContext"><Suspense fallback={<PageFallback />}><VisualContext /></Suspense></PageErrorBoundary>} />
            <Route path="admin" element={<PageErrorBoundary pageName="Administration"><Suspense fallback={<PageFallback />}><Administration /></Suspense></PageErrorBoundary>} />
            <Route path="report/:sessionId" element={<PageErrorBoundary pageName="MissionReport"><Suspense fallback={<PageFallback />}><MissionReport /></Suspense></PageErrorBoundary>} />
            <Route path="reasoning" element={<PageErrorBoundary pageName="Reasoning"><Suspense fallback={<PageFallback />}><ReasoningTrace /></Suspense></PageErrorBoundary>} />
            <Route path="cognition" element={<PageErrorBoundary pageName="Cognition"><Suspense fallback={<PageFallback />}><CognitionDashboard /></Suspense></PageErrorBoundary>} />
            <Route path="hypotheses" element={<PageErrorBoundary pageName="Hypotheses"><Suspense fallback={<PageFallback />}><Hypotheses /></Suspense></PageErrorBoundary>} />
            <Route path="attack-chains" element={<PageErrorBoundary pageName="AttackChains"><Suspense fallback={<PageFallback />}><AttackChains /></Suspense></PageErrorBoundary>} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Route>
        </Routes>
      </BrowserRouter>
    </ErrorBoundary>
  );
}
