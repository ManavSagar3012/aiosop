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
import { AlertTriangle } from 'lucide-react';
import { PageErrorBoundary } from './components/shared/PageErrorBoundary';
import { MissionTimeline } from './pages/MissionTimeline';
import { MissionReport } from './pages/MissionReport';

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

export default function App() {
  return (
    <ErrorBoundary>
      <BrowserRouter>
        <Routes>
          <Route path="/" element={<Layout />}>
            <Route index element={<PageErrorBoundary pageName="Overview"><Overview /></PageErrorBoundary>} />
            <Route path="mission-control" element={<PageErrorBoundary pageName="MissionControl"><MissionControl /></PageErrorBoundary>} />
            <Route path="intelligence" element={<PageErrorBoundary pageName="ResearchIntelligence"><ResearchIntelligence /></PageErrorBoundary>} />
            <Route path="knowledge-graphs" element={<PageErrorBoundary pageName="KnowledgeGraphs"><KnowledgeGraphs /></PageErrorBoundary>} />
            <Route path="findings" element={<PageErrorBoundary pageName="FindingsVerification"><FindingsVerification /></PageErrorBoundary>} />
            <Route path="verification" element={<PageErrorBoundary pageName="RealityVerificationCenter"><RealityVerificationCenter /></PageErrorBoundary>} />
            <Route path="uncertainty" element={<PageErrorBoundary pageName="UncertaintyEngine"><UncertaintyEngine /></PageErrorBoundary>} />
            <Route path="skills" element={<PageErrorBoundary pageName="SkillIntelligence"><SkillIntelligence /></PageErrorBoundary>} />
            <Route path="auth-audit" element={<PageErrorBoundary pageName="AuthAudit"><AuthAudit /></PageErrorBoundary>} />
            <Route path="timeline" element={<PageErrorBoundary pageName="MissionTimeline"><MissionTimeline /></PageErrorBoundary>} />
            <Route path="learning" element={<PageErrorBoundary pageName="LearningAnalytics"><LearningAnalytics /></PageErrorBoundary>} />
            <Route path="differential-auth" element={<PageErrorBoundary pageName="DifferentialAuth"><DifferentialAuth /></PageErrorBoundary>} />
            <Route path="visual-context" element={<PageErrorBoundary pageName="VisualContext"><VisualContext /></PageErrorBoundary>} />
            <Route path="admin" element={<PageErrorBoundary pageName="Administration"><Administration /></PageErrorBoundary>} />
            <Route path="report/:sessionId" element={<PageErrorBoundary pageName="MissionReport"><MissionReport /></PageErrorBoundary>} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Route>
        </Routes>
      </BrowserRouter>
    </ErrorBoundary>
  );
}
