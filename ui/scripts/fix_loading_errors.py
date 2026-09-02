#!/usr/bin/env python3
"""Add loading skeleton states and page-level error boundaries to all pages."""

import os

UI_DIR = "src"

def read_file(rel_path):
    path = os.path.join(UI_DIR, rel_path)
    with open(path, 'r', encoding='utf-8', errors='replace') as f:
        return f.read()

def write_file(rel_path, content):
    path = os.path.join(UI_DIR, rel_path)
    with open(path, 'w', encoding='utf-8', newline='') as f:
        f.write(content)
    print(f"  Written: {rel_path}")

# ===================================================================
# 1. Create PageErrorBoundary component
# ===================================================================
print("\n=== 1. PageErrorBoundary component ===")

page_err_boundary = r"""import React from 'react';
import { AlertTriangle, RotateCcw } from 'lucide-react';

interface Props {
  children: React.ReactNode;
  pageName?: string;
}

interface State {
  hasError: boolean;
  error: Error | null;
}

export class PageErrorBoundary extends React.Component<Props, State> {
  constructor(props: Props) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error: Error) {
    return { hasError: true, error };
  }

  handleReset = () => {
    this.setState({ hasError: false, error: null });
  };

  render() {
    if (this.state.hasError) {
      return (
        <div className="flex flex-col items-center justify-center h-full min-h-[400px] p-12 text-center bg-surface-container-low border border-outline-variant/50">
          <AlertTriangle size={36} className="text-error mb-4 opacity-70" />
          <h2 className="font-label-caps text-label-caps text-error mb-2 uppercase tracking-wider">
            {this.props.pageName || 'Page'} Render Error
          </h2>
          <p className="font-code-sm text-[12px] text-on-surface-variant/70 max-w-md mb-6 leading-relaxed">
            {this.state.error?.message || 'An unexpected error occurred while rendering this page.'}
          </p>
          <button
            onClick={this.handleReset}
            className="flex items-center gap-2 px-6 py-2.5 border border-error text-error font-label-caps text-label-caps hover:bg-error/10 focus-visible:outline focus-visible:outline-2 focus-visible:outline-error transition-all"
          >
            <RotateCcw size={14} /> RETRY
          </button>
        </div>
      );
    }
    return this.props.children;
  }
}
"""

write_file("components/shared/PageErrorBoundary.tsx", page_err_boundary)

# ===================================================================
# 2. Fix App.tsx ErrorBoundary
# ===================================================================
print("\n=== 2. Fix App.tsx ErrorBoundary ===")

app_tsx = read_file("App.tsx")

# Add PageErrorBoundary import
app_tsx = app_tsx.replace(
    "import { AuthAudit } from './pages/AuthAudit';",
    "import { AuthAudit } from './pages/AuthAudit';\nimport { PageErrorBoundary } from './components/shared/PageErrorBoundary';"
)

# Add AlertTriangle import
app_tsx = app_tsx.replace(
    "import { AuthAudit } from './pages/AuthAudit';",
    "import { AuthAudit } from './pages/AuthAudit';\nimport { AlertTriangle } from 'lucide-react';"
)

# Replace the ErrorBoundary class
old_eb = """class ErrorBoundary extends React.Component<{children: React.ReactNode}, {hasError: boolean, error: any}> {
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
}"""

new_eb = """class ErrorBoundary extends React.Component<{children: React.ReactNode}, {hasError: boolean, error: any}> {
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
}"""

app_tsx = app_tsx.replace(old_eb, new_eb)

# Wrap each route with PageErrorBoundary
routes_to_wrap = [
    ("Overview", "Overview"),
    ("MissionControl", "MissionControl"),
    ("ResearchIntelligence", "ResearchIntelligence"),
    ("KnowledgeGraphs", "KnowledgeGraphs"),
    ("FindingsVerification", "FindingsVerification"),
    ("RealityVerificationCenter", "RealityVerificationCenter"),
    ("UncertaintyEngine", "UncertaintyEngine"),
    ("SkillIntelligence", "SkillIntelligence"),
    ("AuthAudit", "AuthAudit"),
    ("MissionTimeline", "MissionTimeline"),
    ("LearningAnalytics", "LearningAnalytics"),
    ("DifferentialAuth", "DifferentialAuth"),
    ("VisualContext", "VisualContext"),
    ("Administration", "Administration"),
    ("MissionReport", "MissionReport"),
]

for comp_name, label in routes_to_wrap:
    old = "element={<" + comp_name + " />}"
    new = "element={<PageErrorBoundary pageName=\"" + label + "\"><" + comp_name + " /></PageErrorBoundary>}"
    if old in app_tsx:
        app_tsx = app_tsx.replace(old, new)
        print("  Wrapped " + comp_name)
    else:
        print("  SKIP: " + comp_name)

write_file("App.tsx", app_tsx)


# ===================================================================
# 3. Add loading skeleton to Overview.tsx
# ===================================================================
print("\n=== 3. Overview.tsx - Loading state ===")

overview = read_file("pages/Overview.tsx")

old_kpi_section = """  return (
    <div className=\"flex flex-col gap-gutter\">"""

new_kpi_section = """  // Show loading skeleton while store data initializes
  if (!findings) {
    return (
      <div className=\"flex flex-col gap-gutter\">
        <div className=\"bg-surface-container-low border border-outline-variant p-5 animate-pulse\">
          <div className=\"flex items-center gap-4\">
            <div className=\"w-12 h-12 bg-surface-container-high/60 border border-outline-variant/40\"></div>
            <div className=\"space-y-2\">
              <div className=\"h-7 w-64 bg-surface-container-high/60\"></div>
              <div className=\"h-4 w-48 bg-surface-container-high/60\"></div>
            </div>
          </div>
        </div>
        <div className=\"grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-gutter\">
          {[1,2,3,4].map(i => (
            <div key={i} className=\"bg-surface-container-low border border-outline-variant p-5 animate-pulse\" style={{animationDelay: i * 80 + 'ms'}}>
              <div className=\"h-3 w-24 bg-surface-container-high/60 mb-3\"></div>
              <div className=\"h-8 w-16 bg-surface-container-high/60 mb-2\"></div>
              <div className=\"h-3 w-32 bg-surface-container-high/60\"></div>
            </div>
          ))}
        </div>
        <div className=\"grid grid-cols-1 lg:grid-cols-3 gap-6\">
          <div className=\"col-span-2 bg-surface-container-low border border-outline-variant p-5 animate-pulse h-[400px]\">
            <div className=\"h-5 w-48 bg-surface-container-high/60 mb-6\"></div>
            <div className=\"space-y-4\">
              {[1,2,3].map(i => (
                <div key={i} className=\"h-16 bg-surface-container-high/60 border border-outline-variant/40\"></div>
              ))}
            </div>
          </div>
          <div className=\"bg-surface-container-low border border-outline-variant p-5 animate-pulse h-[400px]\">
            <div className=\"h-5 w-40 bg-surface-container-high/60 mb-6\"></div>
            <div className=\"space-y-4\">
              {[1,2,3].map(i => (
                <div key={i} className=\"h-20 bg-surface-container-high/60 border border-outline-variant/40\"></div>
              ))}
            </div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className=\"flex flex-col gap-gutter\">"""

overview = overview.replace(old_kpi_section, new_kpi_section)
write_file("pages/Overview.tsx", overview)


# ===================================================================
# 4. Add loading skeleton to MissionControl.tsx
# ===================================================================
print("\n=== 4. MissionControl.tsx - Loading state ===")

mc = read_file("pages/MissionControl.tsx")

old_mc_return = """  return (
    <div className=\"flex flex-col gap-gutter\">"""

new_mc_return = """  if (!agents) {
    return (
      <div className=\"flex flex-col gap-gutter\">
        <div className=\"bg-surface-container-low border border-outline-variant p-5 animate-pulse\">
          <div className=\"flex justify-between items-center\">
            <div className=\"space-y-2\">
              <div className=\"h-3 w-32 bg-surface-container-high/60\"></div>
              <div className=\"h-6 w-48 bg-surface-container-high/60\"></div>
            </div>
            <div className=\"flex gap-2\">
              <div className=\"h-10 w-28 bg-surface-container-high/60\"></div>
              <div className=\"h-10 w-28 bg-surface-container-high/60\"></div>
            </div>
          </div>
        </div>
        <div className=\"grid grid-cols-1 lg:grid-cols-3 gap-gutter\">
          <div className=\"col-span-2 bg-surface-container-low border border-outline-variant p-5 animate-pulse h-[400px]\">
            <div className=\"h-5 w-40 bg-surface-container-high/60 mb-6\"></div>
            {[1,2,3].map(i => (
              <div key={i} className=\"h-16 bg-surface-container-high/60 border border-outline-variant/40 mb-4\"></div>
            ))}
          </div>
          <div className=\"bg-surface-container-low border border-outline-variant p-5 animate-pulse h-[400px]\">
            <div className=\"h-5 w-36 bg-surface-container-high/60 mb-6\"></div>
            <div className=\"h-64 bg-surface-container-high/60 rounded-full mx-auto w-64\"></div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className=\"flex flex-col gap-gutter\">"""

mc = mc.replace(old_mc_return, new_mc_return)
write_file("pages/MissionControl.tsx", mc)


# ===================================================================
# 5. Add loading skeleton to FindingsVerification.tsx
# ===================================================================
print("\n=== 5. FindingsVerification.tsx - Loading state ===")

fv = read_file("pages/FindingsVerification.tsx")

old_fv_return = """  return (
    <div className=\"flex flex-col gap-gutter\">"""

new_fv_return = """  // Loading skeleton while store initializes
  if (!findings) {
    return (
      <div className=\"flex flex-col gap-gutter\">
        <div className=\"bg-surface-container-low border border-outline-variant p-5 animate-pulse\">
          <div className=\"flex items-center gap-4\">
            <div className=\"w-12 h-12 bg-surface-container-high/60\"></div>
            <div className=\"space-y-2\">
              <div className=\"h-3 w-40 bg-surface-container-high/60\"></div>
              <div className=\"h-5 w-56 bg-surface-container-high/60\"></div>
            </div>
          </div>
        </div>
        <div className=\"grid grid-cols-2 sm:grid-cols-4 gap-gutter mb-2\">
          {[1,2,3,4].map(i => (
            <div key={i} className=\"bg-surface-container-low border border-outline-variant p-5 animate-pulse\" style={{animationDelay: i * 60 + 'ms'}}>
              <div className=\"h-3 w-28 bg-surface-container-high/60 mb-3\"></div>
              <div className=\"h-8 w-20 bg-surface-container-high/60\"></div>
            </div>
          ))}
        </div>
        <div className=\"grid grid-cols-1 lg:grid-cols-3 gap-6\">
          <div className=\"col-span-2 bg-surface-container-low border border-outline-variant p-5 animate-pulse h-[500px]\">
            <div className=\"h-5 w-56 bg-surface-container-high/60 mb-6\"></div>
            {[1,2].map(i => (
              <div key={i} className=\"h-32 bg-surface-container-high/60 border border-outline-variant/40 mb-4\"></div>
            ))}
          </div>
          <div className=\"bg-surface-container-low border border-outline-variant p-5 animate-pulse h-[500px]\">
            <div className=\"h-5 w-40 bg-surface-container-high/60 mb-6\"></div>
            {[1,2].map(i => (
              <div key={i} className=\"h-24 bg-surface-container-high/60 border border-outline-variant/40 mb-4\"></div>
            ))}
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className=\"flex flex-col gap-gutter\">"""

fv = fv.replace(old_fv_return, new_fv_return)
write_file("pages/FindingsVerification.tsx", fv)


# ===================================================================
# 6. RealityVerificationCenter.tsx - Add loading skeleton
# ===================================================================
print("\n=== 6. RealityVerificationCenter.tsx - Loading state ===")

rvc = read_file("pages/RealityVerificationCenter.tsx")

old_rvc_return = """  return (
    <div className=\"flex flex-col gap-6\">"""

new_rvc_return = """  // Loading skeleton while store initializes
  if (!verifications) {
    return (
      <div className=\"flex flex-col gap-6\">
        <div className=\"bg-surface-container-low border border-outline-variant p-5 animate-pulse\">
          <div className=\"flex justify-between items-center\">
            <div className=\"space-y-2\">
              <div className=\"h-3 w-36 bg-surface-container-high/60\"></div>
              <div className=\"h-5 w-72 bg-surface-container-high/60\"></div>
            </div>
            <div className=\"flex gap-6\">
              <div className=\"h-10 w-24 bg-surface-container-high/60\"></div>
              <div className=\"h-10 w-24 bg-surface-container-high/60\"></div>
            </div>
          </div>
        </div>
        <div className=\"grid grid-cols-3 gap-6 min-h-0\">
          <div className=\"col-span-2 bg-surface-container-low border border-outline-variant p-5 animate-pulse h-[500px]\">
            <div className=\"h-5 w-36 bg-surface-container-high/60 mb-6\"></div>
            {[1,2].map(i => (
              <div key={i} className=\"h-48 bg-surface-container-high/60 border border-outline-variant/40 mb-4\"></div>
            ))}
          </div>
          <div className=\"bg-surface-container-low border border-outline-variant p-5 animate-pulse h-[500px]\">
            <div className=\"h-5 w-36 bg-surface-container-high/60 mb-6\"></div>
            {[1,2,3].map(i => (
              <div key={i} className=\"h-12 bg-surface-container-high/60 border border-outline-variant/40 mb-3\"></div>
            ))}
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className=\"flex flex-col gap-6\">"""

rvc = rvc.replace(old_rvc_return, new_rvc_return)
write_file("pages/RealityVerificationCenter.tsx", rvc)


print("\n=== ALL FIXES COMPLETE ===")
