import { create } from 'zustand'

export interface Finding {
  id: string
  title: string
  category: string
  severity: 'low' | 'medium' | 'high' | 'critical'
  status: 'hypothesis' | 'validated' | 'verified' | 'report_ready'
  evScore: number
  confidence: number
  historicalConfidence: number
  evidenceCount: number
  agentConsensus: string[]
  engagement_id?: string
  provenance?: string
  replayabilityScore?: number
}

export interface VerificationRequest {
  id: string
  findingId: string
  title: string
  evidenceSources: string[]
  agreedAgents: string[]
  requiredSources: number
}

export interface Uncertainty {
  id: string
  target: string
  knowns: string[]
  unknowns: string[]
  blockedPaths: string[]
}

export interface SkillStat {
  id: string
  name: string
  usage: number
  reputation: number
  revenue_roi: number
  acceptance_rate: number
  total_payout: number
  verified_findings?: number
}

export interface SkillStats {
  loaded_skills: number
  activated_skills: number
  findings_contributed: number
  total_revenue: number
  revenue_roi: number
  top_skills: SkillStat[]
  recent_executions: any[]
}

export interface DiffAuthFinding {
  id: string
  category: string
  resource_id: string
  test_identity_id: string
  expected_result: string
  observed_result: string
  evidence_diff: any
  confidence: number
}

interface IntelligenceState {
  sessionId: string | null
  findings: Finding[]
  verifications: VerificationRequest[]
  uncertainties: Uncertainty[]
  diffAuthFindings: DiffAuthFinding[]
  skillStats: SkillStats | null
  auditLog: any[]
  graphData: { nodes: any[], edges: any[] }
  setSessionId: (id: string) => void
  appendFinding: (finding: Finding) => void
  updateFinding: (id: string, updates: Partial<Finding>) => void
  setFindings: (findings: Finding[]) => void
  appendVerification: (verification: VerificationRequest) => void
  updateVerification: (id: string, updates: Partial<VerificationRequest>) => void
  setVerifications: (verifications: VerificationRequest[]) => void
  appendUncertainty: (uncertainty: Uncertainty) => void
  setUncertainties: (uncertainties: Uncertainty[]) => void
  setDiffAuthFindings: (findings: DiffAuthFinding[]) => void
  setSkillStats: (stats: SkillStats) => void
  setAuditLog: (log: any[]) => void
  appendAuditEntry: (event: any) => void
  setGraphData: (data: { nodes: any[], edges: any[] }) => void
}

export const useIntelligenceStore = create<IntelligenceState>((set) => ({
  sessionId: null,
  findings: [],
  verifications: [],
  uncertainties: [],
  diffAuthFindings: [],
  skillStats: null,
  auditLog: [],
  graphData: { nodes: [], edges: [] },
  setSessionId: (sessionId) => set({ sessionId }),
  appendFinding: (finding) => set((state) => ({ 
    findings: [...state.findings.filter(f => f.id !== finding.id), finding] 
  })),
  updateFinding: (id, updates) => set((state) => ({
    findings: state.findings.map(f => f.id === id ? { ...f, ...updates } : f)
  })),
  setFindings: (findings) => set({ findings }),
  appendVerification: (verification) => set((state) => ({
    verifications: [...state.verifications.filter(v => v.id !== verification.id), verification]
  })),
  updateVerification: (id, updates) => set((state) => ({
    verifications: state.verifications.map(v => v.id === id ? { ...v, ...updates } : v)
  })),
  setVerifications: (verifications) => set({ verifications }),
  appendUncertainty: (uncertainty) => set((state) => ({
    uncertainties: [...state.uncertainties.filter(u => u.id !== uncertainty.id), uncertainty]
  })),
  setUncertainties: (uncertainties) => set({ uncertainties }),
  setDiffAuthFindings: (diffAuthFindings) => set({ diffAuthFindings }),
  setSkillStats: (skillStats) => set({ skillStats }),
  setAuditLog: (auditLog) => set({ auditLog }),
  appendAuditEntry: (event) => set((state) => ({ auditLog: [event, ...state.auditLog].slice(0, 100) })),
  setGraphData: (graphData) => set({ graphData }),
}))
