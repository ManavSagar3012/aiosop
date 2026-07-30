import { create } from 'zustand'

export interface Finding {
  id: string
  title: string
  category: string
  severity: 'low' | 'medium' | 'high' | 'critical'
  status: 'hypothesis' | 'validated' | 'verified' | 'report_ready' | 'rejected'
  evScore: number
  confidence: number
  historicalConfidence: number
  evidenceCount: number
  agentConsensus: string[]
  engagement_id?: string
  provenance?: string
  replayabilityScore?: number
  [key: string]: any
}

export const FINDING_STATUSES = ['hypothesis', 'validated', 'verified', 'report_ready', 'rejected'] as const
export type FindingStatus = typeof FINDING_STATUSES[number]

export interface VerificationRequest {
  id: string
  findingId: string
  title: string
  evidenceSources: string[]
  agreedAgents: string[]
  requiredSources: number
  [key: string]: any
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

export interface AuditLogEntry {
  id: string
  timestamp: string
  event_type: string
  actor_id: string
  severity: string
  action: any
  details?: any
  result?: any
  [key: string]: any
}

interface GraphData {
  nodes: any[]
  edges: any[]
}

interface IntelligenceState {
  sessionId: string | null
  hasCheckedSession: boolean
  lastEventAt: Date | null
  findings: Finding[]
  verifications: VerificationRequest[]
  uncertainties: Uncertainty[]
  diffAuthFindings: DiffAuthFinding[]
  skillStats: SkillStats | null
  auditLog: AuditLogEntry[]
  graphData: GraphData
  reasoningTrace: any[]
  cognitionSummary: any | null
  criticReview: any[]
  invariants: any[]
  payouts: any[]
  setSessionId: (id: string) => void
  setHasCheckedSession: (checked: boolean) => void
  setLastEventAt: (at: Date) => void
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
  setAuditLog: (log: AuditLogEntry[]) => void
  appendAuditEntry: (event: AuditLogEntry) => void
  setGraphData: (data: GraphData) => void
  setReasoningTrace: (trace: any[]) => void
  setCognitionSummary: (summary: any) => void
  setCriticReview: (review: any[]) => void
  setInvariants: (invariants: any[]) => void
  setPayouts: (payouts: any[]) => void
}

export const useIntelligenceStore = create<IntelligenceState>((set) => ({
  sessionId: null,
  hasCheckedSession: false,
  lastEventAt: null,
  findings: [],
  verifications: [],
  uncertainties: [],
  diffAuthFindings: [],
  skillStats: null,
  auditLog: [],
  graphData: { nodes: [], edges: [] },
  reasoningTrace: [],
  cognitionSummary: null,
  criticReview: [],
  invariants: [],
  payouts: [],
  setSessionId: (sessionId) => set({
    sessionId,
    findings: [],
    verifications: [],
    uncertainties: [],
    diffAuthFindings: [],
    auditLog: [],
    graphData: { nodes: [], edges: [] },
    reasoningTrace: [],
    cognitionSummary: null,
    criticReview: [],
    invariants: [],
    payouts: [],
  }),
  setHasCheckedSession: (hasCheckedSession) => set({ hasCheckedSession }),
  setLastEventAt: (lastEventAt) => set({ lastEventAt }),
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
  setReasoningTrace: (reasoningTrace) => set({ reasoningTrace }),
  setCognitionSummary: (cognitionSummary) => set({ cognitionSummary }),
  setCriticReview: (criticReview) => set({ criticReview }),
  setInvariants: (invariants) => set({ invariants }),
  setPayouts: (payouts) => set({ payouts }),
}))
