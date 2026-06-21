import { create } from 'zustand'

export interface SwarmBudget {
  total: number
  spent: number
  system1Requests: number
  system2Requests: number
}

export interface Agent {
  id: string
  type: string
  status: 'idle' | 'running' | 'error' | 'shutdown'
  cost_incurred: number
}

interface SwarmState {
  budget: SwarmBudget
  agents: Agent[]
  currentObjective: string
  currentPhase: string
  setBudget: (budget: Partial<SwarmBudget>) => void
  updateAgent: (id: string, updates: Partial<Agent>) => void
  setAgents: (agents: Agent[]) => void
  setObjective: (objective: string) => void
  setPhase: (phase: string) => void
}

export const useSwarmStore = create<SwarmState>((set) => ({
  budget: {
    total: 1000.0,
    spent: 0.0,
    system1Requests: 0,
    system2Requests: 0,
  },
  agents: [],
  currentObjective: "Awaiting Swarm Initialization...",
  currentPhase: "INITIALIZING",
  setBudget: (updates) => set((state) => ({ budget: { ...state.budget, ...updates } })),
  updateAgent: (id, updates) => set((state) => {
    const exists = state.agents.some(a => a.id === id);
    if (!exists) {
        const newAgent: Agent = {
            id,
            type: updates.type || 'unknown',
            status: updates.status || 'running',
            cost_incurred: updates.cost_incurred || 0
        };
        return { agents: [...state.agents, newAgent] };
    }
    return {
        agents: (state.agents || []).map(a => a.id === id ? { ...a, ...updates } : a)
    };
  }),
  setAgents: (agents) => set({ agents }),
  setObjective: (objective) => set({ currentObjective: objective }),
  setPhase: (phase) => set({ currentPhase: phase }),
}))
