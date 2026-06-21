/**
 * V5 Swarm Load Test Tool
 * Simulates high event volume to verify dashboard scalability.
 */

import { useSwarmStore } from '../store/useSwarmStore';
import { useIntelligenceStore } from '../store/useIntelligenceStore';

export class SwarmLoadTest {
  private timer: NodeJS.Timeout | null = null;

  start(eventsPerSecond: number = 1000) {
    console.log(`[LoadTest] Starting stress test at ${eventsPerSecond} events/sec`);
    
    const interval = 1000 / eventsPerSecond;

    this.timer = setInterval(() => {
      this.simulateEvent();
    }, interval);
  }

  stop() {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
      console.log("[LoadTest] Stress test stopped.");
    }
  }

  private simulateEvent() {
    const swarm = useSwarmStore.getState();
    const intel = useIntelligenceStore.getState();

    // 1. Random Budget Update
    swarm.setBudget({
        spent: swarm.budget.spent + (Math.random() * 0.5),
        system1Requests: swarm.budget.system1Requests + 1
    });

    // 2. Occasional Finding Update
    if (Math.random() > 0.99) {
        intel.appendFinding({
            id: `f-stress-${Date.now()}`,
            title: "Simulated Stress Finding",
            category: "denial_of_service",
            severity: "low",
            status: "hypothesis",
            evScore: Math.random() * 10,
            confidence: Math.random(),
            historicalConfidence: 0.5,
            evidenceCount: 1,
            agentConsensus: ["stress_bot"]
        });
    }
  }
}

export const loadTester = new SwarmLoadTest();
