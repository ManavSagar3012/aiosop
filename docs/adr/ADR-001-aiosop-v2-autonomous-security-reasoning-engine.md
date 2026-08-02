# ADR-001: AIOSOP V2: Autonomous Security Reasoning Engine

- **Status**: proposed
- **Date**: 2026-07-08
- **Deciders**: Core Architecture Team, User
- **Tags**: planning, reasoning-engine, knowledge-base, graph-memory, v2

## Context

The current architecture of the AI Offensive Security Orchestration Platform (AI-OSOP) operates on a **vulnerability-centric** design. The scanning and task scheduling pipeline flows unidirectionally from Recon (discovering endpoints) to vulnerability scanners, producing independent `Vulnerability` findings that are validated and mapped onto a graph memory. 

While AI-OSOP has an `AttackChainAgent` that links findings into simple exploit paths, the engine lacks the capability to reason about multi-step attacker behaviors, privilege states, or strategic progression. Furthermore, attempting to align the system solely with the MITRE ATT&CK framework exposes key limitations:
1. **Granularity Mismatch**: MITRE ATT&CK is post-exploitation and infrastructure-heavy (Active Directory, process injection). Application-layer attacks (JWT manipulation, IDOR, SQLi) are lumped into highly generic techniques like *T1190: Exploit Public-Facing Application*.
2. **Behavior vs. Vulnerability**: Scanners check if an endpoint is vulnerable, whereas real adversaries plan actions based on their current state and capabilities to reach a specific target goal.

## Decision

We propose evolving AI-OSOP into an **Autonomous Security Reasoning Engine (ASRE)**. Instead of mapping strictly to MITRE ATT&CK, the system will use a unified, multi-source knowledge representation, a state-based graph representation, and goal-oriented planning.

### The Five Major Engines

We will design and implement five core engines to drive the platform's reasoning:

| Engine | Purpose |
| :--- | :--- |
| **Security Knowledge Engine** | A unified graph repository merging MITRE ATT&CK, MITRE CAPEC, CWE, OWASP WSTG/ASVS, OWASP API Top 10, CVE databases, curated bug bounty writeups, and internal platform learning data. |
| **Goal Planner** | A logical planner that defines strategic objectives (e.g., *Admin Access*, *Data Exfiltration*, *Cloud Credentials*, *Order Modification*) rather than executing static scanner checklists. |
| **State Engine** | An entity tracker maintaining active runtime parameters including identity contexts, session states, credentials, active privileges, and reachable network zones. |
| **Attack Planner** | A solver utilizing Goal-Oriented Action Planning (GOAP) or Hierarchical Task Networks (HTN) to generate and sequence optimal paths from the current state to the active goal. |
| **Learning Engine** | A reinforcement layer that records successfully traversed paths, effective payloads, and technology-specific heuristics to optimize future runs. |

### Redesigned State-Based Graph Schema

The Neo4j `GraphMemory` will be restructured to place state, capabilities, and goals at the center of the reasoning graph:

```text
Target (Domain/IP)
  ↓
Technology (Service/OS)
  ↓
Framework (Laravel/React)
  ↓
Version (v10.0.0)
  ↓
Identity (User Account)
  ↓
Credential (JWT/API Key)
  ↓
Session (Active State)
  ↓
Role (Standard/Admin)
  ↓
Endpoint (API Route)
  ↓
Parameter (Input Fields)
  ↓
Capability (Possessed Action)
  ↓
Technique (WSTG/ATT&CK Method)
  ↓
Payload (Specific Input)
  ↓
Evidence (HTTP Response/OAST)
  ↓
Finding (Vulnerability ID)
  ↓
Goal (Target Objective)
  ↓
Impact (Exfiltration/Takeover)
```

## Consequences

### Positive
- **State-Aware Planning**: Scanners are executed contextually. For instance, rather than running JWT fuzzer scans blindly, the system recognizes a standard user JWT, maps the *Privilege Escalation* goal, and dynamically initiates JWT signature and IDOR testing.
- **Actionable Chaining**: Leverages OWASP WSTG and bug bounty patterns to chain vulnerabilities (e.g., using SSRF to reach cloud metadata services, extracting an IAM credential, and escalating privileges).
- **Reduced Noise**: Scanning frequency and payload volume are optimized by scheduling only techniques that have their preconditions met by the current active state.

### Negative
- **Complexity**: Transitioning from a simple task queue scheduler to a GOAP/HTN solver significantly increases the platform's complexity and cognitive load.
- **State Space Explosion**: In large networks, calculating state-based combinations and paths can result in high pathfinding latencies in the Graph Memory layer.

### Neutral
- The core MCP scanning binaries (e.g., `nuclei-mcp`, `burp-mcp`, `browser-mcp`) remain unchanged; they are simply scheduled and parameterized dynamically by the Attack Planner instead of running sequentially.

## 5-Phase Implementation Roadmap

```text
Phase 1: Execution Stability (Current)
  ├── Eliminate false negatives across all active scanners.
  ├── Ensure every registered scanner is fully reachable and responsive.
  ├── Resolve orchestrator performance and locking bottlenecks.
  └── Achieve deterministic validation against test benchmarks (e.g., Juice Shop).
        ↓
Phase 2: Security Knowledge Engine
  ├── Merge MITRE ATT&CK/CAPEC/CWE and OWASP WSTG taxonomies.
  └── Build static graph mappings for framework/technology associations.
        ↓
Phase 3: State-Based Graph
  ├── Expand Neo4j Graph Memory schemas to represent credentials, sessions, and roles.
  └── Implement active state synchronization from session memory to graph memory.
        ↓
Phase 4: Goal-Oriented Planner
  ├── Implement the GOAP/HTN solver for dynamic attack path generation.
  └── Replace static templates in `AttackChainAgent` with the new solver.
        ↓
Phase 5: Autonomous Reasoning
  └── Enable the runtime engine to continuously execute task loops, evaluate outcomes,
      and update the state graph dynamically until the target goal is met.
```

## Links
- Maps to `src/ai_osop/agents/attack_chain_agent.py`
- Refines `src/ai_osop/orchestrator/task_scheduler.py`
