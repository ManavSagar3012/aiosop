# AI-OSOP Enhancements Roadmap

This document outlines the detailed engineering roadmap for bridging the gap between AI-OSOP's automated architecture and an elite human security researcher's workflow.

---

## 1. Phase 1: Immediate Improvements (0-30 Days)

### 1.1 WAF Character Probing & Filter Discovery
* **Objective:** Prevent WAF lockouts and payload waste by identifying filtered characters before firing complex payloads.
* **Component:** `src/ai_osop/payload_engine/engine.py` (Add `WAFCharacterProber` to `AdaptivePayloadEngine`).
* **Logic:**
  1. Send individual baseline requests with specific character sets (e.g., `'`, `"`, `<`, `>`, `/`, `;`, `(`, `)`, `[`, `]`, `{`, `}`).
  2. Analyze response codes and body structure to classify characters as `ALLOWED`, `FILTERED`, or `BLOCKED` (triggering 403/406/418).
  3. Feed the character map into `EncodingPipeline` and mutation generators to dynamically prune invalid payload candidates.
* **Verification:** Unit tests simulating custom WAF blocks on specific characters.

### 1.2 Multi-Role Session Manager
* **Objective:** Support horizontal and vertical privilege escalation testing by holding multiple active sessions per engagement.
* **Component:** `src/ai_osop/memory/session_memory.py` (Extend `SessionMemory` with `MultiRoleSessionPool`).
* **Logic:**
  1. Store credentials (tokens/cookies) categorized by privilege tiers (e.g., `admin`, `member`, `anonymous`).
  2. Implement a context manager to execute tasks under different active identities.
  3. Validate access control by checking if privilege differences reflect in response structures.
* **Verification:** Integration tests verifying cross-token request execution.

### 1.3 cURL Proof-of-Concept (PoC) Exporter
* **Objective:** Produce standard, shell-safe, copy-pasteable cURL reproduction strings for all validated HTTP findings.
* **Component:** `src/ai_osop/core/poc_generator.py` and `src/ai_osop/agents/reporting_agent.py`.
* **Logic:**
  1. Extract raw HTTP parameters (headers, body, method, query) from vulnerability evidence.
  2. Format them into a shell-escaped `curl` command.
  3. Append this output to the final finding deliverable markdown.
* **Verification:** Execute unit tests to check shell escape safety on various payload structures.

---

## 2. Phase 2: Short-Term Improvements (1-3 Months)

### 2.1 Passive OSINT Engine
* **Objective:** Discover subdomains and staging endpoints silently using third-party APIs before active enumeration.
* **Component:** Create `src/ai_osop/agents/passive_recon_agent.py` and `PassiveReconMCPAdapter`.
* **Logic:**
  1. Retrieve subdomains from crt.sh, Censys, and Shodan APIs.
  2. Run passive DNS record checks to map target IP historical changes.
  3. Register assets in `GraphMemory` with a `passive` flag before triggering active scans.

### 2.2 Framework-Specific Permutator
* **Objective:** Generate smarter wordlists for subdirectory discovery based on detected backend stacks.
* **Component:** Create `src/ai_osop/core/targeted_permutator.py`.
* **Logic:**
  1. Identify target technology categories (e.g., PHP, Rails, Django, Node.js).
  2. Merge the framework directory footprints (e.g., `composer.json`, `Gemfile`, `wp-config.php`) into the discovery queue.
  3. Prioritize common framework administrative paths.

---

## 3. Phase 3: Medium-Term Improvements (3-6 Months)

### 3.1 Automated Graph Pathfinder
* **Objective:** Discover custom multi-stage exploitation chains dynamically by traversing the graph database.
* **Component:** `src/ai_osop/agents/attack_chain_agent.py` (Replace static `CHAIN_TEMPLATES` with a pathfinding query).
* **Logic:**
  1. Execute Neo4j queries to find paths between discovered inputs and high-value sinks.
  2. Route nodes based on input-output compatibility (e.g., Endpoint A outputs ID $\rightarrow$ Endpoint B consumes ID).
  3. Generate multi-step verification tasks dynamically based on the calculated path.

### 3.2 Sandboxed Post-Exploitation Module
* **Objective:** Safe, read-only impact validation for Remote Code Execution (RCE) and Local File Inclusion (LFI) findings.
* **Component:** Create `src/ai_osop/core/sandbox_exploit.py`.
* **Logic:**
  1. Restrict post-exploitation command injection to standard safe actions (e.g., `whoami`, `id`, `uname`).
  2. Block any command containing destructive keywords (e.g., `rm`, `mv`, `wget`, `curl` outbound scripts).
  3. Structure command outputs into the verified evidence fields.

---

## 4. Phase 4: Long-Term Research Goals (6+ Months)

### 4.1 Logical Business State Machine
* **Objective:** Dynamically construct and audit multi-step business state changes (e.g., checkout flows) for invariants.
* **Logic:**
  1. Track sequential HTTP transactions to reconstruct state dependencies.
  2. Automatically inject modified parameters during specific state-machine transitions (e.g., attempting checkout with negative items).
  3. Flag state transitions that bypass validation gates.
