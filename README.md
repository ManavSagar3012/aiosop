# AI-OSOP: AI Offensive Security Orchestration Platform

> **Production-grade AI-assisted penetration testing ecosystem**

AI-OSOP transforms Burp Suite MCP from a simple tool-access bridge into a **cognitive offensive security operating system** with multi-agent orchestration, persistent memory, and adaptive payload intelligence.

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                    HUMAN OPERATOR LAYER                       │
│         CLI/GUI  │  Approval Console  │  Reports            │
├─────────────────────────────────────────────────────────────┤
│                   ORCHESTRATION LAYER                         │
│    Central Orchestrator  │  Agent Coordination Bus          │
├─────────────────────────────────────────────────────────────┤
│                 REASONING & MEMORY LAYER                      │
│    LLM Core  │  Vector Memory  │  Graph Memory  │  Session   │
├─────────────────────────────────────────────────────────────┤
│                    AGENT ECOSYSTEM                            │
│  Recon  │  Vuln Analysis  │  Payload  │  Exploit  │  Chain   │
├─────────────────────────────────────────────────────────────┤
│                   MCP INTEGRATION LAYER                       │
│  Burp  │  Recon  │  Payload  │  Threat  │  Attack Graph     │
├─────────────────────────────────────────────────────────────┤
│                   EXECUTION SANDBOX                            │
│         Docker/Kubernetes Isolated Environments               │
└─────────────────────────────────────────────────────────────┘
```

## Quick Start

### Prerequisites
- Python 3.11+
- Docker & Docker Compose
- Neo4j 5.x
- PostgreSQL 15+
- Redis 7+

### Installation
```bash
# Clone repository
git clone https://github.com/ai-osop/ai-osop.git
cd ai-osop

# Install dependencies
poetry install

# Configure environment
cp .env.example .env
# Edit .env with your settings

# Start infrastructure
docker-compose up -d neo4j postgres redis

# Run migrations
poetry run alembic upgrade head

# Start API server
poetry run uvicorn ai_osop.api.main:app --reload
```

### Create First Engagement
```bash
curl -X POST http://localhost:8080/engagements   -H "Authorization: Bearer $TOKEN"   -H "Content-Type: application/json"   -d '{
    "engagement_id": "pentest-001",
    "domains": ["example.com"],
    "ips": ["192.168.1.0/24"],
    "approval_required_for": ["rce", "sqli"]
  }'
```

## Core Components

### MCP Ecosystem
| Server | Purpose | Tools |
|--------|---------|-------|
| Burp MCP | Web app testing | scan, proxy, repeater, intruder |
| Recon MCP | Asset discovery | nmap, amass, subfinder, httpx |
| Payload MCP | Payload generation | generate, mutate, analyze |
| Attack Graph MCP | Pathfinding | graph CRUD, path discovery |
| Session Memory MCP | State management | store, retrieve, checkpoint |

### Agent Ecosystem
| Agent | Responsibility | Memory Usage |
|-------|---------------|--------------|
| Recon Agent | DNS, ports, services | Asset inventory |
| Vuln Analysis Agent | Scanning, correlation | Finding database |
| Payload Mutation Agent | Generation, evolution | WAF profiles |
| Exploit Validation Agent | Safe execution | Validation history |
| Attack Chain Agent | Multi-step reasoning | Attack graph |
| Human Oversight Agent | Approval gates | Decision log |

## Safety Architecture

- **Scope Enforcement**: Application-level + network-level (eBPF)
- **Sandboxed Execution**: Docker with seccomp, AppArmor, no-new-privileges
- **Human Approval Gates**: Mandatory for high-impact actions
- **Cryptographic Audit**: SHA-256 chain hashing with HMAC signing
- **Prompt Injection Defense**: Output validation + structured schemas

## Development

```bash
# Run tests
poetry run pytest

# Lint
poetry run black src/
poetry run isort src/
poetry run mypy src/

# Build Docker image
docker build -t ai-osop:latest .
```

## License

MIT License - See [LICENSE](LICENSE) for details.

## Research

AI-OSOP enables publishable research in:
- Autonomous attack graph generation
- Context-aware payload evolution
- Multi-agent coordination for offensive security
- LLM hallucination in security contexts

## Security

For security issues, contact security@ai-osop.dev.
