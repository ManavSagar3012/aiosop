#!/usr/bin/env bash
# AI-OSOP One-Command Unix/macOS Bootstrap & Launcher (Sprint 12 / P3.1)
set -e

echo "================================================================="
echo "INITIALIZING AI-OSOP OFFENSIVE SECURITY ORCHESTRATION PLATFORM"
echo "================================================================="

# 1. Run Preflight
echo -e "\n[Step 1/4] Running Environment Preflight Diagnostics..."
poetry run python scripts/ops/preflight.py

# 2. Check Database Infrastructure
echo -e "\n[Step 2/4] Ensuring Infrastructure Containers are Active..."
docker compose up -d neo4j postgres redis || true

# 3. Run Database Migrations
echo -e "\n[Step 3/4] Applying Authoritative Database Migrations..."
poetry run alembic upgrade head || true

# 4. Ready to Serve
echo -e "\n[Step 4/4] Environment Ready!"
echo "To launch API Gateway: poetry run uvicorn ai_osop.api.main:app --port 8200"
echo "To launch UI Console:  npm --prefix ui run dev"
echo "================================================================="
