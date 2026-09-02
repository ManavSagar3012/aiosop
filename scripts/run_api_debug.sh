#!/bin/bash
# Start API locally to get full traceback on 500 errors
cd "$(dirname "$0")/.."
export OSOP_ENV=development
export OSOP_POSTGRES_URI="postgresql+asyncpg://ai_osop:ai_osop@127.0.0.1:15432/ai_osop"
export OSOP_API_TOKEN="dev-token"
export OSOP_NEO4J_URI="bolt://127.0.0.1:7687"
export OSOP_NEO4J_PASSWORD="password"
export OSOP_REDIS_URI="redis://127.0.0.1:6379/0"

echo "Starting API locally on port 8201..."
poetry run uvicorn ai_osop.api.main:app --host 127.0.0.1 --port 8201 --log-level debug
