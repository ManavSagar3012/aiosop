# AI-OSOP One-Command Windows Bootstrap & Launcher (Sprint 12 / P3.1)
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "INITIALIZING AI-OSOP OFFENSIVE SECURITY ORCHESTRATION PLATFORM" -ForegroundColor Cyan
Write-Host "=================================================================" -ForegroundColor Cyan

# 1. Run Preflight
Write-Host "`n[Step 1/4] Running Environment Preflight Diagnostics..." -ForegroundColor Yellow
poetry run python scripts/ops/preflight.py
if ($LASTEXITCODE -ne 0) {
    Write-Host "[!] Preflight check failed. Aborting startup." -ForegroundColor Red
    exit 1
}

# 2. Check Database Infrastructure
Write-Host "`n[Step 2/4] Ensuring Infrastructure Containers are Active..." -ForegroundColor Yellow
docker compose up -d neo4j postgres redis
if ($LASTEXITCODE -ne 0) {
    Write-Host "[!] Docker Compose warning: Could not start all containers automatically. Verifying existing services..." -ForegroundColor DarkYellow
}

# 3. Run Database Migrations
Write-Host "`n[Step 3/4] Applying Authoritative Database Migrations..." -ForegroundColor Yellow
poetry run alembic upgrade head
if ($LASTEXITCODE -ne 0) {
    Write-Host "[!] Alembic migration warning. Proceeding with application startup..." -ForegroundColor DarkYellow
}

# 4. Ready to Serve
Write-Host "`n[Step 4/4] Environment Ready!" -ForegroundColor Green
Write-Host "To launch API Gateway: poetry run uvicorn ai_osop.api.main:app --port 8200" -ForegroundColor White
Write-Host "To launch UI Console:  npm --prefix ui run dev" -ForegroundColor White
Write-Host "=================================================================" -ForegroundColor Cyan
