# Multi-stage build for AI-OSOP
FROM python:3.11-slim AS builder

WORKDIR /build
RUN apt-get update && apt-get install -y --no-install-recommends     gcc     libpq-dev     && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir poetry
COPY pyproject.toml ./
RUN poetry config virtualenvs.create false     && poetry install --no-interaction --no-ansi --no-root --only main

# Production stage
FROM python:3.11-slim AS production

WORKDIR /app

# Security: Run as non-root
RUN groupadd -r osop && useradd -r -g osop osop

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends     libpq5     iputils-ping     nmap     && rm -rf /var/lib/apt/lists/*

# Copy Python packages from builder
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# Copy application code
COPY src/ ./src/
COPY README.md ./

# Set permissions
RUN chown -R osop:osop /app
USER osop

# Environment
ENV PYTHONPATH=/app/src
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# PATCH (REL-001, 2026-06-15): Was 8080 throughout — but :8080 collides with
# Oracle XDB/TNSLSNR on common dev hosts. Standardize on :8200 to match the
# direct `poetry run uvicorn ... --port 8200` invocation used in production.
EXPOSE 8200

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3     CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8200/health')" || exit 1

CMD ["uvicorn", "ai_osop.api.main:app", "--host", "0.0.0.0", "--port", "8200"]
