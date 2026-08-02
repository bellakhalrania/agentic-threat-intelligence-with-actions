# ============================================================
# Stage 1: Build stage — install build dependencies & packages
# ============================================================
FROM python:3.11-slim AS builder

WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    g++ \
    && rm -rf /var/lib/apt/lists/*

# Copy only requirements for layer caching
COPY requirements.txt .

# Install Python dependencies into a local directory
RUN pip install --no-cache-dir --user -r requirements.txt

# ============================================================
# Stage 2: Runtime stage — minimal image
# ============================================================
FROM python:3.11-slim AS runtime

# Create non-root user
RUN groupadd -r appuser && useradd -r -g appuser -d /app -s /sbin/nologin appuser

WORKDIR /app

# Copy Python packages from builder
COPY --from=builder /root/.local /home/appuser/.local

# Copy application code
COPY --chown=appuser:appuser . .

# Make sure scripts in PATH
ENV PATH=/home/appuser/.local/bin:$PATH \
    PYTHONPATH=/app \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# Create required directories with correct permissions
RUN mkdir -p /app/data /app/reports/generated_reports /app/data/chroma_store /app/data/wazuh_logs && \
    chown -R appuser:appuser /app/data /app/reports

# Switch to non-root user
USER appuser

# Healthcheck — verifies the API is responsive
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" || exit 1

# Expose API port
EXPOSE 8000

# Default: run production ASGI server
CMD ["python", "-m", "gunicorn", "app:app", "--worker-class", "uvicorn.workers.UvicornWorker", "--bind", "0.0.0.0:8000", "--workers", "2", "--timeout", "120", "--access-logfile", "-", "--error-logfile", "-"]