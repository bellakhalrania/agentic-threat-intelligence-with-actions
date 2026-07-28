# remote_agent/Dockerfile
#
# Builds the Remote Response Agent container to run on Machine 2.
# This service listens for response scripts pushed from Machine 1 (the
# Threat Intelligence Platform), executes them, and returns results.
#
# Usage:
#   docker build -f remote_agent/Dockerfile -t remote-response-agent .
#   docker run -d -p 9001:9001 --name remote-agent remote-response-agent

FROM python:3.11-slim

LABEL maintainer="Agentic Threat Intelligence"
LABEL description="Remote Response Agent - executes response scripts on target machines"

WORKDIR /app

# Install system tools needed for response actions (iptables, etc.)
RUN apt-get update && apt-get install -y --no-install-recommends \
    iptables \
    iproute2 \
    net-tools \
    procps \
    && rm -rf /var/lib/apt/lists/*

# Copy and install Python dependencies
COPY remote_agent/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the remote agent code
COPY remote_agent/ /app/remote_agent/

# Create directories for scripts and logs
RUN mkdir -p /app/remote_agent/received_scripts /app/remote_agent/logs

# Set environment defaults
ENV REMOTE_AGENT_HOST=0.0.0.0
ENV REMOTE_AGENT_PORT=9001
ENV REMOTE_AGENT_SCRIPTS_DIR=/app/remote_agent/received_scripts
ENV REMOTE_AGENT_LOG_FILE=/app/remote_agent/logs/execution_log.jsonl
ENV REMOTE_AGENT_TIMEOUT=1800

EXPOSE 9001

CMD ["python", "-m", "uvicorn", "remote_agent.app:app", "--host", "0.0.0.0", "--port", "9001"]