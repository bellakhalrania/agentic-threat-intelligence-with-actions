FROM python:3.11-slim

WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends hydra && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . /app/attack_simulation_agent/
RUN mkdir -p /app/attack_simulation_agent/logs
EXPOSE 9010
CMD ["python", "-m", "uvicorn", "attack_simulation_agent.app:app", "--host", "0.0.0.0", "--port", "9010"]
