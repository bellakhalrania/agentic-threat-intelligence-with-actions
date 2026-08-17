from __future__ import annotations

import logging

from fastapi import FastAPI, HTTPException

from .config import Settings
from .manager import SimulationManager
from .models import SimulationStatus

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
settings = Settings.from_env()
manager = SimulationManager(settings)

app = FastAPI(title="Attack Simulation Agent", version="1.0.0")


@app.get("/health")
def health() -> dict[str, object]:
    return {"status": "ok", "scenario": "ssh_bruteforce", "dry_run": settings.dry_run}


@app.get("/scenarios")
def scenarios() -> dict[str, object]:
    return {"scenarios": [{"id": "ssh_bruteforce", "mitre_technique": "T1110.001"}]}


@app.post("/simulations", response_model=SimulationStatus, status_code=202)
def start_simulation() -> SimulationStatus:
    """Start the environment-configured predefined scenario; no request command/input is accepted."""
    try:
        return manager.start()
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@app.get("/simulations/current", response_model=SimulationStatus | None)
def simulation_status() -> SimulationStatus | None:
    return manager.status()


@app.post("/simulations/stop")
def stop_simulation() -> dict[str, bool]:
    return {"stopped": manager.stop()}
