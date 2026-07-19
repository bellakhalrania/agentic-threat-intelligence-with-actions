"""
FastAPI application for Agentic Threat Intelligence Platform

Provides REST API endpoints for:
- Investigating security events
- Fetching events from connectors (Wazuh, etc.)
- Getting investigation reports
- Managing response actions

Usage:
    uvicorn app:app --reload --host 0.0.0.0 --port 8000

API Documentation:
    http://localhost:8000/docs (Swagger UI)
    http://localhost:8000/redoc (ReDoc)
"""

from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
import json
import logging
from datetime import datetime

# Import project modules
from graph.workflow import threat_intel_workflow
from graph.state import new_investigation_state
from connectors.wazuh_connector import WazuhConnector
import config

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Create FastAPI app
app = FastAPI(
    title="Agentic Threat Intelligence API",
    description="REST API for investigating security events using AI-powered threat intelligence",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)


# Pydantic models for request/response
class EventSource(BaseModel):
    """Event source specification"""
    type: str = Field(..., description="Source type: 'file' or 'connector'")
    path: Optional[str] = Field(None, description="Path to events file (for file type)")
    connector: Optional[str] = Field(None, description="Connector name (for connector type)")
    test_data: Optional[str] = Field(None, description="Path to test data file")


class InvestigationRequest(BaseModel):
    """Request to investigate events"""
    events: Optional[List[Dict[str, Any]]] = Field(None, description="Raw events to investigate")
    source: Optional[EventSource] = Field(None, description="Event source specification")


class InvestigationResponse(BaseModel):
    """Response from investigation"""
    success: bool
    report: Optional[str] = None
    response_actions: Optional[List[Dict[str, Any]]] = None
    campaign_id: Optional[str] = None
    error: Optional[str] = None
    events_processed: int = 0


class HealthResponse(BaseModel):
    """Health check response"""
    status: str
    timestamp: str
    version: str


# Background task for async investigation
async def run_investigation(events: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Run investigation on events"""
    try:
        initial_state = new_investigation_state(raw_events=events)
        final_state = threat_intel_workflow.invoke(initial_state)
        
        return {
            "success": True,
            "report": final_state.get("report"),
            "response_actions": final_state.get("actions_taken"),
            "campaign_id": final_state.get("campaign", {}).get("campaign_id"),
            "events_processed": len(events)
        }
    except Exception as e:
        logger.error(f"Investigation failed: {e}")
        return {
            "success": False,
            "error": str(e),
            "events_processed": len(events)
        }


@app.get("/", response_model=HealthResponse)
async def root():
    """Root endpoint with API info"""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "version": "1.0.0"
    }


@app.get("/health", response_model=HealthResponse)
async def health():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "version": "1.0.0"
    }


@app.post("/investigate", response_model=InvestigationResponse)
async def investigate(request: InvestigationRequest):
    """
    Investigate security events
    
    - **events**: Direct list of raw events to investigate
    - **source**: Event source specification (file or connector)
    
    Returns investigation report and response actions
    """
    try:
        events = []
        
        # Get events from request or source
        if request.events:
            events = request.events
        elif request.source:
            if request.source.type == "file":
                if not request.source.path:
                    raise HTTPException(status_code=400, detail="Path required for file source")
                
                with open(request.source.path, 'r') as f:
                    events = json.load(f)
                    
            elif request.source.type == "connector":
                if not request.source.connector:
                    raise HTTPException(status_code=400, detail="Connector name required")
                
                if request.source.connector == "wazuh":
                    connector = WazuhConnector(
                        test_data_path=request.source.test_data
                    )
                    events = connector.fetch_events()
                else:
                    raise HTTPException(status_code=400, detail=f"Unknown connector: {request.source.connector}")
            else:
                raise HTTPException(status_code=400, detail=f"Unknown source type: {request.source.type}")
        else:
            raise HTTPException(status_code=400, detail="Either events or source must be provided")
        
        if not events:
            return InvestigationResponse(
                success=False,
                error="No events to process",
                events_processed=0
            )
        
        # Run investigation
        result = await run_investigation(events)
        
        return InvestigationResponse(**result)
        
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=f"File not found: {e}")
    except json.JSONDecodeError as e:
        raise HTTPException(status_code=400, detail=f"Invalid JSON: {e}")
    except Exception as e:
        logger.error(f"Error in investigation: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/investigate/file/{file_path:path}")
async def investigate_file(file_path: str):
    """
    Investigate events from a JSON file
    
    - **file_path**: Path to JSON file containing events
    """
    try:
        with open(file_path, 'r') as f:
            events = json.load(f)
        
        result = await run_investigation(events)
        return InvestigationResponse(**result)
        
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail=f"File not found: {file_path}")
    except json.JSONDecodeError as e:
        raise HTTPException(status_code=400, detail=f"Invalid JSON: {e}")
    except Exception as e:
        logger.error(f"Error in investigation: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/investigate/connector/{connector_name}")
async def investigate_connector(connector_name: str, test_data: Optional[str] = None):
    """
    Investigate events from a connector
    
    - **connector_name**: Name of connector (e.g., 'wazuh')
    - **test_data**: Optional path to test data file
    """
    try:
        if connector_name == "wazuh":
            connector = WazuhConnector(test_data_path=test_data)
            events = connector.fetch_events()
        else:
            raise HTTPException(status_code=400, detail=f"Unknown connector: {connector_name}")
        
        if not events:
            return InvestigationResponse(
                success=False,
                error="No events fetched from connector",
                events_processed=0
            )
        
        result = await run_investigation(events)
        return InvestigationResponse(**result)
        
    except Exception as e:
        logger.error(f"Error in investigation: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/connectors")
async def list_connectors():
    """List available connectors"""
    return {
        "connectors": [
            {
                "name": "wazuh",
                "description": "Wazuh security alerts",
                "modes": ["file", "api"]
            }
        ]
    }


@app.get("/config")
async def get_config():
    """Get current configuration (sensitive values masked)"""
    return {
        "wazuh": {
            "api_url": config.WAZUH_API_URL,
            "api_user": config.WAZUH_API_USER,
            "alerts_path": config.WAZUH_ALERTS_PATH,
            "poll_interval": config.WAZUH_POLL_INTERVAL,
            "verify_ssl": config.WAZUH_VERIFY_SSL
        },
        "threat_intel": {
            "abuseipdb_configured": bool(config.ABUSEIPDB_API_KEY),
            "otx_configured": bool(config.OTX_API_KEY),
            "groq_configured": bool(config.GROQ_API_KEY)
        }
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=True)
