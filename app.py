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

from fastapi import FastAPI, HTTPException, BackgroundTasks, Header
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
import json
import logging
import os
from datetime import datetime, timezone

# Import project modules
from graph.workflow import threat_intel_workflow
from graph.state import new_investigation_state
from connectors.wazuh_connector import WazuhConnector
import config

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Ensure threat_intel provider logs are visible
logging.getLogger("intelligence.threat_intel").setLevel(logging.INFO)

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


class CollectionsResponse(BaseModel):
    """ChromaDB collections response"""
    count: int
    collections: List[str]
    timestamp: str


class AttackDbResponse(BaseModel):
    """Attack database response"""
    databases: List[str]
    count: int
    details: Dict[str, Dict[str, int]]
    timestamp: str


class SearchRequest(BaseModel):
    """Search request for ATT&CK knowledge"""
    keyword: str = Field(..., description="Keyword or phrase to search for")
    limit: Optional[int] = Field(None, description="Maximum number of results (default: 25, max: 200)")


class SearchResponse(BaseModel):
    """Search response from ATT&CK knowledge"""
    keyword: str
    results: List[Dict[str, Any]]
    count: int
    timestamp: str


class ActionOnlyRequest(BaseModel):
    """Request containing raw security events"""
    events: List[Dict[str, Any]]


class ActionOnlyResponse(BaseModel):
    success: bool
    actions: List[Dict[str, Any]] = []
    execution_packages: List[Dict[str, Any]] = []
    combined_script: str = ""
    combined_filename: str = ""
    campaign_id: Optional[str] = None
    remote_push_attempted: bool = False
    remote_push_url: str = ""
    remote_execution_result: Optional[Dict[str, Any]] = None
    remote_execution_error: str = ""
    error: Optional[str] = None


class RemoteExecutionWebhookPayload(BaseModel):
    """Execution result posted from Machine 2 remote agent."""
    execution_id: str
    campaign_id: str = ""
    filename: str
    status: str
    success: bool
    exit_code: int
    stdout: str = ""
    stderr: str = ""
    executed_at: str
    duration_ms: float
    agent_host: str = ""
    agent_ip: str = ""


WEBHOOK_RESULTS_PATH = os.getenv(
    "REMOTE_RESULT_STORAGE_PATH",
    "./data/remote_results/execution_results.jsonl",
)
WEBHOOK_SHARED_KEY = os.getenv("REMOTE_WEBHOOK_KEY", "")


def _append_remote_execution_result(entry: Dict[str, Any]) -> None:
    """Persist remote execution callback payload as JSONL."""
    os.makedirs(os.path.dirname(WEBHOOK_RESULTS_PATH), exist_ok=True)
    with open(WEBHOOK_RESULTS_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")


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
    # Check Neo4j connectivity
    neo4j_ok = False
    chroma_ok = False
    try:
        from databases.neo4j_manager import neo4j_manager
        neo4j_ok = neo4j_manager.verify_connectivity()
    except Exception:
        neo4j_ok = False

    try:
        from rag.vector_store import get_attack_collection
        get_attack_collection()
        chroma_ok = True
    except Exception:
        chroma_ok = False

    status = "healthy" if (neo4j_ok or chroma_ok) else "degraded"
    return {
        "status": status,
        "timestamp": datetime.utcnow().isoformat(),
        "version": "1.0.0",
        "checks": {
            "neo4j": "up" if neo4j_ok else "down",
            "chromadb": "up" if chroma_ok else "down"
        }
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


@app.post("/remote/execution-result")
async def receive_remote_execution_result(
    payload: RemoteExecutionWebhookPayload,
    x_webhook_key: Optional[str] = Header(None, alias="X-Webhook-Key"),
):
    """Receive execution-result callbacks from Machine 2 remote agent."""
    if not WEBHOOK_SHARED_KEY:
        raise HTTPException(
            status_code=503,
            detail="Webhook receiver misconfigured: set REMOTE_WEBHOOK_KEY on Machine 3.",
        )

    if not x_webhook_key or x_webhook_key != WEBHOOK_SHARED_KEY:
        raise HTTPException(status_code=403, detail="Invalid webhook authentication key")

    result = payload.model_dump()
    result["received_at"] = datetime.now(timezone.utc).isoformat()

    try:
        _append_remote_execution_result(result)
        logger.info(
            "Remote execution callback received: "
            f"execution_id={result.get('execution_id')} status={result.get('status')} "
            f"campaign={result.get('campaign_id')} agent={result.get('agent_ip') or result.get('agent_host')}"
        )
    except OSError as e:
        logger.error(f"Failed to persist remote execution callback: {e}")
        raise HTTPException(status_code=500, detail="Failed to persist callback payload")

    return {"ok": True}


@app.get("/chroma/collections", response_model=CollectionsResponse)
async def list_chroma_collections():
    """
    List all ChromaDB collections
    
    Returns the count and names of all collections in the ChromaDB instance.
    """
    try:
        from rag.vector_store import get_client
        client = get_client()
        collections = client.list_collections()
        collection_names = [col.name for col in collections]
        
        return CollectionsResponse(
            count=len(collection_names),
            collections=collection_names,
            timestamp=datetime.utcnow().isoformat()
        )
    except Exception as e:
        logger.error(f"Error listing ChromaDB collections: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/db", response_model=AttackDbResponse)
async def list_databases():
    """
    List all SQLite databases in the knowledge/attack/data directory
    
    Returns a list of all .db files found in the attack data directory,
    along with table names and row counts for each database.
    """
    try:
        import sqlite3
        from pathlib import Path
        from knowledge.attack.config import _DATA_DIR
        
        data_dir = Path(_DATA_DIR)
        
        # Find all .db files in the data directory
        db_files = list(data_dir.glob("*.db"))
        db_names = [db.name for db in db_files]
        
        # Get table details for each database
        details = {}
        for db_file in db_files:
            try:
                tables = {}
                conn = sqlite3.connect(str(db_file))
                cursor = conn.cursor()
                
                # Get all table names
                cursor.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name;")
                table_names = [row[0] for row in cursor.fetchall()]
                
                # Count rows in each table
                for table_name in table_names:
                    cursor.execute(f"SELECT COUNT(*) FROM {table_name};")
                    count = cursor.fetchone()[0]
                    tables[table_name] = count
                
                conn.close()
                details[db_file.name] = tables
            except Exception as e:
                logger.error(f"Error reading database {db_file.name}: {e}")
                details[db_file.name] = {"error": str(e)}
        
        return AttackDbResponse(
            databases=db_names,
            count=len(db_names),
            details=details,
            timestamp=datetime.utcnow().isoformat()
        )
    except Exception as e:
        logger.error(f"Error listing databases: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/response/actions", response_model=ActionOnlyResponse)
async def response_actions(request: ActionOnlyRequest):
    """
    Run the investigation workflow and return ONLY the response actions.
    """

    try:
        initial_state = new_investigation_state(
            raw_events=request.events
        )

        final_state = threat_intel_workflow.invoke(initial_state)

        actions = []

        for action_entry in final_state.get("actions_taken", []):
            action_data = action_entry.get("action", action_entry)

            actions.append({
                "action_type": str(action_data.get("action_type", "")),
                "target": action_data.get("target", ""),
                "severity": str(action_data.get("severity", "")),
                "status": str(action_entry.get("status", "")),
                "technique_id": action_data.get("technique_id"),
                "confidence": action_data.get("confidence", 0.0),
                "rationale": action_data.get("rationale", ""),
                "details": action_entry.get("detail", ""),
                "dry_run": action_entry.get("dry_run", True)
            })

        return ActionOnlyResponse(
            success=True,
            actions=actions,
            execution_packages=final_state.get("execution_packages", []),
            combined_script=final_state.get("combined_script", ""),
            combined_filename=final_state.get("combined_filename", ""),
            campaign_id=final_state.get("campaign", {}).get("campaign_id"),
            remote_push_attempted=final_state.get("remote_push_attempted", False),
            remote_push_url=final_state.get("remote_push_url", ""),
            remote_execution_result=final_state.get("remote_execution_result"),
            remote_execution_error=final_state.get("remote_execution_error", ""),
        )

    except Exception as e:
        logger.exception(e)

        return ActionOnlyResponse(
            success=False,
            error=str(e)
        )


@app.post("/attack/search", response_model=SearchResponse)
async def search_attack_knowledge(request: SearchRequest):
    """
    Search the MITRE ATT&CK knowledge base
    
    Searches across all ATT&CK object types (techniques, tactics, software, groups, mitigations)
    for the given keyword.
    
    - **keyword**: Keyword or phrase to search for
    - **limit**: Maximum number of results (default: 25, max: 200)
    """
    try:
        from knowledge.attack.service import AttackService
        
        with AttackService.create() as service:
            results = service.search(request.keyword, limit=request.limit)
            
            # Convert SearchResult objects to dictionaries
            results_dict = []
            for result in results:
                results_dict.append({
                    "attack_id": result.attack_id,
                    "name": result.name,
                    "object_type": result.object_type,
                    "description": result.description
                })
            
            return SearchResponse(
                keyword=request.keyword,
                results=results_dict,
                count=len(results_dict),
                timestamp=datetime.utcnow().isoformat()
            )
    except Exception as e:
        logger.error(f"Error searching ATT&CK knowledge: {e}")
        raise HTTPException(status_code=500, detail=str(e))


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=True)
