# Agentic Threat Intelligence Platform

LangGraph + Groq + RAG (ChromaDB) + Neo4j — turns raw security telemetry
(Sysmon, Suricata, Zeek, Wazuh) into correlated, predictive threat
intelligence reports, using seven specialized AI agents instead of static
SIEM rules.

```
Security Tools Collect Data  →  AI Agents Analyze Data  →  Actionable Intelligence
```

## Quick Links

- **Full architecture:** [`docs/architecture.md`](docs/architecture.md)
- **Pipeline / workflow detail:** [`docs/workflow.md`](docs/workflow.md)
- **Database schema (Neo4j + ChromaDB):** [`docs/database_schema.md`](docs/database_schema.md)
- **Step-by-step install guide:** [`INSTALLATION_GUIDE.md`](INSTALLATION_GUIDE.md)
- **Attack-chain prediction migration:** [`docs/ATTACK_CHAIN_MIGRATION.md`](docs/ATTACK_CHAIN_MIGRATION.md)

## Quick Start

### CLI Mode

```bash
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env   # add your GROQ_API_KEY (https://console.groq.com/keys)
docker run -d --name neo4j-threat-intel -p 7474:7474 -p 7687:7687 -e NEO4J_AUTH=neo4j/changeme neo4j:5.23
curl -L -o data/attack_data/enterprise_attack.json https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json
python -m rag.ingest_attack
python main.py --events data/sample_events/sample_events.json
```

### API Server Mode

```bash
# Start the FastAPI server
uvicorn app:app --reload --host 0.0.0.0 --port 8000

# In another terminal, test the API
curl -X POST http://localhost:8000/investigate \
  -H "Content-Type: application/json" \
  -d '{"events": [{"version": 1, "timestamp": "2026-07-21T09:10:00Z", "rule": {"level": 12, "description": "Possible credential dumping detected", "groups": ["windows", "credential_access", "mimikatz"]}, "agent": {"id": "003", "name": "FINANCE-PC"}, "id": "cred-001", "full_log": "mimikatz.exe privilege::debug sekurlsa::logonpasswords"}]}'
```

See `INSTALLATION_GUIDE.md` for the full walkthrough, troubleshooting, and
optional real telemetry source setup (Sysmon/Suricata/Zeek/Wazuh).

## The Seven Agents

| # | Agent | Job |
|---|---|---|
| 1 | Collection | Normalize raw telemetry into one event schema |
| 2 | IOC Enrichment | Extract & score IPs/hashes/domains/URLs |
| 3 | ATT&CK Mapping (RAG) | Map behavior to MITRE technique IDs |
| 4 | Campaign Correlation | Group isolated events into one attack narrative |
| 5 | Threat Prediction | Forecast the attacker's likely next move (using attack-chain progressions) |
| 6 | Response | Propose and manage response actions |
| 7 | Reporting | Generate the final markdown intelligence report |

## Project Layout

```
agentic-threat-intelligence/
├── main.py / config.py / requirements.txt / app.py
├── graph/          orchestration (LangGraph state + workflow)
├── agents/         the seven agents (collection, enrichment, mapping, correlation, prediction, response, reporting)
├── rag/            ATT&CK ingestion + ChromaDB retrieval + attack-chain progressions
├── llm/            Groq client, prompts, output parsing
├── telemetry/      Sysmon / Suricata / Zeek / Wazuh parsers
├── intelligence/   IOC extraction, ATT&CK lookups, risk scoring, campaign building
├── databases/      Neo4j + Chroma connection managers, models
├── knowledge/       MITRE ATT&CK knowledge layer (SQLite + schema)
├── knowledge_graph/ Neo4j schema, graph writes, analyst queries
├── memory/         cross-run investigation/campaign memory
├── reports/        markdown report templates + generator
├── actions/        response actions management (kill process, quarantine, notify)
├── connectors/      telemetry connectors (Wazuh)
├── data/           ATT&CK data, sample events, raw log inputs
├── tests/          pytest unit tests
└── docs/           architecture, workflow, db schema, migration guides
```

## Key Features

- **Multi-Source Telemetry Ingestion**: Supports Sysmon, Suricata, Zeek, and Wazuh log formats
- **RAG-Based ATT&CK Mapping**: Uses ChromaDB with attack-chain progressions for accurate technique mapping
- **Predictive Threat Intelligence**: Forecasts likely next attacker moves using curated attack-chain knowledge
- **Automated Response Actions**: Proposes and manages response actions (kill process, quarantine, notify)
- **Campaign Correlation**: Groups isolated events into coherent attack narratives
- **REST API**: FastAPI server for integration with existing security infrastructure
- **Knowledge Graph**: Neo4j-based knowledge graph for advanced threat analysis

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | API health check |
| `/health` | GET | Detailed health check (Neo4j, ChromaDB status) |
| `/investigate` | POST | Investigate security events (JSON body) |
| `/investigate/file/{path}` | POST | Investigate events from a JSON file |
| `/investigate/connector/{name}` | POST | Investigate events from a connector (e.g., Wazuh) |
| `/connectors` | GET | List available telemetry connectors |
| `/config` | GET | Get current configuration (sensitive values masked) |

See [`http://localhost:8000/docs`](http://localhost:8000/docs) for interactive API documentation (Swagger UI).

## Testing

```bash
# Run all tests
pytest

# Run specific test file
pytest tests/test_prediction.py

# Run with coverage
pytest --cov=. --cov-report=html
```

## Deployment

### Docker

```bash
# Build and run with Docker Compose
docker-compose up -d

# Production deployment
docker-compose -f docker-compose.prod.yml up -d
```

### Manual Deployment

See [`deploy.sh`](deploy.sh) for production deployment script with:
- Environment configuration
- Service management
- Health checks
- Rollback procedures

## License

MIT License - See LICENSE file for details

