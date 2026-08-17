# Attack Simulation Agent (Machine 1)

This is a standalone FastAPI service for an authorized laboratory attacker host. It has one predefined scenario: `ssh_bruteforce` (MITRE ATT&CK `T1110.001`). It does not accept command text, passwords, targets, or scenario settings via HTTP; these are fixed in the local environment before the service starts.

## Safety controls

- `DRY_RUN=true` is the default and does not start Hydra.
- `TARGET` must exactly equal an entry in `APPROVED_TARGETS`.
- A live run additionally requires `ALLOW_LIVE_ATTACKS=true` and a regular `ATTACK_PASSWORD_FILE`.
- The candidate file is limited to `MAX_ATTEMPTS` lines (default 3); it is never read into logs or event payloads.
- Hydra is invoked only with a fixed argument list, one parallel task by default, a timeout, and no shell.
- `POST /simulations/stop` terminates the Hydra process group.

## Run on Machine 1

```bash
cd attack_simulation_agent
cp .env.example .env
docker compose up -d --build
curl -X POST http://127.0.0.1:9010/simulations
curl http://127.0.0.1:9010/simulations/current
```

The local API binds to loopback only. For a live authorized lab test, set an exact Machine 2 address in both `TARGET` and `APPROVED_TARGETS`, set `DRY_RUN=false` and `ALLOW_LIVE_ATTACKS=true`, and provide an explicit small lab-only candidate file. Do not use production targets or real account passwords.

## Machine 3 correlation

Set `ATTACK_EVENT_WEBHOOK_URL` to Machine 3's existing `.../agent/events` endpoint, and set `ATTACK_EVENT_WEBHOOK_KEY` if it requires `X-Agent-Key`. The agent POSTs `{ "events": [event] }`; the event is correlation context only and does not replace Wazuh telemetry. Events are retained in `logs/attack_events.jsonl` if forwarding is unavailable.

Example normalized event:

```json
{"simulation_id":"attack-...","source":"attack_simulation_agent","attack_type":"ssh_bruteforce","mitre_technique":"T1110.001","target":"192.0.2.20","status":"dry_run","timestamp":"2026-01-01T00:00:00Z"}
```
