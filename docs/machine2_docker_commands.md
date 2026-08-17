# Machine 2 — Docker Inspection & Testing Commands

## 1. Check running containers

```bash
docker compose ps
```

or:

```bash
docker ps
```

## 2. View logs of all services

```bash
docker compose logs --tail=100
```

Follow logs in real time:

```bash
docker compose logs -f
```

## 3. SSH Collector

View recent logs:

```bash
docker compose logs --tail=100 remote-ssh-collector
```

Follow logs in real time:

```bash
docker compose logs -f remote-ssh-collector
```

## 4. Event Forwarder

View recent logs:

```bash
docker compose logs --tail=100 remote-event-forwarder
```

Follow logs in real time:

```bash
docker compose logs -f remote-event-forwarder
```

## 5. Remote Response Agent

View recent logs:

```bash
docker compose logs --tail=100 remote-response-agent
```

Follow logs in real time:

```bash
docker compose logs -f remote-response-agent
```

## 6. Check the event spool

View all events:

```bash
docker exec remote-ssh-collector cat /app/remote_agent/spool/agent_events.jsonl
```

View the last 20 events:

```bash
docker exec remote-ssh-collector tail -20 /app/remote_agent/spool/agent_events.jsonl
```

Follow new events in real time:

```bash
docker exec remote-ssh-collector tail -f /app/remote_agent/spool/agent_events.jsonl
```

The same shared spool can also be checked from the forwarder:

```bash
docker exec remote-event-forwarder tail -20 /app/remote_agent/spool/agent_events.jsonl
```

## 7. Check SSH logs directly on Machine 2

View the last 50 SSH logs:

```bash
journalctl -u sshd -n 50
```

Follow SSH logs in real time:

```bash
journalctl -u sshd -f
```

## 8. Check Remote Response Agent API

Health check:

```bash
curl http://127.0.0.1:9001/health
```

Status:

```bash
curl http://127.0.0.1:9001/status
```

## 9. Check processes inside containers

```bash
docker top remote-ssh-collector
docker top remote-event-forwarder
docker top remote-response-agent
```

## 10. Check Docker volumes

List volumes:

```bash
docker volume ls
```

Inspect the spool volume:

```bash
docker volume inspect remote_agent_spool
```

---

# Complete End-to-End Test

Use three terminals on Machine 2.

### Terminal 1 — SSH Collector

```bash
docker compose logs -f remote-ssh-collector
```

### Terminal 2 — Event Forwarder

```bash
docker compose logs -f remote-event-forwarder
```

### Terminal 3 — Event Spool

```bash
docker exec remote-ssh-collector tail -f /app/remote_agent/spool/agent_events.jsonl
```

Then generate an SSH test from Machine 1.

Expected flow:

```text
Machine 1
   ↓
SSH attack
   ↓
Machine 2 — sshd
   ↓
remote-ssh-collector
   ↓
agent_events.jsonl
   ↓
remote-event-forwarder
   ↓
POST /agent/events
   ↓
Machine 3 — AI Platform
```
