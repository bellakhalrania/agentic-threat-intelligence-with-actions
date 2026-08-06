# Wazuh Commands Reference

## Architecture Overview

- **Machine 2:** Victim EC2 (Wazuh Agent)
- **Machine 3:** Wazuh Manager (running in Docker)

---

## ༺ Machine 2 — Wazuh Agent Commands

### 1. Check if the Wazuh agent service is running

```bash
sudo systemctl status wazuh-agent --no-pager
```

Or simply:

```bash
sudo systemctl is-active wazuh-agent
```

Expected output:

```text
active
```

### 2. Check the Wazuh agent logs

```bash
sudo tail -f /var/ossec/logs/ossec.log
```

You should see messages similar to:

```text
Connected to manager
Sending keepalive
```

or

```text
Agent started
```

### 3. Check if the agent process is running

```bash
ps aux | grep wazuh-agent
```

or

```bash
pgrep -a wazuh
```

### 4. Check the agent configuration

```bash
sudo cat /var/ossec/etc/ossec.conf
```

Look for the manager address:

```xml
<client>
  <server>
    <address>YOUR_MANAGER_IP</address>
  </server>
</client>
```

### 5. Check if the agent can reach the manager

Replace with the IP of Machine 3 (your Wazuh manager):

```bash
ping MACHINE3_IP
```

or check the default Wazuh port (1514):

```bash
nc -zv MACHINE3_IP 1514
```

or

```bash
telnet MACHINE3_IP 1514
```

### 6. Restart the agent (if needed)

```bash
sudo systemctl restart wazuh-agent
```

Then immediately watch the logs:

```bash
sudo tail -f /var/ossec/logs/ossec.log
```

### 7. Verify from the Wazuh Manager (Machine 3)

Since the manager is running in Docker:

```bash
sudo docker exec -it single-node_wazuh.manager_1 /var/ossec/bin/agent_control -l
```

You should see something like:

```text
ID: 001, Name: aws-server, IP: 172.31.19.70, Active
```

If the agent appears as **Active**, it is successfully connected to the Wazuh manager.

---

## ⼺ Machine 3 — Wazuh Manager Commands (Docker)

### 1. Check that the Wazuh containers are running

```bash
sudo docker ps
```

You should see containers similar to:

```text
single-node_wazuh.manager_1
single-node_wazuh.dashboard_1
single-node_indexer_1
```

### 2. Check the manager logs

```bash
sudo docker logs single-node_wazuh.manager_1 --tail 50
```

Or follow them live:

```bash
sudo docker logs -f single-node_wazuh.manager_1
```

### 3. List all registered agents

> ⚠️ This is the command you'll use most often.

```bash
sudo docker exec -it single-node_wazuh.manager_1 /var/ossec/bin/agent_control -l
```

Expected output:

```text
Wazuh agent_control. List of available agents:

ID: 000, Name: wazuh.manager, Active/Local
ID: 001, Name: aws-server, Active
```

If your EC2 agent is **Active**, communication is working.

### 4. Check a specific agent

```bash
sudo docker exec -it single-node_wazuh.manager_1 /var/ossec/bin/agent_control -i 001
```

Replace `001` with your agent ID if different.

### 5. Watch security alerts in real time

> ⚠️ This is the most useful command while testing attacks.

```bash
sudo docker exec -it single-node_wazuh.manager_1 tail -f /var/ossec/logs/alerts/alerts.json
```

As soon as Machine 2 generates an alert, you'll see it here.

### 6. Search only SSH-related alerts

```bash
sudo docker exec -it single-node_wazuh.manager_1 \
grep ssh /var/ossec/logs/alerts/alerts.json | tail -20
```

### 7. Search by source IP (your attacker)

Replace with your attacker IP:

```bash
sudo docker exec -it single-node_wazuh.manager_1 \
grep "172.31.24.217" /var/ossec/logs/alerts/alerts.json | tail -20
```

### 8. Search for failed password events

```bash
sudo docker exec -it single-node_wazuh.manager_1 \
grep "Failed password" /var/ossec/logs/alerts/alerts.json | tail -20
```

### 9. Check manager status

```bash
sudo docker exec -it single-node_wazuh.manager_1 /var/ossec/bin/wazuh-control status
```

Expected output:

```text
wazuh-analysisd: running
wazuh-remoted: running
wazuh-db: running
wazuh-modulesd: running
```

### 10. Check manager internal logs

```bash
sudo docker exec -it single-node_wazuh.manager_1 \
tail -50 /var/ossec/logs/ossec.log
```

### 11. Check alert count

```bash
sudo docker exec -it single-node_wazuh.manager_1 \
wc -l /var/ossec/logs/alerts/alerts.json
```

### 12. Display the latest alert

```bash
sudo docker exec -it single-node_wazuh.manager_1 \
tail -1 /var/ossec/logs/alerts/alerts.json | jq
```

If `jq` isn't installed in the container, use:

```bash
sudo docker exec -it single-node_wazuh.manager_1 \
tail -1 /var/ossec/logs/alerts/alerts.json
```

---

## ⭐ Top 3 Commands You'll Use Most During Demonstrations

### 1⃣ Verify the agent is connected

```bash
sudo docker exec -it single-node_wazuh.manager_1 /var/ossec/bin/agent_control -l
```

### 2⃣ Watch alerts live

```bash
sudo docker exec -it single-node_wazuh.manager_1 tail -f /var/ossec/logs/alerts/alerts.json
```

### 3⃣ Check the manager services

```bash
sudo docker exec -it single-node_wazuh.manager_1 /var/ossec/bin/wazuh-control status
```

These three commands are usually sufficient to confirm that Machine 2 is sending events to the Wazuh Manager and that your detection pipeline is receiving them.

---

## ὐ0 Quick Troubleshooting Flow

```
Agent not showing up?
        │
        ▼
┌───────────────────────────────┐
│ Is the agent service active?│
│ systemctl is-active wazuh-  │
│ agent                       │
└─────┬──────────────────────┘
           │ No
           ▼
    ┌─────────────┐
    │ Restart it:  │
    │ systemctl    │
    │ restart      │
    │ wazuh-agent  │
    └──────┬─────────┘
           │ Yes
           ▼
┌───────────────────────────────┐
│ Can it reach the manager?   │
│ nc -zv MANAGER_IP 1514      │
└─────┬──────────────────────┘
           │ No
           ▼
    ┌────────────────┐
    │ Check SG /       │
    │ firewall rules   │
    └──────────────┬───────┘
           │ Yes
           ▼
┌───────────────────────────────┐
│ Is manager IP correct in   │
│ ossec.conf?                 │
└─────┬──────────────────────┘
           │ No
           ▼
    ┌────────────────┐
    │ Fix the IP and   │
    │ restart agent    │
    └──────────────┬───────┘
           │ Yes
           ▼
┌───────────────────────────────┐
│ Check manager logs for      │
│ errors: docker logs ...     │
└───────────────────────────────┘
```

---

## Ὅd Notes

| Item | Value |
|---|---|
| Default Agent Port | 1514 |
| Agent Config File | `/var/ossec/etc/ossec.conf` |
| Agent Log File | `/var/ossec/logs/ossec.log` |
| Manager Alerts File | `/var/ossec/logs/alerts/alerts.json` |
| Manager Container Name | `single-node_wazuh.manager_1` |



sudo docker cp single-node_wazuh.manager_1:/var/ossec/logs/alerts/alerts.json ./data/wazuh_logs/alerts.json && sudo chown rania:rania ./data/wazuh_logs/alerts.json && chmod 644 ./data/wazuh_logs/alerts.json && python main.py --source wazuh


rsync -avz   -e "ssh -i ~/.ssh/id_ed25519 -o IdentitiesOnly=yes"   --exclude 'venv/'   --exclude '__pycache__/'   --exclude 'received_scripts/'   --exclude 'execution_log.jsonl'   /home/rania/Documents/agentic-threat-intelligence-with-actions/remote_agent/   ubuntu@100.120.11.97:~/remote_agent/
