import json
import logging
import os
import re
import socket
import subprocess
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)

logger = logging.getLogger("ssh_collector")

SPOOL_FILE = Path(
    os.getenv(
        "SSH_COLLECTOR_SPOOL",
        "/app/remote_agent/spool/agent_events.jsonl",
    )
)

POLL_INTERVAL = int(os.getenv("SSH_COLLECTOR_POLL_INTERVAL", "2"))
HOSTNAME = os.getenv("SSH_COLLECTOR_HOST", socket.gethostname())

FAILED_RE = re.compile(
    r"Failed password for (?:invalid user )?(\S+) from (\S+) port"
)

AUTH_FAILURE_RE = re.compile(
    r"authentication failure.*rhost=(\S+).*user=(\S+)"
)

ACCEPTED_RE = re.compile(
    r"Accepted password for (\S+) from (\S+) port"
)


def write_event(event):
    SPOOL_FILE.parent.mkdir(parents=True, exist_ok=True)

    with SPOOL_FILE.open("a", encoding="utf-8") as f:
        f.write(json.dumps(event, ensure_ascii=False) + "\n")

    logger.info(
        "Event written: type=%s src_ip=%s",
        event["event_type"],
        event.get("src_ip"),
    )


def parse_line(line):
    timestamp = datetime.now(timezone.utc).isoformat()

    match = FAILED_RE.search(line)
    if match:
        username, src_ip = match.groups()

        return {
            "event_id": str(uuid.uuid4()),
            "timestamp": timestamp,
            "source": "sshd",
            "event_type": "auth_failed",
            "host": HOSTNAME,
            "src_ip": src_ip,
            "username": username,
            "severity": "high",
            "message": line.strip(),
        }

    match = AUTH_FAILURE_RE.search(line)
    if match:
        src_ip, username = match.groups()

        return {
            "event_id": str(uuid.uuid4()),
            "timestamp": timestamp,
            "source": "sshd",
            "event_type": "auth_failed",
            "host": HOSTNAME,
            "src_ip": src_ip,
            "username": username,
            "severity": "high",
            "message": line.strip(),
        }

    match = ACCEPTED_RE.search(line)
    if match:
        username, src_ip = match.groups()

        return {
            "event_id": str(uuid.uuid4()),
            "timestamp": timestamp,
            "source": "sshd",
            "event_type": "auth_success",
            "host": HOSTNAME,
            "src_ip": src_ip,
            "username": username,
            "severity": "medium",
            "message": line.strip(),
        }

    return None


def main():
    logger.info("Starting SSH event collector")
    logger.info("Host: %s", HOSTNAME)
    logger.info("Spool: %s", SPOOL_FILE)

    process = subprocess.Popen(
        [
            "journalctl",
            "-u",
            "sshd",
            "-f",
            "-n",
            "0",
            "-o",
            "cat",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )

    while True:
        line = process.stdout.readline()

        if line:
            event = parse_line(line)

            if event:
                write_event(event)

        else:
            time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    main()