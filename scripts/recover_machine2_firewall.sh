#!/bin/bash
set -euo pipefail

# block_ip recovery for Machine 2
TARGET_IPS=("92.118.39.14" "59.185.230.105" "165.50.98.176" "205.210.31.100")
SSH_PORT="22"

BACKUP_PATH="/tmp/firewall_backup_before_recovery_$(date +%Y%m%d_%H%M%S).txt"
if command -v iptables-save >/dev/null 2>&1; then
    iptables-save > "$BACKUP_PATH" 2>/dev/null || true
elif command -v nft >/dev/null 2>&1; then
    nft list ruleset > "$BACKUP_PATH" 2>/dev/null || true
fi

echo "Backed up firewall state to $BACKUP_PATH"

remove_iptables_rules() {
    local ip="$1"
    if iptables -C INPUT -s "$ip" -j DROP 2>/dev/null; then
        iptables -D INPUT -s "$ip" -j DROP || true
    fi
    if iptables -C OUTPUT -d "$ip" -j DROP 2>/dev/null; then
        iptables -D OUTPUT -d "$ip" -j DROP || true
    fi
}

remove_nft_rules() {
    local ip="$1"
    if command -v nft >/dev/null 2>&1; then
        local handles
        handles="$(nft -a list ruleset 2>/dev/null | grep -E "ip saddr ${ip} drop|ip daddr ${ip} drop" | grep -o 'handle [0-9]*' | cut -d' ' -f2 || true)"
        for handle in $handles; do
            nft delete rule inet filter input handle "$handle" 2>/dev/null || true
            nft delete rule inet filter output handle "$handle" 2>/dev/null || true
        done
    fi
}

if command -v iptables >/dev/null 2>&1; then
    for ip in "${TARGET_IPS[@]}"; do
        remove_iptables_rules "$ip"
    done
fi

if command -v nft >/dev/null 2>&1; then
    for ip in "${TARGET_IPS[@]}"; do
        remove_nft_rules "$ip"
    done
fi

# Verify and report whether the targeted rules remain
for ip in "${TARGET_IPS[@]}"; do
    if command -v iptables >/dev/null 2>&1; then
        if iptables -C INPUT -s "$ip" -j DROP 2>/dev/null || iptables -C OUTPUT -d "$ip" -j DROP 2>/dev/null; then
            echo "ERROR: targeted block for $ip still present" >&2
            exit 1
        fi
    fi
    if command -v nft >/dev/null 2>&1; then
        if nft list ruleset 2>/dev/null | grep -F "ip saddr $ip drop" >/dev/null 2>&1 || nft list ruleset 2>/dev/null | grep -F "ip daddr $ip drop" >/dev/null 2>&1; then
            echo "ERROR: targeted block for $ip still present" >&2
            exit 1
        fi
    fi
done

echo "Firewall verification passed. The four targeted block rules were removed without flushing the firewall."
