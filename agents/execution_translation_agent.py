"""
agents/execution_translation_agent.py
Eighth pipeline stage (optional - wire into graph/workflow.py to enable).

Translates approved response actions into platform-specific executable scripts
(PowerShell, Bash, Python, etc.). This agent does NOT analyze security events
or recommend actions. It ONLY translates already-approved actions into
executable code.

Input:
- A structured response action from the Response Agent (ActionResult).
- Platform specification (default: linux via bash).

Output:
- A list of execution translation packages, each containing:
  - action_id, action_type, platform, language, filename, script,
    requires_admin, expected_effect, rollback, verification
"""

from typing import List, Dict, Any, Optional
from actions.action_models import ProposedAction
from config import config


class ExecutionTranslationAgent:
    """Translates approved response actions into executable scripts.

    This agent is purely deterministic. It maps each action type + platform
    to a known script template and fills in the target-specific parameters.
    """

    # Allowed platforms and their associated languages
    PLATFORM_LANGUAGES = {
        "linux": "bash",
        "windows": "powershell",
        "macos": "bash",
        "cross_platform": "python",
    }

    def run(
        self,
        actions_taken: List[Dict[str, Any]],
        platform: str = "linux",
    ) -> Dict[str, Any]:
        """Translate approved actions into executable packages.

        Args:
            actions_taken: List of ActionResult dicts from the Response Agent.
                Each must have a status of "executed". Pending actions remain
                unavailable until a human reviewer approves them.
                to be translated.
            platform: Target OS platform (linux, windows, macos).

        Returns:
            Dictionary with:
              - "execution_packages": list of individual execution package dicts
              - "combined_script": a single combined executable script containing all actions
              - "combined_filename": the filename for the combined script
              - "language": the scripting language used
              - "platform": target platform
        """
        print("\n========== EXECUTION TRANSLATION AGENT ==========\n")
        print(f"Target platform: {platform}")

        language = self.PLATFORM_LANGUAGES.get(platform, "bash")
        execution_packages = []

        for idx, action_result in enumerate(actions_taken, 1):
            action = action_result.get("action", {})
            status = action_result.get("status", "")

            print(f"  Processing action {idx}: {action.get('action_type')} "
                  f"(status: {status})")

            # Pending actions must not become executable artifacts before a
            # human decision is recorded in the approval workflow.
            if status != "executed":
                print(f"    Skipping action {idx} (status: {status})")
                continue

            action_type = action.get("action_type", "")
            target = action.get("target", "")
            technique_id = action.get("technique_id") or ""
            confidence = action.get("confidence", 0.0)

            # Build the execution package
            package = self._translate(
                action_type=action_type,
                target=target,
                platform=platform,
                language=language,
                technique_id=technique_id,
                confidence=confidence,
            )

            execution_packages.append(package)

            print(f"    Translated to {platform}/{language}")
            print(f"    Filename: {package.get('filename')}")
            print(f"    Requires admin: {package.get('requires_admin')}")

        # Generate the single combined executable script
        combined_script = self._generate_combined_script(
            execution_packages=execution_packages,
            platform=platform,
            language=language,
        )
        combined_filename = f"response_actions_{len(execution_packages)}_actions.{'sh' if platform != 'windows' else 'ps1'}"

        print(f"Total execution packages generated: {len(execution_packages)}")
        print(f"Combined script generated: {combined_filename}")
        print("===============================================\n")

        return {
            "execution_packages": execution_packages,
            "combined_script": combined_script,
            "combined_filename": combined_filename,
            "language": language,
            "platform": platform,
        }

    def _generate_combined_script(
        self,
        execution_packages: List[Dict[str, Any]],
        platform: str,
        language: str,
    ) -> str:
        """Generate a single combined executable script containing all actions.

        The combined script includes:
          - A header with usage information
          - A main menu/entry point
          - All individual action functions
          - A rollback section
        """
        if platform == "windows":
            return self._generate_combined_powershell(execution_packages)
        else:
            return self._generate_combined_bash(execution_packages)

    def _generate_combined_bash(
        self,
        execution_packages: List[Dict[str, Any]],
    ) -> str:
        """Generate a single combined bash script."""
        lines = [
            "#!/bin/bash",
            "#",
            "# Combined Response Actions Script",
            "# Generated by Agentic Threat Intelligence - Execution Translation Agent",
            f"# Date: $(date -u '+%Y-%m-%dT%H:%M:%SZ')",
            f"# Total Actions: {len(execution_packages)}",
            "#",
            "# Usage:",
            "#   chmod +x this_script.sh",
            "#   sudo ./this_script.sh          # Execute all actions",
            "#   sudo ./this_script.sh --dry-run # Simulate without executing",
            "#   sudo ./this_script.sh --rollback # Rollback all actions",
            "#   sudo ./this_script.sh --action <N> # Execute only action N",
            "#",
            "",
            "set -euo pipefail",
            "",
            "DRY_RUN=false",
            "ROLLBACK=false",
            "SINGLE_ACTION=\"\"",
            "",
            "while [[ $# -gt 0 ]]; do",
            "    case \"$1\" in",
            "        --dry-run) DRY_RUN=true; shift ;;",
            "        --rollback) ROLLBACK=true; shift ;;",
            "        --action) SINGLE_ACTION=\"$2\"; shift 2 ;;",
            "        *) echo \"Unknown option: $1\"; exit 1 ;;",
            "    esac",
            "done",
            "",
            "echo \"========================================\"",
            "echo \"  Response Actions Execution Script\"",
            "echo \"  Mode: $($DRY_RUN && echo 'DRY RUN' || ($ROLLBACK && echo 'ROLLBACK' || echo 'EXECUTE'))\"",
            "echo \"========================================\"",
            "echo \"\",",
        ]

        # Add each action as a named function
        for idx, pkg in enumerate(execution_packages, 1):
            action_type = pkg.get("action_type", "unknown")
            target = pkg.get("target", "unknown")
            action_id = pkg.get("action_id", f"action_{idx}")
            script = pkg.get("script", "")
            rollback = pkg.get("rollback", "# No rollback defined")
            verification = pkg.get("verification", [])
            requires_admin = pkg.get("requires_admin", False)
            expected = pkg.get("expected_effect", "")
            effect = pkg.get("expected_effect", "")

            # Remove shebang from individual scripts since they're functions now
            clean_script = script
            if clean_script.startswith("#!/bin/bash\n"):
                clean_script = clean_script[len("#!/bin/bash\n"):]

            lines.append(f"")
            lines.append(f"# =======================================")
            lines.append(f"# Action {idx}: {action_type}")
            lines.append(f"# Target: {target}")
            lines.append(f"# ID: {action_id}")
            lines.append(f"# Expected: {effect}")
            lines.append(f"# =======================================")
            lines.append(f"action_{idx}() {{")
            lines.append(f"    echo \"[ACTION {idx}] {action_type} -> {target}\"")
            lines.append(f"    echo \"  Expected: {effect}\"")
            if requires_admin:
                lines.append(f"    if [[ $EUID -ne 0 ]]; then")
                lines.append(f"        echo \"  ERROR: Requires root privileges\" >&2")
                lines.append(f"        return 1")
                lines.append(f"    fi")
            lines.append(f"")
            if "$DRY_RUN" in clean_script or "DRY_RUN" in clean_script:
                lines.append(f"    if $DRY_RUN; then")
                lines.append(f"        echo \"  [DRY RUN] Would execute: {action_type} on {target}\"")
                lines.append(f"        return 0")
                lines.append(f"    fi")
            for script_line in clean_script.split("\n"):
                if script_line.strip():
                    lines.append(f"    {script_line}")
            lines.append(f"    echo \"  [OK] {action_type} completed\"")
            lines.append(f"}}")
            lines.append(f"")

            # Rollback function
            lines.append(f"rollback_{idx}() {{")
            lines.append(f"    echo \"[ROLLBACK {idx}] {action_type} -> {target}\"")
            if "$DRY_RUN" in rollback or "DRY_RUN" in rollback:
                lines.append(f"    if $DRY_RUN; then")
                lines.append(f"        echo \"  [DRY RUN] Would rollback: {action_type} on {target}\"")
                lines.append(f"        return 0")
                lines.append(f"    fi")
            for rb_line in rollback.split("\n"):
                if rb_line.strip() and not rb_line.strip().startswith("# Rollback"):
                    lines.append(f"    {rb_line}")
            lines.append(f"    echo \"  [OK] Rollback of {action_type} completed\"")
            lines.append(f"}}")
            lines.append(f"")

            # Verification function
            lines.append(f"verify_{idx}() {{")
            lines.append(f"    echo \"[VERIFY {idx}] {action_type} -> {target}\"")
            if verification:
                for v_line in verification:
                    lines.append(f"    {v_line}")
            else:
                lines.append(f"    echo \"  No automated verification available\"")
            lines.append(f"}}")
            lines.append(f"")

        # Main execution section
        lines.append(f"# =======================================")
        lines.append(f"# Main Execution")
        lines.append(f"# =======================================")
        lines.append(f'echo ""')
        lines.append(f'echo "Starting execution of {len(execution_packages)} action(s)..."')
        lines.append(f'echo ""')
        lines.append(f"")

        if execution_packages:
            lines.append(f"if $ROLLBACK; then")
            for idx in range(len(execution_packages), 0, -1):
                lines.append(f"    rollback_{idx}")
            lines.append(f"elif [[ -n \"$SINGLE_ACTION\" ]]; then")
            lines.append(f"    case \"$SINGLE_ACTION\" in")
            for idx in range(1, len(execution_packages) + 1):
                pkg = execution_packages[idx - 1]
                lines.append(f"        {idx}) action_{idx} ;;")
            lines.append(f"        *) echo \"Unknown action: $SINGLE_ACTION\"; exit 1 ;;")
            lines.append(f"    esac")
            lines.append(f"else")
            for idx in range(1, len(execution_packages) + 1):
                lines.append(f"    action_{idx}")
            lines.append(f"fi")
        else:
            lines.append(f'echo "No actions to execute."')

        lines.append(f"")
        lines.append(f'echo ""')
        lines.append(f'echo "Execution completed."')
        lines.append(f"")

        return "\n".join(lines)

    def _generate_combined_powershell(
        self,
        execution_packages: List[Dict[str, Any]],
    ) -> str:
        """Generate a single combined PowerShell script."""
        lines = [
            "<#",
            ".SYNOPSIS",
            "    Combined Response Actions Script",
            ".DESCRIPTION",
            "    Generated by Agentic Threat Intelligence - Execution Translation Agent",
            f"    Total Actions: {len(execution_packages)}",
            ".PARAMETER DryRun",
            "    Simulate execution without actually running actions",
            ".PARAMETER Rollback",
            "    Rollback all previously executed actions",
            ".PARAMETER ActionNumber",
            "    Execute only a specific action by number",
            ".EXAMPLE",
            f"    .\\this_script.ps1",
            f"    .\\this_script.ps1 -DryRun",
            f"    .\\this_script.ps1 -Rollback",
            f"    .\\this_script.ps1 -ActionNumber 1",
            "#>",
            "",
            "param(",
            "    [switch] \$DryRun,",
            "    [switch] \$Rollback,",
            "    [int] \$ActionNumber = -1",
            ")",
            "",
            "Write-Host \"========================================\"",
            "Write-Host \"  Response Actions Execution Script\"",
            "Write-Host \"  Mode: $(if (\$DryRun) { 'DRY RUN' } elseif (\$Rollback) { 'ROLLBACK' } else { 'EXECUTE' })\"",
            "Write-Host \"========================================\"",
            'Write-Host ""',
            "",
        ]

        # Add each action as a script block function
        for idx, pkg in enumerate(execution_packages, 1):
            action_type = pkg.get("action_type", "unknown")
            target = pkg.get("target", "unknown")
            action_id = pkg.get("action_id", f"action_{idx}")
            script = pkg.get("script", "")
            rollback = pkg.get("rollback", "# No rollback defined")
            effect = pkg.get("expected_effect", "")

            lines.append(f"")
            lines.append(f"# =======================================")
            lines.append(f"# Action {idx}: {action_type}")
            lines.append(f"# Target: {target}")
            lines.append(f"# ID: {action_id}")
            lines.append(f"# Expected: {effect}")
            lines.append(f"# =======================================")
            lines.append(f"function Invoke-Action{idx} {{")
            lines.append(f"    Write-Host \"[ACTION {idx}] {action_type} -> {target}\"")
            lines.append(f"    Write-Host \"  Expected: {effect}\"")
            if "\$DryRun" in script or "DryRun" in script:
                lines.append(f"    if (\$DryRun) {{")
                lines.append(f"        Write-Host \"  [DRY RUN] Would execute: {action_type} on {target}\"")
                lines.append(f"        return")
                lines.append(f"    }}")
            for script_line in script.split("\n"):
                stripped = script_line.strip()
                if stripped and not stripped.startswith("#"):
                    lines.append(f"    {stripped}")
            lines.append(f"    Write-Host \"  [OK] {action_type} completed\"")
            lines.append(f"}}")
            lines.append(f"")

            lines.append(f"function Invoke-Rollback{idx} {{")
            lines.append(f"    Write-Host \"[ROLLBACK {idx}] {action_type} -> {target}\"")
            if "\$DryRun" in rollback or "DryRun" in rollback:
                lines.append(f"    if (\$DryRun) {{")
                lines.append(f"        Write-Host \"  [DRY RUN] Would rollback: {action_type} on {target}\"")
                lines.append(f"        return")
                lines.append(f"    }}")
            for rb_line in rollback.split("\n"):
                stripped = rb_line.strip()
                if stripped and not stripped.startswith("#"):
                    lines.append(f"    {stripped}")
            lines.append(f"    Write-Host \"  [OK] Rollback of {action_type} completed\"")
            lines.append(f"}}")
            lines.append(f"")

        # Main execution
        lines.append(f"# =======================================")
        lines.append(f"# Main Execution")
        lines.append(f"# =======================================")
        lines.append(f'Write-Host ""')
        lines.append(f'Write-Host "Starting execution of {len(execution_packages)} action(s)..."')
        lines.append(f'Write-Host ""')

        if execution_packages:
            lines.append(f"if (\$Rollback) {{")
            for idx in range(len(execution_packages), 0, -1):
                lines.append(f"    Invoke-Rollback{idx}")
            lines.append(f"}} elseif (\$ActionNumber -gt 0) {{")
            lines.append(f"    switch (\$ActionNumber) {{")
            for idx in range(1, len(execution_packages) + 1):
                lines.append(f"        {idx} {{ Invoke-Action{idx} }}")
            lines.append(f"        default {{ Write-Host \"Unknown action: \$ActionNumber\"; exit 1 }}")
            lines.append(f"    }}")
            lines.append(f"}} else {{")
            for idx in range(1, len(execution_packages) + 1):
                lines.append(f"    Invoke-Action{idx}")
            lines.append(f"}}")
        else:
            lines.append(f'Write-Host "No actions to execute."')

        lines.append(f"")
        lines.append(f'Write-Host ""')
        lines.append(f'Write-Host "Execution completed."')

        return "\n".join(lines)

    def _translate(
        self,
        action_type: str,
        target: str,
        platform: str,
        language: str,
        technique_id: str = "",
        confidence: float = 0.0,
    ) -> Dict[str, Any]:
        """Translate a single action into an execution package.

        Dispatches to platform-specific generators based on action_type.
        """
        translator_map = {
            "block_ip": self._translate_block_ip,
            "isolate_host": self._translate_isolate_host,
            "disable_account": self._translate_disable_account,
            "kill_process": self._translate_kill_process,
            "quarantine_file": self._translate_quarantine_file,
            "notify_analyst": self._translate_notify_analyst,
        }

        translator = translator_map.get(action_type)
        if translator is None:
            return self._error_package(
                action_type=action_type,
                target=target,
                reason=f"Unknown action type: {action_type}. Cannot translate.",
            )

        return translator(target, platform, language, technique_id, confidence)

    # ------------------------------------------------------------------
    # Translation generators per action type
    # ------------------------------------------------------------------

    def _translate_block_ip(
        self, target: str, platform: str, language: str,
        technique_id: str, confidence: float,
    ) -> Dict[str, Any]:
        """Generate iptables/nftables block for linux, netsh for windows."""
        action_id = f"block_ip_{hash(target) & 0xffffffff:08x}"

        if platform == "windows":
            script = (
                f"# Block IP {target}\n"
                f"netsh advfirewall firewall add rule name=\"Block {target}\" "
                f"dir=in action=block remoteip={target}\n"
                f"netsh advfirewall firewall add rule name=\"Block {target}_out\" "
                f"dir=out action=block remoteip={target}\n"
            )
            filename = f"block_ip_{target}.ps1"
            admin_required = True
            expected = f"Block all inbound and outbound traffic to/from IP {target}"
            rollback = (
                f"netsh advfirewall firewall delete rule name=\"Block {target}\"\n"
                f"netsh advfirewall firewall delete rule name=\"Block {target}_out\""
            )
            verification = [
                f"netsh advfirewall firewall show rule name=\"Block {target}\"",
                f"Test-NetConnection -ComputerName {target} -Port 443",
            ]
        else:
            # Linux / macOS / cross-platform via bash
            management_source_ip = (config.REMOTE_MANAGER_IP or "").strip()
            management_port = str(getattr(config, "REMOTE_AGENT_PORT", "9001"))
            script = (
                f"#!/bin/bash\n"
                f"set -euo pipefail\n"
                f"# Block only IP {target} without altering global firewall policy\n"
                f"target_ip='{target}'\n"
                f"management_source_ip='{management_source_ip}'\n"
                f"if [ -z \"$management_source_ip\" ] && [ -n \"${{SSH_CLIENT:-}}\" ]; then\n"
                f"    management_source_ip=$(printf '%s\n' \"$SSH_CLIENT\" | awk '{{print $1}}')\n"
                f"fi\n"
                f"if [ -n \"$management_source_ip\" ] && [ \"$target_ip\" = \"$management_source_ip\" ]; then\n"
                f"    echo 'REJECTED: target_ip matches management_source_ip' >&2\n"
                f"    exit 2\n"
                f"fi\n"
                f"if command -v nft &> /dev/null; then\n"
                f"    nft add rule inet filter input ip saddr \"$target_ip\" drop 2>/dev/null || true\n"
                f"    nft add rule inet filter output ip daddr \"$target_ip\" drop 2>/dev/null || true\n"
                f"elif command -v iptables &> /dev/null; then\n"
                f"    iptables -C INPUT -s \"$target_ip\" -j DROP 2>/dev/null || iptables -I INPUT -s \"$target_ip\" -j DROP\n"
                f"    iptables -C OUTPUT -d \"$target_ip\" -j DROP 2>/dev/null || iptables -I OUTPUT -d \"$target_ip\" -j DROP\n"
                f"else\n"
                f"    echo 'ERROR: Neither nft nor iptables found' >&2\n"
                f"    exit 1\n"
                f"fi\n"
                f"if command -v nft &> /dev/null; then\n"
                f"    nft list ruleset 2>/dev/null | grep -F \"ip saddr $target_ip drop\" >/dev/null 2>&1 || {{ echo 'ERROR: Firewall rule not installed' >&2; exit 1; }}\n"
                f"elif command -v iptables &> /dev/null; then\n"
                f"    iptables -C INPUT -s \"$target_ip\" -j DROP 2>/dev/null && iptables -C OUTPUT -d \"$target_ip\" -j DROP 2>/dev/null || {{ echo 'ERROR: Firewall rule not installed' >&2; exit 1; }}\n"
                f"fi\n"
                f"echo 'Blocked IP {target}'\n"
            )
            filename = f"block_ip_{target}.sh"
            admin_required = True
            expected = f"Block only inbound and outbound traffic to/from IP {target} without altering global firewall policy"
            rollback = (
                f"# Rollback\n"
                f"if command -v nft &> /dev/null; then\n"
                f"    nft delete rule inet filter input handle $(nft -a list ruleset 2>/dev/null | "
                f"grep '{target}' | grep -o 'handle [0-9]*' | cut -d' ' -f2 | tail -1) 2>/dev/null || true\n"
                f"    nft delete rule inet filter output handle $(nft -a list ruleset 2>/dev/null | "
                f"grep '{target}' | grep -o 'handle [0-9]*' | cut -d' ' -f2 | tail -1) 2>/dev/null || true\n"
                f"elif command -v iptables &> /dev/null; then\n"
                f"    iptables -D INPUT -s {target} -j DROP 2>/dev/null || true\n"
                f"    iptables -D OUTPUT -d {target} -j DROP 2>/dev/null || true\n"
                f"fi"
            )
            verification = [
                f"iptables -C INPUT -s '{target}' -j DROP 2>/dev/null || "
                f"nft list ruleset 2>/dev/null | grep '{target}'",
            ]

        return {
            "action_id": action_id,
            "action_type": "block_ip",
            "target": target,
            "platform": platform,
            "language": language,
            "filename": filename,
            "script": script,
            "requires_admin": admin_required,
            "expected_effect": expected,
            "rollback": rollback,
            "verification": verification,
        }

    def _translate_isolate_host(
        self, target: str, platform: str, language: str,
        technique_id: str, confidence: float,
    ) -> Dict[str, Any]:
        """Generate host isolation via null routes / firewall block-all."""
        action_id = f"isolate_host_{hash(target) & 0xffffffff:08x}"

        if platform == "windows":
            script = (
                f"# Isolate host {target}\n"
                f"# Block all traffic on the host\n"
                f"netsh advfirewall set allprofiles firewallpolicy blockinbound,blockoutbound\n"
                f"# Log the isolation\n"
                f"Write-Host 'Host {target} isolated - all traffic blocked'"
            )
            filename = f"isolate_host_{target}.ps1"
            admin_required = True
            expected = f"Block all network traffic on host {target}"
            rollback = (
                f"netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound"
            )
            verification = [
                f"netsh advfirewall show allprofiles | findstr 'Firewall Policy'",
            ]
        else:
            script = (
                f"#!/bin/bash\n"
                f"# Isolate host {target} while preserving remote management channel\n"
                f"# NOTE: Keep port 9001 reachable so the remote agent does not self-lock.\n"
                f"MGMT_IP=\"${{REMOTE_MANAGER_IP:?REMOTE_MANAGER_IP is required}}\"\n"
                f"REMOTE_PORT=\"${{REMOTE_AGENT_PORT:-9001}}\"\n"
                f"if command -v iptables &> /dev/null; then\n"
                f"    # Save current rules for rollback\n"
                f"    iptables-save > /tmp/iptables_backup_{hash(target) & 0xffffffff:08x}.txt 2>/dev/null || true\n"
                f"    iptables -P INPUT DROP\n"
                f"    iptables -P OUTPUT DROP\n"
                f"    iptables -P FORWARD DROP\n"
                f"    # Allow loopback\n"
                f"    iptables -A INPUT -i lo -j ACCEPT\n"
                f"    iptables -A OUTPUT -o lo -j ACCEPT\n"
                f"    # Keep established connections alive\n"
                f"    iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT\n"
                f"    iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT\n"
                f"    # Keep control-plane reachable from manager\n"
                f"    iptables -A INPUT -p tcp --dport \"$REMOTE_PORT\" -s \"$MGMT_IP\" -j ACCEPT\n"
                f"    # Keep SSH management reachable from manager\n"
                f"    iptables -A INPUT -p tcp --dport 22 -s \"$MGMT_IP\" -j ACCEPT\n"
                f"    # Allow callback webhook traffic to manager\n"
                f"    iptables -A OUTPUT -p tcp -d \"$MGMT_IP\" --dport 8000 -j ACCEPT\n"
                f"elif command -v nft &> /dev/null; then\n"
                f"    nft add table inet isolate 2>/dev/null || true\n"
                f"    nft add chain inet isolate input '{{ type filter hook input priority 0; policy drop; }}' 2>/dev/null || true\n"
                f"    nft add chain inet isolate output '{{ type filter hook output priority 0; policy drop; }}' 2>/dev/null || true\n"
                f"    nft add rule inet isolate input iif lo accept\n"
                f"    nft add rule inet isolate output oif lo accept\n"
                f"    nft add rule inet isolate input ct state established,related accept\n"
                f"    nft add rule inet isolate output ct state established,related accept\n"
                f"    nft add rule inet isolate input ip saddr $MGMT_IP tcp dport $REMOTE_PORT accept\n"
                f"    # Keep SSH management reachable from manager\n"
                f"    nft add rule inet isolate input ip saddr $MGMT_IP tcp dport 22 accept\n"
                f"    nft add rule inet isolate output ip daddr $MGMT_IP tcp dport 8000 accept\n"
                f"else\n"
                f"    echo 'ERROR: No firewall tool found' >&2\n"
                f"    exit 1\n"
                f"fi\n"
                f"echo 'Host {target} isolated with management channel preserved'"
            )
            filename = f"isolate_host_{target}.sh"
            admin_required = True
            expected = (
                f"Isolate host {target} while preserving manager access on port 9001 "
                f"and SSH (port 22), plus webhook callback to manager:8000"
            )
            rollback = (
                f"# Rollback isolation\n"
                f"if [ -f /tmp/iptables_backup_{hash(target) & 0xffffffff:08x}.txt ]; then\n"
                f"    iptables-restore < /tmp/iptables_backup_{hash(target) & 0xffffffff:08x}.txt\n"
                f"    rm /tmp/iptables_backup_{hash(target) & 0xffffffff:08x}.txt\n"
                f"fi\n"
                f"# Fallback: set policies to ACCEPT\n"
                f"iptables -P INPUT ACCEPT 2>/dev/null || true\n"
                f"iptables -P OUTPUT ACCEPT 2>/dev/null || true\n"
                f"iptables -P FORWARD ACCEPT 2>/dev/null || true"
            )
            verification = [
                f"iptables -L -n 2>/dev/null | head -5",
                f"ping -c 1 -W 2 8.8.8.8 2>&1 | grep -q '100% packet loss' && "
                f"echo 'ISOLATED'",
            ]

        return {
            "action_id": action_id,
            "action_type": "isolate_host",
            "target": target,
            "platform": platform,
            "language": language,
            "filename": filename,
            "script": script,
            "requires_admin": admin_required,
            "expected_effect": expected,
            "rollback": rollback,
            "verification": verification,
        }

    def _translate_disable_account(
        self, target: str, platform: str, language: str,
        technique_id: str, confidence: float,
    ) -> Dict[str, Any]:
        """Generate account disable script."""
        action_id = f"disable_account_{hash(target) & 0xffffffff:08x}"

        if platform == "windows":
            script = (
                f"# Disable account {target}\n"
                f"Disable-ADAccount -Identity '{target}'\n"
                f"# Revoke all Kerberos tickets\n"
                f"Revoke-ADAuthenticationToken -Identity '{target}'\n"
                f"Write-Host 'Account {target} disabled'"
            )
            filename = f"disable_account_{target}.ps1"
            admin_required = True
            expected = f"Disable user account {target} and revoke active sessions"
            rollback = (
                f"Enable-ADAccount -Identity '{target}'\n"
                f"Write-Host 'Account {target} re-enabled'"
            )
            verification = [
                f"Get-ADUser -Identity '{target}' -Properties Enabled | "
                f"Select-Object -ExpandProperty Enabled",
            ]
        else:
            script = (
                f"#!/bin/bash\n"
                f"# Disable account {target}\n"
                f"if id '{target}' &>/dev/null; then\n"
                f"    # Lock the password (prevents login)\n"
                f"    passwd -l '{target}'\n"
                f"    # Force expire password\n"
                f"    chage -E 0 '{target}'\n"
                f"    # Kill active sessions\n"
                f"    pkill -u '{target}' 2>/dev/null || true\n"
                f"    echo 'Account {target} disabled'\n"
                f"else\n"
                f"    echo 'ERROR: Account {target} does not exist' >&2\n"
                f"    exit 1\n"
                f"fi"
            )
            filename = f"disable_account_{target}.sh"
            admin_required = True
            expected = f"Lock password and expire account {target}"
            rollback = (
                f"passwd -u '{target}'\n"
                f"chage -E -1 '{target}'\n"
                f"echo 'Account {target} re-enabled'"
            )
            verification = [
                f"passwd -S '{target}' | grep -q ' L ' && echo 'DISABLED'",
                f"chage -l '{target}' | grep 'Account expires'",
            ]

        return {
            "action_id": action_id,
            "action_type": "disable_account",
            "target": target,
            "platform": platform,
            "language": language,
            "filename": filename,
            "script": script,
            "requires_admin": admin_required,
            "expected_effect": expected,
            "rollback": rollback,
            "verification": verification,
        }

    def _translate_kill_process(
        self, target: str, platform: str, language: str,
        technique_id: str, confidence: float,
    ) -> Dict[str, Any]:
        """Generate process termination script."""
        action_id = f"kill_process_{hash(target) & 0xffffffff:08x}"

        if platform == "windows":
            # target could be a process name like "powershell.exe" or PID
            script = (
                f"# Kill process {target}\n"
                f"Stop-Process -Name '{target}' -Force -ErrorAction SilentlyContinue\n"
                f"# Also find and kill by PID if target is numeric\n"
                f"if ('{target}' -match '^\\d+$') {{\n"
                f"    Stop-Process -Id {target} -Force -ErrorAction SilentlyContinue\n"
                f"}}\n"
                f"Write-Host 'Process {target} terminated'"
            )
            filename = f"kill_process_{target}.ps1"
            admin_required = False
            expected = f"Terminate process {target}"
            rollback = f"# Process termination cannot be rolled back. Restart from known-good binary."
            verification = [
                f"Get-Process -Name '{target}' -ErrorAction SilentlyContinue; "
                f"if (-not $?) {{ echo 'TERMINATED' }}",
            ]
        else:
            script = (
                f"#!/bin/bash\n"
                f"# Kill process {target}\n"
                f"if [[ '{target}' =~ ^[0-9]+$ ]]; then\n"
                f"    # target is a PID\n"
                f"    kill -9 {target} 2>/dev/null || echo 'Process {target} not found'\n"
                f"else\n"
                f"    # target is a process name\n"
                f"    pkill -9 -x '{target}' 2>/dev/null || pkill -9 -f '{target}' 2>/dev/null || "
                f"echo 'Process {target} not found'\n"
                f"fi\n"
                f"echo 'Process {target} terminated'"
            )
            filename = f"kill_process_{target}.sh"
            admin_required = False
            expected = f"Terminate process {target}"
            rollback = f"# Process termination cannot be rolled back. Restart from known-good binary."
            verification = [
                f"pgrep -x '{target}' 2>/dev/null && echo 'STILL_RUNNING' || echo 'TERMINATED'",
            ]

        return {
            "action_id": action_id,
            "action_type": "kill_process",
            "target": target,
            "platform": platform,
            "language": language,
            "filename": filename,
            "script": script,
            "requires_admin": admin_required,
            "expected_effect": expected,
            "rollback": rollback,
            "verification": verification,
        }

    def _translate_quarantine_file(
        self, target: str, platform: str, language: str,
        technique_id: str, confidence: float,
    ) -> Dict[str, Any]:
        """Generate file quarantine script (move + restrict permissions)."""
        action_id = f"quarantine_file_{hash(target) & 0xffffffff:08x}"
        sanitized_target = target.replace("'", "'\\''")

        if platform == "windows":
            script = (
                f"# Quarantine file {target}\n"
                f"$quarantineDir = \"$env:SystemRoot\\Quarantine\\\"\n"
                f"if (-not (Test-Path $quarantineDir)) {{\n"
                f"    New-Item -ItemType Directory -Path $quarantineDir -Force\n"
                f"}}\n"
                f"$filename = [System.IO.Path]::GetFileName('{target}')\n"
                f"$dest = Join-Path $quarantineDir \"$filename.quarantined\"\n"
                f"Move-Item -Path '{target}' -Destination $dest -Force\n"
                f"# Remove inheritance and deny all access\n"
                f"icacls $dest /inheritance:r /deny 'Everyone:(R,W,D)'\n"
                f"Write-Host 'File {target} quarantined to $dest'"
            )
            filename = f"quarantine_file_{hash(target) & 0xffffffff:08x}.ps1"
            admin_required = True
            expected = f"Move {target} to quarantine directory and deny all access"
            rollback = (
                f"# Rollback: restore file\n"
                f"$quarantineDir = \"$env:SystemRoot\\Quarantine\\\"\n"
                f"$filename = [System.IO.Path]::GetFileName('{target}')\n"
                f"$src = Join-Path $quarantineDir \"$filename.quarantined\"\n"
                f"if (Test-Path $src) {{\n"
                f"    Move-Item -Path $src -Destination '{target}' -Force\n"
                f"    Write-Host 'File restored from quarantine'\n"
                f"}}"
            )
            verification = [
                f"Test-Path '{target}' | Select-Object -ExpandProperty Item",
            ]
        else:
            script = (
                f"#!/bin/bash\n"
                f"# Quarantine file {sanitized_target}\n"
                f"QUARANTINE_DIR=\"/var/quarantine/\"\n"
                f"mkdir -p \"$QUARANTINE_DIR\"\n"
                f"FILENAME=\"$(basename '{sanitized_target}')\"\n"
                f"DEST=\"${QUARANTINE_DIR}${FILENAME}.quarantined\"\n"
                f"mv '{sanitized_target}' \"$DEST\"\n"
                f"chmod 000 \"$DEST\"\n"
                f"chown root:root \"$DEST\" 2>/dev/null || true\n"
                f"echo 'File {sanitized_target} quarantined to $DEST'"
            )
            filename = f"quarantine_file_{hash(target) & 0xffffffff:08x}.sh"
            admin_required = True
            expected = f"Move {target} to /var/quarantine/ and remove all permissions"
            rollback = (
                f"QUARANTINE_DIR=\"/var/quarantine/\"\n"
                f"FILENAME=\"$(basename '{sanitized_target}')\"\n"
                f"SRC=\"${QUARANTINE_DIR}${FILENAME}.quarantined\"\n"
                f"if [ -f \"$SRC\" ]; then\n"
                f"    mv \"$SRC\" '{sanitized_target}'\n"
                f"    echo 'File restored from quarantine'\n"
                f"fi"
            )
            verification = [
                f"ls -la '{sanitized_target}' 2>&1 | grep -q 'No such file' && echo 'QUARANTINED'",
            ]

        return {
            "action_id": action_id,
            "action_type": "quarantine_file",
            "target": target,
            "platform": platform,
            "language": language,
            "filename": filename,
            "script": script,
            "requires_admin": admin_required,
            "expected_effect": expected,
            "rollback": rollback,
            "verification": verification,
        }

    def _translate_notify_analyst(
        self, target: str, platform: str, language: str,
        technique_id: str, confidence: float,
    ) -> Dict[str, Any]:
        """Generate analyst notification (alert/log entry)."""
        action_id = f"notify_analyst_{hash(target) & 0xffffffff:08x}"

        script = (
            f"# Notify analyst about: {target}\n"
            f"# Creates an alert entry in the platform audit log.\n"
            f"# This is informational only; no disruptive action is taken.\n"
            f"#\n"
            f"# Related technique: {technique_id or 'N/A'}\n"
            f"# Confidence: {confidence}\n"
            f"#\n"
            f"# Please review the following:\n"
            f"#   - {target}\n"
            f"#\n"
            f"# Manual investigation is required.\n"
        )

        filename = f"notify_analyst_{hash(target) & 0xffffffff:08x}.log"
        admin_required = False
        expected = f"Create analyst notification for {target}"
        rollback = "# No rollback needed for notification actions."
        verification = [
            "# Notification logged; verify via platform audit trail.",
        ]

        return {
            "action_id": action_id,
            "action_type": "notify_analyst",
            "target": target,
            "platform": "cross_platform",
            "language": "text",
            "filename": filename,
            "script": script,
            "requires_admin": admin_required,
            "expected_effect": expected,
            "rollback": rollback,
            "verification": verification,
        }

    # ------------------------------------------------------------------
    # Error package generator
    # ------------------------------------------------------------------

    def _error_package(
        self,
        action_type: str,
        target: str,
        reason: str,
    ) -> Dict[str, Any]:
        """Return an error package when translation is not possible."""
        return {
            "action_id": f"error_{hash(target) & 0xffffffff:08x}",
            "action_type": action_type,
            "target": target,
            "platform": "unknown",
            "language": "unknown",
            "filename": "",
            "script": "",
            "requires_admin": False,
            "expected_effect": "",
            "rollback": "",
            "verification": [],
            "error": reason,
        }
