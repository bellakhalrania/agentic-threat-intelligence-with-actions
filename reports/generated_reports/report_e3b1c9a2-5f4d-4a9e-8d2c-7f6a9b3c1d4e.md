# Threat Intelligence Report

**Campaign:** Unclassified Activity
**Campaign ID:** e3b1c9a2-5f4d-4a9e-8d2c-7f6a9b3c1d4e
**Generated:** 2026-08-07T18:40:46.309838+00:00

---

**Threat Intelligence Report**  
*Investigation Date: 2026‑08‑07*  

---  

## Executive Summary
- An adversary obtained a valid SSH session on **victim‑machine** using the *ubuntu* account (T1078 – Valid Accounts).  
- Concurrent password‑guessing attempts from source IP **172.31.24.217** were recorded (T1110.001 – Password Guessing).  
- The attacker modified **/etc/ssh/sshd_config** and **/etc/ssh/sshd_config.d/60‑cloudimg‑settings.conf**, changing file attributes and hashes (T1565.001 – Stored Data Manipulation) – a persistence mechanism for SSH.  
- Network‑level response actions have been initiated (IP block and host isolation pending approval).  

No explicit “ssh_brute_force_detected” flag is present; therefore the special SSH‑brute‑force wording is omitted.

---

## Timeline  

| Time (UTC) | Event ID | Description |
|------------|----------|-------------|
| 2026‑08‑07 18:39:30 | 0d9c6999‑3575‑49f5‑b47c‑03b69214bae9 | Successful SSH login for user **ubuntu** (authentication_success). |
| 2026‑08‑07 18:39:30 | 097dab6a‑f188‑4b85‑a55d‑7b79ed0adb82 | Failed SSH authentication from **172.31.24.217** targeting **ubuntu** (authentication_failed). |
| 2026‑08‑07 18:39:31 | 896463ab‑538a‑4bd4‑bbdb‑9d653ae54400 | SSH session for **ubuntu** closed (wazuh_rule_5502). |
| 2026‑08‑07 18:39:32 | 77279d51‑4889‑4b05‑bd09‑d89340378603 | Additional failed password attempt from **172.31.24.217** (authentication_failed). |
| 2026‑08‑07 18:39:09.719 | 46963ce1‑29e0‑4b66‑a8f1‑a49177e8cc83 | **/etc/ssh/sshd_config** modified – size, inode, timestamps, MD5/SHA1/SHA256 hashes changed (Stored Data Manipulation). |
| 2026‑08‑07 18:39:09.793 | f8c8ffb3‑dfb2‑4e25‑ba36‑35b34c4c0794 | **/etc/ssh/sshd_config.d/60‑cloudimg‑settings.conf** modified – attributes and hashes changed (Stored Data Manipulation). |

*Note: Two file‑modification events have “Unknown” timestamps in the source data; they are placed here based on event IDs.*

---

## IOCs  

| IOC Type | Value | Reputation | Tags |
|----------|-------|------------|------|
| IP | 100.90.153.71 | benign (AbuseIPDB) | non_public, reserved |
| Hash | f07bf9066bf9d16bebca89f2afb77edf68ef4ce2985322c5604d1cfeb4f27bac | unknown | – |
| Hash | 0a58ca49cb87967980cf4866f00ab1f992831e0feb7046973cdb04c197e2d686 | unknown | – |
| Hash | 78497c7f9b8a75bbfa9724e493e771dfc0082fb2 | unknown | – |
| Hash | 27e5f5bf48173aa469dc53e8b410b6ea7b247ca3 | unknown | – |
| Hash | 82ef0937e683fc5634079ce5883a4187 | unknown | – |
| Hash | 6be45270f45023f885a10f0ed2f6055e | unknown | – |
| Domain | wazuh.manager | unknown | – |
| Hash | 474ef6932d6b998ec97b122a9d86af024b988d64c243f3caf01dd9e5ed41618e | unknown | – |
| Hash | 6bf43c7543d384fe7c3442bd97b1c91b9da62b51521184b6c1e421a7ef8bac1d | unknown | – |
| Hash | cb90e49d699f7ab9c11cafc27de7741209c4bfa2 | unknown | – |
| Hash | beabb9fb2eb1eb4c5f05fd327c3ddf845c8d1d9d | unknown | – |
| Hash | 72d6b267a7e8aec4c6f11b8a72f597a8 | unknown | – |
| Hash | 1e4da5180db2e8f67728a6223787c4f1 | unknown | – |

---

## ATT&CK Techniques (Confirmed)

| Technique ID | Technique Name | Evidence Event(s) |
|--------------|----------------|-------------------|
| T1565.001 | Stored Data Manipulation | 46963ce1‑..., f8c8ffb3‑... |
| T1078 | Valid Accounts | 0d9c6999‑... |
| T1110.001 | Password Guessing | 097dab6a‑..., 77279d51‑... |
| T1021.004 | SSH | 77279d51‑... (also part of password‑guessing event) |

*All listed techniques are derived directly from the `attack_techniques` block.*

---

## Campaign Assessment
- **Objective:** Obtain unauthorized SSH access and modify SSH configuration files to retain persistence.  
- **Key Behaviors:**  
  1. **Valid Account Use (T1078):** Successful login with the *ubuntu* account.  
  2. **Password Guessing (T1110.001):** Repeated failed attempts from a single external IP (172.31.24.217).  
  3. **Stored Data Manipulation (T1565.001):** Direct alteration of `sshd_config` and a supplemental config file, changing hashes (SHA256 0a58ca49… and 6bf43c75…).  
  4. **SSH Remote Service (T1021.004):** The activity is confined to the SSH service.  

The combination of a valid session, brute‑force attempts, and configuration tampering indicates a focused effort to establish and maintain SSH‑based persistence.

---

## Predicted Next Steps (Forecast)

| Technique ID | Technique Name | Rationale |
|--------------|----------------|-----------|
| T1003 | OS Credential Dumping | After gaining a valid SSH account, attackers often harvest additional credentials to expand access. |
| T1098 | Account Manipulation | The adversary may create or modify privileged accounts to ensure long‑term control. |
| T1083 | File and Directory Discovery | With persistence in place, the attacker is likely to enumerate the filesystem for sensitive data or additional credential stores. |

*These are probabilistic forecasts and have **not** been observed in the current data.*

---

## Recommendations  

| Mitigation | Related Technique(s) |
|------------|----------------------|
| Enforce SSH key‑based authentication and disable password authentication where possible. | T1110.001, T1021.004 |
| Implement multi‑factor authentication for privileged SSH accounts. | T1078 |
| Deploy file integrity monitoring (FIM) with alerting on changes to `/etc/ssh/sshd_config*`. | T1565.001 |
| Regularly review SSH login logs for anomalous source IPs and failed attempts. | T1110.001, T1021.004 |
| Restrict SSH access to known management IP ranges via firewall or security groups. | T1021.004 |
| Conduct a post‑incident account audit to verify that no unauthorized privileged accounts were created. | T1078 |
| Apply least‑privilege principles to the *ubuntu* account and any other service accounts. | T1078 |
| Ensure that any configuration changes are reviewed and approved through a change‑management process. | T1565.001 |

---

## Response Actions  

| Action Type | Target | Status | Severity | Rationale |
|-------------|--------|--------|----------|-----------|
| block_ip | 172.31.24.217 | pending_approval | high | Source IP performed SSH login attempts and password guessing (T1110.001); blocking prevents further brute‑force activity. |
| isolate_host | Unknown | pending_approval | high | Intended to contain the compromised host while investigation continues. (Details incomplete in source data.) |

*All actions are recorded as pending human approval; no action is marked as completed.*  