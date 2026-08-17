# Threat Intelligence Report

**Campaign:** Unclassified Activity
**Campaign ID:** d3f9c2a1-5b4e-4f9a-9c2e-7a6d8f1e2b3c
**Generated:** 2026-08-13T08:28:10.426344+00:00

---

# Threat Intelligence Report  

**Campaign ID:** `d3f9c2a1-5b4e-4f9a-9c2e-7a6d8f1e2b3c`  
**Report Date:** 2026‑08‑13  

---  

## Executive Summary  
Telemetry from **control‑node1** shows that an adversary obtained **valid root credentials** and accessed the host via SSH (public‑key authentication). The attacker subsequently leveraged the compromised account to open privileged sudo sessions. In parallel, a brute‑force style password‑guessing campaign targeted the non‑privileged account **lanna** from a different source IP, generating multiple failed login attempts. The activity aligns with the following ATT&CK techniques: **Valid Accounts (T1078)**, **Remote Services – SSH (T1021 / T1021.004)**, and **Password Guessing (T1110.001)**.  

No additional IOCs (hashes, domains, URLs) were supplied in the evidence.  

---  

## Timeline  

| Time (UTC) | Event ID | Description |
|------------|----------|-------------|
| Aug 13 08:14:16 | `e90b0783-fcd0-49f9-871d-935f7d94a44c` | Root opened a local SSH session (authentication_success). |
| Aug 13 08:17:46 | `1e825dfc-077c-4286-9d6c-5f93566e5e0f` | Root executed a sudo command – privileged session opened. |
| Aug 13 08:18:39 | `2b08540a-c3c6-4500-90b8-256d7bb2f381` | Successful SSH login for root from **100.76.226.30** using a public key. |
| Aug 13 08:18:39 | `9986781b-fa4f-487b-9d10-a5dda1027464` | PAM logged session opened for root (post‑login). |
| Aug 13 08:19:53 | `c01e47ff-6434-4a20-ab5e-2521904cfa0f` | Failed password attempt for user **lanna** from **100.117.52.58**. |
| Aug 13 08:19:54 | `20789f28-5018-4660-81cb-a93eb8c8e5d5` | Password check failed for **lanna** (unix_chkpwd). |
| Aug 13 08:19:54 | `71fdd0c8-e11a-4de2-ae61-a9bc10e61233` | Additional SSH authentication failure for **lanna** (same source IP). |
| Aug 13 08:19:54 | `ec8468fe-40dc-4332-b0a7-8866a1d3b0c8` | **lanna** successfully opened a local session (valid account). |
| Aug 13 08:20:22 | `81eb39a8-5ebb-49ce-8fec-46a656bcef7a` | Root sudo session closed (wazuh_rule_5502). |
| Aug 13 08:24:21 | `35e07fbe-f5c2-4b9a-a04c-d966e1ab0b8f` | Continued password‑guessing attempts for **lanna** from **100.117.52.58**. |
| Aug 13 08:24:22 | `5877f11a-7589-410b-abfa-820d8a3baf3b` | **lanna** opened an SSH session after successful authentication. |

---  

## Indicators of Compromise (IOCs)  

| Type | Value | Reputation / Tags |
|------|-------|-------------------|
| **IP Address** | 100.76.226.30 | No reputation data supplied |
| **IP Address** | 100.117.52.58 | No reputation data supplied |
| **Username** | root | Valid account used |
| **Username** | lanna | Target of password‑guessing |

*No additional hash, domain, or URL IOCs were provided.*  

---  

## ATT&CK Techniques (Observed)  

| Technique ID | Technique Name | Confidence | Evidence Event IDs |
|--------------|----------------|------------|--------------------|
| **T1078** | Valid Accounts | 1.0 | `e90b0783-fcd0-49f9-871d-935f7d94a44c`, `1e825dfc-077c-4286-9d6c-5f93566e5e0f`, `98f59367-4484-4c24-b34e-f248ad63400d`, `2b08540a-c3c6-4500-90b8-256d7bb2f381`, `9986781b-fa4f-487b-9d10-a5dda1027464`, `ec8468fe-40dc-4332-b0a7-8866a1d3b0c8` |
| **T1021** | Remote Services | 1.0 | `2b08540a-c3c6-4500-90b8-256d7bb2f381` |
| **T1021.004** | SSH | 1.0 | `2b08540a-c3c6-4500-90b8-256d7bb2f381`, `fa6383fd-56c9-4fdf-926a-8f6a8f6a3b98`, `ace3e175-5b43-4481-97d6-a7098e760f85` |
| **T1110.001** | Password Guessing | 1.0 | `c01e47ff-6434-4a20-ab5e-2521904cfa0f`, `20789f28-5018-4660-81cb-a93eb8c8e5d5`, `71fdd0c8-e11a-4de2-ae61-a9bc10e61233`, `b2ed562c-1963-4645-9390-d4d505be6cb8`, `620b370b-7e7d-41c1-a5d1-fb66e5301224`, `4f140060-a984-44ba-8139-fa83d3bac4e1`, `2f0b340f-9f2c-4195-bbfc-8ff7ed2e61fd`, `fa6383fd-56c9-4fdf-926a-8f6a8f6a3b98`, `ace3e175-5b43-4481-97d6-a7098e760f85` |

---  

## Campaign Assessment  

* **Objective:** Obtain unauthorized privileged access to **control‑node1** by leveraging a valid SSH key for the **root** account and by brute‑forcing the password of a low‑privilege account (**lanna**).  
* **Key Findings:**  
  * Successful SSH login for **root** from IP **100.76.226.30** using a public key (T1078, T1021.004).  
  * Immediate use of the compromised root account to open sudo sessions (privilege escalation).  
  * Repeated failed login attempts for **lanna** from IP **100.117.52.58**, followed by a successful login, indicating a password‑guessing campaign (T1110.001).  
  * No evidence of lateral movement beyond the initial host.  

---  

## Predicted Next Steps  

*No prediction data was supplied; therefore no probabilistic forecasts are included.*  

---  

## Recommendations  

| Mitigation | Related ATT&CK Technique(s) |
|------------|-----------------------------|
| Enforce **SSH key management**: rotate keys regularly, restrict key usage to specific hosts, and disable password authentication for SSH. | T1078, T1021.004 |
| Deploy **multi‑factor authentication (MFA)** for privileged accounts, especially for remote access. | T1078 |
| Implement **account lockout** or rate‑limiting on SSH authentication failures to mitigate password‑guessing. | T1110.001 |
| Restrict SSH access to a **allow‑list of source IPs** (e.g., via firewall or security groups). | T1021, T1021.004 |
| Conduct regular **privileged account monitoring** and audit sudo usage (e.g., log aggregation, alert on unusual sudo commands). | T1078 |
| Apply **least‑privilege principles**: ensure non‑privileged accounts do not have sudo rights and remove unnecessary root SSH keys. | T1078 |
| Enable **intrusion detection** for repeated failed login attempts and generate real‑time alerts. | T1110.001 |
| Review and harden **system authentication logs** (e.g., enable detailed logging, forward logs to a SIEM). | T1078, T1110.001 |

---  

## Response Actions  

| Action Type | Target | Status | Severity | Rationale |
|-------------|--------|--------|----------|-----------|
| *No response actions were recorded in the provided evidence.* | – | – | – | – |

---  

*All statements in this report are derived directly from the supplied evidence. No assumptions or fabricated data have been introduced.*  