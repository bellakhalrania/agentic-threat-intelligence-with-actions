# Threat Intelligence Report

**Campaign:** Unclassified Activity
**Campaign ID:** a3f5c9e2-7b4d-4f1a-9c2e-6d8f3b1a2c7d
**Generated:** 2026-08-10T19:01:44.592121+00:00

---

**Threat Intelligence Report**  
*Campaign ID:* `a3f5c9e2-7b4d-4f1a-9c2e-6d8f3b1a2c7d`  
*Report Date:* 2026‑08‑10  

---  

## Executive Summary
A rapid series of SSH login attempts targeting the non‑existent user **“debian”** was observed on host **victim‑machine**. All attempts originated from source IP **59.185.230.105** and were logged as “Invalid user” and “Failed password” events, indicating a credential‑guessing (brute‑force) campaign against the SSH service. The activity maps to ATT&CK techniques **T1110.001 (Password Guessing)**, **T1021.004 (SSH)** and the generic **T1110 (Brute Force)**. No successful authentication was recorded.

---  

## Timeline  

| Timestamp (UTC) | Event ID | Description |
|-----------------|----------|-------------|
| 2023‑08‑10T18:02:12Z | ee23062c-54e4-407a-b676-fd459dea778f | Failed password for invalid user “debian” from 59.185.230.105 (port 53203). |
| 2023‑08‑10T18:02:14Z | c3086206-81cd-45f5-b1be-7f9c56843b43 | Invalid user “debian” from 59.185.230.105 (port 2944). |
| 2023‑08‑10T18:02:16Z | bd7f75b3-2297-43ce-afcf-0d19b7ac4474 | Failed password for invalid user “debian” from 59.185.230.105 (port 2944). |
| 2023‑08‑10T18:02:21Z | 1d48051d-f2df-43f1-99fa-7435909d12fd | Failed password for invalid user “debian” from 59.185.230.105 (port 57586). |
| 2023‑08‑10T18:02:25Z | 831121cf-702a-450a-9a4a-98135b4ef750 | Failed password for invalid user “debian” from 59.185.230.105 (port 13426). |
| 2023‑08‑10T18:02:31Z | 7d4cf211-ed30-4243-8387-39b0d4c4b92b | Failed password for invalid user “debian” from 59.185.230.105 (port 15979). |
| 2023‑08‑10T18:02:37Z | 8799a848-46cc-421d-ba26-ac136ec21c79 | Failed password for invalid user “debian” from 59.185.230.105 (port 18824). |
| 2023‑08‑10T18:02:45Z | f355965c-9e1d-4a06-9075-ca02b4250675 | Failed password for invalid user “debian” from 59.185.230.105 (port 17372). |
| 2023‑08‑10T18:02:49Z | f08ccd17-475c-4e74-bbad-efd01ad392bc | Failed password for invalid user “debian” from 59.185.230.105 (port 52683). |
| 2023‑08‑10T18:02:53Z | b76df4a1-70da-4928-adb4-96ae0b2c040a | Wazuh rule 5712 triggered on failed password (port 6143). |
| 2023‑08‑10T18:03:01Z | d7425d9b-bb75-4a82-b665-69b3feeafced | Failed password for invalid user “debian” from 59.185.230.105 (port 56838). |
| 2023‑08‑10T18:03:06Z | 3e5cea6c-5a46-4a47-a009-d10ad51b3f20 | Failed password for invalid user “debian” from 59.185.230.105 (port 42114). |
| 2026‑08‑10T18:02:13.053Z | ee23062c-54e4-407a-b676-fd459dea778f | Same as above (event re‑ingested with 2026 timestamp). |
| 2026‑08‑10T18:02:15.279Z | c3086206-81cd-45f5-b1be-7f9c56843b43 | Same as above (re‑ingested). |
| 2026‑08‑10T18:02:17.418Z | d51b1a29-a652-4aa6-81f2-996622f68005 | PAM authentication failure – multiple failed logins in short period (T1110). |
| 2026‑08‑10T18:02:18.892Z | bd7f75b3-2297-43ce-afcf-0d19b7ac4474 | Same as above (re‑ingested). |
| 2026‑08‑10T18:02:20.912Z | 55169762-2603-4d68-9b21-cc74a332d042 | Same as above (re‑ingested). |
| 2026‑08‑10T18:02:21.018Z | 7cde01d2-157f-4016-8ad1-d8a1d82650a2 | PAM: User login failed (T1110.001). |
| 2026‑08‑10T18:02:22.857Z | 1d48051d-f2df-43f1-99fa-7435909d12fd | Same as above (re‑ingested). |
| 2026‑08‑10T18:02:24‑… | … | (Further re‑ingested events continue in the same pattern). |

---  

## Indicators of Compromise (IOCs)

| Type | Value | Context |
|------|-------|---------|
| **Source IP** | `59.185.230.105` | Origin of all SSH login attempts. |
| **Target Host** | `victim-machine` | Host where attempts were observed. |
| **Username** | `debian` | Non‑existent account repeatedly targeted. |
| **Service** | `ssh` | Protocol under attack. |

*No file hashes, domains, or additional network indicators were provided.*

---  

## ATT&CK Techniques (Confirmed)

| ATT&CK ID | Technique Name | Evidence Event IDs |
|-----------|----------------|--------------------|
| **T1110.001** | Password Guessing | ee23062c‑..., c3086206‑..., bd7f75b3‑..., 55169762‑..., 1d48051d‑..., 88712f3a‑..., 5252a039‑..., 831121cf‑..., 68cc2bc7‑..., 05035e5d‑..., bd7f75b3‑..., etc. |
| **T1021.004** | SSH | ee23062c‑..., c3086206‑..., bd7f75b3‑..., 55169762‑..., 1d48051d‑..., 831121cf‑..., 68cc2bc7‑..., etc. |
| **T1110** | Brute Force (generic) | d51b1a29‑a652‑4aa6‑81f2‑996622f68005 |

---  

## Campaign Assessment
The activity constitutes a **credential‑guessing brute‑force campaign** against the SSH service on *victim‑machine*. The attacker repeatedly attempts authentication for a non‑existent user, varying source ports, which is characteristic of automated tools. No successful login was recorded, and the volume of failures triggered Wazuh rule 5712 (authentication‑failure detection). The campaign’s objective is to gain unauthorized SSH access.

---  

## Predicted Next Steps
*No data available.*  

---  

## Recommendations  

| Recommendation | Relevant ATT&CK Technique |
|----------------|---------------------------|
| Enforce account lockout after a configurable number of failed SSH attempts. | T1110.001 |
| Deploy SSH key‑based authentication and disable password authentication where possible. | T1021.004 |
| Implement network‑level rate‑limiting or geo‑blocking for repeated connections from the same source IP. | T1110 |
| Continuously monitor SSH logs for anomalous login patterns and integrate with a SIEM for real‑time alerts. | T1110.001 |
| Conduct a post‑incident review of the “debian” account and remove any unused accounts. | T1110.001 |
| Ensure the Wazuh rule set is up‑to‑date and that high‑severity alerts (e.g., rule level 10) trigger immediate response. | T1110 |

---  

## Response Actions  

| Action Type | Target | Status | Severity | Rationale |
|-------------|--------|--------|----------|-----------|
| *No response actions recorded in the provided evidence.* | – | – | – | – |

---  

*All statements in this report are derived exclusively from the supplied evidence.*