# Threat Intelligence Report

**Campaign:** Unclassified Activity
**Campaign ID:** e3b2f9a1-4c6d-4f8a-9d2e-7a5c1b6d9f3e
**Generated:** 2026-09-03T16:01:00.885253+00:00

---

**Threat Intelligence Report**  
*Victim Endpoint: `victim‑endpoint`*  
*Report Date: 2026‑09‑03*  

---  

## Executive Summary
Multiple SSH authentication attempts were observed from a single external source (IP 100.81.172.118). The activity consists of eight failed logins followed by two successful logins for the user **anna**, indicating a successful credential‑guessing operation. Deterministic rule mapping links each failed attempt to ATT&CK technique **T1110 – Brute Force** with a confidence of 0.9. The source IP is listed in the IOC feed as **benign (0 % confidence)**, but the observed behavior suggests a coordinated brute‑force credential‑guessing campaign targeting the victim endpoint.

## Timeline
| Time (UTC) | Event ID | Description |
|------------|----------|-------------|
| 2026‑09‑03 15:59:50.539649 | c1b08f08-2a99-4eb6-88d4-5ee02e7d905a | SSH authentication **failed** for user *anna* from 100.81.172.118 |
| 2026‑09‑03 15:59:50.540171 | 5d4d3f87-38dc-47d9-bc73-e0be7f8a67c4 | SSH authentication **failed** for user *anna* from 100.81.172.118 |
| 2026‑09‑03 15:59:50.540397 | 718ee510-f3ca-4ad7-b1b6-9343939305f2 | SSH authentication **succeeded** for user *anna* from 100.81.172.118 |
| 2026‑09‑03 15:59:53.254031 | 0761f82c-e506-48c5-9d88-a3df44a08ca9 | SSH authentication **failed** for user *anna* from 100.81.172.118 |
| 2026‑09‑03 15:59:53.254345 | dab8babb-13bf-4c66-b4a8-d54b92eda3f1 | SSH authentication **failed** for user *anna* from 100.81.172.118 |
| 2026‑09‑03 15:59:55.110834 | 5f3dea3e-e338-4380-a459-8fa5d81cbdc8 | SSH authentication **failed** for user *anna* from 100.81.172.118 |
| 2026‑09‑03 15:59:55.111115 | 41dd6788-23dd-41e5-a098-a4704af9541c | SSH authentication **failed** for user *anna* from 100.81.172.118 |
| 2026‑09‑03 15:59:55.111311 | 9b425c1b-4c36-4293-8112-affacd299687 | SSH authentication **succeeded** for user *anna* from 100.81.172.118 |
| 2026‑09‑03 15:59:57.110790 | 1af4bf35-baf0-433d-8188-4c89fd07cddf | SSH authentication **failed** for user *anna* from 100.81.172.118 |
| 2026‑09‑03 15:59:57.??? (timestamp truncated) | efe00f41-fc6a-4910-81eb-398b0812a913 | SSH authentication **failed** for user *anna* from 100.81.172.118 |

*Total failed attempts: **8**  
Total successful attempts: **2***  

## Indicators of Compromise (IOCs)
| Type | Value | Reputation / Tag |
|------|-------|-------------------|
| IPv4 | 100.81.172.118 | Benign (IOC feed confidence 0 %) |

*No additional file hashes, domains, or URLs were provided.*

## ATT&CK Techniques
| ATT&CK ID | Technique Name | Confidence |
|-----------|----------------|------------|
| **T1110** | Brute Force | 0.90 (deterministic rule) |

*All eight failed‑login events map to T1110 via the `ssh_authentication_failed` rule.*

## Campaign Assessment
The activity matches the description of a **credential‑guessing brute‑force campaign** (objective: “Obtain valid credentials for the victim‑endpoint”). All events originate from the same external IP, and the deterministic rule consistently maps the failures to T1110. The presence of two successful logins confirms that a valid password was eventually discovered for the account *anna*.

## Predicted Next Steps
*No probabilistic forecasts were supplied in the evidence.*  

## Recommendations
| Recommendation | Relevant ATT&CK Technique |
|----------------|---------------------------|
| Enforce account lockout after a configurable number of failed SSH attempts. | T1110 |
| Deploy SSH key‑based authentication and disable password authentication where possible. | T1110 |
| Enable multi‑factor authentication (MFA) for privileged and remote accounts. | T1110 |
| Increase monitoring of SSH logs for repeated failed attempts and alert on anomalous source IPs. | T1110 |
| Conduct a credential audit for the compromised account (*anna*) and rotate its password immediately. | T1110 |
| Review firewall rules and consider temporary blocking of the source IP (100.81.172.118) pending further investigation. | T1110 |
| Harden SSH service (e.g., change default port, use fail2ban or equivalent). | T1110 |

## Response Actions

| Action Type | Target | Status | Severity | Rationale |
|---|---|---|---|---|
| ActionType.BLOCK_IP | 100.81.172.118 | executed | ActionSeverity.HIGH | The IP performed a high‑confidence brute‑force attack (T1110, confidence 0.9) and achieved a successful authentication, indicating it is the active threat source. |
| ActionType.ISOLATE_HOST | victim-endpoint | pending_approval | ActionSeverity.HIGH | The endpoint was the victim of successful credential theft and subsequent login; isolating it prevents further lateral movement and data exfiltration. |
| ActionType.DISABLE_ACCOUNT | anna | executed | ActionSeverity.HIGH | User 'anna' successfully authenticated after multiple failed attempts, suggesting her credentials have been compromised; disabling the account stops abuse (Valid Accounts – T1078). |
| ActionType.NOTIFY_ANALYST | SOC_analyst | executed | ActionSeverity.HIGH | High‑severity brute‑force campaign (e3b2f9a1‑4c6d‑4f8a‑9d2e‑7a5c1b6d9f3e) with successful credential compromise detected. Recommended actions: block source IP, isolate host, and disable compromised user account. |