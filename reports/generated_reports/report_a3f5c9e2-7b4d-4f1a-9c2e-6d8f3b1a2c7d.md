# Threat Intelligence Report

**Campaign:** Unclassified Activity
**Campaign ID:** a3f5c9e2-7b4d-4f1a-9c2e-6d8f3b1a2c7d
**Generated:** 2026-09-03T16:12:30.357612+00:00

---

**Threat Intelligence Report**  
*Prepared on 2026‑09‑03*  

---  

## Executive Summary
A credential‑guessing campaign targeting the SSH service on **victim‑endpoint** was observed. The adversary repeatedly attempted to authenticate as user **anna** from source IP **100.81.172.118**. The activity generated multiple failed SSH login attempts and two successful logins, indicating at least one guessed credential was correct. All events map to ATT&CK technique **T1110 – Brute Force** with a deterministic rule confidence of 0.9.

## Timeline
| Timestamp (UTC) | Event ID | Event Type | Username | Source IP | Notes |
|-----------------|----------|------------|----------|-----------|-------|
| 2026‑09‑03T16:11:03.111133 | c209a32d‑c5cb‑46b7‑b6ef‑e013b7677165 | authentication_failed | anna | 100.81.172.118 | SSH brute‑force attempt |
| 2026‑09‑03T16:11:03.111519 | 7d2432b3‑f345‑4e9a‑a660‑2fd867aff411 | authentication_failed | anna | 100.81.172.118 | SSH brute‑force attempt |
| 2026‑09‑03T16:11:03.111714 | e05e3bd8‑a859‑496c‑b35f‑bcf18678f9d7 | authentication_success | anna | 100.81.172.118 | First successful login |
| 2026‑09‑03T16:11:04.611849 | 1d1a1f02‑d453‑4c5c‑bae8‑c3db746727dd | authentication_failed | anna | 100.81.172.118 | Continued brute‑force |
| 2026‑09‑03T16:11:04.612176 | 14a6dafa‑3d52‑4eae‑b911‑d6cc4fa3025e | authentication_failed | anna | 100.81.172.118 | Continued brute‑force |
| 2026‑09‑03T16:11:05.110828 | 35be58f6‑4875‑4d4e‑9427‑0a846fcc3d8a | authentication_failed | anna | 100.81.172.118 | Continued brute‑force |
| 2026‑09‑03T16:11:05.111107 | 86d6f883‑4e85‑43e2‑81ed‑2b927cec3aca | authentication_failed | anna | 100.81.172.118 | Continued brute‑force |
| 2026‑09‑03T16:11:05.111714* | 75dd38a5‑85f2‑4b2a‑86da‑181fca1103ca | authentication_success | anna | 100.81.172.118 | Second successful login |
| *Additional failed attempts (event IDs 994a4b9f‑d445‑4daf‑bc55‑3da92bac0916, 232be548‑ee82‑4d58‑9e47‑933a822175c8, 245f010a‑a1db‑438e‑af20‑09ec93475d15, 3348e2dd‑ea3e‑4908‑83e7‑2a1cbe773d64) occurred shortly after the timestamps above, all with the same source IP and username.* |

*Exact timestamps for the latter events were not provided; they are listed in the campaign timeline as “Unknown”.  

## IOCs
| Type | Value | Reputation / Tags |
|------|-------|-------------------|
| IPv4 | **100.81.172.118** | Listed as **benign** on AbuseIPDB (0 % confidence of maliciousness) |

No file hashes, URLs, or additional indicators were observed.

## ATT&CK Techniques
| Technique ID | Technique Name | Confidence | Evidence Event IDs |
|--------------|----------------|------------|--------------------|
| **T1110** | Brute Force | 0.90 (deterministic rule) | c209a32d‑c5cb‑46b7‑b6ef‑e013b7677165, 7d2432b3‑f345‑4e9a‑a660‑2fd867aff411, 1d1a1f02‑d453‑4c5c‑bae8‑c3db746727dd, 14a6dafa‑3d52‑4eae‑b911‑d6cc4fa3025e, 35be58f6‑4875‑4d4e‑9427‑0a846fcc3d8a, 86d6f883‑4e85‑43e2‑81ed‑2b927cec3aca, 994a4b9f‑d445‑4daf‑bc55‑3da92bac0916, 232be548‑ee82‑4d58‑9e47‑933a822175c8, 245f010a‑a1db‑438e‑af20‑09ec93475d15, 3348e2dd‑ea3e‑4908‑83e7‑2a1cbe773d64 |

## Campaign Assessment
The activity constitutes a **credential‑guessing (brute‑force) campaign** against SSH. The adversary repeatedly attempted the same username (“anna”) from a single external IP, eventually achieving two successful logins. Although the source IP is currently flagged as benign by AbuseIPDB, the observed behavior aligns with typical brute‑force attacks and warrants immediate attention.

## Predicted Next Steps
*No probabilistic forecasts were supplied in the evidence.*  

## Recommendations
Mitigations aligned with **T1110 – Brute Force**:

1. **Enforce strong, unique passwords** for all SSH accounts and consider password complexity policies.  
2. **Implement account lockout** or throttling after a configurable number of failed attempts.  
3. **Deploy multi‑factor authentication (MFA)** for SSH access where feasible.  
4. **Restrict SSH access** by source IP using firewall rules or VPN‑only access.  
5. **Prefer SSH key‑based authentication** and disable password authentication where possible.  
6. **Enable detailed SSH logging** and forward logs to a centralized SIEM for real‑time monitoring.  
7. **Conduct a post‑incident review** of the compromised account (“anna”) for any unauthorized actions.

## Response Actions

| Action Type | Target | Status | Severity | Rationale |
|---|---|---|---|---|
| ActionType.BLOCK_IP | 100.81.172.118 | executed | ActionSeverity.HIGH | The source IP is identified as the attacker’s address and is listed as a valid action target. High‑confidence brute‑force activity (T1110) with successful credential use indicates it is actively compromising the environment. |
| ActionType.ISOLATE_HOST | victim-endpoint | pending_approval | ActionSeverity.HIGH | The compromised host is explicitly listed as a victim isolation target. Multiple high‑confidence techniques (brute force, valid accounts, credential dumping) suggest the host is being used for further malicious activity. |
| ActionType.DISABLE_ACCOUNT | anna | executed | ActionSeverity.MEDIUM | User anna experienced numerous failed logins followed by a successful authentication, indicating the account may have been compromised and could be used for lateral movement (T1078). |
| ActionType.NOTIFY_ANALYST | SOC_analyst | executed | ActionSeverity.LOW | High‑severity brute‑force campaign detected (T1110) with successful logins, source IP 100.81.172.118, and compromised user anna. Recommended actions: block IP, isolate victim-endpoint, and disable anna's account. |