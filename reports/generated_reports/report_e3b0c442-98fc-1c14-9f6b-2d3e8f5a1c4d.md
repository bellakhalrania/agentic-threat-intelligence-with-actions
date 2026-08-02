# Threat Intelligence Report

**Campaign:** Unclassified Activity
**Campaign ID:** e3b0c442-98fc-1c14-9f6b-2d3e8f5a1c4d
**Generated:** 2026-08-02T14:25:08.049641+00:00

---

# Threat Intelligence Report  
**Campaign ID:** e3b0c442-98fc-1c14-9f6b-2d3e8f5a1c4d  
**Report Date:** 2026‑08‑02  

---

## Executive Summary  
A series of failed SSH authentication attempts originating from **172.31.24.217** targeted the non‑existent user *labur* on host *ip‑172‑31‑19‑70*. The activity is consistent with **Password Guessing (T1110.001)** and **SSH brute‑force (T1021.004)**, culminating in a **Brute Force (T1110)** event. Subsequent events show the attacker leveraged **sudo privileges (T1548.003)** and **Valid Accounts (T1078)** to open a root session.  

**Possible SSH Brute Force Attack (T1110)**  
- **Failed attempts:** 7 (5 explicit authentication failures + 2 PAM failures)  
- **Source IP:** 172.31.24.217  

The attacker did not use any external IP addresses beyond the internal source listed above.

---

## Timeline  

| Timestamp (UTC) | Event ID | Description |
|-----------------|----------|-------------|
| 14:21:09 | 650d8c30-6dac-440b-9833-09106e4befd4 | Failed SSH authentication for invalid user *labur* from 172.31.24.217 |
| 14:21:12 | 66eda7e3-2f01-41b4-a9ce-7a84aec8cac7 | Second failed SSH authentication for *labur* |
| 14:21:14 | b92743e8-424b-4ba5-91e3-7b1fd0133a3a | Third failed SSH authentication for *labur* |
| 14:21:20 | 94b29a49-25a8-4b7a-8604-08545b20c1fe | Fourth failed SSH authentication for *labur* |
| 14:21:26 | 89c49078-cd26-44b0-95b4-b57266a3499e | Fifth failed SSH authentication for *labur* |
| 14:21:27 | ee7733a7-786e-4dda-b54a-a1f012f312f1 | PAM reports two additional authentication failures |
| 14:21:56 | d5ced034-a68a-4a40-a40f-8b6a2698f0c9 | Successful sudo session opened for user *root* by *ubuntu* |
| 14:22:07 | bc0514bc-aa53-4ee2-8ea6-aadf5d91c91b | Sudo session closed for *root* |

---

## IOCs  

| Type | Value | Source |
|------|-------|--------|
| IP Address | 172.31.24.217 | Event 650d8c30-6dac-440b-9833-09106e4befd4 |
| Host | ip‑172‑31‑19‑70 | Event 650d8c30-6dac-440b-9833-09106e4befd4 |
| Username | labur | Event 650d8c30-6dac-440b-9833-09106e4befd4 |

---

## ATT&CK Techniques  

| Technique ID | Technique Name | Confidence | Evidence Event ID | Mapping Source |
|--------------|----------------|------------|-------------------|----------------|
| T1548.003 | Sudo and Sudo Caching | 1.0 | 8e10608c-84f1-4e41-bd72-31184e7a4645 | event_metadata |
| T1548.003 | Sudo and Sudo Caching | 0.95 | 235cbb63-74d3-494a-b23f-3a5b7e2305c5 | llm |
| T1110.001 | Password Guess