# Threat Intelligence Report

**Campaign:** Unclassified Activity
**Campaign ID:** d3f9c2a1-5b4e-4f9a-8c2e-7a1b6e9f3d4c
**Generated:** 2026-09-03T12:02:55.860260+00:00

---

# Threat Intelligence Report  

**Campaign ID:** `d3f9c2a1-5b4e-4f9a-8c2e-7a1b6e9f3d4c`  
**Report Date:** 2026‑09‑03  

---

## Executive Summary
A brute‑force credential‑guessing campaign targeted the SSH service on the host **victim‑endpoint**.  
- Source IP **100.81.172.118** attempted four failed logins for user **anna** and subsequently achieved a successful authentication.  
- The activity maps to ATT&CK technique **T1110 – Brute Force** with a confidence of 0.7.  
- The successful login indicates that the adversary now possesses valid credentials on the victim system, raising the risk of further lateral movement or credential harvesting.  
- Immediate containment actions are pending approval; an analyst has already been notified.

---

## Timeline  

| Timestamp (UTC) | Event ID | Description |
|-----------------|----------|-------------|
| 2026‑09‑03T12:02:08.301473+00:00 | `81a029e5-25ac-4dc5-9340-2a35f69e5960` | SSH authentication **failed** for user *anna* from IP 100.81.172.118. |
| 2026‑09‑03T12:02:08.301787+00:00 | `9f382045-