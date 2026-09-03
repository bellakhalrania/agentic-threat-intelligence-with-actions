# Threat Intelligence Report

**Campaign:** Unclassified Activity
**Campaign ID:** d3f9c2a1-5b6e-4f8a-9c2d-7e1f3b6a9c4e
**Generated:** 2026-09-03T11:59:44.360696+00:00

---

# Threat Intelligence Report  

**Campaign ID:** `d3f9c2a1-5b6e-4f8a-9c2d-7e1f3b6a9c4e`  
**Report Date:** 2026‑09‑03  

---  

## Executive Summary  
Multiple SSH authentication failures followed by a successful login were observed on **victim‑endpoint** from the same external source IP **100.81.172.118**. The activity maps to ATT&CK technique **T1110 – Brute Force** with a confidence of 0.7, indicating a credential‑guessing campaign that succeeded in obtaining valid credentials for the user **anna**. No malicious reputation was associated with the IP (AbuseIPDB → benign, confidence 0.0), but the observed behavior is indicative of an active brute‑force attack.

---  

## Timeline  

| Timestamp (UTC) | Event ID | Event Type | Source IP | Username | Service |
|-----------------|----------|------------|-----------|----------|---------|
| 2026‑09‑03T11:59:04.110726+00:00 | `af7504ea-1032-438d-bcb5-e1f64634b07a` | authentication_failed | 100.81.172.118 | anna | ssh |
| 2026‑09‑03T11:59:04.111271+00:00 | `665478d3-c3d6-41c8-863c-3b18dc507d79` | authentication_failed | 100.81.172.118 | anna | ssh |
| 2026‑09‑03T11:59:04.111498+00:00 | `5bfe0165-cf8c-4ce6-9bda-94fa7ae35b8a` | authentication_success | 100.81.172.118 | anna | ssh |
| 2026‑09‑03T11:59:05.860719+