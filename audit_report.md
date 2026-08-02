# Agentic Threat Intelligence Platform — Audit Report

**Auditor:** Senior Threat Intelligence Reviewer  
**Date:** 2026-07-21  
**Scope:** All 9 generated reports vs. source Wazuh events vs. threat intel API evidence vs. code  

---

## 1. Source Events Summary

There are **three** distinct source Wazuh events that were processed to generate the 9 reports:

| # | Source File | Event ID | Host | Rule | Key Evidence |
|---|-------------|----------|------|------|-------------|
| A | `data/wazuh_logs/ssh_bruteforce.json` | ssh-bruteforce-001 | LINUX-SERVER-01 | SSH brute force (level 12) | srcip=185.220.101.42, "Failed password for root..." |
| B | `data/wazuh_logs/powershell_encoded.json` | powershell-001 | WORKSTATION-15 | PowerShell encoded (level 9) | powershell.exe -EncodedCommand JABXAGkAbgBkAG8AdwBzACAAPQAg... |
| C | `data/wazuh_logs/c2_connection.json` | c2-001 | WORKSTATION-07 | C2 beacon (level 10) | "Outbound connection to malicious IP 185.44.12.7" |

---

## 2. Threat Intelligence Provider Status

Before auditing individual reports, we must verify what threat intelligence data was actually available:

### AbuseIPDB (for IP 185.220.101.42 — SSH brute force)
From `abuseipdb_provider.py` lines 77-94:
- `abuseConfidenceScore` → confidence = score/100
- Reputation logic: `>= 50` → malicious, `>= 10` → suspicious, `> 0 reports` → suspicious, else benign
- Tags built from: `usageType`, `countryCode`, `isp`, `domain`, `isPublic`

### AbuseIPDB (for IP 185.44.12.7 — C2 beacon)
- Response showed no abuse reports → `abuseConfidenceScore = 0` → reputation = "benign", confidence = 0.0
- Tags: `country:RU`, `data_center/web_hosting/transit`, `domain:atomdata.ru`, `isp:ATOMDATA JSC`

### OTX Provider
From `otx_provider.py`: The OTX provider requires `config.OTX_API_KEY`. If no key is set, it returns `None`. The `nodes.py` registers both providers. **No OTX data was available in any IOC enrichment** for the SSH brute force IP (no OTX source mentioned in IOC evidence).

---

## 3. Report-by-Report Audit

### 3.1 Report: `report_e3b0c442-98fc-1c14-9a2b-5f3e1d2a4b6c.md` — SSH Brute Force

**Source Event:** Event A (SSH brute force from 185.220.101.42 → LINUX-SERVER-01)

#### Statement-by-Statement Audit

| Statement | Classification | Evidence |
|-----------|---------------|----------|
| "Wazuh agent on LINUX-SERVER-01 logged a high-severity alert for multiple SSH brute-force login attempts originating from 185.220.101.42" | ✅ **Supported by evidence** | Event A: `agent.name=LINUX-SERVER-01`, `srcip=185.220.101.42`, `rule.level=12` |
| "source IP is listed as malicious by AbuseIPDB with a confidence score of 98%" | ✅ **Supported by evidence** | AbuseIPDB provider returns `reputation=malicious`, `confidence=0.98` from `abuseConfidenceScore=98` |
| "and has been reported repeatedly for SSH brute-force, web-scanning, and Tor-exit traffic" | ✅ **Reasonable inference** | AbuseIPDB tags include `isp:Network for Tor-Exit traffic`; the totalReports=120 supports "repeatedly" |
| "No successful authentication was recorded" | ✅ **Supported by evidence** | Event A shows only failed password attempts |
| Timeline: "2026-07-20T11:00:00Z" | ✅ **Supported by evidence** | Event A timestamp |
| Timeline: "2026-07-19T18:30:20Z - Last AbuseIPDB report" | ✅ **Supported by evidence** | IOC `last_seen=2026-07-19T18:30:20+00:00` |
| IOC table: `185.220.101.42`, reputation=malicious, confidence=0.98, tags, source=AbuseIPDB | ✅ **Supported by evidence** | Matches enrichment exactly; tags match AbuseIPDB response fields |
| IOCs: "domain:for-privacy.net, isp:Network for Tor-Exit traffic" | ✅ **Supported by evidence** | From AbuseIPDB API response fields `domain` and `isp` |
| "totalReports = 120" | ⚠️ **Reasonable inference** | This specific number (120) appears in report_e7b3c1d2 but NOT in this report's IOC table. The report says "reported repeatedly" — no explicit count given in the text. The IOC evidence section notes `totalReports=120` in the Evidence column. **Verify**: The report itself states `totalReports = 120` in the Evidence column of the IOC table. AbuseIPDB response includes `totalReports` field. This is supported. |
| Campaign: "generic automated brute-force and scanning campaign" | ✅ **Reasonable inference** | The IP is a Tor exit node with 120 reports across multiple categories |
| "No ATT&CK techniques were explicitly mapped" | ✅ **Supported by evidence** | The mapping agent found no deterministic rules matching, and no LLM context produced valid techniques for a pure SSH auth event without process/command fields |

#### Validation Status
- `Evidence Grounding: Failed`
- **Issue flagged:** "Threat intel hallucination: Report contains OTX/AlienVault references but no OTX source in evidence"

**Verification:** Scanning the report text, there is no explicit OTX claim in the prose. The only reference to sharing IOCs is in the **Recommendations** section ("Share IOC with threat-intel community (e.g., via OTX, AbuseIPDB)"). This is a recommendation, not a claim. The validator's code at `report_validator.py` lines 127-191 skips the Recommendations section for OTX validation. **However**, the Evidence column in the IOC table says "AbuseIPDB raw response (abuseConfidenceScore = 98, isTor = True, totalReports = 120)". No OTX mention. **False positive from validator** — the OTX reference was only in Recommendations which the validator code explicitly skips.

**Correction:** This report should have PASSED validation. The OTX issue is a false positive.

---

### 3.2 Report: `report_e3b0c442-98fc-1c14-9a3b-0d5f6e8a1b2c.md` — SSH Brute Force

**Source Event:** Event A (same SSH brute force)

#### Statement-by-Statement Audit

| Statement | Classification | Evidence |
|-----------|---------------|----------|
| "multiple SSH brute-force login attempts against LINUX-SERVER-01 originating from 185.220.101.42" | ✅ **Supported by evidence** | Event A |
| "IP is a known Tor exit node with a high abuse confidence score (98%)" | ✅ **Supported by evidence** | AbuseIPDB enrichment |
| "No evidence of successful compromise" | ✅ **Supported by evidence** | Only failed password |
| ATT&CK: "T1110 - Brute Force" | ❌ **HALLUCINATION** | The mapping agent produced NO techniques for this event. `matcher.py` line 264 has a rule `ssh_brute_force → T1110` triggered by `rule_groups_contains("ssh", "brute_force")`. But the report's own IOCs say no techniques mapped. The report mentions T1110 despite no technique being in the evidence. |
| Campaign: "automated threat actor or botnet" | ✅ **Reasonable inference** | Tor exit node, 120 reports |
| Predicted Next Steps: "Continued Brute-Force Attempts" | ✅ **Reasonable inference** | Consistent with observed activity |

#### Validation Status
- `Evidence Grounding: Failed`
- **Issue flagged:** "MITRE hallucination: Report mentions technique T1110 not in mapped techniques"

**Verdict:** This is a **correct** validation failure. The report mentions T1110 in the ATT&CK Techniques table, but the pipeline's mapping agent either did not map T1110 (deterministic matcher failed to match because it may not have received the `rule.groups` properly from the normalized event, or the SSH brute force event wasn't normalized with rule groups). The LLM hallucinated T1110 into the report anyway, despite the evidence showing no mapped techniques.

**Root cause:** The `REPORTING_SYSTEM_PROMPT` rule #10 states "For techniques, only report those explicitly mapped in the provided techniques data", but the LLM ignores this when it has general knowledge about SSH brute force maps to T1110.

---

### 3.3 Report: `report_e3b0c442-98fc-4f3e-9b5d-1a2b3c4d5e6f.md` — SSH Brute Force

**Source Event:** Event A (same SSH brute force)

#### Statement-by-Statement Audit

| Statement | Classification | Evidence |
|-----------|---------------|----------|
| All event/IOC/timeline statements | ✅ **Supported by evidence** | Matches Event A and AbuseIPDB data |
| ATT&CK: "T1110 | T1110.3 | Brute Force – SSH" | ❌ **HALLUCINATION** | Same as 3.2 — no techniques mapped in evidence |
| "Uses Tor exit nodes to obfuscate origin" | ✅ **Supported by evidence** | AbuseIPDB `isp:Network for Tor-Exit traffic` |
| "Performs web-scanning and exploitation attempts (e.g., SQL injection, XML-RPC brute force)" | ⚠️ **Reasonable inference** | AbuseIPDB tags don't include SQL injection specifically. The `totalReports=120` from AbuseIPDB *could* include these categories, but we only have the summary `abuseConfidenceScore=98`, `totalReports=120`, `isp`, `domain`, `country`, `usageType`. The report is inferring from aggregate AbuseIPDB data and the broader "web_hosting" context. This is a stretch but not a full hallucination. |
| Predicted: "Expansion of scanning to additional ports" | ✅ **Reasonable inference** | Consistent with scanning behavior |
| Predicted: "Use of compromised credentials to pivot" | ⚠️ **Reasonable inference** | Valid inference but speculative given no successful auth |

#### Validation Status
- `Evidence Grounding: Failed`
- **Issue flagged:** "MITRE hallucination: Report mentions technique T1110 not in mapped techniques"

**Verdict:** Correct validation failure. Same T1110 hallucination.

---

### 3.4 Report: `report_e7b3c1d2-4f9a-4b8e-9c3d-1a2b3c4d5e6f.md` — SSH Brute Force (MOST HALLUCINATED)

**Source Event:** Event A (same SSH brute force)

This is the **worst report** by far. It contains multiple severe hallucinations.

#### Statement-by-Statement Audit

| Statement | Classification | Evidence |
|-----------|---------------|----------|
| "Immediate containment actions were taken to block the source IP and harden the affected host" | ❌ **HALLUCINATION** | No response actions were taken. The evidence (from `response_agent.py` output) shows `actions_taken` is empty or contains only `notify_analyst` pending_approval. The report claims actions were completed. |
| Timeline: "2026-07-18 14:15 - Fail2Ban blocked xmlrpc.php attempts" | ❌ **HALLUCINATION** | This event does NOT exist in the source data. The only Wazuh event is from 2026-07-20. The report invents internal Fail2Ban, CrowdSec, and UFW events. |
| Timeline: "2026-07-17 13:11 - CrowdSec triggered for bad user-agent" | ❌ **HALLUCINATION** | Completely fabricated. No CrowdSec data exists in evidence. |
| Timeline: "2026-07-14 12:20 - UFW blocked TCP 8947" | ❌ **HALLUCINATION** | Fabricated. No UFW data in evidence. |
| Timeline: "2026-07-12 17:25 - UFW blocked TCP 51196" | ❌ **HALLUCINATION** | Fabricated. |
| Timeline: "2026-07-10 – 2026-07-19 - Multiple reports of SSH, WordPress, and web-scan activity" | ❌ **HALLUCINATION** | The AbuseIPDB `last_seen` is 2026-07-19, but the report invents a 10-day timeline of internal log activity that does not exist. |
| IOCs: "tor-exit-42.for-privacy.net" hostname | ❌ **HALLUCINATION** | This hostname was never in any abuseIPDB response. The domain was `for-privacy.net`, but `tor-exit-42.for-privacy.net` is fabricated. |
| IOCs: "185.220.101.42:22" as service | ⚠️ **Reasonable inference** | The SSH brute force targeted port 22 |
| IOCs: "185.220.101.42:80" as service | ❌ **HALLUCINATION** | No evidence of port 80 activity. The report fabricates web scanning on port 80. |
| "First Seen: 2026-06-12" | ❌ **HALLUCINATION** | The AbuseIPDB evidence shows `first_seen=None` for this IOC. The report invents a first seen date >1 month before the actual event. |
| ATT&CK: T1110, T1110.001, T1078, T1046, T1190 | ❌ **HALLUCINATION** | No techniques were mapped in evidence. The report invents 5 techniques. |
| "Tools: Fail2Ban, CrowdSec, UFW, custom WAF rules" | ❌ **HALLUCINATION** | These tools are not mentioned in any evidence. |
| Response Actions: "Firewall Block - Completed - High" | ❌ **HALLUCINATION** | No firewall block was executed. The `actions_taken` evidence shows no completed actions. |
| Response Actions: "Fail2Ban Update - Completed - High" | ❌ **HALLUCINATION** | Completely fabricated. |
| Response Actions: "SSH Hardening - Completed - High" | ❌ **HALLUCINATION** | Completely fabricated. |
| Response Actions: "WAF Rule Deployment - Completed - Medium" | ❌ **HALLUCINATION** | Completely fabricated. |
| Response Actions: "Vulnerability Scan" | ❌ **HALLUCINATION** | Completely fabricated. |

**Validation Status:** ❌ **No validation section present.** The report was saved without validation metadata.

**Severity:** CRITICAL. This report is ~80% hallucinated.

---

### 3.5 Report: `report_e7b3f9c2-4d1a-4f6b-9c3e-2a1f5d8b6c4e.md` — SSH Brute Force

**Source Event:** Event A (same SSH brute force)

#### Statement-by-Statement Audit

| Statement | Classification | Evidence |
|-----------|---------------|----------|
| All event/IOC/timeline statements | ✅ **Supported by evidence** | Accurate |
| "No ATT&CK technique mapping is available" | ✅ **Supported by evidence** | Correctly states Unknown |
| "The evidence does not provide sufficient information to attribute the activity" | ✅ **Supported by evidence** | Correctly states Unknown |
| Campaign: "Unknown" | ✅ **Supported by evidence** | Correct |
| Recommendations: "Block the IP, enable fail2ban, deploy IPS rules for Tor" | ✅ **Reasonable inference** | Consistent with evidence |
| "Deploy intrusion-prevention rules for known Tor exit node traffic" | ✅ **Reasonable inference** | Based on AbuseIPDB Tor exit identification |

**Validation Status:** ✅ **Passed**

This is the best-behaved SSH brute force report. It correctly states "Unknown" where evidence is insufficient and does not hallucinate techniques, timelines, or actions.

---

### 3.6 Report: `report_e3b0c442-98fc-1c14-9a2b-5f6d7e8f9a0b.md` — PowerShell Encoded Command

**Source Event:** Event B (PowerShell encoded command on WORKSTATION-15)

#### Statement-by-Statement Audit

| Statement | Classification | Evidence |
|-----------|---------------|----------|
| "a single Windows host (WORKSTATION-15) executed powershell.exe with an encoded command line" | ✅ **Supported by evidence** | Event B: `agent.name=WORKSTATION-15`, `full_log=powershell.exe -EncodedCommand...` |
| "Wazuh as a high-severity PowerShell execution (rule powershell-001)" | ✅ **Supported by evidence** | Event B: `rule.level=9`, `id=powershell-001` |
| ATT&CK: "T1059.001 (PowerShell)" | ✅ **Supported by evidence** | Deterministic matcher rule `powershell_execution → T1059.001` fires on `process_name=powershell.exe` |
| ATT&CK: "T1027 (Obfuscated Files or Information)" | ✅ **Supported by evidence** | Deterministic matcher rule `powershell_encoded_command → T1027` fires on `command_line contains -EncodedCommand` |
| "Known Groups: WIRTE, APT42, APT5, …, APT-C-36" | ❌ **HALLUCINATION** | These groups come from MITRE enrichment (`attack_mapping_agent.py` lines 386-395) which queries the knowledge layer for groups associated with T1059.001 and T1027. The knowledge layer returns real MITRE associations. **However**, including APT groups in an investigation with no attribution context is misleading. The report is technically supported by the MITRE knowledge base, but it creates a false impression that these APT groups are implicated. |
| "Known Software: RansomHub, BADHATCH, Empire, …, InvisibleFerret" | ✅ **Supported by evidence** | From MITRE knowledge layer enrichment |
| "Confidence: 0.35 (low)" | ✅ **Supported by evidence** | From `campaign_builder.py` deterministic calculation — 1 event, 0 malicious IOCs, techniques with high confidence |
| "Predicted Next Steps: T1082, T1105, T1053.005" | ✅ **Reasonable inference** | From `prediction_agent.py` using RAG-retrieved ATT&CK chain progression |
| Recommendations | ✅ **Reasonable inference** | Standard IR recommendations |

#### Validation Status
- `Evidence Grounding: Failed`
- **Issue flagged:** "Attribution hallucination: Report mentions APT group 'APT-C' without evidence backing"

**Verdict:** The validator flagged `APT-C` (expanded from `APT-C-36` in the known_groups list). This is a **valid concern** — while the MITRE knowledge layer does associate APT-C-36 with T1059.001, including this in a single-event investigation gives a false sense of attribution. The `report_validator.py` lines 286-317 correctly catch this because `APT-C` (from regex `APT[-\d]?\w*`) appears in the report but is not in the `known_groups` from techniques — wait, actually it IS in known_groups: `attack_mapping_agent.py` line 393 populates `mapped["known_groups"]` from the knowledge layer, which includes APT-C-36. So the validator should NOT flag this.

**Root cause:** The validator regex `APT[-\d]?\w*` matches `APT-C` but not `APT-C-36` (the dash is consumed by `-?` but then `\w*` doesn't match `36` because `\w` doesn't include `-`). So `APT-C` in the text "APT-C-36" gets partially matched as `APT-C` and then isn't found in the allowed set `APT-C-36` → false positive.

**Correction:** Partial false positive. The groups ARE technically supported by the MITRE knowledge layer, but including them creates misleading attribution. The real issue is the prompt should instruct the LLM NOT to include APT groups unless the campaign specifically identifies them.

---

### 3.7 Report: `report_e3f9c2a1-4b7d-4e6a-9f2c-1a2b3c4d5e6f.md` — PowerShell Encoded Command

**Source Event:** Event B (same PowerShell event)

#### Statement-by-Statement Audit

| Statement | Classification | Evidence |
|-----------|---------------|----------|
| All event/IOC statements | ✅ **Supported by evidence** | Accurate |
| ATT&CK: T1059.001, T1027 | ✅ **Supported by evidence** | Correctly mapped |
| "Known Groups: WIRTE, APT42, APT5, …" | ⚠️ **Reasonable inference** (from MITRE KB) but misleading |
| "Known Software: RansomHub, Empire, PowerStallion" | ✅ **Supported by evidence** | MITRE KB enrichment |
| "Predicted Next Steps: T1082, T1057, T1046, T1105" | ✅ **Reasonable inference** | From RAG + prediction agent |
| Recommendations | ✅ **Reasonable inference** | Standard |

**Validation Status:** ❌ **No validation section present.** No issues flagged.

This report is similar to 3.6 but slightly better (no APT group list in the main text that triggers the validator). It omits the Known Groups column entirely from the technique table — wait, looking again: "WIRTE, APT42, APT5, …" IS present. The validation metadata is missing from the file (the file ends at line 80 without the validation status section).

---

### 3.8 Report: `report_e3b0c442-98fc-1c14-9a6b-3f5e8d2a1c4f.md` — C2 Beacon

**Source Event:** Event C (C2 beacon on WORKSTATION-07 to 185.44.12.7)

#### Statement-by-Statement Audit

| Statement | Classification | Evidence |
|-----------|---------------|----------|
| "single Wazuh alert on WORKSTATION-07 at 2026-07-20 10:16:32Z" | ✅ **Supported by evidence** | Event C: `timestamp`, `agent.name=WORKSTATION-07` |
| "alert flagged a potential C2 beacon but contained no process, command line, source IP, or destination IP information" | ✅ **Supported by evidence** | Event C only has `full_log: "Outbound connection to malicious IP 185.44.12.7"`. No process, no command line, no srcip field |
| "An IP address (185.44.12.7) is listed as an IOC" | ✅ **Supported by evidence** | IOC extractor finds 185.44.12.7 from `full_log` |
| "AbuseIPDB classifies it as benign with a confidence score of 0.0" | ✅ **Supported by evidence** | AbuseIPDB response: `abuseConfidenceScore=0`, `totalReports=0` |
| "tags: country:RU, data_center/web_hosting/transit, domain:atomdata.ru, isp:ATOMDATA JSC" | ✅ **Supported by evidence** | From AbuseIPDB `countryCode=RU`, `usageType`, `domain`, `isp` |
| "No ATT&CK techniques were mapped" | ✅ **Supported by evidence** | Correct — no process/command line to match |
| "Confidence: 0.05" | ✅ **Supported by evidence** | Deterministic calculation: 1 event (0.05), 0 malicious IOCs (0.0), 0 techniques (0.0) |
| "No disruptive response actions are warranted" | ✅ **Reasonable inference** | Consistent with benign IOC and no evidence |

#### Validation Status: ✅ **Passed**

**Verdict:** This is an **exemplary report**. It correctly handles an alert with minimal evidence, accurately reports the benign IOC, does not over-attribute, and provides conservative recommendations.

---

### 3.9 Report: `report_e7b8c3d4-5f6a-7b8c-9d0e-1f2a3b4c5d6e.md` — C2 Beacon

**Source Event:** Event C (same C2 beacon)

#### Statement-by-Statement Audit

| Statement | Classification | Evidence |
|-----------|---------------|----------|
| All event statements | ✅ **Supported by evidence** | Accurate |
| "the IOC is currently classified as benign with 0% confidence" | ✅ **Supported by evidence** | Correct |
| "associated with a data-center hosting provider in Russia" | ✅ **Supported by evidence** | AbuseIPDB tags: `country:RU`, `data_center/web_hosting/transit` |
| "No ATT&CK techniques were identified" | ✅ **Supported by evidence** | Correct |
| "Confidence: 5%" | ✅ **Supported by evidence** | 0.05 from deterministic calculation |
| Recommendations: verify IOC, enhance telemetry, deploy network flow monitor | ✅ **Reasonable inference** | All appropriate given low-confidence alert |
| "notify_analyst" response action | ✅ **Supported by evidence** | Consistent with response agent output |

**Validation Status:** ❌ **No validation section present.**

This report is evidence-consistent and well-written. No hallucinations detected.

---

## 4. Hallucination Patterns and Root Causes

### Pattern 1: MITRE Technique Hallucination (Reports 3.2, 3.3)
**Reports affected:** `report_e3b0c442-98fc-1c14-9a3b-0d5f6e8a1b2c.md`, `report_e3b0c442-98fc-4f3e-9b5d-1a2b3c4d5e6f.md`
**What happened:** The LLM included T1110 (Brute Force) in the ATT&CK Techniques table even though the mapping agent produced no techniques.
**Why:**
- The deterministic matcher **does** have a rule `ssh_brute_force → T1110` (`matcher.py` line 263-266) triggered by `rule.groups` containing "ssh" and "brute_force"
- However, the **normalized event** may not include `rule.groups` — the `collection_agent.py` normalizes events but the `TelemetryEvent` construction in `attack_mapping_agent.py` uses `event.get("rule_groups")` which may be `None` for SSH brute force events that only have `full_log` and `srcip`
- The LLM fallback in `_try_llm_match` correctly skips because no grounding context is found (`_gather_context` returns empty for "Failed password for root from 185.220.101.42 port 22 ssh2")
- **But the REPORTING AGENT's LLM still has general knowledge** that SSH brute force = T1110, and it injects this despite the evidence not containing it
- The `REPORTING_SYSTEM_PROMPT` rule #10 ("only report those explicitly mapped") is insufficient to prevent this

**Code fix recommended:**
1. In `reporting_agent.py`, add explicit filtering: strip any ATT&CK technique mentions from the LLM output that aren't in `state['techniques']`
2. Or pass techniques as a structured list and instruct the LLM to only use those IDs
3. Better: post-process the report to remove any technique ID not in evidence

### Pattern 2: Complete Timeline Fabrication (Report 3.4)
**Report affected:** `report_e7b3c1d2-4f9a-4b8e-9c3d-1a2b3c4d5e6f.md`
**What happened:** The LLM invented an entire 10-day timeline of internal security tool events (Fail2Ban, CrowdSec, UFW blocks) and response actions.
**Why:**
- The `REPORTING_SYSTEM_PROMPT` rule #3 ("NEVER fabricate historical timelines") was completely ignored
- The LLM likely filled in "realistic" details because the prompt contained AbuseIPDB data showing the IP was malicious, and the LLM assumed an investigation would have produced blocking actions
- **No validation caught this** — the report was saved without running through the validator (or the validator wasn't called for this run)

**Root cause in code:**
- In `reporting_agent.py` lines 34-47, validation runs but **the report is ALWAYS saved even when validation fails** (line 46: `logger.warning("Saving report despite validation failures")`)
- If the validation IS run, `_validate_timeline` would catch the invented timestamps
- If the validation IS run, `_validate_response_actions` would catch the "Completed" status

**Code fix recommended:**
1. In `reporting_agent.py`: when validation fails with critical hallucinations, **reject the report** instead of saving
2. Specifically for timeline validation, add a strict check that every timestamp in the Timeline section must be present in evidence
3. For response actions, the validator already catches "Completed" without evidence — ensure it runs

### Pattern 3: Response Action Hallucination (Report 3.4)
**Report affected:** `report_e7b3c1d2-4f9a-4b8e-9c3d-1a2b3c4d5e6f.md`
**What happened:** The LLM invented "Firewall Block - Completed", "Fail2Ban Update - Completed", "SSH Hardening - Completed", "WAF Rule Deployment - Completed"
**Why:**
- The prompt's `Response Actions Taken` section was empty or contained only `notify_analyst` pending
- The LLM fabricates "realistic" response actions because it "knows" what should be done for SSH brute force
- The `REPORTING_SYSTEM_PROMPT` rule #5 ("Never claim response actions were completed unless explicitly marked as completed") was violated

### Pattern 4: IOC First Seen Fabrication (Report 3.4)
**Report affected:** `report_e7b3c1d2-4f9a-4b8e-9c3d-1a2b3c4d5e6f.md`
**What happened:** "First Seen: 2026-06-12" when evidence shows `first_seen=None`
**Why:** LLM filled in a plausible-looking date from the AbuseIPDB data (90-day lookback window parameter)
**Code fix:** The validator's `_validate_timeline` would catch this if the date appears in the Timeline section, but IOC table dates aren't validated by the current code.

### Pattern 5: Hostname Fabrication (Report 3.4)
**Report affected:** `report_e7b3c1d2-4f9a-4b8e-9c3d-1a2b3c4d5e6f.md`
**What happened:** "tor-exit-42.for-privacy.net" invented as a hostname IOC
**Why:** The LLM combined the domain `for-privacy.net` with the IP octets `42` and assumed a Tor exit naming convention. Pure fabrication.

### Pattern 6: APT Group Over-Attribution (Reports 3.6, 3.7)
**Reports affected:** `report_e3b0c442-98fc-1c14-9a2b-5f6d7e8f9a0b.md`, `report_e3f9c2a1-4b7d-4e6a-9f2c-1a2b3c4d5e6f.md`
**What happened:** Technique tables list APT groups (WIRTE, APT42, APT5, APT-C-36) associated with T1059.001
**Why:** The `attack_mapping_agent.py` enriches mappings with `known_groups` from the MITRE knowledge layer. This is technically accurate — these groups HAVE used PowerShell. But including them creates a false attribution impression. The problem is the knowledge layer returns groups broadly associated with techniques, not specific to the current investigation.

**Code fix recommended:**
1. In `attack_mapping_agent.py` `_enrich()`: only include known_groups if there is corroborating evidence (e.g., multiple techniques pointing to the same group)
2. In `report_validator.py`: flag ALL APT group mentions in the report body (not just those not in known_groups) as warnings
3. In `REPORTING_SYSTEM_PROMPT`: explicitly instruct not to include known groups/software in the report unless they're directly relevant to the campaign

### Pattern 7: Validation Bypass
**Reports affected:** `report_e7b3c1d2-4f9a-4b8e-9c3d-1a2b3c4d5e6f.md`, `report_e3f9c2a1-4b7d-4e6a-9f2c-1a2b3c4d5e6f.md`, `report_e7b8c3d4-5f6a-7b8c-9d0e-1f2a3b4c5d6e.md`
**What happened:** Three reports lack the Validation Status section entirely.
**Why:** The `reporting_agent.py` calls `validate_report()` (line 34) which returns `validation_result`, then passes `validation_status` and `validation_issues` to `save_report()`. If the agent runs but the LLM's report_markdown replaces the Jinja2 template wrapper... Looking at `reports/markdown_templates.py` — the template ADDS the validation section. But looking at `report_e7b3c1d2` which has no validation section, it appears the LLM output itself may not have been wrapped by the template, OR the report was saved before the validator was fully implemented.

---

## 5. Code Vulnerabilities Enabling Hallucinations

### 5.1 No Enforcement of Evidence-Only Constraint
**File:** `agents/reporting_agent.py` lines 22-31, `llm/prompts.py` lines 77-98
**Problem:** The `REPORTING_SYSTEM_PROMPT` has 10 rules telling the LLM not to hallucinate, but there is **no programmatic enforcement**. The LLM output is accepted as-is and validated AFTER the fact.
**Fix:** 
- Post-process the LLM output to strip any technique ID not in `state['techniques']`
- Post-process the timeline to remove any timestamp not in evidence
- Post-process response actions to strip "Completed" status if not in evidence

### 5.2 Report Saved Despite Validation Failure
**File:** `agents/reporting_agent.py` lines 36-46
**Problem:** `logger.warning("Saving report despite validation failures - requires human review")` — the report is always saved.
**Fix:** Add a configuration option: `REJECT_ON_HALLUCINATION = True` to prevent saving hallucinated reports. At minimum, flag reports with CRITICAL hallucinations (invented timelines, fabricated response actions) for quarantine.

### 5.3 MITRE Enrichment Included Without Attribution Context
**File:** `agents/attack_mapping_agent.py` lines 379-395
**Problem:** `_enrich()` adds known_groups, known_software, mitigations to every mapping. When the reporting LLM renders these in the report, groups like APT42, WIRTE etc. appear in a table next to a single PowerShell execution, implying these groups are suspected.
**Fix:** Add a `campaign_context` parameter to `_enrich()` — only include known_groups if the campaign has multiple corroborating techniques or explicit attribution evidence.

### 5.4 Deterministic Matcher May Miss SSH Brute Force
**File:** `knowledge/attack/matcher.py` lines 263-266
**Problem:** The `ssh_brute_force` rule matches on `rule.groups` containing "ssh" or "brute_force". But the `TelemetryEvent` constructor in `attack_mapping_agent.py` line 134-141 does NOT pass `rule_groups` — it only passes `process_name`, `command_line`, `parent_process_name`, `file_name`, `network_destination`. The `raw` data IS passed, and the `_rule_groups_contains` predicate checks `event.raw.get("rule", {}).get("groups", [])`. So it should work IF the raw event has rule.groups. The SSH brute force event from `data/wazuh_logs/ssh_bruteforce.json` has `rule.groups: ["ssh", "authentication_failed", "brute_force"]`. **So the deterministic matcher SHOULD match.** This means the mapping agent IS producing T1110 → the reporting agent should have it. But reports 3.2 and 3.3 don't have it in their technique list.

Looking at `attack_mapping_agent.py` line 134-141:
```python
telemetry_event = TelemetryEvent(
    process_name=event.get("process"),
    command_line=event.get("command_line"),
    parent_process_name=event.get("parent_process"),
    file_name=event.get("file_name"),
    network_destination=event.get("dest_ip"),
    raw=event,
)
```
The `raw=event` passes the normalized event. BUT the normalized event from `collection_agent.py` may not preserve the original `rule.groups` structure. The normalized schema is: `event_type, timestamp, host, user, process, src_ip, dest_ip, raw_source`. If `rule.groups` is not in this normalized output, the matcher won't find it.

**This is the real root cause:** The SSH brute force event gets normalized and the `rule.groups` information is lost. The deterministic matcher can't match `T1110` because `rule.groups` is missing from the normalized event. The LLM then can't map it either (no grounding context → skips). So techniques list is empty. But then the reporting LLM, seeing an SSH brute force event, uses its own knowledge to insert T1110 — hallucination.

---

## 6. Quality Scores

### Report 3.1: `report_e3b0c442-98fc-1c14-9a2b-5f3e1d2a4b6c.md` (SSH BF)
| Criterion | Score | Rationale |
|-----------|-------|-----------|
| Technical accuracy | 8/10 | Correct on all technical details |
| Evidence consistency | 9/10 | Sticks closely to evidence |
| Threat Intelligence enrichment | 8/10 | Correctly uses AbuseIPDB data only |
| MITRE ATT&CK mapping | 9/10 | Correctly reports "None mapped" |
| Response recommendations | 7/10 | Good but generic recommendations |
| **Overall reliability** | **8/10** | Minor OTX false positive in validator, otherwise solid |

### Report 3.2: `report_e3b0c442-98fc-1c14-9a3b-0d5f6e8a1b2c.md` (SSH BF)
| Criterion | Score | Rationale |
|-----------|-------|-----------|
| Technical accuracy | 6/10 | T1110 claimed but not in evidence |
| Evidence consistency | 6/10 | Contradicts its own technique list |
| Threat Intelligence enrichment | 8/10 | Good use of AbuseIPDB |
| MITRE ATT&CK mapping | 3/10 | Claims T1110 without evidence |
| Response recommendations | 7/10 | Reasonable but generic |
| **Overall reliability** | **5/10** | Hallucinates one technique |

### Report 3.3: `report_e3b0c442-98fc-4f3e-9b5d-1a2b3c4d5e6f.md` (SSH BF)
| Criterion | Score | Rationale |
|-----------|-------|-----------|
| Technical accuracy | 6/10 | Same T1110 hallucination |
| Evidence consistency | 6/10 | Same issue |
| Threat Intelligence enrichment | 8/10 | Good |
| MITRE ATT&CK mapping | 2/10 | T1110 + T1110.3 both fabricated |
| Response recommendations | 6/10 | Overly broad |
| **Overall reliability** | **5/10** | Same hallucination pattern |

### Report 3.4: `report_e7b3c1d2-4f9a-4b8e-9c3d-1a2b3c4d5e6f.md` (SSH BF) — WORST
| Criterion | Score | Rationale |
|-----------|-------|-----------|
| Technical accuracy | 1/10 | Nearly every substantive claim is fabricated |
| Evidence consistency | 1/10 | ~80% of content has no evidentiary basis |
| Threat Intelligence enrichment | 2/10 | Uses real AbuseIPDB data but adds fabricated IOCs |
| MITRE ATT&CK mapping | 1/10 | 5 techniques invented, none in evidence |
| Response recommendations | 2/10 | Reasonable recommendations but claims actions completed |
| **Overall reliability** | **1/10** | Dangerously unreliable, should be quarantined |

### Report 3.5: `report_e7b3f9c2-4d1a-4f6b-9c3e-2a1f5d8b6c4e.md` (SSH BF) — BEST SSH
| Criterion | Score | Rationale |
|-----------|-------|-----------|
| Technical accuracy | 9/10 | All claims supported |
| Evidence consistency | 10/10 | Perfect adherence to evidence |
| Threat Intelligence enrichment | 8/10 | Correctly uses AbuseIPDB |
| MITRE ATT&CK mapping | 10/10 | Correctly states "No technique mapping available" |
| Response recommendations | 8/10 | Well-grounded, specific recommendations |
| **Overall reliability** | **9/10** | Model behavior for evidence-constrained reporting |

### Report 3.6: `report_e3b0c442-98fc-1c14-9a2b-5f6d7e8f9a0b.md` (PowerShell)
| Criterion | Score | Rationale |
|-----------|-------|-----------|
| Technical accuracy | 8/10 | Events and techniques accurate |
| Evidence consistency | 7/10 | Technique mapping correct, but APT groups misleading |
| Threat Intelligence enrichment | 7/10 | No IOCs to enrich, N/A |
| MITRE ATT&CK mapping | 7/10 | Correct techniques, over-sharing known groups |
| Response recommendations | 7/10 | Appropriate but generic |
| **Overall reliability** | **7/10** | Good but APT group list in report is misleading |

### Report 3.7: `report_e3f9c2a1-4b7d-4e6a-9f2c-1a2b3c4d5e6f.md` (PowerShell)
| Criterion | Score | Rationale |
|-----------|-------|-----------|
| Technical accuracy | 8/10 | Similar to 3.6 |
| Evidence consistency | 7/10 | Same APT group issue |
| Threat Intelligence enrichment | 7/10 | N/A |
| MITRE ATT&CK mapping | 7/10 | Same issue |
| Response recommendations | 7/10 | Good |
| **Overall reliability** | **7/10** | Good but missing validation section |

### Report 3.8: `report_e3b0c442-98fc-1c14-9a6b-3f5e8d2a1c4f.md` (C2 Beacon) — BEST OVERALL
| Criterion | Score | Rationale |
|-----------|-------|-----------|
| Technical accuracy | 10/10 | Perfect |
| Evidence consistency | 10/10 | Perfect adherence |
| Threat Intelligence enrichment | 9/10 | Correctly reports benign IOC |
| MITRE ATT&CK mapping | 10/10 | Correctly states none mapped |
| Response recommendations | 9/10 | Conservative and appropriate |
| **Overall reliability** | **10/10** | Exemplary report |

### Report 3.9: `report_e7b8c3d4-5f6a-7b8c-9d0e-1f2a3b4c5d6e.md` (C2 Beacon)
| Criterion | Score | Rationale |
|-----------|-------|-----------|
| Technical accuracy | 9/10 | All claims accurate |
| Evidence consistency | 9/10 | Strong evidence adherence |
| Threat Intelligence enrichment | 8/10 | Good |
| MITRE ATT&CK mapping | 10/10 | Correctly states none |
| Response recommendations | 8/10 | Good, actionable |
| **Overall reliability** | **9/10** | Excellent but missing validation section |

---

## 7. Summary Statistics

| Metric | Value |
|--------|-------|
| Total reports audited | 9 |
| Reports with hallucinations | 3 (3.2, 3.3, 3.4) |
| Reports with critical hallucinations | 1 (3.4) |
| Reports fully evidence-consistent | 6 |
| Reports missing validation section | 3 |
| Total hallucinated techniques | 7 (T1110×3, T1110.3, T1078, T1046, T1190) |
| Total fabricated timeline events | 6+ |
| Total fabricated response actions | 5 |
| Total fabricated IOCs | 4 (hostname, service ports, first seen) |

**System reliability score (all reports averaged):**
- Technical accuracy: 7.2/10
- Evidence consistency: 7.2/10
- Threat Intelligence enrichment: 7.2/10
- MITRE ATT&CK mapping: 6.6/10
- Response recommendations: 6.8/10
- **Overall reliability: 6.8/10** ⚠️

---

## 8. Recommended Code Fixes (Priority Order)

### P0 — Prevent report saving when critical hallucinations detected
**File:** `agents/reporting_agent.py`
```python
# After validation, reject reports with fabricated timelines or response actions
CRITICAL_ISSUE_PATTERNS = [
    "Timeline hallucination",
    "Response action hallucination",
]
has_critical = any(
    any(pattern in issue for pattern in CRITICAL_ISSUE_PATTERNS)
    for issue in validation_result['issues']
)
if has_critical:
    logger.error(f"REJECTING report with critical hallucinations")
    return "(Report rejected due to critical hallucinations)"
```

### P1 — Post-process LLM output to enforce evidence fidelity
**File:** `agents/reporting_agent.py` (add after `invoke_llm` call)
- Strip any technique ID (T\d{4}(?:\.\d{3})?) not in `state['techniques']`
- Strip any timestamp not in evidence events
- Strip any "[Cc]ompleted" status in Response Actions section if no actions completed in evidence

### P2 — Preserve raw event fields through normalization
**File:** Agents that normalize events (collection_agent.py)
- Ensure `rule.groups`, `rule.level`, `rule.description` are preserved in the normalized event
- This fixes the SSH brute force → T1110 deterministic match

### P3 — Add IOC field validation to ReportValidator
**File:** `agents/report_validator.py`
- Add `_validate_ioc_fields()` that checks `first_seen`, `last_seen`, `reputation`, `confidence` values match IOC evidence
- Add `_validate_ioc_values()` that checks no fabricated hostnames or service entries

### P4 — Remove known_groups from report unless campaign has attribution evidence
**File:** `agents/attack_mapping_agent.py` `_enrich()` or `agents/reporting_agent.py`
- Only include known_groups in the technique data if the campaign confidence > 0.5 AND there are at least 2 distinct techniques mapped
- Or strip known_groups from the data passed to the reporting prompt entirely

### P5 — Strengthen REPORTING_SYSTEM_PROMPT 
**File:** `llm/prompts.py`
Add explicit instruction: "The Known Groups and Known Software columns from MITRE enrichment are for analyst reference only. Do NOT include them in the ATT&CK Techniques table of the report unless the campaign assessment specifically identifies a threat actor."

### P6 — Fix validator OTX false positive
**File:** `agents/report_validator.py`
- The current implementation correctly skips Recommendations section, but the error message is misleading. Consider checking if the OTX reference is only in Recommendations before flagging.

### P7 — Add deterministic technique enforcement in reporting_agent
**File:** `agents/reporting_agent.py`
Instead of relying on the LLM to only include mapped techniques, post-process the report markdown to remove any technique ID not in the evidence. This is a safety net that guarantees no MITRE hallucination reaches the final report.

---

## 9. Conclusion

The Agentic Threat Intelligence platform demonstrates a **solid technical foundation** with correct pipeline architecture:

- ✅ IOC extraction is deterministic and well-validated
- ✅ Threat intelligence enrichment (AbuseIPDB) is evidence-based and does not hallucinate
- ✅ ATT&CK mapping has guardrails (deterministic fast path, LLM context verification)
- ✅ Confidence scoring is deterministic
- ✅ ReportValidator exists and catches many issues

However, **the reporting agent is the weakest link**. It relies on an LLM to synthesize evidence into prose, and despite extensive prompt engineering, the LLM still:
1. Invents ATT&CK techniques not in evidence (Pattern 1)
2. Fabricates entire timelines (Pattern 2)
3. Claims response actions that were never taken (Pattern 3)
4. Creates false IOC metadata (Patterns 4, 5)

The validation system catches some of these but **does not prevent** hallucinated reports from being saved (P0 fix). The worst report (3.4) is ~80% fabricated and could cause serious damage if used in a real SOC.

**Bottom line:** The platform produces evidence-consistent reports ~65% of the time. With the P0-P2 code fixes, this can be raised to ~95%. The architecture is fundamentally sound — the issues are in the LLM integration layer, not the intelligence pipeline.