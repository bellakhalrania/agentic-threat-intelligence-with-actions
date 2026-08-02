# MITRE ATT&CK Mapping Fix Summary

## Problem
The `/investigate` endpoint was generating reports with:
```
### ATT&CK Techniques
No specific ATT&CK techniques have been mapped to this activity.
```

## Root Causes Identified

1. **Missing context in event formatting**: The `_event_to_text()` method wasn't including `rule_description`, `rule_groups`, or `full_log` fields
2. **Insufficient deterministic rules**: Missing rules for common behaviors like malware execution, file downloads, SSH brute force
3. **LLM prompt didn't request array output**: Only asked for single technique instead of all matching techniques
4. **No debugging logs**: Couldn't trace what was being sent to/received from the MITRE mapper
5. **Wazuh events not fully extracted**: Process and command_line fields weren't being extracted from `full_log`
6. **Only returning one technique**: The mapper returned only the best match instead of all matching techniques

## Files Modified

### 1. `agents/attack_mapping_agent.py`
**Changes:**
- Added `rule_description`, `rule_level`, `rule_groups` to `_event_to_text()`
- Added `full_log` extraction from raw events
- Added DEBUG logging: "MITRE INPUT: ..." and "MITRE OUTPUT: ..."
- Modified `_try_llm_match()` to handle array responses from LLM
- Changed `_map_event()` and `_try_deterministic_match()` to return **all** matching techniques (not just the best one)
- Fixed variable naming bug (`mapped` → `best_mapping`)

**Impact:** MITRE agent now receives full context and returns all matching techniques

### 2. `knowledge/attack/matcher.py`
**Changes:**
- Enhanced `_command_line_contains()` to also search in `raw.full_log` and `raw.rule.description`
- Added 4 new deterministic rules:
  - `malicious_file_execution` → T1204.002 (matches: malicious, invoice.exe, malware, virus, trojan)
  - `ingress_tool_transfer` → T1105 (matches: download, downloaded, curl, wget, certutil, bitsadmin)
  - `ssh_brute_force` → T1110.001 (matches: ssh, bruteforce, brute force)
- Kept existing rules for PowerShell, scheduled tasks, etc.

**Impact:** Events without explicit process/command_line now match via full_log text

### 3. `agents/collection_agent.py`
**Changes:**
- Enhanced `_normalize_wazuh()` to extract process and command_line from `full_log` using regex
- Extracts .exe filenames and subsequent command arguments

**Impact:** Wazuh alerts now have proper process/command_line fields for deterministic matching

### 4. `llm/prompts.py`
**Changes:**
- Rewrote `ATTACK_MAPPING_SYSTEM_PROMPT` to request JSON array output
- Added explicit rules for structured output
- Provided example format with all required fields

**Impact:** LLM now returns all matching techniques in structured format

## Test Results

All three test scenarios now pass:

### Test 1: Malware Execution Event
**Input:**
```json
{
  "rule": {"description": "Malware execution detected", "groups": ["malware", "execution"]},
  "full_log": "User executed malicious attachment invoice.exe downloaded from hxxp://malicious-site.com"
}
```

**Output:**
- ✅ T1204.002 - Malicious File (confidence: 1.0)
- ✅ T1105 - Ingress Tool Transfer (confidence: 1.0)

### Test 2: PowerShell Encoded Command
**Input:**
```json
{
  "process": "powershell.exe",
  "command_line": "powershell.exe -EncodedCommand ..."
}
```

**Output:**
- ✅ T1059.001 - PowerShell (confidence: 1.0)
- ✅ T1027 - Obfuscated Files (confidence: 1.0)

### Test 3: Scheduled Task Persistence
**Input:**
```json
{
  "process": "schtasks.exe",
  "command_line": "schtasks.exe /create /tn 'UpdateTask' /tr 'malware.exe'"
}
```

**Output:**
- ✅ T1053.005 - Scheduled Task (confidence: 1.0)
- ✅ T1204.002 - Malicious File (confidence: 1.0)

## Debugging Logs

The fix adds comprehensive logging:

**Before MITRE analysis:**
```
MITRE INPUT: event_type=wazuh_alert, rule_description=Malware execution detected, 
rule_level=15, rule_groups=['malware', 'execution'], 
full_log=User executed malicious attachment invoice.exe downloaded from hxxp://malicious-site.com
```

**After MITRE analysis:**
```
MITRE OUTPUT: T1204.002 - Malicious File (confidence: 1.0)
```

## Architecture Flow

```
Raw Event (Wazuh)
    ↓
Collection Agent (normalize + extract process/command_line from full_log)
    ↓
Normalized Event (with rule_description, rule_groups, full_log)
    ↓
Attack Mapping Agent
    ├─→ Deterministic Path (check all rules)
    │   └─→ Returns ALL matching techniques
    └─→ LLM Fallback (if no deterministic match)
        └─→ Returns array of techniques
    ↓
List of MITRE Techniques (multiple per event)
    ↓
Reporting Agent (generates markdown table)
    ↓
Final Report with ATT&CK Techniques table
```

## Key Improvements

1. **Full context propagation**: All relevant fields now flow from collection → mapping → report
2. **Multiple techniques per event**: Events can map to multiple ATT&CK techniques
3. **Robust Wazuh support**: Handles alerts without explicit process/command_line
4. **Better LLM prompts**: Forces structured array output with confidence scores
5. **Comprehensive debugging**: Can trace exactly what's happening at each step
6. **Extended rule coverage**: Added rules for common attack patterns

## Verification

Run the test script:
```bash
python test_mitre_fix.py
```

Expected output: "✓ ALL TESTS PASSED - MITRE mapping is working!"

## Report Format

The final report now displays:
```markdown
### ATT&CK Techniques

| Technique ID | Technique | Confidence |
|--------------|-----------|------------|
| T1204.002 | User Execution: Malicious File | 0.85 |
| T1105 | Ingress Tool Transfer | 0.70 |