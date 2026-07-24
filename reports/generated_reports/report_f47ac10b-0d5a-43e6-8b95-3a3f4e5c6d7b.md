# Threat Intelligence Report

**Campaign:** Unclassified Activity
**Campaign ID:** f47ac10b-0d5a-43e6-8b95-3a3f4e5c6d7b
**Generated:** 2026-07-24T11:20:50.583485+00:00

---

### Executive Summary
A potential lateral movement was detected on the network, utilizing the Service Execution technique (T1569.002) with high confidence. This technique involves the creation of a service on a remote host, in this case, PSEXESVC.exe on HR-PC01 by user root. The confidence level in this assessment is 0.2, indicating a moderate level of certainty in the campaign's objective and activities.

### Timeline
- **2026-07-21T09:15:30Z**: A wazuh_alert event was triggered on host FINANCE-PC, indicating the creation of PSEXESVC.exe on remote host HR-PC01 by user root.

### IOCs
No IOCs are available for this incident.

### ATT&CK Techniques
| Attack ID | Technique Name | Confidence |
| --- | --- | --- |
| T1569.002 | Service Execution | 1.0 |

### Campaign Assessment
The campaign, identified as 'Unclassified Activity', has an objective that is currently unknown. The evidence suggests the use of the Service Execution technique (T1569.002) with high confidence, as indicated by the creation of PSEXESVC.exe on a remote host. The confidence in the campaign assessment is 0.2.

### Predicted Next Steps
No likely next techniques were predicted due to the lack of suitable follow-on techniques in the knowledge base.

### Recommendations
Based on the confirmed technique T1569.002 (Service Execution), it is recommended to implement the following mitigations:
- Privileged Account Management
- Behavior Prevention on Endpoint
- Restrict File and Directory Permissions

### Response Actions
| Action Type | Target | Status | Severity | Rationale |
| --- | --- | --- | --- | --- |
| notify_analyst | FINANCE-PC and HR-PC01 | pending_approval | medium | Potential lateral movement detected using Service Execution technique (T1569.002) |
| kill_process | PSEXESVC.exe on HR-PC01 | pending_approval | medium | PSEXESVC.exe was created on remote host HR-PC01, indicating potential malicious activity |