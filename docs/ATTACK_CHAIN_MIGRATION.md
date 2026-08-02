# Attack-Chain Prediction Migration Guide

## Overview

This migration upgrades the Prediction Agent's RAG knowledge base from individual ATT&CK technique descriptions to attack-chain progression documents. This enables the agent to retrieve likely next techniques based on common attack patterns rather than just semantic similarity.

## What Changed

### Before
- ChromaDB collection: `attack_techniques`
- Documents: Individual technique descriptions
- Query: "Attack chain progression following: PowerShell"
- Result: Semantically similar techniques (not necessarily next steps)

### After
- ChromaDB collection: `attack_chain` (new)
- Documents: Attack-chain progression documents with:
  - Source technique ID and name
  - Possible next technique IDs and names
  - Explanation of why the transition is common
  - ATT&CK tactic information
- Query: "Attack chain progression following: PowerShell"
- Result: Documents describing common progressions (e.g., "After T1059.001 PowerShell, attackers commonly use T1105 Ingress Tool Transfer")

## Migration Steps

### Step 1: Update Configuration

The `config.py` has been updated with a new collection name:

```python
CHROMA_COLLECTION_ATTACK_CHAIN = os.getenv("CHROMA_COLLECTION_ATTACK_CHAIN", "attack_chain")
```

No action required - this is already done.

### Step 2: Generate the New Collection

Run the attack-chain ingestion script to build the new ChromaDB collection:

```bash
PYTHONPATH=/home/rania/Documents/agentic-threat-intelligence-with-actions python rag/attack_chain_ingestion.py
```

This script:
- Reads curated attack-chain progressions from `ATTACK_CHAIN_PROGRESSIONS`
- Validates each technique against the MITRE ATT&CK knowledge layer
- Builds documents with source technique, next techniques, and explanations
- Ingests 18 documents into the `attack_chain` ChromaDB collection

**Expected output:**
```
INFO: Built attack-chain document for T1059.001 with 5 next techniques
INFO: Built attack-chain document for T1059.003 with 4 next techniques
...
INFO: Built 18 attack-chain progression documents total
INFO: Successfully ingested 18 attack-chain documents into collection 'attack_chain'
```

### Step 3: Verify the Collection

Run the test script to verify the new attack-chain retrieval works:

```bash
PYTHONPATH=/home/rania/Documents/agentic-threat-intelligence-with-actions python test_attack_chain_prediction.py
```

**Expected output:**
- Query: "Attack chain progression following: PowerShell"
- Retrieved 5 documents
- Candidate IDs: ['T1003', 'T1055', 'T1059.001', 'T1059.003', 'T1083', 'T1105', 'T1204.002', 'T1547', 'T1566']
- Predicted techniques: T1105 (Ingress Tool Transfer), T1003 (OS Credential Dumping)

### Step 4: (Optional) Remove Old Collection

The old `attack_techniques` collection is no longer used by the Prediction Agent. You can remove it to save space:

```bash
python -c "
import chromadb
from config import config

client = chromadb.PersistentClient(path=config.CHROMA_PERSIST_DIR)
try:
    client.delete_collection(name=config.CHROMA_COLLECTION_ATTACK)
    print(f'Deleted collection: {config.CHROMA_COLLECTION_ATTACK}')
except Exception as e:
    print(f'Could not delete collection: {e}')
"
```

**Note:** Keep the old collection if other parts of your system still use it.

## Hallucination Protections (Unchanged)

All existing hallucination protections remain in place:

1. **Candidate-set constraint**: LLM can only predict IDs from RAG-returned candidate set
2. **Knowledge-layer validation**: Every predicted ID is validated against MITRE AttackService
3. **Deprecated ID rejection**: IDs not in current ATT&CK version are discarded
4. **Fail-closed behavior**: If validation fails, no predictions are returned

## Debug Logs

The following debug logs have been added:

### Attack Chain Retriever (`rag/attack_chain_retriever.py`)
- `ATTACK_CHAIN_RETRIEVER: Query: <query>` - Shows the retrieval query
- `ATTACK_CHAIN_RETRIEVER: Retrieved <n> documents` - Shows number of documents retrieved
- `ATTACK_CHAIN_RETRIEVER: Candidate IDs extracted: <ids>` - Shows extracted candidate IDs

### Prediction Agent (`agents/prediction_agent.py`)
- `PREDICTION_AGENT: Observed techniques: <names>` - Shows input techniques
- `PREDICTION_AGENT: RAG context length: <n> characters` - Shows context size
- `PREDICTION_AGENT: Candidate IDs from RAG: <ids>` - Shows candidate IDs
- `PREDICTION_AGENT: Invoking LLM with prompt...` - Shows LLM invocation
- `PREDICTION_AGENT: LLM response...` - Shows LLM response
- `PREDICTION_AGENT: Parsed LLM result: <result>` - Shows parsed result
- `PREDICTION_AGENT: Techniques predicted by LLM (before validation): <list>` - Shows predictions before validation
- `PREDICTION_AGENT: Techniques after validation: <list>` - Shows final validated predictions
- `PredictionAgent: <n>/<m> predicted techniques passed validation` - Shows validation ratio

## Attack-Chain Progressions

The following 18 attack-chain progressions are currently defined:

| Source Technique | Next Techniques | Reason |
|-----------------|-----------------|--------|
| T1059.001 (PowerShell) | T1105, T1003, T1547, T1055, T1566 | Download payloads, steal credentials, establish persistence |
| T1059.003 (Windows Command Shell) | T1105, T1003, T1547, T1055 | Download tools, dump credentials, establish persistence |
| T1190 (Exploit Public-Facing Application) | T1059.001, T1059.003, T1003, T1083, T1105 | Command execution, credential theft, account creation |
| T1566 (Phishing) | T1059.001, T1204.002, T1105, T1055 | PowerShell execution, malicious files, payload download |
| T1003 (OS Credential Dumping) | T1078, T1098, T1552, T1075, T1110 | Create accounts, modify permissions, steal credential files |
| T1552 (Unsecured Credentials) | T1078, T1075, T1110, T1098 | Create accounts, alternate auth, brute force |
| T1021 (Remote Services) | T1003, T1059.001, T1055, T1083 | Credential dumping, PowerShell execution, code obfuscation |
| T1021.001 (SMB/Windows Admin Shares) | T1003, T1059.001, T1055 | Credential dumping, PowerShell execution, code obfuscation |
| T1547 (Boot or Logon Autostart) | T1059.001, T1003, T1055, T1543 | PowerShell maintenance, credential dumping, code obfuscation |
| T1055 (Obfuscated Files/Information) | T1059.001, T1003, T1547, T1105 | PowerShell execution, credential dumping, persistence |
| T1005 (Data from Local System) | T1041, T1560, T1025 | C2 exfiltration, data archiving, remote transfer |
| T1113 (Screen Capture) | T1041, T1560, T1025 | C2 exfiltration, data archiving, remote transfer |
| T1041 (C2) | T1560, T1025, T1071 | Data archiving, remote transfer, web exfiltration |
| T1567 (Exfiltration Over Web Service) | T1560, T1025, T1071 | Data archiving, remote transfer, web exfiltration |
| T1071 (Web Protocols) | T1059.001, T1055, T1003 | PowerShell execution, code obfuscation, credential dumping |
| T1102 (Web Protocol) | T1059.001, T1055, T1003 | PowerShell execution, code obfuscation, credential dumping |
| T1486 (Data Encrypted for Impact) | T1490, T1489, T1491 | Data destruction, service shutdown, data manipulation |
| T1490 (Data Destruction) | T1486, T1489, T1491 | Ransomware encryption, service shutdown, data manipulation |

## Adding New Progressions

To add new attack-chain progressions:

1. Edit `rag/attack_chain_ingestion.py`
2. Add entries to the `ATTACK_CHAIN_PROGRESSIONS` dictionary:

```python
ATTACK_CHAIN_PROGRESSIONS = {
    # ... existing entries ...
    "T1564.001": {
        "next_techniques": ["T1059.001", "T1105", "T1003"],
        "reason": "After creating hidden files, attackers often use PowerShell to execute commands, download payloads, and dump credentials."
    },
}
```

3. Re-run the ingestion script:

```bash
PYTHONPATH=/home/rania/Documents/agentic-threat-intelligence-with-actions python rag/attack_chain_ingestion.py
```

## Troubleshooting

### Issue: "No documents found for query"

**Cause**: The attack_chain collection doesn't exist or is empty.

**Solution**: Run the ingestion script to build the collection.

### Issue: "Could not retrieve technique TXXXX"

**Cause**: The technique ID in `ATTACK_CHAIN_PROGRESSIONS` doesn't exist in your MITRE ATT&CK knowledge layer.

**Solution**: Remove the invalid technique ID from the progressions dictionary and re-run ingestion.

### Issue: "Candidate IDs from RAG: []"

**Cause**: The query didn't match any documents in the collection.

**Solution**: 
- Verify the collection has documents (check ingestion logs)
- Try a different query (e.g., "PowerShell" instead of "T1059.001")
- Add more progressions to cover your use cases

### Issue: "Predicted techniques after validation: []"

**Cause**: All predicted techniques failed validation (either not in candidate set or not in knowledge layer).

**Solution**: Check the debug logs to see which techniques were rejected and why.

## Rollback

To rollback to the old behavior:

1. Restore the old `attack_chain_retriever.py`:
   - Change import back to `from rag.vector_store import query_similar`
   - Change function call back to `query_similar(query, n_results=n_results)`
   - Restore old metadata extraction logic

2. Delete the new collection:
   ```bash
   python -c "
   import chromadb
   from config import config
   client = chromadb.PersistentClient(path=config.CHROMA_PERSIST_DIR)
   client.delete_collection(name=config.CHROMA_COLLECTION_ATTACK_CHAIN)
   "
   ```

## Summary

- ✅ New `attack_chain` ChromaDB collection created
- ✅ 18 attack-chain progression documents ingested
- ✅ Retriever updated to query new collection
- ✅ Debug logs added for visibility
- ✅ All hallucination protections maintained
- ✅ PowerShell + malware download scenario tested successfully
