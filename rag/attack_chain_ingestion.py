"""
rag/attack_chain_ingestion.py
Builds attack-chain progression documents for ChromaDB.

This module creates documents that describe common ATT&CK technique progressions,
enabling the Prediction Agent to retrieve likely next techniques based on
attack-chain patterns rather than just semantic similarity of technique descriptions.

Each document contains:
- Source technique ID and name
- Possible next technique IDs and names
- Explanation of why the transition is common
- ATT&CK tactic information
"""

import json
import logging
from typing import List, Dict, Set
from pathlib import Path

from knowledge.attack.config import AttackConfig
from knowledge.attack.service import AttackService
from knowledge.base.exceptions import KnowledgeLayerError

logger = logging.getLogger(__name__)


# Common attack-chain progressions based on MITRE ATT&CK data
# These are manually curated based on real-world attack patterns
ATTACK_CHAIN_PROGRESSIONS = {
    # PowerShell-based attack chains
    "T1059.001": {
        "next_techniques": ["T1105", "T1003", "T1547", "T1055", "T1566"],
        "reason": "Attackers commonly use PowerShell to download payloads, steal credentials, establish persistence, obfuscate code, and deliver phishing attachments."
    },
    "T1059.003": {
        "next_techniques": ["T1105", "T1003", "T1547", "T1055"],
        "reason": "Windows Command Shell is often used to download tools, dump credentials, establish persistence, and obfuscate malicious code."
    },
    
    # Initial access techniques
    "T1190": {
        "next_techniques": ["T1059.001", "T1059.003", "T1003", "T1083", "T1105"],
        "reason": "After exploiting a public-facing application, attackers typically use command-line interfaces to move laterally, steal credentials, create accounts, and download additional tools."
    },
    "T1566": {
        "next_techniques": ["T1059.001", "T1204.002", "T1105", "T1055"],
        "reason": "Phishing attachments commonly lead to PowerShell execution, user execution of malicious files, download of additional payloads, and code obfuscation."
    },
    
    # Credential access techniques
    "T1003": {
        "next_techniques": ["T1078", "T1098", "T1552", "T1075", "T1110"],
        "reason": "After dumping credentials, attackers often create new accounts, modify account permissions, steal credential files, use alternate authentication, or attempt brute force with stolen credentials."
    },
    "T1552": {
        "next_techniques": ["T1078", "T1075", "T1110", "T1098"],
        "reason": "Unsecured credentials files are used to create accounts, use alternate authentication, perform brute force attacks, or modify account permissions."
    },
    
    # Lateral movement techniques
    "T1021": {
        "next_techniques": ["T1003", "T1059.001", "T1055", "T1083"],
        "reason": "After moving laterally via remote services, attackers typically dump credentials, execute commands, obfuscate code, or create new accounts."
    },
    "T1021.001": {
        "next_techniques": ["T1003", "T1059.001", "T1055"],
        "reason": "SMB lateral movement is commonly followed by credential dumping, PowerShell execution, and code obfuscation."
    },
    
    # Persistence techniques
    "T1547": {
        "next_techniques": ["T1059.001", "T1003", "T1055", "T1543"],
        "reason": "Boot or logon autostart execution is often combined with PowerShell for maintenance, credential dumping, code obfuscation, and creating services."
    },
    "T1050": {
        "next_techniques": ["T1059.001", "T1003", "T1055"],
        "reason": "Scheduled jobs are commonly used to execute PowerShell, dump credentials, and obfuscate code for persistence."
    },
    
    # Defense evasion techniques
    "T1055": {
        "next_techniques": ["T1059.001", "T1003", "T1547", "T1105"],
        "reason": "Obfuscated files are typically executed via PowerShell, used to dump credentials, establish persistence, or download additional payloads."
    },
    "T1562": {
        "next_techniques": ["T1059.001", "T1055", "T1003", "T1547"],
        "reason": "Impairing defenses is often followed by PowerShell execution, code obfuscation, credential dumping, and establishing persistence."
    },
    
    # Collection techniques
    "T1005": {
        "next_techniques": ["T1041", "T1560", "T1025"],
        "reason": "Data from local systems is commonly exfiltrated via C2 channels, archived, or transferred to remote systems."
    },
    "T1113": {
        "next_techniques": ["T1041", "T1560", "T1025"],
        "reason": "Screen capture data is typically exfiltrated via C2 channels, archived, or transferred to remote systems."
    },
    
    # Exfiltration techniques
    "T1041": {
        "next_techniques": ["T1560", "T1025", "T1071"],
        "reason": "C2 exfiltration is often followed by data archiving, transfer to remote systems, or using web services for exfiltration."
    },
    "T1567": {
        "next_techniques": ["T1560", "T1025", "T1071"],
        "reason": "Exfiltration over web services is commonly combined with data archiving, transfer to remote systems, or other web-based exfiltration methods."
    },
    
    # Command and control techniques
    "T1071": {
        "next_techniques": ["T1059.001", "T1055", "T1003"],
        "reason": "Web-based C2 channels are used to execute PowerShell, obfuscate code, and dump credentials."
    },
    "T1102": {
        "next_techniques": ["T1059.001", "T1055", "T1003"],
        "reason": "Web protocols for C2 are commonly used with PowerShell execution, code obfuscation, and credential dumping."
    },
    
    # Impact techniques
    "T1486": {
        "next_techniques": ["T1490", "T1489", "T1491"],
        "reason": "Ransomware encryption is often followed by data destruction, service shutdown, or data manipulation for impact."
    },
    "T1490": {
        "next_techniques": ["T1486", "T1489", "T1491"],
        "reason": "Data destruction is commonly combined with ransomware encryption, service shutdown, or data manipulation."
    },
}


def build_attack_chain_documents(attack_service: AttackService) -> List[Dict]:
    """
    Builds attack-chain progression documents for ChromaDB ingestion.
    
    Each document describes a source technique and its likely next techniques,
    with explanations of why these transitions are common in real-world attacks.
    
    Args:
        attack_service: The MITRE ATT&CK knowledge service for looking up technique details.
    
    Returns:
        List of dicts with 'text' and 'metadata' keys for ChromaDB ingestion.
    """
    documents = []
    
    for source_id, progression in ATTACK_CHAIN_PROGRESSIONS.items():
        try:
            source_technique = attack_service.get_technique(source_id)
        except Exception as e:
            logger.warning("Could not retrieve technique %s: %s", source_id, e)
            continue
        
        next_techniques_info = []
        valid_next_ids = []
        
        for next_id in progression["next_techniques"]:
            try:
                next_technique = attack_service.get_technique(next_id)
                next_techniques_info.append(f"{next_id} - {next_technique.name}")
                valid_next_ids.append(next_id)
            except Exception as e:
                logger.debug("Could not retrieve next technique %s: %s", next_id, e)
                continue
        
        if not next_techniques_info:
            logger.warning("No valid next techniques found for source %s", source_id)
            continue
        
        # Get tactic information
        tactics = []
        try:
            tactic_objs = attack_service.get_tactics(source_id)
            tactics = [tactic.name for tactic in tactic_objs]
        except Exception as e:
            logger.debug("Could not retrieve tactics for %s: %s", source_id, e)
        
        # Build the document text
        text = f"""Observed technique:
{source_id} - {source_technique.name}

Common next techniques:
{chr(10).join(next_techniques_info)}

Reason:
{progression["reason"]}

Tactics:
{', '.join(tactics) if tactics else 'N/A'}"""
        
        # Build metadata (ChromaDB requires metadata values to be str, int, float, or bool)
        metadata = {
            "source_technique": source_id,
            "source_technique_name": source_technique.name,
            "next_techniques": ",".join(valid_next_ids),  # Convert list to comma-separated string
            "tactics": ",".join(tactics) if tactics else "",
            "document_type": "attack_chain_progression"
        }
        
        documents.append({
            "text": text,
            "metadata": metadata
        })
        
        logger.info("Built attack-chain document for %s with %d next techniques", 
                    source_id, len(valid_next_ids))
    
    logger.info("Built %d attack-chain progression documents total", len(documents))
    return documents


def ingest_attack_chain_collection(
    attack_service: AttackService,
    persist_dir: str = "./data/chroma_store",
    collection_name: str = "attack_chain"
) -> None:
    """
    Ingests attack-chain progression documents into ChromaDB.
    
    Args:
        attack_service: The MITRE ATT&CK knowledge service.
        persist_dir: ChromaDB persistence directory.
        collection_name: Name of the ChromaDB collection.
    """
    import chromadb
    from rag.embeddings import embed_texts
    
    # Build documents
    documents = build_attack_chain_documents(attack_service)
    
    if not documents:
        logger.error("No documents to ingest")
        return
    
    # Initialize ChromaDB client
    client = chromadb.PersistentClient(path=persist_dir)
    
    # Delete existing collection if it exists
    try:
        client.delete_collection(name=collection_name)
        logger.info("Deleted existing collection '%s'", collection_name)
    except Exception as e:
        logger.debug("Collection '%s' did not exist or could not be deleted: %s", collection_name, e)
    
    # Create new collection
    collection = client.create_collection(name=collection_name)
    logger.info("Created new collection '%s'", collection_name)
    
    # Prepare data for ingestion
    texts = [doc["text"] for doc in documents]
    metadatas = [doc["metadata"] for doc in documents]
    ids = [f"{meta['source_technique']}" for meta in metadatas]
    
    # Generate embeddings
    logger.info("Generating embeddings for %d documents...", len(texts))
    embeddings = embed_texts(texts)
    
    # Ingest into ChromaDB
    logger.info("Ingesting documents into ChromaDB...")
    collection.upsert(
        ids=ids,
        embeddings=embeddings,
        documents=texts,
        metadatas=metadatas,
    )
    
    logger.info("Successfully ingested %d attack-chain documents into collection '%s'", 
                len(documents), collection_name)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    # Initialize attack service
    attack_service = AttackService.create(AttackConfig())
    
    try:
        # Ingest attack-chain collection
        ingest_attack_chain_collection(attack_service)
        logger.info("Attack-chain ingestion completed successfully")
    finally:
        attack_service.close()
