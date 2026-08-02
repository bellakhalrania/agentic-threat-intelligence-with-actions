"""
rag/attack_chain_retriever.py
Given a sequence of already-mapped techniques (a partial attack chain),
retrieve ATT&CK techniques that commonly follow them - used by the
Prediction Agent in addition to raw LLM reasoning, to ground predictions
in retrieved ATT&CK knowledge rather than pure model guesswork.

Now queries the dedicated attack_chain ChromaDB collection which contains
documents describing technique progressions rather than individual technique
descriptions.
"""

import logging
from typing import Tuple, Set
from rag.vector_store import query_attack_chain

logger = logging.getLogger(__name__)


def retrieve_likely_next_techniques_with_ids(
    technique_names: list[str], n_results: int = 5
) -> Tuple[str, Set[str]]:
    """
    Retrieves attack-chain progression documents for given observed techniques
    and returns both the formatted context text AND the set of candidate technique
    IDs found in the results.

    The candidate ID set is used by PredictionAgent as a constraint: the LLM
    may only predict technique IDs that appear in this set, preventing it from
    inventing IDs from training data.

    Now queries the attack_chain collection which contains documents describing
    common technique progressions (e.g., "After T1059.001 PowerShell, attackers
    commonly use T1105 Ingress Tool Transfer to download payloads").

    Args:
        technique_names: List of observed technique names.
        n_results: Number of progression documents to retrieve.

    Returns:
        Tuple of (context_text: str, candidate_ids: set[str])
    """
    if not technique_names:
        return "No techniques observed yet.", set()

    query = "Attack chain progression following: " + ", ".join(technique_names)
    
    logger.info("ATTACK_CHAIN_RETRIEVER: Query: %s", query)
    
    results = query_attack_chain(query, n_results=n_results)
    
    documents = results.get("documents", [[]])[0]
    metadatas = results.get("metadatas", [[]])[0]
    
    logger.info("ATTACK_CHAIN_RETRIEVER: Retrieved %d documents", len(documents))

    if not documents:
        logger.warning("ATTACK_CHAIN_RETRIEVER: No documents found for query")
        return "No related techniques found.", set()

    candidate_ids: Set[str] = set()
    blocks = []
    
    for doc, meta in zip(documents, metadatas):
        # Extract next techniques from metadata (stored as comma-separated string)
        next_techniques_str = meta.get("next_techniques", "")
        if next_techniques_str:
            # Split comma-separated string back into list
            next_techniques = [t.strip() for t in next_techniques_str.split(",") if t.strip()]
            candidate_ids.update(next_techniques)
        
        # Format the document for context
        source_tech = meta.get("source_technique", "Unknown")
        source_name = meta.get("source_technique_name", "")
        block = f"[{source_tech} - {source_name}]\n{doc}"
        blocks.append(block)
    
    logger.info("ATTACK_CHAIN_RETRIEVER: Candidate IDs extracted: %s", sorted(candidate_ids))
    
    return "\n\n".join(blocks), candidate_ids


def retrieve_likely_next_techniques(technique_names: list[str], n_results: int = 5) -> str:
    """
    Legacy wrapper — returns only the context text.
    Prefer retrieve_likely_next_techniques_with_ids() for new callers.
    """
    context, _ = retrieve_likely_next_techniques_with_ids(technique_names, n_results)
    return context
