"""
rag/vector_store.py
Connects to a local persistent ChromaDB instance and exposes simple
add/query helpers for the ATT&CK technique collection.
"""

import chromadb
from config import config
from rag.embeddings import embed_texts

_client = None


def get_client():
    global _client
    if _client is None:
        _client = chromadb.PersistentClient(path=config.CHROMA_PERSIST_DIR)
    return _client


def get_attack_collection():
    client = get_client()
    try:
        return client.get_or_create_collection(name=config.CHROMA_COLLECTION_ATTACK)
    except (KeyError, Exception) as e:
        # Handle corrupted ChromaDB data by recreating the collection
        print(f"ChromaDB collection error: {e}. Recreating collection...")
        try:
            client.delete_collection(name=config.CHROMA_COLLECTION_ATTACK)
        except:
            pass
        return client.create_collection(name=config.CHROMA_COLLECTION_ATTACK)


def add_chunks(chunks: list[dict]):
    """chunks: list of {text, metadata} dicts (see rag/chunking.py)."""
    if not chunks:
        return
    collection = get_attack_collection()
    texts = [c["text"] for c in chunks]
    metadatas = [c["metadata"] for c in chunks]
    ids = [f"{m.get('technique_id', 'unknown')}-{i}" for i, m in enumerate(metadatas)]
    embeddings = embed_texts(texts)

    collection.upsert(
        ids=ids,
        embeddings=embeddings,
        documents=texts,
        metadatas=metadatas,
    )


def query_similar(query_text: str, n_results: int = 3) -> dict:
    collection = get_attack_collection()
    embedding = embed_texts([query_text])[0]
    return collection.query(query_embeddings=[embedding], n_results=n_results)


def get_attack_chain_collection():
    """Get or create the attack_chain collection for progression-based predictions."""
    client = get_client()
    try:
        return client.get_or_create_collection(name=config.CHROMA_COLLECTION_ATTACK_CHAIN)
    except (KeyError, Exception) as e:
        # Handle corrupted ChromaDB data by recreating the collection
        print(f"ChromaDB collection error: {e}. Recreating collection...")
        try:
            client.delete_collection(name=config.CHROMA_COLLECTION_ATTACK_CHAIN)
        except:
            pass
        return client.create_collection(name=config.CHROMA_COLLECTION_ATTACK_CHAIN)


def query_attack_chain(query_text: str, n_results: int = 5) -> dict:
    """Query the attack_chain collection for progression-based predictions."""
    collection = get_attack_chain_collection()
    embedding = embed_texts([query_text])[0]
    return collection.query(query_embeddings=[embedding], n_results=n_results)
