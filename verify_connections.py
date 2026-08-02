#!/usr/bin/env python3
"""
verify_connections.py
Test all API keys and service connections to verify they are working correctly.
Run this script to ensure your configuration is valid before using the platform.
"""

import os
import sys
from dotenv import load_dotenv
from config import config

# Load environment variables
load_dotenv()

# Prints a formatted section header
def print_header(text):
    """Print a formatted header"""
    print(f"\n{'='*60}")
    print(f"  {text}")
    print(f"{'='*60}\n")

# Prints a success message with a checkmark
def print_success(text):
    """Print success message"""
    print(f"✅ {text}")

# Prints an error message with a cross mark
def print_error(text):
    """Print error message"""
    print(f"❌ {text}")

# Prints a warning message with a warning icon
def print_warning(text):
    """Print warning message"""
    print(f"⚠️  {text}")

# Checks that the Groq LLM API key is set and can be used to get a response
def check_groq_connection():
    """Test Groq API connection"""
    print("Testing Groq API connection...")
    
    if not config.GROQ_API_KEY:
        print_error("GROQ_API_KEY is not set")
        return False
    
    try:
        from llm.groq_client import llm
        from langchain_core.messages import HumanMessage
        
        # Simple test query
        response = llm.invoke([HumanMessage(content="Say 'OK' if you receive this.")])
        
        if "OK" in response.content:
            print_success("Groq API connection successful")
            print(f"   Model: {config.GROQ_MODEL}")
            return True
        else:
            print_error("Groq API returned unexpected response")
            return False
    except Exception as e:
        print_error(f"Groq API connection failed: {e}")
        return False

# Checks that the AbuseIPDB API key is valid by querying a known test IP
def check_abuseipdb_connection():
    """Test AbuseIPDB API connection"""
    print("Testing AbuseIPDB API connection...")
    
    if not config.ABUSEIPDB_API_KEY:
        print_warning("ABUSEIPDB_API_KEY is not set (optional)")
        return None
    
    try:
        import requests
        
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {
            "Key": config.ABUSEIPDB_API_KEY,
            "Accept": "application/json"
        }
        params = {
            "ipAddress": "8.8.8.8",  # Test with Google DNS
            "maxAgeInDays": 90
        }
        
        response = requests.get(url, headers=headers, params=params, timeout=10)
        
        if response.status_code == 200:
            print_success("AbuseIPDB API connection successful")
            return True
        elif response.status_code == 401:
            print_error("AbuseIPDB API key is invalid")
            return False
        else:
            print_error(f"AbuseIPDB API returned status {response.status_code}")
            return False
    except Exception as e:
        print_error(f"AbuseIPDB API connection failed: {e}")
        return False

# Checks that the AlienVault OTX API key is valid by fetching the current user profile
def check_otx_connection():
    """Test AlienVault OTX API connection"""
    print("Testing AlienVault OTX API connection...")
    
    if not config.OTX_API_KEY:
        print_warning("OTX_API_KEY is not set (optional)")
        return None
    
    try:
        import requests
        
        # Direct API call to test authentication
        url = "https://otx.alienvault.com/api/v1/user/me"
        headers = {
            "X-OTX-API-KEY": config.OTX_API_KEY
        }
        
        response = requests.get(url, headers=headers, timeout=10)
        
        if response.status_code == 200:
            print_success("AlienVault OTX API connection successful")
            return True
        elif response.status_code == 401:
            print_error("AlienVault OTX API key is invalid")
            return False
        else:
            print_error(f"AlienVault OTX API returned status {response.status_code}")
            return False
    except ImportError:
        print_warning("requests module not installed")
        return None
    except Exception as e:
        print_error(f"AlienVault OTX API connection failed: {e}")
        return False

# Checks connectivity to the Neo4j database and runs a simple test query
def check_neo4j_connection():
    """Test Neo4j database connection"""
    print("Testing Neo4j database connection...")
    
    try:
        from databases.neo4j_manager import Neo4jManager
        
        neo4j = Neo4jManager()
        
        # Test connection
        if neo4j.verify_connectivity():
            result = neo4j.run_query("RETURN 'Connection OK' AS status")
            
            if result and result[0]['status'] == 'Connection OK':
                print_success("Neo4j database connection successful")
                print(f"   URI: {config.NEO4J_URI}")
                print(f"   User: {config.NEO4J_USER}")
                neo4j.close()
                return True
            else:
                print_error("Neo4j query returned unexpected result")
                neo4j.close()
                return False
        else:
            print_error("Neo4j connectivity verification failed")
            neo4j.close()
            return False
    except Exception as e:
        print_error(f"Neo4j database connection failed: {e}")
        return False

# Checks that ChromaDB can be initialized and its collections listed
def check_chromadb_connection():
    """Test ChromaDB connection"""
    print("Testing ChromaDB connection...")
    
    try:
        import chromadb
        from config import config
        
        # Test basic ChromaDB connection
        client = chromadb.PersistentClient(path=config.CHROMA_PERSIST_DIR)
        
        # Try to list collections
        try:
            collections = client.list_collections()
            print_success("ChromaDB connection successful")
            print(f"   Collections: {len(collections)}")
            for col in collections:
                print(f"   - {col.name}")
        except Exception as e:
            # If listing fails, at least verify the client was created
            print_success("ChromaDB connection successful (collection listing skipped)")
            print(f"   Warning: Could not list collections: {e}")
        
        return True
    except Exception as e:
        print_error(f"ChromaDB connection failed: {e}")
        return False

# Checks that the ATT&CK knowledge base is reachable and searchable
def check_attack_knowledge_base():
    """Test ATT&CK knowledge base"""
    print("Testing ATT&CK knowledge base...")
    
    try:
        from knowledge.attack.service import AttackService
        from knowledge.attack.config import AttackConfig, DEFAULT_DATABASE_PATH
        
        with AttackService.create(AttackConfig()) as service:
            # Test a simple query
            techniques = service.search("power", limit=1)
            
            if techniques:
                print_success("ATT&CK knowledge base accessible")
                print(f"   Database path: {DEFAULT_DATABASE_PATH}")
                return True
            else:
                print_warning("ATT&CK knowledge base accessible but no results")
                return True
    except Exception as e:
        print_error(f"ATT&CK knowledge base check failed: {e}")
        return False

# Checks that the Wazuh API is reachable and credentials are valid
def check_wazuh_connection():
    """Test Wazuh API connection"""
    print("Testing Wazuh API connection...")
    
    if not config.WAZUH_API_PASSWORD:
        print_warning("WAZUH_API_PASSWORD is not set (optional)")
        return None
    
    try:
        import requests
        import urllib3
        
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        
        url = f"{config.WAZUH_API_URL}/security/user/authenticate?raw=true"
        auth = (config.WAZUH_API_USER, config.WAZUH_API_PASSWORD)
        
        response = requests.get(url, auth=auth, verify=False, timeout=10)
        
        if response.status_code == 200:
            print_success("Wazuh API connection successful")
            print(f"   URL: {config.WAZUH_API_URL}")
            print(f"   User: {config.WAZUH_API_USER}")
            return True
        elif response.status_code == 401:
            print_error("Wazuh API credentials are invalid")
            return False
        else:
            print_error(f"Wazuh API returned status {response.status_code}")
            return False
    except Exception as e:
        print_error(f"Wazuh API connection failed: {e}")
        return False

# Runs all connection checks and prints a final summary
def main():
    """Run all connection checks"""
    print_header("API Key and Service Connection Verification")
    
    results = {
        "Groq LLM": check_groq_connection(),
        "AbuseIPDB": check_abuseipdb_connection(),
        "AlienVault OTX": check_otx_connection(),
        "Neo4j": check_neo4j_connection(),
        "ChromaDB": check_chromadb_connection(),
        "ATT&CK Knowledge Base": check_attack_knowledge_base(),
        "Wazuh": check_wazuh_connection(),
    }
    
    print_header("Summary")
    
    passed = sum(1 for v in results.values() if v is True)
    failed = sum(1 for v in results.values() if v is False)
    skipped = sum(1 for v in results.values() if v is None)
    
    for service, status in results.items():
        if status is True:
            print_success(f"{service}")
        elif status is False:
            print_error(f"{service}")
        else:
            print_warning(f"{service} (skipped)")
    
    print(f"\nTotal: {passed} passed, {failed} failed, {skipped} skipped")
    
    if failed > 0:
        print("\n❌ Some connections failed. Please check your .env file.")
        sys.exit(1)
    else:
        print("\n✅ All configured connections are working!")
        sys.exit(0)

if __name__ == "__main__":
    main()