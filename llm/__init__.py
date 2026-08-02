"""
llm/
LLM integration package for the Agentic Threat Intelligence Platform.
"""

from .groq_client import llm, invoke_llm

__all__ = ["llm", "invoke_llm"]