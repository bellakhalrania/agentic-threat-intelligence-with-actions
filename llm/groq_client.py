"""
llm/groq_client.py
Single, shared connection to Groq's LLM API. Every agent imports `llm`
from this module instead of creating its own client, so model/config
changes happen in one place.
"""

import time
from langchain_groq import ChatGroq
from groq import RateLimitError
from config import config

llm = ChatGroq(
    api_key=config.GROQ_API_KEY,
    model=config.GROQ_MODEL,
    temperature=config.GROQ_TEMPERATURE,
)


def invoke_llm(system_prompt: str, user_prompt: str, max_retries: int = 3) -> str:
    """Convenience wrapper for a single-turn system+user call with retry logic.
    
    Args:
        system_prompt: The system prompt for the LLM
        user_prompt: The user prompt for the LLM
        max_retries: Maximum number of retry attempts for rate limit errors
    
    Returns:
        The LLM response content
    
    Raises:
        RateLimitError: If max retries are exceeded
    """
    messages = [
        ("system", system_prompt),
        ("human", user_prompt),
    ]
    
    for attempt in range(max_retries + 1):
        try:
            response = llm.invoke(messages)
            return response.content
        except RateLimitError as e:
            if attempt == max_retries:
                raise
            # Extract retry delay from error message if available, otherwise use exponential backoff
            retry_delay = 2 ** attempt  # 1s, 2s, 4s
            print(f"Rate limit hit. Retrying in {retry_delay}s... (attempt {attempt + 1}/{max_retries})")
            time.sleep(retry_delay)
