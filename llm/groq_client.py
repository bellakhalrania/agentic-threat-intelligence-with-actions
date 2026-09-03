"""
llm/groq_client.py
Single, shared connection to Groq's LLM API. Every agent imports `llm`
from this module instead of creating its own client, so model/config
changes happen in one place.
"""

import time
import logging
from langchain_groq import ChatGroq
from groq import RateLimitError
from config import config

logger = logging.getLogger(__name__)

# Token limits for different models (conservative estimates)
MODEL_TOKEN_LIMITS = {
    "llama-3.1-8b-instant": 6000,  # On-demand tier limit
    "llama-3.3-70b-versatile": 8000,  # On-demand tier limit
    "llama-3.1-70b-versatile": 8000,
    "openai/gpt-oss-120b": 8000,  # On-demand tier limit
    "mixtral-8x7b-32768": 32000,
}

# Reserve tokens for system prompt and response
RESERVED_TOKENS = 1000
# Leave headroom for tokenizer differences and request overhead.
TOKEN_SAFETY_MARGIN = 500
# Approximate characters per token for compact JSON prompts.
CHARS_PER_TOKEN = 3.0

llm = ChatGroq(
    api_key=config.GROQ_API_KEY,
    model=config.GROQ_MODEL,
    temperature=config.GROQ_TEMPERATURE,
    max_tokens=RESERVED_TOKENS,
)


def estimate_token_count(text: str) -> int:
    """Estimate the number of tokens in a text string.
    
    Uses a conservative estimate of ~3.5 characters per token.
    
    Args:
        text: The text to estimate tokens for
        
    Returns:
        Estimated token count
    """
    return int(len(text) / CHARS_PER_TOKEN)


def get_model_token_limit(model_name: str) -> int:
    """Get the token limit for a specific model.
    
    Args:
        model_name: The name of the model
        
    Returns:
        Token limit for the model (defaults to 6000 if unknown)
    """
    return MODEL_TOKEN_LIMITS.get(model_name, 6000)


def truncate_to_token_limit(text: str, max_tokens: int) -> str:
    """Truncate text to fit within token limit.
    
    Args:
        text: The text to truncate
        max_tokens: Maximum number of tokens allowed
        
    Returns:
        Truncated text that fits within the token limit
    """
    estimated_tokens = estimate_token_count(text)
    if estimated_tokens <= max_tokens:
        return text
    
    # Calculate how many characters to keep
    max_chars = int(max_tokens * CHARS_PER_TOKEN)
    truncated = text[:max_chars]
    
    logger.warning(
        f"Text truncated from ~{estimated_tokens} to ~{max_tokens} tokens "
        f"({len(text)} -> {len(truncated)} chars)"
    )
    
    return truncated


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
        ValueError: If the combined prompt exceeds token limits
    """
    model_name = config.GROQ_MODEL
    token_limit = get_model_token_limit(model_name)
    
    # Estimate tokens for system prompt
    system_tokens = estimate_token_count(system_prompt)
    
    # Calculate available tokens for user prompt
    available_tokens = token_limit - RESERVED_TOKENS - TOKEN_SAFETY_MARGIN - system_tokens
    
    if available_tokens <= 0:
        raise ValueError(
            f"System prompt too large: ~{system_tokens} tokens exceeds model limit of {token_limit}"
        )
    
    # Truncate user prompt if necessary
    truncated_user_prompt = truncate_to_token_limit(user_prompt, available_tokens)
    
    messages = [
        ("system", system_prompt),
        ("human", truncated_user_prompt),
    ]
    
    logger.info(
        f"Invoking LLM with model={model_name}, "
        f"system_tokens=~{system_tokens}, user_tokens=~{estimate_token_count(truncated_user_prompt)}, "
        f"total_estimated=~{system_tokens + estimate_token_count(truncated_user_prompt)}"
    )
    
    for attempt in range(max_retries + 1):
        try:
            response = llm.invoke(messages)
            return response.content
        except RateLimitError as e:
            if attempt == max_retries:
                raise
            # Extract retry delay from error message if available, otherwise use exponential backoff
            retry_delay = 2 ** attempt  # 1s, 2s, 4s
            logger.warning(f"Rate limit hit. Retrying in {retry_delay}s... (attempt {attempt + 1}/{max_retries})")
            time.sleep(retry_delay)
