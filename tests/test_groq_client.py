from types import SimpleNamespace
from unittest.mock import Mock, patch

import httpx
import llm.groq_client as groq_client
from groq import RateLimitError


def test_gpt_oss_model_has_on_demand_token_limit():
    assert groq_client.get_model_token_limit("openai/gpt-oss-120b") == 8000
    assert groq_client.llm.max_tokens == groq_client.RESERVED_TOKENS


def test_invoke_llm_truncates_prompt_with_safety_margin():
    fake_llm = Mock()
    fake_llm.invoke.return_value = SimpleNamespace(content="ok")
    system_prompt = "system " * 100
    user_prompt = "user " * 10000

    with patch.object(groq_client, "llm", fake_llm), patch.object(
        groq_client.config, "GROQ_MODEL", "openai/gpt-oss-120b"
    ):
        result = groq_client.invoke_llm(system_prompt, user_prompt)

    assert result == "ok"
    sent_messages = fake_llm.invoke.call_args.args[0]
    sent_user_prompt = sent_messages[1][1]
    max_user_tokens = (
        groq_client.get_model_token_limit("openai/gpt-oss-120b")
        - groq_client.RESERVED_TOKENS
        - groq_client.TOKEN_SAFETY_MARGIN
        - groq_client.estimate_token_count(system_prompt)
    )
    assert groq_client.estimate_token_count(sent_user_prompt) <= max_user_tokens
    assert len(sent_user_prompt) < len(user_prompt)


def test_invoke_llm_switches_to_fallback_key_after_rate_limit():
    first_llm = Mock()
    second_llm = Mock()
    first_llm.invoke.side_effect = RateLimitError(
        "rate limited",
        response=httpx.Response(429, request=httpx.Request("POST", "https://api.groq.com")),
        body=None,
    )
    second_llm.invoke.return_value = SimpleNamespace(content="fallback response")

    with patch.object(groq_client, "llm_clients", [first_llm, second_llm]), patch.object(
        groq_client, "llm", first_llm
    ), patch.object(groq_client.time, "sleep"):
        result = groq_client.invoke_llm("system", "user", max_retries=0)

    assert result == "fallback response"
    first_llm.invoke.assert_called_once()
    second_llm.invoke.assert_called_once()