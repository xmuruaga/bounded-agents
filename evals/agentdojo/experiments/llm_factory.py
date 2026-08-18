"""
LLM factory — config-driven, provider-agnostic.

All configuration comes from .env (or environment variables).
Supports two providers:
  - "bedrock"   → AnthropicBedrock (ABSK API key or IAM)
  - "anthropic" → Anthropic (direct API key)
"""

from __future__ import annotations

import os
import re
import ssl
from collections.abc import Sequence
from pathlib import Path

from dotenv import load_dotenv

from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement
from agentdojo.agent_pipeline.llms.anthropic_llm import (
    _anthropic_to_assistant_message,
    _conversation_to_anthropic,
    _function_to_anthropic,
)
from agentdojo.functions_runtime import EmptyEnv, Env, FunctionsRuntime
from agentdojo.types import ChatMessage

# Load .env from the agentdojo benchmark root
load_dotenv(Path(__file__).resolve().parent.parent / ".env")


def _ssl_verify() -> bool:
    val = os.getenv("SSL_VERIFY", "true").lower()
    return val not in ("false", "0", "no")


def _disable_ssl_verification() -> None:
    _orig = ssl.create_default_context
    def _no_verify(*args, **kwargs):
        ctx = _orig(*args, **kwargs)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx
    ssl.create_default_context = _no_verify


if not _ssl_verify():
    _disable_ssl_verification()


def _get_config() -> dict:
    return {
        "provider": os.getenv("LLM_PROVIDER", "anthropic"),
        "model": os.getenv("LLM_MODEL", "claude-sonnet-4-6"),
        "region": os.getenv("AWS_DEFAULT_REGION", "us-east-1"),
        "bedrock_api_key": os.getenv("AWS_BEARER_TOKEN_BEDROCK", ""),
        "anthropic_api_key": os.getenv("ANTHROPIC_API_KEY", ""),
        "ssl_verify": _ssl_verify(),
    }


class BedrockLLM(BasePipelineElement):
    """LLM pipeline element using Claude via AWS Bedrock (sync client)."""
    name: str | None = None
    _MAX_TOKENS = 4096

    def __init__(self, client, model: str, temperature: float | None = 0.0):
        from anthropic import NOT_GIVEN
        self._not_given = NOT_GIVEN
        self.client = client
        self.model = model
        self.temperature = temperature

    def query(self, query: str, runtime: FunctionsRuntime, env: Env = EmptyEnv(),
              messages: Sequence[ChatMessage] = [], extra_args: dict = {},
    ) -> tuple[str, FunctionsRuntime, Env, Sequence[ChatMessage], dict]:
        system_prompt, anthropic_messages = _conversation_to_anthropic(messages)
        anthropic_tools = [_function_to_anthropic(tool) for tool in runtime.functions.values()]
        completion = self.client.messages.create(
            model=self.model, messages=anthropic_messages,
            tools=anthropic_tools or self._not_given, max_tokens=self._MAX_TOKENS,
            system=system_prompt or self._not_given,
            temperature=self.temperature if self.temperature is not None else self._not_given,
        )
        output = _anthropic_to_assistant_message(completion)
        if output["tool_calls"] is not None:
            invalid = [i for i, tc in enumerate(output["tool_calls"])
                       if re.match(r"^[a-zA-Z0-9_-]{1,64}$", tc.function) is None]
            for idx in sorted(invalid, reverse=True):
                del output["tool_calls"][idx]
        messages = [*messages, output]
        return query, runtime, env, messages, extra_args


def make_llm(model: str | None = None, provider: str | None = None) -> BasePipelineElement:
    cfg = _get_config()
    provider = provider or cfg["provider"]
    model = model or cfg["model"]

    if provider == "bedrock":
        from anthropic import AnthropicBedrock
        kwargs: dict = {"aws_region": cfg["region"]}
        if cfg["bedrock_api_key"]:
            kwargs["api_key"] = cfg["bedrock_api_key"]
        client = AnthropicBedrock(**kwargs)
        llm = BedrockLLM(client, model)
    elif provider == "anthropic":
        from anthropic import Anthropic
        from agentdojo.agent_pipeline.llms.anthropic_llm import AnthropicLLM
        kwargs = {}
        if cfg["anthropic_api_key"]:
            kwargs["api_key"] = cfg["anthropic_api_key"]
        client = Anthropic(**kwargs)
        llm = AnthropicLLM(client, model)
    else:
        raise ValueError(f"Unknown LLM_PROVIDER='{provider}'.")

    llm.name = model
    return llm


DEFAULT_MODEL = _get_config()["model"]
