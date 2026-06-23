from __future__ import annotations

from ..credentials import decrypt_credentials
from .anthropic import AnthropicClient
from .base import ChatClient
from .google import GeminiClient
from .openai_compat import OpenAICompatClient


def _api_key(p) -> str:
    creds = decrypt_credentials(p.api_key_encrypted) if p.api_key_encrypted else None
    return (creds or {}).get("api_key", "") if creds else ""


def build_client(p) -> ChatClient:
    """Construct the adapter for an LlmProvider row. Raises ValueError on an
    unknown provider kind (should never happen — schema validates the kind)."""
    key = _api_key(p)
    if p.provider in ("openai", "openai_compatible", "azure_openai"):
        return OpenAICompatClient(
            provider=p.provider, model=p.model, base_url=p.base_url, api_key=key,
            azure_deployment=p.azure_deployment, azure_api_version=p.azure_api_version,
            extra=p.extra)
    if p.provider == "anthropic":
        return AnthropicClient(model=p.model, api_key=key, base_url=p.base_url, extra=p.extra)
    if p.provider == "google":
        return GeminiClient(model=p.model, api_key=key, base_url=p.base_url, extra=p.extra)
    raise ValueError(f"unknown provider kind {p.provider!r}")
