from __future__ import annotations

from typing import Any, Dict, List
import httpx

from .config import settings


class OllamaError(RuntimeError):
    pass


async def ollama_chat(messages: List[Dict[str, str]]) -> str:
    url = f"{settings.ollama_base_url}/api/chat"
    payload: Dict[str, Any] = {
        "model": settings.ollama_model,
        "messages": messages,
        "stream": False,
    }

    timeout = httpx.Timeout(300.0, connect=10.0, read=300.0, write=60.0)


    #  IMPORTANT on Windows: ignore proxy env / system proxy
    async with httpx.AsyncClient(timeout=timeout, trust_env=False) as client:
        try:
            resp = await client.post(url, json=payload)
        except httpx.RequestError as e:
            # show real root cause
            raise OllamaError(f"Ollama unreachable: {repr(e)}") from e

    if resp.status_code >= 400:
        raise OllamaError(f"Ollama HTTP {resp.status_code}: {resp.text[:500]}")

    data = resp.json()
    content = ((data.get("message") or {}).get("content") or "").strip()
    return content
