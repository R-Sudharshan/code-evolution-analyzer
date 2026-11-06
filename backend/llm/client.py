import json
import time

from backend.config import (
    OPENAI_API_KEY,
    OPENAI_BASE_URL,
    OPENAI_MODEL,
    OPENAI_TIMEOUT,
    OPENAI_MAX_RETRIES,
)


class LLMDisabled(RuntimeError):
    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(reason)


class LLMError(RuntimeError):
    pass


def llm_status() -> dict:
    if not OPENAI_API_KEY:
        return {
            "enabled": False,
            "reason": "OPENAI_API_KEY (or PENTAI_OPENAI_API_KEY) is not set. "
            "The reasoning agent requires an OpenAI-compatible API key: "
            "export OPENAI_API_KEY=sk-... ; optionally OPENAI_BASE_URL, PENTAI_OPENAI_MODEL.",
            "model": OPENAI_MODEL,
            "base_url": OPENAI_BASE_URL,
        }
    return {"enabled": True, "model": OPENAI_MODEL, "base_url": OPENAI_BASE_URL}


class LLMClient:
    def __init__(self):
        self.client = None
        if OPENAI_API_KEY:
            try:
                from openai import OpenAI

                self.client = OpenAI(
                    api_key=OPENAI_API_KEY,
                    base_url=OPENAI_BASE_URL,
                    timeout=OPENAI_TIMEOUT,
                    max_retries=OPENAI_MAX_RETRIES,
                )
            except Exception as e:  # pragma: no cover
                raise LLMDisabled(f"openai client init failed: {e}") from e

    def chat_json(self, system: str, user: str, schema_name: str = "result") -> dict:
        if not self.client:
            raise LLMDisabled(llm_status()["reason"])
        from backend.storage import repos

        messages = [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ]
        cache_key = f"llm::{hash(messages[0]['content'] + '\u241f' + messages[1]['content'])}"
        cached = repos.llm_cache().get(cache_key)
        if cached:
            return cached["result"]
        try:
            resp = self.client.chat.completions.create(
                model=OPENAI_MODEL,
                messages=messages,
                response_format={"type": "json_object"},
                temperature=0.1,
            )
        except Exception as e:
            raise LLMError(f"LLM API error: {e}") from e
        content = resp.choices[0].message.content or ""
        try:
            data = json.loads(content or "")
        except Exception as e:
            raise LLMError(f"LLM returned non-JSON content: {content[:200]!r}") from e
        repos.llm_cache().put(
            cache_key,
            {"result": data, "model": OPENAI_MODEL, "created_at": time.strftime("%Y-%m-%dT%H:%M:%S%z")},
        )
        return data
