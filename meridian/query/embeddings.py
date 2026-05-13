"""Embedding helpers for the query layer.

Three backends, selected by env (highest precedence first):
  - CF_ACCOUNT_ID + CF_API_TOKEN: Cloudflare Workers AI
    (`@cf/baai/bge-large-en-v1.5`).
  - EMBED_ENDPOINT=https://...: HuggingFace TEI server.
  - neither set: local FastEmbed.

All three produce 1024-d bge-large-en-v1.5 vectors with the bge query
prefix applied per the model's training protocol.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from functools import lru_cache


MODEL_NAME = "BAAI/bge-large-en-v1.5"
QUERY_PREFIX = "Represent this sentence for searching relevant passages: "

EMBED_ENDPOINT = os.environ.get("EMBED_ENDPOINT", "").rstrip("/")
EMBED_TIMEOUT = int(os.environ.get("EMBED_TIMEOUT_SECONDS", "60"))
CF_ACCOUNT_ID = os.environ.get("CF_ACCOUNT_ID", "")
CF_API_TOKEN = os.environ.get("CF_API_TOKEN", "")
CF_MODEL = os.environ.get("CF_EMBED_MODEL", "@cf/baai/bge-large-en-v1.5")


def _backend() -> str:
    if CF_ACCOUNT_ID and CF_API_TOKEN:
        return "cloudflare"
    if EMBED_ENDPOINT:
        return "tei"
    return "fastembed"


@lru_cache(maxsize=1)
def _local_model():
    from fastembed import TextEmbedding
    return TextEmbedding(model_name=MODEL_NAME)


def _embed_remote_tei(texts: list[str]) -> list[list[float]]:
    body = json.dumps({"inputs": texts}).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    api_key = os.environ.get("EMBED_API_KEY")
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    req = urllib.request.Request(
        f"{EMBED_ENDPOINT}/embed", data=body, headers=headers, method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=EMBED_TIMEOUT) as resp:
            return [list(v) for v in json.loads(resp.read())]
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", errors="replace")[:500]
        raise RuntimeError(f"TEI HTTP {e.code}: {detail}") from e
    except (urllib.error.URLError, TimeoutError) as e:
        raise RuntimeError(f"TEI unreachable at {EMBED_ENDPOINT}: {e}") from e


def _embed_remote_cloudflare(texts: list[str]) -> list[list[float]]:
    url = f"https://api.cloudflare.com/client/v4/accounts/{CF_ACCOUNT_ID}/ai/run/{CF_MODEL}"
    body = json.dumps({"text": texts}).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {CF_API_TOKEN}",
    }
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=EMBED_TIMEOUT) as resp:
            payload = json.loads(resp.read())
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", errors="replace")[:500]
        raise RuntimeError(f"Cloudflare AI HTTP {e.code}: {detail}") from e
    except (urllib.error.URLError, TimeoutError) as e:
        raise RuntimeError(f"Cloudflare AI unreachable: {e}") from e
    if not payload.get("success"):
        raise RuntimeError(f"Cloudflare AI errors: {payload.get('errors')}")
    return [list(v) for v in (payload.get("result", {}).get("data") or [])]


def _embed_batch(texts: list[str]) -> list[list[float]]:
    backend = _backend()
    if backend == "cloudflare":
        return _embed_remote_cloudflare(texts)
    if backend == "tei":
        return _embed_remote_tei(texts)
    return [[float(x) for x in v] for v in _local_model().embed(texts)]


def embed_query(query: str) -> list[float]:
    """Embed a single query string with the bge query prefix."""
    text = QUERY_PREFIX + query
    return [float(x) for x in _embed_batch([text])[0]]


def embed_query_batch(queries: list[str]) -> list[list[float]]:
    """Embed multiple queries in one model call (more efficient than looping)."""
    texts = [QUERY_PREFIX + q for q in queries]
    return [[float(x) for x in v] for v in _embed_batch(texts)]


def vector_to_pgvector_literal(vec: list[float]) -> str:
    """Serialize a vector for psycopg's `%s::vector` parameter binding."""
    return "[" + ",".join(f"{x:.6f}" for x in vec) + "]"
