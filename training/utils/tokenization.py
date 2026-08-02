from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


def _digest(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()
    return hashlib.sha256(encoded).hexdigest()


def tokenizer_identity(
    tokenizer: Any,
    tokenizer_name: str,
    *,
    add_special_tokens: bool,
    token_schema_version: str,
) -> tuple[str, dict[str, Any], dict[str, Any] | None]:
    revision = getattr(tokenizer, "_commit_hash", None) or tokenizer.init_kwargs.get("_commit_hash")
    if not revision:
        try:
            from huggingface_hub import try_to_load_from_cache

            cached = try_to_load_from_cache(tokenizer_name, "tokenizer.json", revision="main")
            if isinstance(cached, str):
                parts = Path(cached).parts
                snapshot_index = parts.index("snapshots")
                revision = parts[snapshot_index + 1]
        except (ImportError, ValueError, IndexError):
            revision = None
    if not revision:
        raise ValueError("Tokenizer did not expose an exact resolved commit revision")
    backend_schema = (
        json.loads(tokenizer.backend_tokenizer.to_str())
        if getattr(tokenizer, "backend_tokenizer", None) else None
    )
    configuration = {
        "tokenizer_name": tokenizer_name,
        "resolved_revision": revision,
        "add_special_tokens": add_special_tokens,
        "token_schema_version": token_schema_version,
        "tokenizer_class": type(tokenizer).__name__,
        "special_tokens_map": tokenizer.special_tokens_map,
        "model_max_length": tokenizer.model_max_length,
        "padding_side": tokenizer.padding_side,
        "truncation_side": tokenizer.truncation_side,
        "backend_schema_sha256": _digest(backend_schema) if backend_schema else None,
    }
    return _digest({**configuration, "backend_schema": backend_schema}), configuration, backend_schema


__all__ = ["tokenizer_identity"]
