from __future__ import annotations

from typing import Any

import numpy as np


THRESHOLDS = (512, 1024, 2048, 4096, 8192)


def numeric_distribution(values_input: list[int]) -> dict[str, Any]:
    if not values_input:
        return {
            "count": 0,
            "mean": None,
            "median": None,
            "p90": None,
            "p95": None,
            "p99": None,
            "max": None,
        }
    values = np.asarray(values_input, dtype=np.int64)
    return {
        "count": int(values.size),
        "mean": float(values.mean()),
        "median": float(np.median(values)),
        "p90": float(np.percentile(values, 90)),
        "p95": float(np.percentile(values, 95)),
        "p99": float(np.percentile(values, 99)),
        "max": int(values.max()),
    }


def token_length_distribution(lengths: list[int]) -> dict[str, Any]:
    result = numeric_distribution(lengths)
    if not lengths:
        result.update({f"percent_gt_{threshold}": None for threshold in THRESHOLDS})
        return result
    values = np.asarray(lengths, dtype=np.int64)
    result.update(
        {
            f"percent_gt_{threshold}": float(
                100 * np.count_nonzero(values > threshold) / values.size
            )
            for threshold in THRESHOLDS
        }
    )
    return result


def apk_token_statistics(
    apk_hash: str,
    token_shard: dict[str, Any],
    status: str = "complete",
    error: str | None = None,
) -> dict[str, Any]:
    examples = token_shard.get("examples", ())
    lengths = [item["token_count"] for item in examples]
    truncated = sum(bool(item["is_truncated"]) for item in examples)
    return {
        "apk_hash": apk_hash,
        "status": status,
        "error": error,
        "slice_count": len(examples),
        "complete_slice_count": len(examples) - truncated,
        "truncated_slice_count": truncated,
        "total_token_count": sum(lengths),
        "mean_slice_token_count": (sum(lengths) / len(lengths)) if lengths else None,
        "max_slice_token_count": max(lengths) if lengths else None,
        "zero_slices": not lengths,
    }


__all__ = [
    "THRESHOLDS",
    "apk_token_statistics",
    "numeric_distribution",
    "token_length_distribution",
]
