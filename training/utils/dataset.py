"""Load versioned token caches with APK-level labels and dynamic padding."""

from __future__ import annotations

import json
import hashlib
import math
import random
from pathlib import Path
from typing import Any, Mapping, Sequence

import torch


VALID_SPLITS = frozenset({"train", "validation", "test"})
SPLIT_VERSION = "apk-splits-v1"
DEFAULT_SPLIT_RATIOS = {"train": 0.70, "validation": 0.15, "test": 0.15}
DEFAULT_SPLIT_SEED = 42


def split_mapping_digest(mapping: Mapping[str, str]) -> str:
    encoded = json.dumps(mapping, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def create_apk_splits(
    metadata: Mapping[str, Mapping[str, Any]],
    *,
    seed: int = DEFAULT_SPLIT_SEED,
    ratios: Mapping[str, float] = DEFAULT_SPLIT_RATIOS,
) -> dict[str, str]:
    """Create a deterministic label-stratified split over the full hash inventory."""

    if set(ratios) != VALID_SPLITS or not math.isclose(sum(ratios.values()), 1.0):
        raise ValueError("Split ratios must define train/validation/test and sum to one")
    by_label: dict[str, list[str]] = {}
    for apk_hash, record in metadata.items():
        by_label.setdefault(str(record["label"]), []).append(apk_hash)
    mapping: dict[str, str] = {}
    split_order = ("train", "validation", "test")
    for label in sorted(by_label):
        hashes = sorted(by_label[label])
        random.Random(f"{seed}:{label}").shuffle(hashes)
        exact = {name: len(hashes) * ratios[name] for name in split_order}
        counts = {name: math.floor(exact[name]) for name in split_order}
        remainder = len(hashes) - sum(counts.values())
        ranked = sorted(split_order, key=lambda name: (-(exact[name] - counts[name]), split_order.index(name)))
        for name in ranked[:remainder]:
            counts[name] += 1
        cursor = 0
        for name in split_order:
            for apk_hash in hashes[cursor : cursor + counts[name]]:
                mapping[apk_hash] = name
            cursor += counts[name]
    return dict(sorted(mapping.items()))


def create_or_validate_apk_splits(
    path: Path,
    metadata: Mapping[str, Mapping[str, Any]],
    *,
    seed: int = DEFAULT_SPLIT_SEED,
    ratios: Mapping[str, float] = DEFAULT_SPLIT_RATIOS,
) -> dict[str, str]:
    expected = create_apk_splits(metadata, seed=seed, ratios=ratios)
    if path.exists():
        existing = load_apk_splits(path, set(metadata))
        if existing != expected:
            raise ValueError("Immutable APK split mapping conflicts with the configured full inventory")
        return existing
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    try:
        temporary.write_text(json.dumps(expected, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)
    return expected


def load_apk_metadata(path: Path) -> dict[str, dict[str, Any]]:
    records: dict[str, dict[str, Any]] = {}
    with path.open(encoding="utf-8") as file:
        for line in file:
            if not line.strip():
                continue
            record = json.loads(line)
            apk_hash = record["apk_hash"]
            if apk_hash in records and records[apk_hash] != record:
                raise ValueError(f"Conflicting APK metadata for {apk_hash}")
            records[apk_hash] = record
    return records


def load_apk_statistics(path: Path) -> dict[str, dict[str, Any]]:
    return load_apk_metadata(path)


def load_apk_splits(path: Path, known_hashes: set[str] | None = None) -> dict[str, str]:
    if not path.exists():
        raise FileNotFoundError(f"Fixed APK split mapping is missing: {path}")
    mapping = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(mapping, dict) or not mapping:
        raise ValueError("APK split mapping must be a non-empty JSON object")
    invalid = {apk_hash: split for apk_hash, split in mapping.items() if split not in VALID_SPLITS}
    if invalid:
        raise ValueError(f"Invalid APK split assignments: {invalid!r}")
    if known_hashes is not None:
        missing = known_hashes - set(mapping)
        extra = set(mapping) - known_hashes
        if missing or extra:
            raise ValueError(f"APK split mapping mismatch: missing={sorted(missing)!r}, extra={sorted(extra)!r}")
    return mapping


def load_token_examples(
    token_dir: Path,
    metadata: Mapping[str, Mapping[str, Any]],
    splits: Mapping[str, str],
    split: str,
    *,
    label_ids: Mapping[str, int] = {"Benign": 0, "Malicious": 1},
    apk_statistics: Mapping[str, Mapping[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    if split not in VALID_SPLITS:
        raise ValueError(f"Unknown split: {split!r}")
    examples: list[dict[str, Any]] = []
    for apk_hash, assigned_split in sorted(splits.items()):
        if assigned_split != split:
            continue
        if apk_hash not in metadata:
            raise ValueError(f"Split references unknown APK hash {apk_hash}")
        shard_path = token_dir / f"{apk_hash}.pt"
        if not shard_path.exists():
            if apk_statistics is not None:
                status_record = apk_statistics.get(apk_hash)
                if status_record is None:
                    raise ValueError(f"APK {apk_hash} has no preprocessing outcome")
                if status_record.get("status") in {
                    "failed", "timed_out", "extraction_partial"
                }:
                    continue
            raise FileNotFoundError(f"Token shard is missing: {shard_path}")
        shard = torch.load(shard_path, map_location="cpu", weights_only=True)
        if shard.get("apk_hash") != apk_hash:
            raise ValueError(f"Token shard APK mismatch in {shard_path}")
        label_name = metadata[apk_hash]["label"]
        if label_name not in label_ids:
            raise ValueError(f"No label ID configured for {label_name!r}")
        for item in shard.get("examples", ()):
            if item["apk_hash"] != apk_hash:
                raise ValueError(f"Slice-level APK mismatch in {shard_path}")
            examples.append(
                {
                    "example_id": item["example_id"],
                    "apk_hash": apk_hash,
                    "input_ids": item["input_ids"],
                    "label": label_ids[label_name],
                }
            )
    return examples


class DynamicPaddingCollator:
    def __init__(self, tokenizer: Any, *, pad_to_multiple_of: int | None = None) -> None:
        self.tokenizer = tokenizer
        self.pad_to_multiple_of = pad_to_multiple_of

    def __call__(self, features: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
        if not features:
            raise ValueError("Cannot collate an empty batch")
        batch = self.tokenizer.pad(
            [{"input_ids": item["input_ids"]} for item in features],
            padding=True,
            pad_to_multiple_of=self.pad_to_multiple_of,
            return_tensors="pt",
        )
        batch["labels"] = torch.tensor([item["label"] for item in features], dtype=torch.long)
        batch["example_ids"] = [item["example_id"] for item in features]
        batch["apk_hashes"] = [item["apk_hash"] for item in features]
        return batch


__all__ = [
    "DEFAULT_SPLIT_RATIOS",
    "DEFAULT_SPLIT_SEED",
    "DynamicPaddingCollator",
    "SPLIT_VERSION",
    "create_apk_splits",
    "create_or_validate_apk_splits",
    "load_apk_metadata",
    "load_apk_statistics",
    "load_apk_splits",
    "load_token_examples",
    "split_mapping_digest",
]
