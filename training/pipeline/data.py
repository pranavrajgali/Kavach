"""Validated artifact joins, selection, and exact-once datasets."""

from __future__ import annotations

import gzip
import hashlib
import heapq
import json
import random
from collections import Counter, deque
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Iterator, Mapping, Sequence

import torch
from torch.utils.data import Dataset, IterableDataset
from transformers import AutoTokenizer, DataCollatorWithPadding

from training.pipeline.config import LABEL_IDS, ResolvedConfig, ResolvedFilters, resolve_path
from training.utils.dataset import load_apk_metadata, load_apk_splits, load_apk_statistics, split_mapping_digest


APPROVED_STATUSES = frozenset({"completed", "completed_with_truncation", "capped", "zero_sink"})
SUPPORTED_CATEGORIES = frozenset({
    "accessibility", "class_loader", "execution", "native_loading", "reflection", "sms",
})
FATAL_REASONS = frozenset({
    "missing_or_malformed_fields", "label_split_mismatch", "tokenizer_mismatch",
    "duplicate_example_id", "other_validation_failure",
})


class RejectionReason(str, Enum):
    UNAVAILABLE_STATUS = "unavailable_preprocessing_status"
    INTERNALLY_TRUNCATED = "internally_truncated"
    EXCLUDED_EXAMPLE = "excluded_example"
    EXCLUDED_CATEGORY = "excluded_or_unsupported_category"
    LENGTH_FILTER = "length_filter"
    CONTEXT_REJECTED = "context_rejected"
    MALFORMED = "missing_or_malformed_fields"
    LABEL_SPLIT_MISMATCH = "label_split_mismatch"
    TOKENIZER_MISMATCH = "tokenizer_mismatch"
    DUPLICATE = "duplicate_example_id"
    OTHER = "other_validation_failure"


@dataclass(frozen=True)
class Rejection:
    reason: RejectionReason
    example_id: str | None
    apk_hash: str
    detail: str

    @property
    def fatal(self) -> bool:
        return self.reason.value in FATAL_REASONS


@dataclass(frozen=True)
class PreparedRecord:
    example_id: str
    apk_hash: str
    label_name: str
    label: int
    sink_category: str
    input_ids: tuple[int, ...]
    token_count: int
    internal_truncated: bool
    context_truncated: bool

    def __getitem__(self, key: str) -> Any:
        if key == "input_ids":
            return list(self.input_ids)
        return getattr(self, key)

    def model_fields(self) -> dict[str, Any]:
        return {"input_ids": list(self.input_ids), "labels": self.label}

    def manifest_fields(self) -> dict[str, Any]:
        return {
            "example_id": self.example_id, "apk_hash": self.apk_hash,
            "label_name": self.label_name, "label": self.label,
            "sink_category": self.sink_category, "token_count": self.token_count,
            "internal_truncated": self.internal_truncated,
            "context_truncated": self.context_truncated,
        }


@dataclass(frozen=True)
class Corpus:
    root: Path
    manifest: dict[str, Any]
    metadata: dict[str, dict[str, Any]]
    splits: dict[str, str]
    statistics: dict[str, dict[str, Any]]
    token_dir: Path
    shard_names: tuple[str, ...]
    tokenizer_manifest: dict[str, Any]
    tokenizer_fingerprint: str = ""


@dataclass(frozen=True)
class ScanSummary:
    count: int
    class_counts: dict[str, int]
    category_counts: dict[str, int]
    apk_count: int
    internal_truncated: int
    context_truncated: int
    stored_records: int = 0
    rejected_records: int = 0
    rejection_counts: dict[str, int] | None = None


@dataclass(frozen=True)
class PreflightResult:
    summary: ScanSummary
    records: tuple[dict[str, Any], ...]
    eligible_ids: frozenset[str]
    rejections: tuple[Rejection, ...]


def _reject(reason: RejectionReason, apk_hash: str, item: Any, detail: str) -> Rejection:
    example_id = item.get("example_id") if isinstance(item, Mapping) else None
    return Rejection(reason, example_id if isinstance(example_id, str) else None, apk_hash, detail)


def _filters(config: Mapping[str, Any]) -> ResolvedFilters:
    if isinstance(config, ResolvedConfig):
        return config.filters
    data = config["data"]
    return ResolvedFilters(
        frozenset(data.get("include_sink_categories") or ()),
        frozenset(data.get("exclude_sink_categories") or ()),
        frozenset(data.get("excluded_example_ids") or ()),
        frozenset(data.get("tiny_disallowed_boundaries") or ()),
    )


def apply_context_policy(input_ids: Sequence[int], max_length: int, policy: str) -> tuple[list[int], bool]:
    if policy != "head":
        raise NotImplementedError("sink_centered context handling is unavailable")
    values = list(input_ids)
    return (values, False) if len(values) <= max_length else (values[:max_length], True)


def prepare_record(
    item: Any, apk_hash: str, corpus: Corpus, config: Mapping[str, Any], *, expected_split: str,
) -> PreparedRecord | Rejection:
    filters = _filters(config)
    status = corpus.statistics.get(apk_hash, {}).get("status")
    if status not in APPROVED_STATUSES:
        return _reject(RejectionReason.UNAVAILABLE_STATUS, apk_hash, item, f"status={status!r}")
    if corpus.splits.get(apk_hash) != expected_split:
        return _reject(RejectionReason.LABEL_SPLIT_MISMATCH, apk_hash, item, "immutable split mismatch")
    required = {"example_id", "apk_hash", "input_ids", "token_count", "is_truncated", "sink_category"}
    if not isinstance(item, Mapping) or not required <= set(item):
        return _reject(RejectionReason.MALFORMED, apk_hash, item, "missing required token fields")
    if not isinstance(item["example_id"], str) or not isinstance(item["sink_category"], str):
        return _reject(RejectionReason.MALFORMED, apk_hash, item, "invalid identifier/category type")
    if item["apk_hash"] != apk_hash or type(item["token_count"]) is not int or type(item["is_truncated"]) is not bool:
        return _reject(RejectionReason.MALFORMED, apk_hash, item, "invalid provenance or scalar type")
    if not isinstance(item["input_ids"], (list, tuple)) or any(type(token) is not int for token in item["input_ids"]):
        return _reject(RejectionReason.MALFORMED, apk_hash, item, "input_ids must contain integers")
    if item["token_count"] != len(item["input_ids"]):
        return _reject(RejectionReason.MALFORMED, apk_hash, item, "token_count does not match input_ids")
    metadata = corpus.metadata[apk_hash]
    statistic = corpus.statistics[apk_hash]
    label_name = metadata.get("label")
    if label_name not in LABEL_IDS:
        return _reject(RejectionReason.LABEL_SPLIT_MISMATCH, apk_hash, item, f"unknown label={label_name!r}")
    if statistic.get("label") not in (None, label_name) or statistic.get("split") not in (None, expected_split):
        return _reject(RejectionReason.LABEL_SPLIT_MISMATCH, apk_hash, item, "metadata/statistics disagreement")
    if item["example_id"] in filters.excluded_example_ids:
        return _reject(RejectionReason.EXCLUDED_EXAMPLE, apk_hash, item, "configured exclusion")
    if item["is_truncated"] and config["data"]["exclude_internally_truncated"]:
        return _reject(RejectionReason.INTERNALLY_TRUNCATED, apk_hash, item, "internal tokenizer truncation")
    length = item["token_count"]
    maximum = config["data"]["max_token_length"]
    if length < config["data"]["min_token_length"] or (maximum is not None and length > maximum):
        return _reject(RejectionReason.LENGTH_FILTER, apk_hash, item, f"token_count={length}")
    category = item["sink_category"]
    if (category not in SUPPORTED_CATEGORIES
            or (filters.included_categories and category not in filters.included_categories)
            or category in filters.excluded_categories):
        return _reject(RejectionReason.EXCLUDED_CATEGORY, apk_hash, item, f"category={category!r}")
    try:
        ids, context_truncated = apply_context_policy(
            item["input_ids"], config["data"]["max_context_length"], config["data"]["context_policy"]
        )
    except (TypeError, ValueError, NotImplementedError) as error:
        return _reject(RejectionReason.CONTEXT_REJECTED, apk_hash, item, str(error))
    return PreparedRecord(
        item["example_id"], apk_hash, label_name, LABEL_IDS[label_name], category,
        tuple(ids), length, item["is_truncated"], context_truncated,
    )


def load_corpus(config: ResolvedConfig) -> Corpus:
    root = resolve_path(config["data"]["root"])
    manifests = root / "manifests"
    dataset_manifest = json.loads((manifests / "dataset_v1.json").read_text(encoding="utf-8"))
    metadata = load_apk_metadata(manifests / "apk_metadata.jsonl")
    splits = load_apk_splits(manifests / "apk_splits_v1.json", set(metadata))
    statistics = load_apk_statistics(manifests / "apk_statistics_v1.jsonl")
    if set(statistics) != set(metadata):
        raise ValueError("APK statistics inventory does not match APK metadata")
    for apk_hash in metadata:
        label, split = metadata[apk_hash].get("label"), splits[apk_hash]
        if label not in LABEL_IDS:
            raise ValueError(f"Unknown label {label!r} for {apk_hash}")
        if statistics[apk_hash].get("label") not in (None, label) or statistics[apk_hash].get("split") not in (None, split):
            raise ValueError(f"Metadata/statistics disagreement for {apk_hash}")
    if dataset_manifest.get("split_mapping_sha256") != split_mapping_digest(splits):
        raise ValueError("Immutable split digest does not match dataset manifest")
    fingerprint = config["data"]["tokenizer_fingerprint"] or dataset_manifest.get("tokenizer_fingerprint")
    if not isinstance(fingerprint, str) or not fingerprint:
        raise ValueError("No valid tokenizer fingerprint was configured or recorded")
    token_dir = root / "tokens" / fingerprint
    shard_index = json.loads((token_dir / "shard_index.json").read_text(encoding="utf-8"))
    names = shard_index.get("shards")
    if not isinstance(names, list) or any(not isinstance(name, str) for name in names):
        raise ValueError("Token shard index must contain a string list")
    if len(names) != len(set(names)):
        raise ValueError("Token shard index contains duplicate shard names")
    if shard_index.get("schema_version") != dataset_manifest.get("token_schema_version"):
        raise ValueError("Token shard-index schema mismatch")
    if shard_index.get("tokenizer_fingerprint") != fingerprint:
        raise ValueError("Token shard-index fingerprint mismatch")
    tokenizer_manifest = json.loads((manifests / f"tokenizer_{fingerprint}.json").read_text(encoding="utf-8"))
    if not isinstance(tokenizer_manifest.get("configuration"), dict):
        raise ValueError("Tokenizer manifest has no valid configuration")
    for name in names:
        apk_hash = Path(name).stem
        if apk_hash not in metadata or apk_hash not in statistics:
            raise ValueError(f"Indexed shard references unknown APK: {name}")
        if not (token_dir / name).is_file():
            raise FileNotFoundError(f"Indexed token shard is missing: {name}")
    return Corpus(root, dataset_manifest, metadata, splits, statistics, token_dir,
                  tuple(names), tokenizer_manifest, fingerprint)


def load_validated_shard(corpus: Corpus, shard_name: str) -> dict[str, Any]:
    apk_hash = Path(shard_name).stem
    shard = torch.load(corpus.token_dir / shard_name, map_location="cpu", weights_only=True)
    if not isinstance(shard, dict):
        raise ValueError(f"Token shard is not a mapping: {shard_name}")
    checks = {
        "schema_version": corpus.manifest["token_schema_version"],
        "slice_schema_version": "slice-v1",
        "normalization_version": corpus.manifest["normalization_version"],
        "normalization_config_sha256": corpus.manifest["normalization_config_sha256"],
        "tokenizer_fingerprint": corpus.tokenizer_fingerprint or corpus.manifest["tokenizer_fingerprint"],
        "apk_hash": apk_hash,
    }
    for key, expected in checks.items():
        if shard.get(key) != expected:
            reason = "tokenizer mismatch" if key == "tokenizer_fingerprint" else f"incompatible {key}"
            raise ValueError(f"{reason} in {shard_name}: {shard.get(key)!r} != {expected!r}")
    if not isinstance(shard.get("examples", ()), (list, tuple)):
        raise ValueError(f"Malformed examples collection in {shard_name}")
    return shard


def preflight_split(corpus: Corpus, config: ResolvedConfig, split: str) -> PreflightResult:
    if len(corpus.shard_names) != len(set(corpus.shard_names)):
        raise ValueError("Token shard inventory contains duplicate shard names")
    records: list[dict[str, Any]] = []
    rejections: list[Rejection] = []
    seen: set[str] = set()
    stored = 0
    for shard_name in corpus.shard_names:
        apk_hash = Path(shard_name).stem
        if corpus.splits[apk_hash] != split:
            continue
        try:
            shard = load_validated_shard(corpus, shard_name)
        except Exception as error:
            reason = RejectionReason.TOKENIZER_MISMATCH if "tokenizer" in str(error).lower() else RejectionReason.OTHER
            rejections.append(Rejection(reason, None, apk_hash, str(error)))
            stored += 1
            continue
        for item in shard.get("examples", ()):
            stored += 1
            result = prepare_record(item, apk_hash, corpus, config, expected_split=split)
            if isinstance(result, Rejection):
                rejections.append(result)
                continue
            if result.example_id in seen:
                rejections.append(Rejection(RejectionReason.DUPLICATE, result.example_id, apk_hash, "duplicate example ID"))
                continue
            seen.add(result.example_id)
            records.append(result.manifest_fields())
    if stored != len(records) + len(rejections):
        raise RuntimeError("Preflight reconciliation failed")
    fatal = [item for item in rejections if item.fatal]
    if fatal:
        counts = Counter(item.reason.value for item in fatal)
        raise ValueError(f"Fatal data-integrity rejections: {dict(sorted(counts.items()))}")
    if not records:
        counts = Counter(item.reason.value for item in rejections)
        raise ValueError(f"No eligible records after preflight; rejections={dict(sorted(counts.items()))}")
    classes = Counter(item["label_name"] for item in records)
    categories = Counter(item["sink_category"] for item in records)
    rejection_counts = Counter(item.reason.value for item in rejections)
    summary = ScanSummary(
        len(records), dict(sorted(classes.items())), dict(sorted(categories.items())),
        len({item["apk_hash"] for item in records}), sum(item["internal_truncated"] for item in records),
        sum(item["context_truncated"] for item in records), stored, len(rejections),
        dict(sorted(rejection_counts.items())),
    )
    return PreflightResult(summary, tuple(records), frozenset(seen), tuple(rejections))


def scan_split(corpus: Corpus, config: ResolvedConfig, split: str, manifest_path: Path | None = None) -> ScanSummary:
    """Compatibility wrapper; provenance writing now happens after preflight."""
    result = preflight_split(corpus, config, split)
    if manifest_path is not None:
        from training.pipeline.provenance import write_jsonl_atomic
        write_jsonl_atomic(manifest_path, result.records)
    return result.summary


class TinyDataset(Dataset):
    def __init__(self, records: Sequence[PreparedRecord | Mapping[str, Any]]) -> None:
        self.records = list(records)

    def __len__(self) -> int:
        return len(self.records)

    def __getitem__(self, index: int) -> dict[str, Any]:
        record = self.records[index]
        if isinstance(record, PreparedRecord):
            return record.model_fields()
        return {"input_ids": record["input_ids"], "labels": record.get("labels", record.get("label"))}


class TokenShardIterableDataset(IterableDataset):
    """Sized deterministic exact-once stream with standard or bounded APK interleaving."""

    def __init__(self, corpus: Corpus, config: ResolvedConfig, split: str,
                 preflight: PreflightResult | int) -> None:
        self.corpus, self.config, self.split = corpus, config, split
        if isinstance(preflight, int):
            checked = preflight_split(corpus, config, split)
            if checked.summary.count != preflight:
                raise ValueError("Declared iterable length differs from preflight")
            self.preflight = checked
        else:
            self.preflight = preflight
        self.seed, self.epoch = config["run"]["seed"], 0
        self.peak_resident_queues = 0

    def __len__(self) -> int:
        return self.preflight.summary.count

    def set_epoch(self, epoch: int) -> None:
        self.epoch = epoch

    def __iter__(self) -> Iterator[dict[str, Any]]:
        if torch.utils.data.get_worker_info() is not None:
            raise RuntimeError("TokenShardIterableDataset currently requires dataloader_workers=0")
        sampler = self.config["data"]["sampler"]
        sampler_type = sampler["type"]
        self.peak_resident_queues = 0
        if sampler_type == "standard":
            yield from self._iter_standard()
        elif sampler_type == "apk_interleaved":
            active = sampler["active_apk_shards"]
            if type(active) is not int or active <= 0:
                raise ValueError("data.sampler.active_apk_shards must be a positive integer")
            yield from self._iter_apk_interleaved(active)
        else:
            raise ValueError(f"Unsupported sampler type: {sampler_type!r}")

    def _eligible_records(self, shard_name: str) -> list[PreparedRecord]:
        apk_hash = Path(shard_name).stem
        shard = load_validated_shard(self.corpus, shard_name)
        records = []
        for item in shard.get("examples", ()):
            result = prepare_record(item, apk_hash, self.corpus, self.config, expected_split=self.split)
            if isinstance(result, PreparedRecord) and result.example_id in self.preflight.eligible_ids:
                records.append(result)
        return records

    def _verify_yielded(self, yielded: set[str]) -> None:
        if yielded != self.preflight.eligible_ids or len(yielded) != self.preflight.summary.count:
            raise RuntimeError(
                f"Iterable/preflight drift: yielded={len(yielded)} expected={len(self.preflight.eligible_ids)}"
            )

    def _iter_standard(self) -> Iterator[dict[str, Any]]:
        rng = random.Random(self.seed + self.epoch)
        shard_names = list(self.corpus.shard_names)
        rng.shuffle(shard_names)
        yielded: set[str] = set()
        for shard_name in shard_names:
            apk_hash = Path(shard_name).stem
            if self.corpus.splits[apk_hash] != self.split:
                continue
            records = self._eligible_records(shard_name)
            rng.shuffle(records)
            for record in records:
                if record.example_id in yielded:
                    raise RuntimeError(f"Iterable yielded duplicate example ID: {record.example_id}")
                yielded.add(record.example_id)
                yield record.model_fields()
        self._verify_yielded(yielded)

    def _iter_apk_interleaved(self, maximum_active: int) -> Iterator[dict[str, Any]]:
        shard_names = [
            name for name in self.corpus.shard_names
            if self.corpus.splits[Path(name).stem] == self.split
        ]
        random.Random(self.seed + self.epoch).shuffle(shard_names)
        remaining = iter(shard_names)
        active: deque[tuple[str, deque[PreparedRecord]]] = deque()
        yielded: set[str] = set()

        def refill() -> None:
            while len(active) < maximum_active:
                try:
                    shard_name = next(remaining)
                except StopIteration:
                    return
                apk_hash = Path(shard_name).stem
                records = self._eligible_records(shard_name)
                digest = hashlib.sha256(f"{self.seed}:{self.epoch}:{apk_hash}".encode()).digest()
                random.Random(int.from_bytes(digest, "big")).shuffle(records)
                if records:
                    active.append((apk_hash, deque(records)))
                    self.peak_resident_queues = max(self.peak_resident_queues, len(active))
                    if self.peak_resident_queues > maximum_active:
                        raise RuntimeError("APK queue residency exceeded configured bound")

        refill()
        while active:
            apk_hash, queue = active.popleft()
            record = queue.popleft()
            if record.example_id in yielded:
                raise RuntimeError(f"Iterable yielded duplicate example ID: {record.example_id}")
            yielded.add(record.example_id)
            yield record.model_fields()
            if queue:
                active.append((apk_hash, queue))
            else:
                refill()
        self._verify_yielded(yielded)


def _candidate_score(seed: int, example_id: str) -> int:
    return int(hashlib.sha256(f"{seed}:{example_id}".encode()).hexdigest(), 16)


def select_smoke_records(corpus: Corpus, config: ResolvedConfig | Mapping[str, Any],
                         preflight: PreflightResult | None = None) -> list[PreparedRecord]:
    """Select a stable smoke subset, preferring unique APKs without balancing or resampling."""
    checked = preflight or preflight_split(corpus, config, config["data"]["train_split"])
    target = config["data"]["smoke_examples"]
    ranked: list[PreparedRecord] = []
    split = config["data"]["train_split"]
    for shard_name in corpus.shard_names:
        apk_hash = Path(shard_name).stem
        if corpus.splits[apk_hash] != split:
            continue
        shard = load_validated_shard(corpus, shard_name)
        for item in shard.get("examples", ()):
            record = prepare_record(item, apk_hash, corpus, config, expected_split=split)
            if isinstance(record, PreparedRecord) and record.example_id in checked.eligible_ids:
                ranked.append(record)
    ranked.sort(key=lambda item: (_candidate_score(config["run"]["seed"], item.example_id), item.example_id))
    unique_apks: list[PreparedRecord] = []
    repeated: list[PreparedRecord] = []
    seen_apks: set[str] = set()
    for record in ranked:
        destination = unique_apks if record.apk_hash not in seen_apks else repeated
        destination.append(record)
        seen_apks.add(record.apk_hash)
    chosen = (unique_apks + repeated)[:target]
    if len(chosen) != target:
        raise ValueError(f"Could not select {target} smoke records from {len(ranked)} eligible records")
    return chosen


def _tiny_candidates(corpus: Corpus, preflight: PreflightResult,
                     config: ResolvedConfig | Mapping[str, Any]) -> list[PreparedRecord]:
    size = config["data"]["tiny_candidate_pool"]
    heaps: dict[str, list[tuple[int, str, PreparedRecord]]] = {name: [] for name in LABEL_IDS}
    split = config["data"]["train_split"]
    for shard_name in corpus.shard_names:
        apk_hash = Path(shard_name).stem
        if corpus.splits[apk_hash] != split:
            continue
        shard = load_validated_shard(corpus, shard_name)
        for item in shard.get("examples", ()):
            record = prepare_record(item, apk_hash, corpus, config, expected_split=split)
            if not isinstance(record, PreparedRecord) or record.example_id not in preflight.eligible_ids:
                continue
            if record.internal_truncated or record.context_truncated:
                continue
            score = _candidate_score(config["run"]["seed"], record.example_id)
            entry = (-score, record.example_id, record)
            heap = heaps[record.label_name]
            if len(heap) < size:
                heapq.heappush(heap, entry)
            elif entry > heap[0]:
                heapq.heapreplace(heap, entry)
    return [entry[2] for heap in heaps.values() for entry in heap]


def _slice_metadata(corpus: Corpus, candidates: Sequence[PreparedRecord]) -> dict[str, dict[str, Any]]:
    wanted_by_apk: dict[str, set[str]] = {}
    for record in candidates:
        wanted_by_apk.setdefault(record.apk_hash, set()).add(record.example_id)
    found: dict[str, dict[str, Any]] = {}
    for apk_hash, wanted in wanted_by_apk.items():
        with gzip.open(corpus.root / "slices" / "v1" / f"{apk_hash}.jsonl.gz", "rt", encoding="utf-8") as file:
            for line in file:
                item = json.loads(line)
                if item["example_id"] in wanted:
                    found[item["example_id"]] = item
    missing = {item for values in wanted_by_apk.values() for item in values} - set(found)
    if missing:
        raise ValueError(f"Canonical slice metadata missing for {len(missing)} tiny candidates")
    return found


def select_tiny_records(corpus: Corpus, config: ResolvedConfig | Mapping[str, Any],
                        preflight: PreflightResult | None = None) -> list[PreparedRecord]:
    checked = preflight or preflight_split(corpus, config, config["data"]["train_split"])
    candidates = _tiny_candidates(corpus, checked, config)
    metadata = _slice_metadata(corpus, candidates)
    clean = []
    for record in candidates:
        meta = metadata[record.example_id]
        boundaries = {item["kind"] for item in meta.get("unresolved_boundaries", ())}
        if not meta.get("issues") and not meta.get("is_truncated") and not boundaries & _filters(config).tiny_disallowed_boundaries:
            clean.append(record)
    target = config["data"]["tiny_examples"] // 2
    chosen: list[PreparedRecord] = []
    token_hashes: set[str] = set()
    for label_name in LABEL_IDS:
        candidates_for_label = sorted(
            (item for item in clean if item.label_name == label_name),
            key=lambda item: _candidate_score(config["run"]["seed"], item.example_id),
        )
        label_chosen: list[PreparedRecord] = []
        used_apks: set[str] = set()
        used_categories: set[str] = set()
        for preference in ("both", "apk", "any"):
            for record in candidates_for_label:
                digest = hashlib.sha256(torch.tensor(record.input_ids, dtype=torch.int64).numpy().tobytes()).hexdigest()
                if digest in token_hashes or record in label_chosen:
                    continue
                new_apk = record.apk_hash not in used_apks
                new_category = record.sink_category not in used_categories
                if preference == "both" and not (new_apk and new_category):
                    continue
                if preference == "apk" and not new_apk:
                    continue
                label_chosen.append(record)
                token_hashes.add(digest)
                used_apks.add(record.apk_hash)
                used_categories.add(record.sink_category)
                if len(label_chosen) == target:
                    break
            if len(label_chosen) == target:
                break
        if len(label_chosen) != target:
            raise ValueError(f"Could not select {target} clean unique {label_name} records")
        chosen.extend(label_chosen)
    random.Random(config["run"]["seed"]).shuffle(chosen)
    return chosen


def validate_tokenizer(corpus: Corpus, tokenizer: Any) -> Any:
    """Validate a loaded tokenizer against the immutable token-artifact manifest."""
    expected = corpus.tokenizer_manifest["configuration"]
    if tokenizer.pad_token is None or tokenizer.pad_token_id is None:
        raise ValueError("Configured tokenizer has no pad token")
    if tokenizer.special_tokens_map != expected.get("special_tokens_map"):
        raise ValueError("Local tokenizer special tokens do not match token artifact manifest")
    backend = json.loads(tokenizer.backend_tokenizer.to_str())
    digest = hashlib.sha256(json.dumps(backend, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    if digest != expected.get("backend_schema_sha256"):
        raise ValueError("Local tokenizer backend does not match token artifact fingerprint")
    return tokenizer


def load_local_tokenizer(corpus: Corpus, config: ResolvedConfig) -> Any:
    path = resolve_path(config["model"]["tokenizer"] or config["model"]["checkpoint"])
    tokenizer = AutoTokenizer.from_pretrained(path, local_files_only=True)
    return validate_tokenizer(corpus, tokenizer)


def create_collator(tokenizer: Any, config: ResolvedConfig) -> DataCollatorWithPadding:
    return DataCollatorWithPadding(
        tokenizer, padding=True, pad_to_multiple_of=config["trainer"]["pad_to_multiple_of"], return_tensors="pt"
    )
