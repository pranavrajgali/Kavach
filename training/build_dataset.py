from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable, Mapping

import torch
from transformers import AutoTokenizer


TRAINING_DIR = Path(__file__).resolve().parent
REPO_ROOT = TRAINING_DIR.parent
sys.path.insert(0, str(REPO_ROOT))

from kavach_ai.backend.pipeline.stage2_static.decompile import ExtractionStatus, extract_apk
from kavach_ai.backend.pipeline.stage2_static.jni_bridge import analyze_jni_bridges
from kavach_ai.backend.pipeline.stage3_ml.normalization import (
    NORMALIZATION_CONFIG,
    NORMALIZATION_VERSION,
    build_method_normalization_maps,
    canonical_sink_identity,
    register_example_identity,
    serialize_program_slice,
    stable_example_id,
)
from kavach_ai.backend.pipeline.stage3_ml.slicing import (
    DEFAULT_SINK_RULES,
    SliceLimits,
    find_sinks,
    slice_sinks,
)
from training.utils.dataset import (
    DEFAULT_SPLIT_RATIOS,
    DEFAULT_SPLIT_SEED,
    SPLIT_VERSION,
    create_or_validate_apk_splits,
    split_mapping_digest,
)
from training.utils.preprocessing import (
    ApkProcessingStatus,
    PREPROCESSING_VERSION,
    SELECTION_VERSION,
    TERMINAL_STATUSES,
    PreprocessingBudgets,
    category_counts,
    remove_worker_output,
    run_interruptible_process,
    select_sinks_by_category,
    sink_record,
)
from training.utils.static_ir import (
    EXTRACTOR_VERSION,
    STATIC_IR_VERSION,
    read_static_ir,
    static_ir_record,
    write_static_ir,
)
from training.utils.token_statistics import numeric_distribution, token_length_distribution
from training.utils.tokenization import tokenizer_identity


DATASET_VERSION = "dataset-v1"
JNI_CACHE_VERSION = "jni-cache-v1"
SLICE_SCHEMA_VERSION = "slice-v1"
TOKEN_SCHEMA_VERSION = "tokens-v1"
MODEL_NAME = "cisco-ai/SecureBERT2.0-base"
ADD_SPECIAL_TOKENS = True
DATA_ROOT = TRAINING_DIR / "data"
SOURCE_ROOT = REPO_ROOT / "data"
SLICE_POLICY = "sink_only"
SLICE_ORIGIN = "sink"
TARGET_SEMANTICS = "P(source APK is malicious | this normalized sink-centred slice)"
WEAK_LABEL_WARNING = (
    "Labels describe the source APK, not intrinsic maliciousness of every retained slice."
)
DEFAULT_BUDGETS = PreprocessingBudgets()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _canonical_digest(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()
    return hashlib.sha256(encoded).hexdigest()


def _policy_config(budgets: PreprocessingBudgets) -> dict[str, Any]:
    return {
        "slice_policy": SLICE_POLICY,
        "selection_version": SELECTION_VERSION,
        "limits": vars(SliceLimits()),
        "sink_rules": [vars(rule) for rule in DEFAULT_SINK_RULES],
        "max_slices_per_apk": budgets.max_slices_per_apk,
        "max_total_slice_instructions": budgets.max_total_slice_instructions,
    }


NORMALIZATION_CONFIG_SHA256 = _canonical_digest(NORMALIZATION_CONFIG)


def _atomic(path: Path, writer: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        writer(temporary)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _write_json(path: Path, value: Any) -> None:
    _atomic(
        path,
        lambda temporary: temporary.write_text(
            json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        ),
    )


def _write_jsonl(
    path: Path, records: Iterable[dict[str, Any]], *, compressed: bool = False
) -> None:
    values = tuple(records)

    def writer(temporary: Path) -> None:
        opener = gzip.open if compressed else open
        with opener(temporary, "wt", encoding="utf-8") as file:
            for record in values:
                file.write(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")

    _atomic(path, writer)


def _read_jsonl(path: Path, *, compressed: bool = False) -> list[dict[str, Any]]:
    opener = gzip.open if compressed else open
    with opener(path, "rt", encoding="utf-8") as file:
        return [json.loads(line) for line in file if line.strip()]


def _read_statistics(path: Path) -> dict[str, dict[str, Any]]:
    if not path.exists():
        return {}
    return {item["apk_hash"]: item for item in _read_jsonl(path)}


def _jsonable_issue(issue: Any) -> dict[str, Any]:
    method = getattr(issue, "method", None)
    severity = getattr(issue, "severity", None)
    return {
        "code": getattr(issue, "code", "UNKNOWN"),
        "message": getattr(issue, "message", str(issue)),
        "severity": getattr(severity, "value", severity),
        "method": (
            {"dex_name": method.dex_name, "full_signature": method.full_signature}
            if method
            else None
        ),
        "instruction_index": getattr(issue, "instruction_index", None),
        "opcode": getattr(issue, "opcode", None),
    }


def _slice_record(
    apk_hash: str,
    program_slice: Any,
    methods: tuple[Any, ...],
    policy_digest: str,
    method_maps: Mapping[Any, Any] | None = None,
) -> dict[str, Any]:
    identity = canonical_sink_identity(apk_hash, program_slice)
    text = serialize_program_slice(program_slice, methods, method_maps=method_maps)
    return {
        "schema_version": SLICE_SCHEMA_VERSION,
        "slicer_config_sha256": policy_digest,
        "slice_origin": SLICE_ORIGIN,
        "example_id": stable_example_id(apk_hash, program_slice),
        "apk_hash": apk_hash,
        "sink_identity": identity,
        "sink_category": program_slice.sink.category,
        "raw_slice_text": text.raw_slice_text,
        "normalized_slice_text": text.normalized_slice_text,
        "normalization_version": text.normalization_version,
        "normalization_config_sha256": NORMALIZATION_CONFIG_SHA256,
        "is_truncated": program_slice.truncated,
        "retained_instruction_count": len(program_slice.retained_instructions),
        "involved_methods": [
            {"dex_name": item.dex_name, "full_signature": item.full_signature}
            for item in program_slice.involved_methods
        ],
        "unresolved_boundaries": [
            {
                "kind": item.kind.value,
                "method": {
                    "dex_name": item.method.dex_name,
                    "full_signature": item.method.full_signature,
                },
                "instruction_index": item.instruction_index,
                "target_signature": item.target_signature,
            }
            for item in program_slice.unresolved_boundaries
        ],
        "issues": [_jsonable_issue(item) for item in program_slice.issues],
    }


def _slice_worker(
    static_path: str,
    output_path: str,
    progress_path: str,
    apk_hash: str,
    policy_digest: str,
    budgets_value: dict[str, Any],
) -> None:
    budgets = PreprocessingBudgets(**budgets_value)
    started = time.monotonic()
    static_started = time.monotonic()
    static_ir = read_static_ir(Path(static_path))
    static_read_seconds = time.monotonic() - static_started

    sink_started = time.monotonic()
    all_sinks = find_sinks(static_ir.methods)
    candidates = select_sinks_by_category(all_sinks, budgets.max_slices_per_apk)
    sink_seconds = time.monotonic() - sink_started
    _write_json(
        Path(progress_path),
        {
            "usable_method_count": sum(method.is_usable for method in static_ir.methods),
            "sink_method_count": len({item.method for item in all_sinks}),
            "total_sink_count": len(all_sinks),
            "candidate_selected_sink_count": len(candidates),
            "selected_sink_count": 0,
            "omitted_sink_count": len(all_sinks),
            "retained_sink_categories": {},
            "omitted_sink_categories": category_counts(all_sinks),
            "stage_runtime_seconds": {
                "static_ir_read": static_read_seconds,
                "sink_detection_and_selection": sink_seconds,
            },
        },
    )

    slicing_started = time.monotonic()
    slicing = slice_sinks(
        static_ir.methods,
        candidates,
        max_total_instructions=budgets.max_total_slice_instructions,
    )
    slicing_seconds = time.monotonic() - slicing_started
    instruction_rejected = len(slicing.slices) < len(candidates)
    rejected_sink = candidates[len(slicing.slices)] if instruction_rejected else None
    cap_reason = (
        "max_total_slice_instructions"
        if instruction_rejected
        else "max_slices_per_apk"
        if len(candidates) < len(all_sinks)
        else None
    )

    normalization_started = time.monotonic()
    method_maps = build_method_normalization_maps(static_ir.methods)
    identities: dict[str, dict[str, object]] = {}
    records: list[dict[str, Any]] = []
    for program_slice in slicing.slices:
        record = _slice_record(
            apk_hash, program_slice, static_ir.methods, policy_digest, method_maps
        )
        register_example_identity(identities, record["example_id"], record["sink_identity"])
        records.append(record)
    normalization_seconds = time.monotonic() - normalization_started
    published = tuple(slicing.sinks)
    omitted = tuple(item for item in all_sinks if item not in set(published))
    truncated_reasons = sorted(
        {
            boundary["kind"]
            for record in records
            if record["is_truncated"]
            for boundary in record["unresolved_boundaries"]
        }
        | {
            issue["code"]
            for record in records
            if record["is_truncated"]
            for issue in record["issues"]
        }
    )
    value = {
        "records": records,
        "summary": {
            "usable_method_count": sum(method.is_usable for method in static_ir.methods),
            "sink_method_count": len({item.method for item in all_sinks}),
            "total_sink_count": len(all_sinks),
            "candidate_selected_sink_count": len(candidates),
            "selected_sink_count": len(published),
            "omitted_sink_count": len(omitted),
            "retained_instruction_count": sum(
                item["retained_instruction_count"] for item in records
            ),
            "complete_slice_count": sum(not item["is_truncated"] for item in records),
            "truncated_slice_count": sum(item["is_truncated"] for item in records),
            "retained_sink_categories": category_counts(published),
            "omitted_sink_categories": category_counts(omitted),
            "cap_reason": cap_reason,
            "rejected_sink": sink_record(rejected_sink),
            "truncation_reasons": truncated_reasons,
            "stage_runtime_seconds": {
                "static_ir_read": static_read_seconds,
                "sink_detection_and_selection": sink_seconds,
                "slicing": slicing_seconds,
                "normalization_serialization": normalization_seconds,
                "slice_worker_total": time.monotonic() - started,
            },
        },
    }
    with gzip.open(output_path, "wt", encoding="utf-8") as file:
        json.dump(value, file, sort_keys=True, separators=(",", ":"))


def _tokenize_records(
    tokenizer: Any,
    apk_hash: str,
    records: list[dict[str, Any]],
    policy_digest: str,
) -> dict[str, Any]:
    examples = []
    for record in records:
        input_ids = tokenizer(
            record["normalized_slice_text"],
            add_special_tokens=ADD_SPECIAL_TOKENS,
            padding=False,
            truncation=False,
        )["input_ids"]
        examples.append(
            {
                "example_id": record["example_id"],
                "apk_hash": apk_hash,
                "input_ids": input_ids,
                "token_count": len(input_ids),
                "is_truncated": record["is_truncated"],
                "sink_category": record["sink_category"],
                "slice_origin": SLICE_ORIGIN,
            }
        )
    return {
        "schema_version": TOKEN_SCHEMA_VERSION,
        "slice_schema_version": SLICE_SCHEMA_VERSION,
        "slicer_config_sha256": policy_digest,
        "normalization_version": NORMALIZATION_VERSION,
        "normalization_config_sha256": NORMALIZATION_CONFIG_SHA256,
        "apk_hash": apk_hash,
        "examples": examples,
    }


def _validate_slice_records(
    records: list[dict[str, Any]], apk_hash: str, policy_digest: str
) -> None:
    identities: dict[str, dict[str, object]] = {}
    for item in records:
        if (
            item.get("schema_version") != SLICE_SCHEMA_VERSION
            or item.get("slicer_config_sha256") != policy_digest
            or item.get("normalization_config_sha256") != NORMALIZATION_CONFIG_SHA256
            or item.get("slice_origin") != SLICE_ORIGIN
            or item.get("apk_hash") != apk_hash
        ):
            raise ValueError("incompatible canonical slice shard")
        register_example_identity(identities, item["example_id"], item["sink_identity"])


def _validate_token_shard(
    shard: dict[str, Any], apk_hash: str, tokenizer_fingerprint: str, policy_digest: str
) -> None:
    if (
        shard.get("schema_version") != TOKEN_SCHEMA_VERSION
        or shard.get("apk_hash") != apk_hash
        or shard.get("tokenizer_fingerprint") != tokenizer_fingerprint
        or shard.get("slice_schema_version") != SLICE_SCHEMA_VERSION
        or shard.get("slicer_config_sha256") != policy_digest
        or shard.get("normalization_config_sha256") != NORMALIZATION_CONFIG_SHA256
    ):
        raise ValueError("incompatible token shard")
    seen: set[str] = set()
    for example in shard.get("examples", ()):
        if example.get("apk_hash") != apk_hash:
            raise ValueError("token example APK hash mismatch")
        if example.get("token_count") != len(example.get("input_ids", ())):
            raise ValueError("token example length metadata mismatch")
        if "attention_mask" in example or "label" in example:
            raise ValueError("token shard contains dynamic or label fields")
        if example["example_id"] in seen:
            raise ValueError(f"duplicate token example_id {example['example_id']}")
        seen.add(example["example_id"])


def _inventory() -> tuple[dict[str, dict[str, Any]], list[tuple[Path, str, str]]]:
    paths = [
        path
        for label in ("Benign", "Malicious")
        for path in sorted((SOURCE_ROOT / label).glob("*.apk"))
    ]
    metadata: dict[str, dict[str, Any]] = {}
    items: list[tuple[Path, str, str]] = []
    print(f"Hashing full inventory of {len(paths)} APKs...", flush=True)
    for number, path in enumerate(paths, 1):
        apk_hash = _sha256_file(path)
        label = path.parent.name
        relative = str(path.relative_to(REPO_ROOT))
        existing = metadata.get(apk_hash)
        if existing and existing["label"] != label:
            raise ValueError(
                f"APK hash {apk_hash} has conflicting labels: {existing['label']} and {label}"
            )
        if existing:
            existing.setdefault("duplicate_source_paths", []).append(relative)
        else:
            metadata[apk_hash] = {
                "apk_hash": apk_hash,
                "label": label,
                "apk_size_bytes": path.stat().st_size,
                "source_path": relative,
            }
            items.append((path, apk_hash, label))
        if number == 1 or number % 25 == 0 or number == len(paths):
            print(f"  [hash {number}/{len(paths)}]", flush=True)
    return metadata, items


def _select_work(
    items: list[tuple[Path, str, str]],
    *,
    limit_per_class: int | None,
    size_quantiles_per_class: int | None,
) -> list[tuple[Path, str, str]]:
    if limit_per_class is not None and size_quantiles_per_class is not None:
        raise ValueError("choose only one subset-selection mode")
    if limit_per_class is None and size_quantiles_per_class is None:
        return items
    selected: list[tuple[Path, str, str]] = []
    for label in ("Benign", "Malicious"):
        values = sorted(
            (item for item in items if item[2] == label),
            key=lambda item: (item[0].stat().st_size, item[1]),
        )
        if limit_per_class is not None:
            selected.extend(values[:limit_per_class])
            continue
        count = min(size_quantiles_per_class or 0, len(values))
        if count == 1:
            selected.append(values[len(values) // 2])
        elif count > 1:
            indexes = [round(index * (len(values) - 1) / (count - 1)) for index in range(count)]
            selected.extend(values[index] for index in indexes)
    return selected


def _blank_stat(
    metadata: Mapping[str, Any], split: str, previous: Mapping[str, Any] | None
) -> dict[str, Any]:
    attempts = int((previous or {}).get("attempt_count", 0)) + 1
    return {
        "apk_hash": metadata["apk_hash"],
        "label": metadata["label"],
        "split": split,
        "apk_size_bytes": metadata["apk_size_bytes"],
        "status": ApkProcessingStatus.FAILED.value,
        "extraction_status": None,
        "failure_stage": None,
        "error": None,
        "cap_reason": None,
        "truncation_reasons": [],
        "usable_method_count": 0,
        "sink_method_count": 0,
        "total_sink_count": 0,
        "candidate_selected_sink_count": 0,
        "selected_sink_count": 0,
        "omitted_sink_count": 0,
        "slice_count": 0,
        "complete_slice_count": 0,
        "truncated_slice_count": 0,
        "retained_instruction_count": 0,
        "retained_sink_categories": {},
        "omitted_sink_categories": {},
        "rejected_sink": None,
        "total_token_count": 0,
        "token_length_distribution": token_length_distribution([]),
        "stage_runtime_seconds": {},
        "reused_static_ir": False,
        "reused_slice_shard": False,
        "canonical_slices_complete": False,
        "attempt_count": attempts,
        "retry_count": attempts - 1,
        "zero_sink": False,
    }


def _persist_statistics(path: Path, statistics: Mapping[str, dict[str, Any]]) -> None:
    _write_jsonl(path, (statistics[key] for key in sorted(statistics)))


def _group_statistics(
    statistics: Mapping[str, dict[str, Any]], token_dir: Path
) -> dict[str, Any]:
    groups: dict[str, list[int]] = defaultdict(list)
    class_slice_counts: dict[str, list[int]] = defaultdict(list)
    statuses = Counter(item["status"] for item in statistics.values())
    for item in statistics.values():
        class_slice_counts[item["label"]].append(int(item["slice_count"]))
        if item["status"] not in TERMINAL_STATUSES:
            continue
        path = token_dir / f"{item['apk_hash']}.pt"
        if not path.exists():
            continue
        shard = torch.load(path, map_location="cpu", weights_only=True)
        for example in shard.get("examples", ()):
            length = int(example["token_count"])
            groups["all"].append(length)
            groups[f"class:{item['label']}"].append(length)
            groups[f"truncated:{bool(example['is_truncated'])}"].append(length)
            groups[f"status:{item['status']}"].append(length)
            groups[f"sink_category:{example['sink_category']}"].append(length)
            groups[f"apk:{item['apk_hash']}"].append(length)
    return {
        "token_lengths": {
            key: token_length_distribution(values) for key, values in sorted(groups.items())
        },
        "slice_counts_by_class": {
            key: numeric_distribution(values)
            for key, values in sorted(class_slice_counts.items())
        },
        "apk_status_counts": dict(sorted(statuses.items())),
    }


def _format_eta(started: float, completed: int, total: int) -> str:
    elapsed = time.monotonic() - started
    remaining = elapsed / completed * (total - completed) if completed else 0
    return f"elapsed={elapsed / 60:.1f}m eta={remaining / 60:.1f}m"


def main(
    *,
    limit_per_class: int | None = None,
    size_quantiles_per_class: int | None = None,
    budgets: PreprocessingBudgets = DEFAULT_BUDGETS,
) -> None:
    static_dir = DATA_ROOT / "static_ir" / "v1"
    slice_dir = DATA_ROOT / "slices" / "v1"
    manifest_dir = DATA_ROOT / "manifests"
    work_dir = DATA_ROOT / ".work" / "decompile"
    slice_work_dir = DATA_ROOT / ".work" / "slicing"
    for path in (static_dir, slice_dir, manifest_dir, work_dir, slice_work_dir):
        path.mkdir(parents=True, exist_ok=True)

    metadata, inventory_items = _inventory()
    _write_jsonl(manifest_dir / "apk_metadata.jsonl", metadata.values())
    splits = create_or_validate_apk_splits(
        manifest_dir / "apk_splits_v1.json", metadata
    )
    split_digest = split_mapping_digest(splits)

    policy_config = _policy_config(budgets)
    policy_digest = _canonical_digest(policy_config)
    tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)
    tokenizer_fingerprint, tokenizer_configuration, tokenizer_schema = tokenizer_identity(
        tokenizer,
        MODEL_NAME,
        add_special_tokens=ADD_SPECIAL_TOKENS,
        token_schema_version=TOKEN_SCHEMA_VERSION,
    )
    token_dir = DATA_ROOT / "tokens" / tokenizer_fingerprint
    token_dir.mkdir(parents=True, exist_ok=True)
    tokenizer_schema_name = f"tokenizer_{tokenizer_fingerprint}.json"
    _write_json(
        manifest_dir / tokenizer_schema_name,
        {"configuration": tokenizer_configuration, "backend_schema": tokenizer_schema},
    )

    work_items = _select_work(
        inventory_items,
        limit_per_class=limit_per_class,
        size_quantiles_per_class=size_quantiles_per_class,
    )
    statistics_path = manifest_dir / "apk_statistics_v1.jsonl"
    statistics = {
        apk_hash: item
        for apk_hash, item in _read_statistics(statistics_path).items()
        if apk_hash in metadata
    }
    started = time.monotonic()
    print(f"Processing {len(work_items)} of {len(inventory_items)} unique APKs...", flush=True)

    for number, (apk_path, apk_hash, label) in enumerate(work_items, 1):
        apk_started = time.monotonic()
        static_path = static_dir / f"{apk_hash}.json.gz"
        slice_path = slice_dir / f"{apk_hash}.jsonl.gz"
        token_path = token_dir / f"{apk_hash}.pt"
        worker_path = slice_work_dir / f"{apk_hash}.{os.getpid()}.json.gz"
        progress_path = slice_work_dir / f"{apk_hash}.{os.getpid()}.progress.json"
        previous = statistics.get(apk_hash)
        print(f"[{number}/{len(work_items)}] {label}/{apk_path.name}", flush=True)

        if previous and previous.get("status") in TERMINAL_STATUSES:
            try:
                records = _read_jsonl(slice_path, compressed=True)
                _validate_slice_records(records, apk_hash, policy_digest)
                shard = torch.load(token_path, map_location="cpu", weights_only=True)
                _validate_token_shard(shard, apk_hash, tokenizer_fingerprint, policy_digest)
                print(
                    f"  resumed terminal {previous['status']}; slices={len(records)} "
                    f"{_format_eta(started, number, len(work_items))}",
                    flush=True,
                )
                continue
            except Exception:
                pass

        stat = _blank_stat(metadata[apk_hash], splits[apk_hash], previous)
        generated_artifact: Path | None = None
        try:
            static_ir = None
            static_started = time.monotonic()
            if static_path.exists():
                try:
                    cached = read_static_ir(static_path)
                    if cached.apk_hash == apk_hash and cached.extraction_status == ExtractionStatus.SUCCESS.value:
                        static_ir = cached
                        stat["reused_static_ir"] = True
                except Exception:
                    static_ir = None
            stat["stage_runtime_seconds"]["static_ir_cache_read"] = time.monotonic() - static_started

            if static_ir is None:
                stat["failure_stage"] = "extraction"
                extraction_started = time.monotonic()
                extraction = extract_apk(
                    apk_path,
                    artifact_root=work_dir,
                    run_jadx_analysis=False,
                )
                stat["stage_runtime_seconds"]["extraction"] = time.monotonic() - extraction_started
                generated_artifact = Path(extraction.artifact_path)
                if extraction.apk_hash != apk_hash:
                    raise ValueError("APK hash changed during extraction")
                jni_started = time.monotonic()
                stat["failure_stage"] = "jni"
                jni_result = analyze_jni_bridges(extraction)
                stat["stage_runtime_seconds"]["jni"] = time.monotonic() - jni_started
                static_write_started = time.monotonic()
                stat["failure_stage"] = "static_ir_write"
                record = static_ir_record(
                    apk_hash,
                    extraction.methods,
                    jni_result,
                    extraction.status.value,
                    extraction.issues,
                )
                _atomic(static_path, lambda temporary: write_static_ir(temporary, record))
                stat["stage_runtime_seconds"]["static_ir_write"] = time.monotonic() - static_write_started
                stat["extraction_status"] = extraction.status.value
                stat["usable_method_count"] = len(extraction.usable_methods)
                if extraction.status is ExtractionStatus.PARTIAL:
                    stat["status"] = ApkProcessingStatus.EXTRACTION_PARTIAL.value
                    stat["failure_stage"] = "extraction"
                    stat["error"] = "ExtractionResult status is PARTIAL"
                    continue
                if extraction.status is ExtractionStatus.FAILED:
                    stat["status"] = ApkProcessingStatus.FAILED.value
                    stat["failure_stage"] = "extraction"
                    stat["error"] = "ExtractionResult status is FAILED"
                    continue
            else:
                stat["extraction_status"] = static_ir.extraction_status
                stat["usable_method_count"] = sum(method.is_usable for method in static_ir.methods)

            records: list[dict[str, Any]] | None = None
            summary: dict[str, Any] | None = None
            if previous and previous.get("canonical_slices_complete") and slice_path.exists():
                try:
                    records = _read_jsonl(slice_path, compressed=True)
                    _validate_slice_records(records, apk_hash, policy_digest)
                    summary_keys = (
                        "usable_method_count", "sink_method_count", "total_sink_count",
                        "candidate_selected_sink_count", "selected_sink_count",
                        "omitted_sink_count", "retained_instruction_count",
                        "complete_slice_count", "truncated_slice_count",
                        "retained_sink_categories", "omitted_sink_categories",
                        "cap_reason", "rejected_sink", "truncation_reasons",
                    )
                    summary = {key: previous.get(key) for key in summary_keys}
                    summary["stage_runtime_seconds"] = {}
                    stat["reused_slice_shard"] = True
                except Exception:
                    records = None
                    summary = None

            if records is None or summary is None:
                remove_worker_output(worker_path)
                remove_worker_output(progress_path)
                worker_started = time.monotonic()
                stat["failure_stage"] = "slicing"
                run = run_interruptible_process(
                    _slice_worker,
                    (
                        str(static_path),
                        str(worker_path),
                        str(progress_path),
                        apk_hash,
                        policy_digest,
                        vars(budgets),
                    ),
                    timeout_seconds=budgets.max_slicing_seconds_per_apk,
                )
                stat["stage_runtime_seconds"]["slice_worker_wall"] = time.monotonic() - worker_started
                if run.timed_out:
                    if progress_path.exists():
                        progress = json.loads(progress_path.read_text(encoding="utf-8"))
                        stat.update(
                            {
                                key: value
                                for key, value in progress.items()
                                if key != "stage_runtime_seconds"
                            }
                        )
                        stat["stage_runtime_seconds"].update(
                            progress.get("stage_runtime_seconds", {})
                        )
                    stat["status"] = ApkProcessingStatus.TIMED_OUT.value
                    stat["error"] = f"Exceeded {budgets.max_slicing_seconds_per_apk} seconds"
                    continue
                if run.exit_code != 0 or not worker_path.exists():
                    raise RuntimeError(f"slice worker failed with exit code {run.exit_code}")
                with gzip.open(worker_path, "rt", encoding="utf-8") as file:
                    worker_value = json.load(file)
                records = worker_value["records"]
                summary = worker_value["summary"]
                _validate_slice_records(records, apk_hash, policy_digest)
            stat.update({key: value for key, value in summary.items() if key != "stage_runtime_seconds"})
            stat["stage_runtime_seconds"].update(summary["stage_runtime_seconds"])
            stat["slice_count"] = len(records)
            stat["zero_sink"] = summary["total_sink_count"] == 0

            if stat["zero_sink"]:
                stat["status"] = ApkProcessingStatus.ZERO_SINK.value
            elif summary["cap_reason"]:
                stat["status"] = ApkProcessingStatus.CAPPED.value
            elif summary["truncated_slice_count"]:
                stat["status"] = ApkProcessingStatus.COMPLETED_WITH_TRUNCATION.value
            else:
                stat["status"] = ApkProcessingStatus.COMPLETED.value

            if not stat["reused_slice_shard"]:
                stat["failure_stage"] = "canonical_slice_write"
                _write_jsonl(slice_path, records, compressed=True)
            stat["canonical_slices_complete"] = True
            stat["failure_stage"] = "tokenization"
            token_started = time.monotonic()
            token_shard = _tokenize_records(tokenizer, apk_hash, records, policy_digest)
            token_shard["tokenizer_fingerprint"] = tokenizer_fingerprint
            _atomic(token_path, lambda temporary: torch.save(token_shard, temporary))
            stat["stage_runtime_seconds"]["tokenization"] = time.monotonic() - token_started
            _validate_token_shard(token_shard, apk_hash, tokenizer_fingerprint, policy_digest)
            lengths = [int(item["token_count"]) for item in token_shard["examples"]]
            stat["total_token_count"] = sum(lengths)
            stat["token_length_distribution"] = token_length_distribution(lengths)
            stat["failure_stage"] = None
        except Exception as exc:
            stat["status"] = ApkProcessingStatus.FAILED.value
            stat["failure_stage"] = stat["failure_stage"] or "pipeline"
            stat["error"] = f"{type(exc).__name__}: {exc}"
        finally:
            stat["stage_runtime_seconds"]["total"] = time.monotonic() - apk_started
            statistics[apk_hash] = stat
            _persist_statistics(statistics_path, statistics)
            remove_worker_output(worker_path)
            remove_worker_output(progress_path)
            if generated_artifact is not None:
                shutil.rmtree(generated_artifact, ignore_errors=True)
            print(
                f"  {stat['status']}; sinks={stat['selected_sink_count']}/{stat['total_sink_count']} "
                f"slices={stat['slice_count']} tokens={stat['total_token_count']} "
                f"{_format_eta(started, number, len(work_items))}",
                flush=True,
            )

    grouped_statistics = _group_statistics(statistics, token_dir)
    git_revision = subprocess.run(
        ("git", "rev-parse", "HEAD"),
        cwd=REPO_ROOT,
        text=True,
        capture_output=True,
        check=False,
    ).stdout.strip() or None
    manifest = {
        "dataset_version": DATASET_VERSION,
        "model_input_field": "normalized_slice_text",
        "slice_policy": SLICE_POLICY,
        "slice_origin": SLICE_ORIGIN,
        "target_semantics": TARGET_SEMANTICS,
        "weak_label_warning": WEAK_LABEL_WARNING,
        "code_revision": git_revision,
        "extractor_version": EXTRACTOR_VERSION,
        "offline_extraction_config": {"jadx_enabled_for_dataset_build": False},
        "static_ir_schema_version": STATIC_IR_VERSION,
        "jni_cache_version": JNI_CACHE_VERSION,
        "preprocessing_version": PREPROCESSING_VERSION,
        "preprocessing": {
            "budget_profile": "provisional-validation-v1",
            "budgets": vars(budgets),
            "selection_version": SELECTION_VERSION,
            "content_config_sha256": policy_digest,
        },
        "slicer_version": "slicer-v1",
        "slicer_config": policy_config,
        "normalization_version": NORMALIZATION_VERSION,
        "normalization_config": NORMALIZATION_CONFIG,
        "normalization_config_sha256": NORMALIZATION_CONFIG_SHA256,
        "token_schema_version": TOKEN_SCHEMA_VERSION,
        "tokenizer_fingerprint": tokenizer_fingerprint,
        "tokenizer": tokenizer_configuration,
        "tokenizer_schema_file": tokenizer_schema_name,
        "split_status": "fixed",
        "split_version": SPLIT_VERSION,
        "split_seed": DEFAULT_SPLIT_SEED,
        "split_ratios": DEFAULT_SPLIT_RATIOS,
        "split_mapping_sha256": split_digest,
        "family_leakage_warning": (
            "Hash-level splitting prevents exact-duplicate leakage, not family or repackaging leakage."
        ),
        "statistics": grouped_statistics,
        "counts": {
            "source_apks": sum(
                1
                for label in ("Benign", "Malicious")
                for _ in (SOURCE_ROOT / label).glob("*.apk")
            ),
            "unique_apks": len(metadata),
            "processed_apks": len(statistics),
            "unprocessed_apks": len(metadata) - len(statistics),
            **{
                f"{status}_apks": sum(item["status"] == status for item in statistics.values())
                for status in sorted({item["status"] for item in statistics.values()})
            },
        },
        "files": {
            "apk_metadata": "apk_metadata.jsonl",
            "apk_statistics": "apk_statistics_v1.jsonl",
            "apk_splits": "apk_splits_v1.json",
        },
    }
    _write_json(manifest_dir / "dataset_v1.json", manifest)
    _write_json(
        token_dir / "shard_index.json",
        {
            "schema_version": TOKEN_SCHEMA_VERSION,
            "tokenizer_fingerprint": tokenizer_fingerprint,
            "shards": [
                f"{apk_hash}.pt"
                for apk_hash, item in sorted(statistics.items())
                if item["status"] in TERMINAL_STATUSES and (token_dir / f"{apk_hash}.pt").exists()
            ],
        },
    )
    print(json.dumps(grouped_statistics, indent=2), flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Build the versioned static-to-token dataset.")
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "--limit-per-class",
        type=int,
        default=None,
        help="Process the N smallest APKs per class while preserving full inventory manifests.",
    )
    group.add_argument(
        "--size-quantiles-per-class",
        type=int,
        default=None,
        help="Process N deterministic APK-size quantiles per class.",
    )
    parser.add_argument("--max-slicing-seconds-per-apk", type=float, default=300.0)
    parser.add_argument("--max-slices-per-apk", type=int, default=256)
    parser.add_argument("--max-total-slice-instructions", type=int, default=65_536)
    arguments = parser.parse_args()
    if arguments.limit_per_class is not None and arguments.limit_per_class <= 0:
        parser.error("--limit-per-class must be positive")
    if arguments.size_quantiles_per_class is not None and arguments.size_quantiles_per_class <= 0:
        parser.error("--size-quantiles-per-class must be positive")
    main(
        limit_per_class=arguments.limit_per_class,
        size_quantiles_per_class=arguments.size_quantiles_per_class,
        budgets=PreprocessingBudgets(
            arguments.max_slicing_seconds_per_apk,
            arguments.max_slices_per_apk,
            arguments.max_total_slice_instructions,
        ),
    )
