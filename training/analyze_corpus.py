"""Reproducible, read-only audit of the Track-2 sink-slice corpus.

The audit streams canonical JSONL records and loads one token/static-IR shard at
a time. It never regenerates labels, splits, slices, normalization, or tokens.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import math
import random
import statistics
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

import torch


TRAINING_DIR = Path(__file__).resolve().parent
REPO_ROOT = TRAINING_DIR.parent
sys.path.insert(0, str(REPO_ROOT))

from kavach_ai.backend.pipeline.stage3_ml.slicing import DEFAULT_SINK_RULES
from training.build_dataset import (
    NORMALIZATION_CONFIG_SHA256,
    SLICE_ORIGIN,
    SLICE_SCHEMA_VERSION,
    TOKEN_SCHEMA_VERSION,
)
from training.utils.dataset import (
    load_apk_metadata,
    load_apk_splits,
    load_apk_statistics,
    split_mapping_digest,
)
from training.utils.preprocessing import TERMINAL_STATUSES
from training.utils.token_statistics import numeric_distribution, token_length_distribution


AUDIT_VERSION = "corpus-audit-v1"
DEFAULT_SEED = 42
KNOWN_LABELS = frozenset({"Benign", "Malicious"})
KNOWN_STATUSES = (
    "completed",
    "completed_with_truncation",
    "capped",
    "zero_sink",
    "extraction_partial",
    "failed",
    "timed_out",
)
UNAVAILABLE_STATUSES = frozenset({"failed", "timed_out", "extraction_partial"})
CONTEXT_LIMITS = (1024, 2048)
TOKEN_THRESHOLDS = (512, 1024, 2048, 4096, 8192)


@dataclass(slots=True)
class ExampleRecord:
    """Compact cross-artifact representation; full text/tokens are not retained."""

    example_id: str
    apk_hash: str
    label: str
    split: str
    apk_status: str
    sink_category: str
    is_truncated: bool
    retained_instruction_count: int
    involved_method_count: int
    unresolved_boundary_count: int
    raw_character_count: int
    normalized_character_count: int
    reasons: tuple[str, ...]
    slice_path: str
    slice_line: int
    sink_instruction_index: int | None
    normalized_sha256: str
    token_sha256: str | None = None
    token_count: int | None = None


def percentage(numerator: int | float, denominator: int | float) -> float | None:
    """Return a percentage or ``None`` for an empty denominator."""

    return 100.0 * numerator / denominator if denominator else None


def assign_quartiles(values: Mapping[str, int]) -> dict[str, str]:
    """Assign deterministic rank quartiles, breaking value ties by APK hash."""

    ordered = sorted(values, key=lambda key: (values[key], key))
    count = len(ordered)
    if not count:
        return {}
    return {
        key: f"Q{min(3, (4 * index) // count) + 1}"
        for index, key in enumerate(ordered)
    }


def selected_category_counts(
    found_counts: Mapping[str, int], selected_total: int
) -> dict[str, int]:
    """Recover category totals for the deterministic round-robin selector."""

    if selected_total < 0 or selected_total > sum(found_counts.values()):
        raise ValueError("selected_total is outside the found sink count")
    remaining = {key: int(value) for key, value in sorted(found_counts.items())}
    selected = Counter()
    while sum(selected.values()) < selected_total:
        progressed = False
        for category in sorted(remaining):
            if remaining[category] and sum(selected.values()) < selected_total:
                remaining[category] -= 1
                selected[category] += 1
                progressed = True
        if not progressed:
            break
    return dict(sorted(selected.items()))


def context_impact(lengths: Sequence[int], limit: int) -> dict[str, Any]:
    """Summarize head truncation magnitude without claiming sink retention."""

    affected = [value for value in lengths if value > limit]
    discarded = [value - limit for value in affected]
    retained_fraction = [limit / value for value in affected]
    return {
        "context_limit": limit,
        "affected_count": len(affected),
        "affected_percentage": percentage(len(affected), len(lengths)),
        "mean_tokens_discarded_affected": (
            statistics.fmean(discarded) if discarded else None
        ),
        "median_tokens_discarded_affected": (
            statistics.median(discarded) if discarded else None
        ),
        "mean_fraction_retained_affected": (
            statistics.fmean(retained_fraction) if retained_fraction else None
        ),
        "median_fraction_retained_affected": (
            statistics.median(retained_fraction) if retained_fraction else None
        ),
    }


def hash_token_ids(input_ids: Iterable[int]) -> str:
    """Hash a token sequence without constructing a second serialized sequence."""

    digest = hashlib.sha256()
    for token_id in input_ids:
        value = int(token_id)
        if value < 0:
            raise ValueError("token IDs must be non-negative")
        digest.update(value.to_bytes(8, "big", signed=False))
    return digest.hexdigest()


def duplicate_summary(
    groups: Mapping[str, Sequence[Mapping[str, str]]]
) -> dict[str, Any]:
    """Summarize exact-hash duplicate groups and split crossings."""

    duplicate_groups = []
    for digest, members in sorted(groups.items()):
        if len(members) < 2:
            continue
        apks = sorted({item["apk_hash"] for item in members})
        splits = sorted({item["split"] for item in members})
        duplicate_groups.append(
            {
                "sha256": digest,
                "record_count": len(members),
                "duplicate_records_beyond_first": len(members) - 1,
                "apk_count": len(apks),
                "splits": splits,
                "within_same_apk": any(
                    count > 1
                    for count in Counter(item["apk_hash"] for item in members).values()
                ),
                "across_apks": len(apks) > 1,
                "cross_split": len(splits) > 1,
                "sample_example_ids": [item["example_id"] for item in members[:10]],
            }
        )
    return {
        "exact_duplicate_records_beyond_first": sum(
            item["duplicate_records_beyond_first"] for item in duplicate_groups
        ),
        "duplicate_group_count": len(duplicate_groups),
        "within_apk_group_count": sum(item["within_same_apk"] for item in duplicate_groups),
        "across_apk_group_count": sum(item["across_apks"] for item in duplicate_groups),
        "cross_split_group_count": sum(item["cross_split"] for item in duplicate_groups),
        "groups": duplicate_groups,
    }


def simulate_epoch(
    examples: Sequence[ExampleRecord], *, epoch_size: int, seed: int = DEFAULT_SEED
) -> dict[str, Any]:
    """Simulate a class-balanced epoch with near-uniform APK exposure per class."""

    if epoch_size <= 0:
        raise ValueError("epoch_size must be positive")
    by_class: dict[str, dict[str, list[ExampleRecord]]] = {
        label: defaultdict(list) for label in sorted(KNOWN_LABELS)
    }
    for example in examples:
        by_class[example.label][example.apk_hash].append(example)
    if any(not by_class[label] for label in KNOWN_LABELS):
        raise ValueError("both classes need at least one eligible APK")

    randomizer = random.Random(seed)
    targets = {
        "Benign": epoch_size // 2,
        "Malicious": epoch_size - epoch_size // 2,
    }
    selected: list[ExampleRecord] = []
    for label in ("Benign", "Malicious"):
        apk_hashes = sorted(by_class[label])
        remaining = targets[label]
        while remaining:
            cycle = list(apk_hashes)
            randomizer.shuffle(cycle)
            for apk_hash in cycle[:remaining]:
                selected.append(randomizer.choice(by_class[label][apk_hash]))
            remaining -= min(remaining, len(cycle))

    class_counts = Counter(item.label for item in selected)
    apk_counts = Counter(item.apk_hash for item in selected)
    category_counts = Counter(item.sink_category for item in selected)
    unique_examples = len({item.example_id for item in selected})
    return {
        "seed": seed,
        "epoch_size": len(selected),
        "class_counts": dict(sorted(class_counts.items())),
        "class_percentages": {
            key: percentage(value, len(selected)) for key, value in sorted(class_counts.items())
        },
        "unique_apks_represented": len(apk_counts),
        "eligible_apks": sum(len(value) for value in by_class.values()),
        "slices_per_apk": numeric_distribution(list(apk_counts.values())),
        "sink_category_counts": dict(sorted(category_counts.items())),
        "unique_examples": unique_examples,
        "duplicate_draws": len(selected) - unique_examples,
        "duplicate_repeat_percentage": percentage(len(selected) - unique_examples, len(selected)),
    }


def _outcome_table(records: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    statuses = Counter(str(item["status"]) for item in records)
    return {
        "total_apks": len(records),
        "statuses": {
            status: {
                "count": statuses.get(status, 0),
                "percentage": percentage(statuses.get(status, 0), len(records)),
            }
            for status in (*KNOWN_STATUSES, *sorted(set(statuses) - set(KNOWN_STATUSES)))
        },
    }


def _coverage_table(records: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    total = sum(int(item.get("total_sink_count", 0)) for item in records)
    candidate = sum(int(item.get("candidate_selected_sink_count", 0)) for item in records)
    published = sum(int(item.get("slice_count", 0)) for item in records)
    omitted = sum(int(item.get("omitted_sink_count", 0)) for item in records)
    omission_reasons = Counter()
    for item in records:
        count = int(item.get("omitted_sink_count", 0))
        if not count:
            continue
        cap_reason = item.get("cap_reason")
        status = item.get("status")
        stage = str(item.get("failure_stage") or "")
        if cap_reason == "max_slices_per_apk":
            reason = "slice_count_cap"
        elif cap_reason == "max_total_slice_instructions":
            reason = "retained_instruction_cap"
        elif status == "timed_out":
            reason = "timeout"
        elif stage in {"slicing", "slice_worker"}:
            reason = "slice_failure"
        elif stage in {"normalization", "canonical_slice_write", "tokenization"}:
            reason = "normalization_or_tokenization_failure"
        else:
            reason = "other"
        omission_reasons[reason] += count
    return {
        "total_sinks_found": total,
        "candidate_selected_sinks": candidate,
        "published_slices": published,
        "omitted_sinks": omitted,
        "published_over_total_percentage": percentage(published, total),
        "omitted_by_reason": dict(sorted(omission_reasons.items())),
    }


def _frequency_table(records: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    total = len(records)
    counts = Counter(item["status"] for item in records)
    cap_reasons = Counter(
        str(item.get("cap_reason"))
        for item in records
        if item.get("status") == "capped"
    )
    values = {
        "capped": counts.get("capped", 0),
        "capped_slice_count": cap_reasons.get("max_slices_per_apk", 0),
        "capped_retained_instructions": cap_reasons.get(
            "max_total_slice_instructions", 0
        ),
        "timed_out": counts.get("timed_out", 0),
        "extraction_partial": counts.get("extraction_partial", 0),
        "failed": counts.get("failed", 0),
        "zero_sink": counts.get("zero_sink", 0),
    }
    return {
        key: {"count": value, "percentage_of_apks": percentage(value, total)}
        for key, value in values.items()
    }


def _internal_truncation(examples: Sequence[ExampleRecord]) -> dict[str, Any]:
    complete = sum(not item.is_truncated for item in examples)
    truncated = len(examples) - complete
    reasons = Counter(reason for item in examples if item.is_truncated for reason in item.reasons)
    call_depth = sum(
        item.is_truncated and any("CALL_DEPTH" in reason.upper() for reason in item.reasons)
        for item in examples
    )
    instruction_limit = sum(
        item.is_truncated
        and any("INSTRUCTION" in reason.upper() for reason in item.reasons)
        for item in examples
    )
    return {
        "slice_count": len(examples),
        "complete_slice_count": complete,
        "truncated_slice_count": truncated,
        "truncated_percentage": percentage(truncated, len(examples)),
        "retained_instructions": numeric_distribution(
            [item.retained_instruction_count for item in examples]
        ),
        "involved_methods": numeric_distribution(
            [item.involved_method_count for item in examples]
        ),
        "truncation_reason_counts": dict(sorted(reasons.items())),
        "call_depth_limit_slice_count": call_depth,
        "instruction_limit_slice_count": instruction_limit,
    }


def _token_group(examples: Sequence[ExampleRecord]) -> dict[str, Any]:
    lengths = [int(item.token_count) for item in examples if item.token_count is not None]
    return {
        "distribution": token_length_distribution(lengths),
        "context_impact": {
            str(limit): context_impact(lengths, limit) for limit in CONTEXT_LIMITS
        },
    }


def _slice_imbalance(records: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    counts = [int(item.get("slice_count", 0)) for item in records]
    total = sum(counts)
    ordered = sorted(counts, reverse=True)
    contributions = {}
    for fraction in (0.01, 0.05, 0.10):
        top_count = max(1, math.ceil(len(ordered) * fraction)) if ordered else 0
        contributions[f"top_{int(fraction * 100)}_percent_apks"] = percentage(
            sum(ordered[:top_count]), total
        )
    return {
        "apk_count": len(records),
        "slice_count": total,
        "slices_per_apk": numeric_distribution(counts),
        "slice_contribution_percentages": contributions,
    }


def _quartile_analysis(
    assignments: Mapping[str, str],
    statistics_by_hash: Mapping[str, Mapping[str, Any]],
    examples: Sequence[ExampleRecord],
) -> dict[str, Any]:
    examples_by_apk: dict[str, list[ExampleRecord]] = defaultdict(list)
    for example in examples:
        examples_by_apk[example.apk_hash].append(example)
    output: dict[str, Any] = {}
    for quartile in ("Q1", "Q2", "Q3", "Q4"):
        hashes = {key for key, value in assignments.items() if value == quartile}
        for label in (None, "Benign", "Malicious"):
            selected_hashes = {
                key
                for key in hashes
                if label is None or statistics_by_hash[key]["label"] == label
            }
            stats = [statistics_by_hash[key] for key in sorted(selected_hashes)]
            selected_examples = [
                item for key in selected_hashes for item in examples_by_apk.get(key, ())
            ]
            total_sinks = sum(int(item.get("total_sink_count", 0)) for item in stats)
            slices = sum(int(item.get("slice_count", 0)) for item in stats)
            failed_or_timeout = sum(
                item["status"] in {"failed", "timed_out"} for item in stats
            )
            key = quartile if label is None else f"{quartile}:{label}"
            output[key] = {
                "apk_count": len(stats),
                "total_sinks": total_sinks,
                "published_slices": slices,
                "sink_coverage_percentage": percentage(slices, total_sinks),
                "slices_per_apk": numeric_distribution(
                    [int(item.get("slice_count", 0)) for item in stats]
                ),
                "internal_truncation_percentage": percentage(
                    sum(item.is_truncated for item in selected_examples),
                    len(selected_examples),
                ),
                "cap_percentage": percentage(
                    sum(item["status"] == "capped" for item in stats), len(stats)
                ),
                "timeout_or_failed_percentage": percentage(failed_or_timeout, len(stats)),
                "partial_extraction_percentage": percentage(
                    sum(item["status"] == "extraction_partial" for item in stats),
                    len(stats),
                ),
                "median_token_length": (
                    statistics.median(
                        int(item.token_count)
                        for item in selected_examples
                        if item.token_count is not None
                    )
                    if selected_examples
                    else None
                ),
            }
    return output


def _category_analysis(
    statistics_records: Sequence[Mapping[str, Any]],
    examples: Sequence[ExampleRecord],
    hard_failures: list[str],
) -> dict[str, Any]:
    found: dict[str, Counter[str]] = defaultdict(Counter)
    selected: dict[str, Counter[str]] = defaultdict(Counter)
    published: dict[str, Counter[str]] = defaultdict(Counter)
    for item in statistics_records:
        label = str(item["label"])
        retained = Counter({key: int(value) for key, value in item.get("retained_sink_categories", {}).items()})
        omitted = Counter({key: int(value) for key, value in item.get("omitted_sink_categories", {}).items()})
        found_apk = retained + omitted
        try:
            selected_apk = selected_category_counts(
                found_apk, int(item.get("candidate_selected_sink_count", 0))
            )
        except ValueError as exc:
            hard_failures.append(f"{item['apk_hash']}: category selection totals invalid: {exc}")
            selected_apk = {}
        for scope in ("all", label):
            found[scope].update(found_apk)
            selected[scope].update(selected_apk)
            published[scope].update(retained)

    examples_by_scope_category: dict[tuple[str, str], list[ExampleRecord]] = defaultdict(list)
    for example in examples:
        examples_by_scope_category[("all", example.sink_category)].append(example)
        examples_by_scope_category[(example.label, example.sink_category)].append(example)

    output: dict[str, Any] = {}
    categories = sorted(set(found["all"]) | {item.sink_category for item in examples})
    for scope in ("all", "Benign", "Malicious"):
        output[scope] = {}
        for category in categories:
            values = examples_by_scope_category[(scope, category)]
            lengths = [int(item.token_count) for item in values if item.token_count is not None]
            found_count = found[scope][category]
            output[scope][category] = {
                "found_count": found_count,
                "selected_count": selected[scope][category],
                "published_count": published[scope][category],
                "retention_percentage": percentage(published[scope][category], found_count),
                "internal_truncation_percentage": percentage(
                    sum(item.is_truncated for item in values), len(values)
                ),
                "median_token_length": statistics.median(lengths) if lengths else None,
                "percent_gt_1024": percentage(sum(value > 1024 for value in lengths), len(lengths)),
                "percent_gt_2048": percentage(sum(value > 2048 for value in lengths), len(lengths)),
            }
    return output


def _read_static_instruction_counts(
    static_dir: Path, apk_hashes: Sequence[str], warnings: list[str]
) -> dict[str, int]:
    counts: dict[str, int] = {}
    for number, apk_hash in enumerate(apk_hashes, 1):
        path = static_dir / f"{apk_hash}.json.gz"
        if not path.exists():
            continue
        try:
            with gzip.open(path, "rt", encoding="utf-8") as file:
                record = json.load(file)
            counts[apk_hash] = sum(
                len(method.get("instructions", ())) for method in record.get("methods", ())
            )
        except Exception as exc:  # cache audit must continue to canonical training data
            warnings.append(f"Could not read static IR instruction count for {apk_hash}: {exc}")
        if number % 50 == 0 or number == len(apk_hashes):
            print(f"  [static IR {number}/{len(apk_hashes)}]", flush=True)
    return counts


def _md_number(value: Any, digits: int = 2) -> str:
    if value is None:
        return "N/A"
    if isinstance(value, float):
        return f"{value:,.{digits}f}"
    return f"{value:,}" if isinstance(value, int) else str(value)


def _md_table(headers: Sequence[str], rows: Iterable[Sequence[Any]]) -> list[str]:
    lines = [
        "| " + " | ".join(headers) + " |",
        "|" + "|".join("---" for _ in headers) + "|",
    ]
    lines.extend("| " + " | ".join(str(value) for value in row) + " |" for row in rows)
    return lines


def _render_markdown(report: Mapping[str, Any]) -> str:
    failures = report["hard_failures"]
    warnings = report["warnings"]
    recommendation = report["recommendation"]
    lines = [
        "# Track-2 Full Corpus Audit",
        "",
        f"Audit version: `{report['audit_version']}`  ",
        f"Recommendation: **{recommendation.upper()}**",
        "",
        "## Executive summary",
        "",
        f"- APK inventory: {_md_number(report['inventory']['unique_apks'])} unique hashes.",
        f"- Canonical/token examples: {_md_number(report['consistency']['canonical_slice_count'])} / {_md_number(report['consistency']['token_record_count'])}.",
        f"- Hard failures: {len(failures)}; warnings: {len(warnings)}.",
        f"- Exact normalized-content cross-split duplicate groups: {report['duplicates']['normalized_content']['cross_split_group_count']}.",
        f"- Exact token-sequence cross-split duplicate groups: {report['duplicates']['token_sequences']['cross_split_group_count']}.",
        "",
        "## Hard failures",
        "",
    ]
    lines.extend([f"- {item}" for item in failures] or ["- None."])
    lines.extend(["", "## Warnings", ""])
    lines.extend([f"- {item}" for item in warnings] or ["- None."])

    lines.extend(["", "## APK outcomes", ""])
    outcome_rows = []
    for scope, table in report["apk_outcomes"].items():
        for status, value in table["statuses"].items():
            outcome_rows.append((scope, status, value["count"], _md_number(value["percentage"])))
    lines.extend(_md_table(("Scope", "Status", "Count", "% APKs"), outcome_rows))

    lines.extend(["", "## Sink coverage and failure frequency", ""])
    coverage_rows = []
    for scope, value in report["sink_coverage"].items():
        coverage_rows.append(
            (
                scope,
                value["total_sinks_found"],
                value["candidate_selected_sinks"],
                value["published_slices"],
                value["omitted_sinks"],
                _md_number(value["published_over_total_percentage"]),
            )
        )
    lines.extend(
        _md_table(
            ("Scope", "Found", "Candidate selected", "Published", "Omitted", "Coverage %"),
            coverage_rows,
        )
    )
    lines.extend(["", "Omission reasons are sink counts when derivable:", ""])
    lines.append("```json")
    lines.append(json.dumps({key: value["omitted_by_reason"] for key, value in report["sink_coverage"].items()}, indent=2))
    lines.append("```")
    lines.extend(["", "APK cap/unavailable frequencies:", ""])
    frequency_rows = []
    for scope, values in report["cap_and_failure_frequency"].items():
        for outcome, value in values.items():
            frequency_rows.append(
                (scope, outcome, value["count"], _md_number(value["percentage_of_apks"]))
            )
    lines.extend(_md_table(("Scope", "Outcome", "APKs", "% APKs"), frequency_rows))

    lines.extend(["", "## Internal slice truncation", ""])
    trunc_rows = []
    for scope, value in report["internal_truncation"].items():
        trunc_rows.append(
            (
                scope,
                value["complete_slice_count"],
                value["truncated_slice_count"],
                _md_number(value["truncated_percentage"]),
                value["call_depth_limit_slice_count"],
                value["instruction_limit_slice_count"],
            )
        )
    lines.extend(_md_table(("Scope", "Complete", "Truncated", "% truncated", "Call-depth hits", "Instruction-limit hits"), trunc_rows))
    overall_truncation = report["internal_truncation"]["all"]
    lines.extend(["", "Overall retained-evidence distributions:", ""])
    lines.append("```json")
    lines.append(
        json.dumps(
            {
                "retained_instructions": overall_truncation["retained_instructions"],
                "involved_methods": overall_truncation["involved_methods"],
                "truncation_reason_counts": overall_truncation["truncation_reason_counts"],
            },
            indent=2,
        )
    )
    lines.append("```")

    lines.extend(["", "## Token and context length", ""])
    token_rows = []
    for scope, value in report["token_context"].items():
        dist = value["distribution"]
        token_rows.append(
            (
                scope,
                dist["count"],
                _md_number(dist["mean"]),
                _md_number(dist["median"]),
                _md_number(dist["p90"]),
                _md_number(dist["p95"]),
                _md_number(dist["p99"]),
                dist["max"],
                _md_number(dist["percent_gt_512"]),
                _md_number(dist["percent_gt_1024"]),
                _md_number(dist["percent_gt_2048"]),
                _md_number(dist["percent_gt_4096"]),
                _md_number(dist["percent_gt_8192"]),
            )
        )
    lines.extend(_md_table(("Scope", "N", "Mean", "Median", "p90", "p95", "p99", "Max", ">512 %", ">1024 %", ">2048 %", ">4096 %", ">8192 %"), token_rows))
    lines.extend(["", "Context impact for affected sequences:", ""])
    impact_rows = []
    for limit, value in report["token_context"]["all"]["context_impact"].items():
        impact_rows.append(
            (
                limit,
                value["affected_count"],
                _md_number(value["affected_percentage"]),
                _md_number(value["mean_tokens_discarded_affected"]),
                _md_number(value["median_tokens_discarded_affected"]),
                _md_number(value["mean_fraction_retained_affected"], 4),
                _md_number(value["median_fraction_retained_affected"], 4),
            )
        )
    lines.extend(_md_table(("Limit", "Affected", "%", "Mean discarded", "Median discarded", "Mean retained fraction", "Median retained fraction"), impact_rows))

    lines.extend(["", "### Sink-position limitation", "", report["sink_position_analysis"]["explanation"], ""])

    lines.extend(["## APK-size quartiles", ""])
    for basis, values in report["apk_size_relationship"].items():
        lines.extend([f"### {basis.replace('_', ' ').title()}", ""])
        if values.get("available") is False:
            lines.append(values["reason"])
            lines.append("")
            continue
        rows = []
        for scope, item in values["groups"].items():
            rows.append(
                (
                    scope,
                    item["apk_count"],
                    item["total_sinks"],
                    _md_number(item["sink_coverage_percentage"]),
                    item["published_slices"],
                    _md_number(item["slices_per_apk"]["median"]),
                    _md_number(item["slices_per_apk"]["p90"]),
                    _md_number(item["internal_truncation_percentage"]),
                    _md_number(item["cap_percentage"]),
                    _md_number(item["timeout_or_failed_percentage"]),
                    _md_number(item["partial_extraction_percentage"]),
                    _md_number(item["median_token_length"]),
                )
            )
        lines.extend(_md_table(("Group", "APKs", "Sinks", "Coverage %", "Slices", "Median/APK", "p90/APK", "Truncated %", "Capped %", "Timeout/failed %", "Partial %", "Median tokens"), rows))
        lines.append("")

    lines.extend(["## Category retention", ""])
    category_rows = []
    for scope, categories in report["category_retention"].items():
        for category, value in categories.items():
            category_rows.append(
                (
                    scope,
                    category,
                    value["found_count"],
                    value["selected_count"],
                    value["published_count"],
                    _md_number(value["retention_percentage"]),
                    _md_number(value["internal_truncation_percentage"]),
                    _md_number(value["median_token_length"]),
                    _md_number(value["percent_gt_1024"]),
                    _md_number(value["percent_gt_2048"]),
                )
            )
    lines.extend(_md_table(("Scope", "Category", "Found", "Selected", "Published", "Retention %", "Truncated %", "Median tokens", ">1024 %", ">2048 %"), category_rows))

    lines.extend(["", "## Class and APK imbalance", ""])
    imbalance_rows = []
    for scope, value in report["apk_slice_imbalance"].items():
        dist = value["slices_per_apk"]
        imbalance_rows.append((scope, value["apk_count"], value["slice_count"], _md_number(dist["mean"]), _md_number(dist["median"]), _md_number(dist["p90"]), _md_number(dist["p95"]), dist["max"], _md_number(value["slice_contribution_percentages"]["top_1_percent_apks"]), _md_number(value["slice_contribution_percentages"]["top_5_percent_apks"]), _md_number(value["slice_contribution_percentages"]["top_10_percent_apks"])))
    lines.extend(_md_table(("Scope", "APKs", "Slices", "Mean", "Median", "p90", "p95", "Max", "Top 1% share", "Top 5% share", "Top 10% share"), imbalance_rows))
    sampler = report["sampler_simulation"]
    lines.extend(["", "Deterministic APK-aware class-balanced epoch simulation:", ""])
    lines.append("```json")
    lines.append(json.dumps(sampler, indent=2))
    lines.append("```")

    lines.extend(["", "## Duplicates and leakage", ""])
    duplicate_rows = []
    for name, value in report["duplicates"].items():
        duplicate_rows.append((name, value["exact_duplicate_records_beyond_first"], value["duplicate_group_count"], value["within_apk_group_count"], value["across_apk_group_count"], value["cross_split_group_count"]))
    lines.extend(_md_table(("Representation", "Duplicate records", "Groups", "Within APK groups", "Across APK groups", "Cross-split groups"), duplicate_rows))

    lines.extend(["", "## Outliers", ""])
    extreme = report["outliers"]["token_records_gt_8192"]
    lines.append(f"All token records above 8,192 ({len(extreme)}):")
    lines.append("")
    lines.extend(_md_table(("Example ID", "APK", "Class", "Split", "Category", "Tokens", "Instructions", "Methods", "Boundaries", "Raw chars", "Normalized chars", "Canonical record"), ((item["example_id"], item["apk_hash"], item["label"], item["split"], item["sink_category"], item["token_count"], item["retained_instruction_count"], item["involved_method_count"], item["unresolved_boundary_count"], item["raw_character_count"], item["normalized_character_count"], f"{item['slice_path']}:{item['slice_line']}") for item in extreme)))
    lines.extend(["", "### APKs with exactly 256 published slices", ""])
    lines.extend(
        _md_table(
            ("APK", "Class", "Split", "Status", "Found sinks", "Cap reason"),
            (
                (item["apk_hash"], item["label"], item["split"], item["status"], item["total_sink_count"], item["cap_reason"])
                for item in report["outliers"]["apks_at_256_slices"]
            ),
        )
    )
    lines.extend(["", "### Highest internal-truncation-rate APKs", ""])
    lines.extend(
        _md_table(
            ("APK", "Class", "Slices", "Truncated", "% truncated"),
            (
                (item["apk_hash"], item["label"], item["slice_count"], item["truncated_slice_count"], _md_number(item["truncated_percentage"]))
                for item in report["outliers"]["highest_truncation_rate_apks"]
            ),
        )
    )
    lines.extend(["", "### Highest sink-count APKs", ""])
    lines.extend(
        _md_table(
            ("APK", "Class", "Status", "Found", "Candidate", "Published", "Omitted", "Cap reason"),
            (
                (item["apk_hash"], item["label"], item["status"], item["total_sink_count"], item["candidate_selected_sink_count"], item["slice_count"], item["omitted_sink_count"], item["cap_reason"])
                for item in report["outliers"]["highest_sink_count_apks"]
            ),
        )
    )
    lines.extend(["", "### Zero-sink APKs", ""])
    lines.extend(
        _md_table(
            ("APK", "Class", "Split", "Bytes"),
            ((item["apk_hash"], item["label"], item["split"], item["apk_size_bytes"]) for item in report["outliers"]["zero_sink_apks"]),
        )
    )
    lines.extend(["", "### Partial, failed, or timed-out APKs", ""])
    lines.extend(
        _md_table(
            ("APK", "Class", "Split", "Status", "Stage", "Error"),
            ((item["apk_hash"], item["label"], item["split"], item["status"], item["failure_stage"], str(item["error"]).replace("|", "\\|")) for item in report["outliers"]["unavailable_apks"]),
        )
    )
    lines.extend(["", "Full deterministic duplicate-group summaries are in the JSON report."])

    lines.extend(["", "## Metrics unavailable from current artifacts", ""])
    lines.extend(f"- {item}" for item in report["unavailable_metrics"])

    lines.extend(["", "## Consistency", "", "```json", json.dumps(report["consistency"], indent=2), "```", "", "## Recommendation", "", f"**{recommendation.upper()}**"])
    return "\n".join(lines) + "\n"


def audit_corpus(
    data_root: Path,
    *,
    include_static_ir_instructions: bool = True,
    sampler_seed: int = DEFAULT_SEED,
) -> dict[str, Any]:
    """Audit a completed corpus without modifying any existing artifact."""

    manifest_dir = data_root / "manifests"
    manifest = json.loads((manifest_dir / "dataset_v1.json").read_text(encoding="utf-8"))
    metadata = load_apk_metadata(manifest_dir / "apk_metadata.jsonl")
    statistics_by_hash = load_apk_statistics(manifest_dir / "apk_statistics_v1.jsonl")
    splits = load_apk_splits(manifest_dir / "apk_splits_v1.json", set(metadata))
    hard_failures: list[str] = []
    warnings: list[str] = []

    if set(statistics_by_hash) != set(metadata):
        hard_failures.append(
            "APK statistics inventory mismatch: "
            f"missing={len(set(metadata) - set(statistics_by_hash))}, "
            f"extra={len(set(statistics_by_hash) - set(metadata))}"
        )
    for apk_hash, item in metadata.items():
        if item.get("label") not in KNOWN_LABELS:
            hard_failures.append(f"{apk_hash}: unknown label {item.get('label')!r}")
    for apk_hash, item in statistics_by_hash.items():
        if item.get("label") != metadata.get(apk_hash, {}).get("label"):
            hard_failures.append(f"{apk_hash}: statistics label conflicts with metadata")
        if item.get("split") != splits.get(apk_hash):
            hard_failures.append(f"{apk_hash}: statistics split conflicts with immutable mapping")
        if item.get("status") not in KNOWN_STATUSES:
            hard_failures.append(f"{apk_hash}: unknown processing status {item.get('status')!r}")

    manifest_counts = manifest.get("counts", {})
    if manifest_counts.get("unique_apks") != len(metadata):
        hard_failures.append("manifest unique APK count does not match metadata")
    if manifest.get("split_mapping_sha256") != split_mapping_digest(splits):
        hard_failures.append("manifest split mapping digest does not match immutable split file")

    statistics_records = [statistics_by_hash[key] for key in sorted(statistics_by_hash)]
    expected_categories = {rule.category for rule in DEFAULT_SINK_RULES}
    observed_categories: set[str] = set()
    examples: list[ExampleRecord] = []
    examples_by_id: dict[str, ExampleRecord] = {}
    normalized_groups: dict[str, list[dict[str, str]]] = defaultdict(list)
    canonical_counts = Counter()
    slice_dir = data_root / "slices" / "v1"
    policy_digest = manifest["preprocessing"]["content_config_sha256"]

    print("Streaming canonical slice shards...", flush=True)
    for number, apk_hash in enumerate(sorted(metadata), 1):
        stat = statistics_by_hash.get(apk_hash)
        if stat is None:
            continue
        path = slice_dir / f"{apk_hash}.jsonl.gz"
        status = stat["status"]
        if status in TERMINAL_STATUSES and not path.exists():
            hard_failures.append(f"{apk_hash}: terminal outcome is missing canonical slice shard")
            continue
        if status not in TERMINAL_STATUSES:
            if path.exists():
                warnings.append(f"{apk_hash}: retryable outcome has a stale canonical slice shard")
            continue
        local_count = local_truncated = 0
        with gzip.open(path, "rt", encoding="utf-8") as file:
            for line_number, line in enumerate(file, 1):
                if not line.strip():
                    continue
                item = json.loads(line)
                local_count += 1
                required = {
                    "apk_hash", "example_id", "sink_category", "sink_identity",
                    "normalized_slice_text", "raw_slice_text", "is_truncated",
                    "retained_instruction_count", "involved_methods", "issues",
                    "unresolved_boundaries",
                }
                missing = required - set(item)
                if missing:
                    hard_failures.append(f"{path}:{line_number}: missing fields {sorted(missing)}")
                    continue
                if item.get("apk_hash") != apk_hash:
                    hard_failures.append(f"{path}:{line_number}: APK hash mismatch")
                if (
                    item.get("schema_version") != SLICE_SCHEMA_VERSION
                    or item.get("slice_origin") != SLICE_ORIGIN
                    or item.get("slicer_config_sha256") != policy_digest
                    or item.get("normalization_config_sha256") != NORMALIZATION_CONFIG_SHA256
                ):
                    hard_failures.append(f"{path}:{line_number}: incompatible canonical schema/fingerprint")
                identity = item.get("sink_identity", {})
                if identity.get("apk_hash") != apk_hash:
                    hard_failures.append(f"{path}:{line_number}: sink identity APK mismatch")
                example_id = str(item["example_id"])
                if example_id in examples_by_id:
                    hard_failures.append(f"duplicate canonical example_id {example_id}")
                    continue
                category = str(item["sink_category"])
                observed_categories.add(category)
                reasons = tuple(
                    sorted(
                        {str(value.get("code")) for value in item.get("issues", ()) if value.get("code")}
                        | {str(value.get("kind")) for value in item.get("unresolved_boundaries", ()) if value.get("kind")}
                    )
                )
                normalized_text = item["normalized_slice_text"]
                if not isinstance(normalized_text, str) or not isinstance(item["raw_slice_text"], str):
                    hard_failures.append(f"{path}:{line_number}: slice text is not a string")
                    continue
                normalized_hash = hashlib.sha256(normalized_text.encode("utf-8")).hexdigest()
                record = ExampleRecord(
                    example_id=example_id,
                    apk_hash=apk_hash,
                    label=metadata[apk_hash]["label"],
                    split=splits[apk_hash],
                    apk_status=status,
                    sink_category=category,
                    is_truncated=bool(item["is_truncated"]),
                    retained_instruction_count=int(item["retained_instruction_count"]),
                    involved_method_count=len(item["involved_methods"]),
                    unresolved_boundary_count=len(item["unresolved_boundaries"]),
                    raw_character_count=len(item["raw_slice_text"]),
                    normalized_character_count=len(normalized_text),
                    reasons=reasons,
                    slice_path=str(path.relative_to(REPO_ROOT)),
                    slice_line=line_number,
                    sink_instruction_index=identity.get("instruction_index"),
                    normalized_sha256=normalized_hash,
                )
                examples.append(record)
                examples_by_id[example_id] = record
                normalized_groups[normalized_hash].append(
                    {"example_id": example_id, "apk_hash": apk_hash, "split": splits[apk_hash]}
                )
                local_truncated += record.is_truncated
        canonical_counts[apk_hash] = local_count
        if local_count != int(stat.get("slice_count", 0)):
            hard_failures.append(f"{apk_hash}: canonical count {local_count} != ledger slice_count {stat.get('slice_count')}")
        if local_truncated != int(stat.get("truncated_slice_count", 0)):
            hard_failures.append(f"{apk_hash}: canonical truncated count does not match ledger")
        if number % 100 == 0 or number == len(metadata):
            print(f"  [canonical {number}/{len(metadata)}]", flush=True)

    unknown_categories = sorted(observed_categories - expected_categories)
    if unknown_categories:
        warnings.append(f"Observed sink categories outside DEFAULT_SINK_RULES: {unknown_categories}")

    token_fingerprint = manifest["tokenizer_fingerprint"]
    token_dir = data_root / "tokens" / token_fingerprint
    token_groups: dict[str, list[dict[str, str]]] = defaultdict(list)
    token_seen: set[str] = set()
    token_counts = Counter()
    print("Streaming token shards...", flush=True)
    for number, apk_hash in enumerate(sorted(metadata), 1):
        stat = statistics_by_hash.get(apk_hash)
        if stat is None:
            continue
        path = token_dir / f"{apk_hash}.pt"
        status = stat["status"]
        if status in TERMINAL_STATUSES and not path.exists():
            hard_failures.append(f"{apk_hash}: terminal outcome is missing token shard")
            continue
        if status not in TERMINAL_STATUSES:
            if path.exists():
                warnings.append(f"{apk_hash}: retryable outcome has a stale token shard")
            continue
        shard = torch.load(path, map_location="cpu", weights_only=True)
        if (
            shard.get("schema_version") != TOKEN_SCHEMA_VERSION
            or shard.get("apk_hash") != apk_hash
            or shard.get("tokenizer_fingerprint") != token_fingerprint
            or shard.get("slice_schema_version") != SLICE_SCHEMA_VERSION
            or shard.get("slicer_config_sha256") != policy_digest
            or shard.get("normalization_config_sha256") != NORMALIZATION_CONFIG_SHA256
        ):
            hard_failures.append(f"{path}: incompatible token shard metadata/fingerprint")
        total_tokens = 0
        for item in shard.get("examples", ()):
            example_id = str(item.get("example_id"))
            if example_id in token_seen:
                hard_failures.append(f"duplicate token example_id {example_id}")
                continue
            token_seen.add(example_id)
            record = examples_by_id.get(example_id)
            if record is None:
                hard_failures.append(f"{path}: token example {example_id} has no canonical slice")
                continue
            if (
                item.get("apk_hash") != apk_hash
                or item.get("sink_category") != record.sink_category
                or bool(item.get("is_truncated")) != record.is_truncated
            ):
                hard_failures.append(f"{path}: token/canonical metadata mismatch for {example_id}")
            if "attention_mask" in item or "label" in item:
                hard_failures.append(f"{path}: token example contains label or permanent mask")
            input_ids = item.get("input_ids", ())
            token_count = int(item.get("token_count", -1))
            if token_count != len(input_ids):
                hard_failures.append(f"{path}: token_count mismatch for {example_id}")
            digest = hash_token_ids(input_ids)
            record.token_count = token_count
            record.token_sha256 = digest
            total_tokens += token_count
            token_counts[apk_hash] += 1
            token_groups[digest].append(
                {"example_id": example_id, "apk_hash": apk_hash, "split": splits[apk_hash]}
            )
        if token_counts[apk_hash] != canonical_counts[apk_hash]:
            hard_failures.append(f"{apk_hash}: token record count does not match canonical count")
        if total_tokens != int(stat.get("total_token_count", 0)):
            hard_failures.append(f"{apk_hash}: token total does not match ledger")
        if number % 100 == 0 or number == len(metadata):
            print(f"  [tokens {number}/{len(metadata)}]", flush=True)

    missing_tokens = sorted(set(examples_by_id) - token_seen)
    if missing_tokens:
        hard_failures.append(f"{len(missing_tokens)} canonical examples have no token record")

    shard_index_path = token_dir / "shard_index.json"
    if not shard_index_path.exists():
        hard_failures.append("token shard index is missing")
    else:
        shard_index = json.loads(shard_index_path.read_text(encoding="utf-8"))
        expected_shards = {
            f"{apk_hash}.pt"
            for apk_hash, item in statistics_by_hash.items()
            if item["status"] in TERMINAL_STATUSES and (token_dir / f"{apk_hash}.pt").exists()
        }
        if (
            shard_index.get("schema_version") != TOKEN_SCHEMA_VERSION
            or shard_index.get("tokenizer_fingerprint") != token_fingerprint
            or set(shard_index.get("shards", ())) != expected_shards
        ):
            hard_failures.append("token shard index is incompatible or incomplete")

    source_size_assignments = assign_quartiles(
        {key: int(value["apk_size_bytes"]) for key, value in metadata.items()}
    )
    if include_static_ir_instructions:
        print("Reading static IR instruction counts (one shard at a time)...", flush=True)
        instruction_counts = _read_static_instruction_counts(
            data_root / "static_ir" / "v1", sorted(metadata), warnings
        )
        instruction_assignments = assign_quartiles(instruction_counts)
    else:
        instruction_counts = {}
        instruction_assignments = {}
        warnings.append("Extracted-instruction quartiles were skipped by CLI option")

    groups: dict[str, list[ExampleRecord]] = defaultdict(list)
    for item in examples:
        groups["all"].append(item)
        groups[f"class:{item.label}"].append(item)
        groups[f"sink_category:{item.sink_category}"].append(item)
        groups[f"status:{item.apk_status}"].append(item)
        groups[f"truncated:{item.is_truncated}"].append(item)
        groups[f"apk_size:{source_size_assignments[item.apk_hash]}"] .append(item)

    outcome_scopes = {
        "all": statistics_records,
        "Benign": [item for item in statistics_records if item["label"] == "Benign"],
        "Malicious": [item for item in statistics_records if item["label"] == "Malicious"],
    }
    category_retention = _category_analysis(statistics_records, examples, hard_failures)
    all_categories = category_retention["all"]
    category_total = sum(item["published_count"] for item in all_categories.values())
    dominant = sorted(
        (
            {"category": key, "published_count": value["published_count"], "published_percentage": percentage(value["published_count"], category_total)}
            for key, value in all_categories.items()
        ),
        key=lambda item: (-item["published_count"], item["category"]),
    )
    rare = [item for item in dominant if item["published_count"] < max(10, category_total * 0.001)]
    if dominant and dominant[0]["published_percentage"] is not None and dominant[0]["published_percentage"] > 50:
        warnings.append(f"Dominant sink category {dominant[0]['category']} contributes {dominant[0]['published_percentage']:.2f}% of slices")
    if rare:
        warnings.append("Rare sink categories are present; see category retention report")

    normalized_duplicates = duplicate_summary(normalized_groups)
    token_duplicates = duplicate_summary(token_groups)
    if normalized_duplicates["cross_split_group_count"]:
        warnings.append("Exact normalized slice content crosses immutable splits")
    if token_duplicates["cross_split_group_count"]:
        warnings.append("Exact token sequences cross immutable splits")

    token_all = _token_group(groups["all"])
    manifest_all = manifest.get("statistics", {}).get("token_lengths", {}).get("all", {})
    if manifest_all.get("count") != token_all["distribution"]["count"]:
        hard_failures.append("manifest global token count does not match audited token records")

    apk_outcomes = {key: _outcome_table(value) for key, value in outcome_scopes.items()}
    status_total = sum(value["count"] for value in apk_outcomes["all"]["statuses"].values())
    if status_total != len(metadata):
        hard_failures.append("APK status totals do not reconcile with unique inventory")
    for status in KNOWN_STATUSES:
        manifest_value = manifest_counts.get(f"{status}_apks", 0)
        audited_value = apk_outcomes["all"]["statuses"][status]["count"]
        if manifest_value != audited_value:
            hard_failures.append(f"manifest status count mismatch for {status}")

    outlier_records = sorted(
        (
            {
                "example_id": item.example_id,
                "apk_hash": item.apk_hash,
                "label": item.label,
                "split": item.split,
                "sink_category": item.sink_category,
                "token_count": item.token_count,
                "is_truncated": item.is_truncated,
                "retained_instruction_count": item.retained_instruction_count,
                "involved_method_count": item.involved_method_count,
                "unresolved_boundary_count": item.unresolved_boundary_count,
                "raw_character_count": item.raw_character_count,
                "normalized_character_count": item.normalized_character_count,
                "slice_path": item.slice_path,
                "slice_line": item.slice_line,
                "sink_instruction_index": item.sink_instruction_index,
            }
            for item in examples
            if int(item.token_count or 0) > 8192
        ),
        key=lambda item: (-int(item["token_count"]), item["example_id"]),
    )
    if outlier_records:
        warnings.append(f"{len(outlier_records)} token records exceed 8,192 tokens; maximum is {outlier_records[0]['token_count']}")
        maximum = outlier_records[0]
        warnings.append(
            "Maximum token outlier expands "
            f"{maximum['retained_instruction_count']} retained instructions and "
            f"{maximum['unresolved_boundary_count']} unresolved boundaries from "
            f"{maximum['raw_character_count']} raw characters to "
            f"{maximum['normalized_character_count']} normalized characters"
        )

    apk_truncation_rates = []
    for item in statistics_records:
        slices = int(item.get("slice_count", 0))
        if slices:
            apk_truncation_rates.append(
                {
                    "apk_hash": item["apk_hash"],
                    "label": item["label"],
                    "slice_count": slices,
                    "truncated_slice_count": int(item.get("truncated_slice_count", 0)),
                    "truncated_percentage": percentage(int(item.get("truncated_slice_count", 0)), slices),
                }
            )
    apk_truncation_rates.sort(key=lambda item: (-float(item["truncated_percentage"] or 0), -item["slice_count"], item["apk_hash"]))

    token_context = {key: _token_group(value) for key, value in sorted(groups.items()) if not key.startswith("apk_size:")}
    internal_truncation = {
        key: _internal_truncation(value)
        for key, value in sorted(groups.items())
        if key == "all" or key.startswith(("class:", "sink_category:", "apk_size:"))
    }
    report: dict[str, Any] = {
        "audit_version": AUDIT_VERSION,
        "sampler_seed": sampler_seed,
        "manifest_dataset_version": manifest.get("dataset_version"),
        "tokenizer_fingerprint": token_fingerprint,
        "split_mapping_sha256": split_mapping_digest(splits),
        "inventory": {
            "unique_apks": len(metadata),
            "duplicate_source_files": sum(
                len(item.get("duplicate_source_paths", ())) for item in metadata.values()
            ),
            "conflicting_label_hashes": 0,
            "labels": dict(sorted(Counter(item["label"] for item in metadata.values()).items())),
            "splits": dict(sorted(Counter(splits.values()).items())),
        },
        "hard_failures": sorted(set(hard_failures)),
        "warnings": sorted(set(warnings)),
        "apk_outcomes": apk_outcomes,
        "sink_coverage": {key: _coverage_table(value) for key, value in outcome_scopes.items()},
        "cap_and_failure_frequency": {key: _frequency_table(value) for key, value in outcome_scopes.items()},
        "internal_truncation": internal_truncation,
        "token_context": token_context,
        "sink_position_analysis": {
            "recoverable": False,
            "head_tail_sink_centered_metrics": None,
            "explanation": (
                "The canonical sink instruction index is retained, but neither canonical records nor token shards store a reliable normalized instruction/character span to token-offset mapping. Head-only, tail-only, and sink-centred sink-retention percentages therefore cannot be derived without guessing. The smallest future addition is `sink_token_start` and `sink_token_end` (exclusive) in each token example, computed from tokenizer offset mappings; retaining the normalized sink character span would make the derivation auditable. Existing corpus artifacts were not changed."
            ),
        },
        "apk_size_relationship": {
            "source_byte_size": {
                "available": True,
                "groups": _quartile_analysis(source_size_assignments, statistics_by_hash, examples),
            },
            "extracted_instruction_count": (
                {
                    "available": True,
                    "apk_count_with_static_ir": len(instruction_counts),
                    "groups": _quartile_analysis(instruction_assignments, statistics_by_hash, examples),
                }
                if instruction_assignments
                else {
                    "available": False,
                    "reason": "Static-IR instruction counting was skipped or no readable static IR was present.",
                }
            ),
        },
        "category_retention": category_retention,
        "category_dominance": {"descending": dominant, "rare": rare},
        "apk_slice_imbalance": {key: _slice_imbalance(value) for key, value in outcome_scopes.items()},
        "sampler_simulation": simulate_epoch(examples, epoch_size=len(examples), seed=sampler_seed),
        "duplicates": {
            "normalized_content": normalized_duplicates,
            "token_sequences": token_duplicates,
        },
        "outliers": {
            "maximum_token_record": outlier_records[0] if outlier_records else None,
            "token_records_gt_8192": outlier_records,
            "apks_at_256_slices": [
                {key: item.get(key) for key in ("apk_hash", "label", "split", "status", "total_sink_count", "slice_count", "cap_reason")}
                for item in statistics_records
                if int(item.get("slice_count", 0)) == 256
            ],
            "highest_truncation_rate_apks": apk_truncation_rates[:25],
            "highest_sink_count_apks": [
                {key: item.get(key) for key in ("apk_hash", "label", "split", "status", "total_sink_count", "candidate_selected_sink_count", "slice_count", "omitted_sink_count", "cap_reason")}
                for item in sorted(statistics_records, key=lambda value: (-int(value.get("total_sink_count", 0)), value["apk_hash"]))[:25]
            ],
            "zero_sink_apks": [
                {key: item.get(key) for key in ("apk_hash", "label", "split", "apk_size_bytes", "status")}
                for item in statistics_records if item["status"] == "zero_sink"
            ],
            "unavailable_apks": [
                {key: item.get(key) for key in ("apk_hash", "label", "split", "apk_size_bytes", "status", "failure_stage", "error")}
                for item in statistics_records if item["status"] in UNAVAILABLE_STATUSES
            ],
        },
        "unavailable_metrics": [
            "Reliable sink token spans and head/tail/sink-centred window retention metrics are unavailable because instruction-to-token offsets were not stored.",
            "Per-slice maximum observed call depth is not stored; only structured truncation issues/boundaries can be counted.",
            "Omitted sink reasons before sink detection cannot be quantified for failed/partial extraction because no complete sink inventory exists for those APKs.",
        ],
        "consistency": {
            "metadata_record_count": len(metadata),
            "statistics_record_count": len(statistics_by_hash),
            "canonical_slice_count": len(examples),
            "token_record_count": len(token_seen),
            "manifest_global_token_count": manifest_all.get("count"),
            "unique_canonical_example_ids": len(examples_by_id),
            "unique_token_example_ids": len(token_seen),
            "all_apks_have_one_split": set(splits) == set(metadata),
            "labels_valid": all(item["label"] in KNOWN_LABELS for item in metadata.values()),
            "unknown_statuses": sorted({item["status"] for item in statistics_records} - set(KNOWN_STATUSES)),
            "unknown_categories": unknown_categories,
            "conflicting_label_hash_count": 0,
            "hard_failure_count": len(set(hard_failures)),
        },
    }
    if report["hard_failures"]:
        report["recommendation"] = "not ready for tiny overfit test"
    elif report["warnings"]:
        report["recommendation"] = "ready with warnings for tiny overfit test"
    else:
        report["recommendation"] = "ready for tiny overfit test"
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-root", type=Path, default=TRAINING_DIR / "data")
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=TRAINING_DIR / "data" / "analysis" / "corpus_audit_v1",
    )
    parser.add_argument("--sampler-seed", type=int, default=DEFAULT_SEED)
    parser.add_argument(
        "--skip-static-ir-instructions",
        action="store_true",
        help="Skip the expensive extracted-instruction quartile analysis.",
    )
    arguments = parser.parse_args()
    report = audit_corpus(
        arguments.data_root,
        include_static_ir_instructions=not arguments.skip_static_ir_instructions,
        sampler_seed=arguments.sampler_seed,
    )
    arguments.output_dir.mkdir(parents=True, exist_ok=True)
    json_path = arguments.output_dir / "corpus_audit.json"
    markdown_path = arguments.output_dir / "corpus_audit.md"
    json_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    markdown_path.write_text(_render_markdown(report), encoding="utf-8")
    print(f"JSON report: {json_path}")
    print(f"Markdown report: {markdown_path}")
    print(f"Recommendation: {report['recommendation']}")
    print(f"Hard failures: {len(report['hard_failures'])}; warnings: {len(report['warnings'])}")
    return 2 if report["hard_failures"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
