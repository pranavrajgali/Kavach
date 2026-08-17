"""Compact, read-only metrics for a resumable V2 extraction checkpoint.

The functions consume stable summaries emitted by extraction.  They neither know
where APKs live nor mutate artifacts, which keeps audit code safe to run while a
checkpoint is still being produced.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from math import ceil
from statistics import mean, median
from typing import Iterable, Mapping, Sequence


CHECKPOINT_AUDIT_SCHEMA = "checkpoint-audit-v2alpha1"
TERMINAL_FAILURES = frozenset({"FAILED", "TIMEOUT", "OOM", "PARTIAL"})


@dataclass(frozen=True)
class PhaseMeasure:
    phase: str
    status: str
    runtime_seconds: float = 0.0
    max_rss_kb: int | None = None
    storage_bytes: int = 0


@dataclass(frozen=True)
class APKCheckpointRecord:
    apk_sha256: str
    label: str
    split: str
    raw_occurrences: int
    artifact_hashes: tuple[str, ...]
    artifact_token_counts: tuple[int, ...] = ()
    lane_counts: tuple[tuple[str, int], ...] = ()
    behavior_counts: tuple[tuple[str, int], ...] = ()
    phase_measures: tuple[PhaseMeasure, ...] = ()
    source_endpoint_counts: tuple[tuple[str, int], ...] = ()
    endpoint_definition_counts: tuple[tuple[str, int], ...] = ()

    def __post_init__(self) -> None:
        if len(self.apk_sha256) != 64:
            raise ValueError("apk_sha256 must contain 64 characters")
        if self.raw_occurrences < len(self.artifact_hashes):
            raise ValueError("raw_occurrences cannot be smaller than collapsed artifacts")
        if any(value < 0 for value in self.artifact_token_counts):
            raise ValueError("token counts must be non-negative")
        if self.artifact_token_counts and len(self.artifact_token_counts) != len(self.artifact_hashes):
            raise ValueError("token counts must align with artifact hashes")


def _percentile(values: Sequence[int], percentile: float) -> int | None:
    """Nearest-rank percentile, deterministic and dependency-free."""

    if not values:
        return None
    ordered = sorted(values)
    return ordered[max(0, ceil(percentile * len(ordered)) - 1)]


def _distribution(values: Sequence[int]) -> dict[str, int | float | None]:
    return {
        "count": len(values),
        "mean": mean(values) if values else None,
        "median": median(values) if values else None,
        "p90": _percentile(values, 0.90),
        "p95": _percentile(values, 0.95),
        "max": max(values) if values else None,
    }


def build_checkpoint_metrics(
    records: Iterable[APKCheckpointRecord], *, total_planned_apks: int | None = None,
    token_thresholds: Sequence[int] = (512, 1024, 2048, 4096),
) -> dict[str, object]:
    """Aggregate a compact checkpoint without reading APKs or generated files."""

    values = tuple(records)
    hashes = [item.apk_sha256 for item in values]
    if len(hashes) != len(set(hashes)):
        raise ValueError("checkpoint contains duplicate APK identities")
    if total_planned_apks is not None and total_planned_apks < len(values):
        raise ValueError("total_planned_apks cannot be smaller than this checkpoint")
    thresholds = tuple(sorted(set(token_thresholds)))
    if any(value <= 0 for value in thresholds):
        raise ValueError("token thresholds must be positive")

    class_counts = Counter(item.label for item in values)
    split_counts = Counter(item.split for item in values)
    composition = Counter((item.label, item.split) for item in values)
    artifact_counts = [len(item.artifact_hashes) for item in values]
    raw_counts = [item.raw_occurrences for item in values]
    token_counts = [token for item in values for token in item.artifact_token_counts]
    raw_total, collapsed_total = sum(raw_counts), sum(artifact_counts)

    class_coverage = {}
    for label in sorted(class_counts):
        members = [item for item in values if item.label == label]
        counts = [len(item.artifact_hashes) for item in members]
        class_coverage[label] = {
            "apk_count": len(members), "zero_artifact_apks": sum(value == 0 for value in counts),
            "artifact_apks": sum(value > 0 for value in counts),
            "artifact_count": sum(counts), "artifact_apk_distribution": _distribution(counts),
        }

    lane_counts: Counter[str] = Counter()
    behavior_counts: Counter[str] = Counter()
    source_endpoint_counts: Counter[str] = Counter()
    endpoint_definition_counts: Counter[str] = Counter()
    endpoint_definition_apks: Counter[str] = Counter()
    phase_status: dict[str, Counter[str]] = defaultdict(Counter)
    phase_runtime: Counter[str] = Counter()
    phase_storage: Counter[str] = Counter()
    phase_rss: dict[str, list[int]] = defaultdict(list)
    for item in values:
        lane_counts.update(dict(item.lane_counts))
        behavior_counts.update(dict(item.behavior_counts))
        source_endpoint_counts.update(dict(item.source_endpoint_counts))
        definitions = dict(item.endpoint_definition_counts)
        endpoint_definition_counts.update(definitions)
        endpoint_definition_apks.update(definitions.keys())
        for phase in item.phase_measures:
            phase_status[phase.phase][phase.status] += 1
            phase_runtime[phase.phase] += phase.runtime_seconds
            phase_storage[phase.phase] += phase.storage_bytes
            if phase.max_rss_kb is not None:
                phase_rss[phase.phase].append(phase.max_rss_kb)

    semantic_owners: dict[str, list[APKCheckpointRecord]] = defaultdict(list)
    for item in values:
        for semantic_hash in set(item.artifact_hashes):
            semantic_owners[semantic_hash].append(item)
    duplicate_groups = [members for members in semantic_owners.values() if len(members) > 1]
    cross_split = sum(len({item.split for item in group}) > 1 for group in duplicate_groups)
    elapsed = sum(phase_runtime.values())
    remaining = None if total_planned_apks is None or not values else (
        elapsed / len(values) * (total_planned_apks - len(values))
    )

    return {
        "schema_version": CHECKPOINT_AUDIT_SCHEMA,
        "apk_count": len(values),
        "class_counts": dict(sorted(class_counts.items())),
        "split_counts": dict(sorted(split_counts.items())),
        "class_split_counts": {
            f"{label}/{split}": count for (label, split), count in sorted(composition.items())
        },
        "class_coverage": class_coverage,
        "zero_artifact_apks": sum(count == 0 for count in artifact_counts),
        "artifact_apk_distribution": _distribution(artifact_counts),
        "raw_occurrence_apk_distribution": _distribution(raw_counts),
        "raw_occurrences": raw_total,
        "collapsed_artifacts": collapsed_total,
        "within_apk_duplicates_removed": raw_total - collapsed_total,
        "within_apk_duplicate_rate": ((raw_total - collapsed_total) / raw_total if raw_total else 0.0),
        "lane_counts": dict(sorted(lane_counts.items())),
        "behavior_counts": dict(sorted(behavior_counts.items())),
        "source_endpoint_counts": dict(source_endpoint_counts.most_common()),
        "endpoint_definition_counts": dict(endpoint_definition_counts.most_common()),
        "endpoint_definition_apk_coverage": {
            definition: endpoint_definition_apks[definition]
            for definition, _ in endpoint_definition_counts.most_common()
        },
        "token_distribution": _distribution(token_counts),
        "token_thresholds": {
            str(limit): {"count": sum(value > limit for value in token_counts),
                         "rate": sum(value > limit for value in token_counts) / len(token_counts)}
            for limit in thresholds
        } if token_counts else {str(limit): {"count": 0, "rate": 0.0} for limit in thresholds},
        "cross_apk_exact_group_count": len(duplicate_groups),
        "cross_split_exact_group_count": cross_split,
        "phase_status": {key: dict(sorted(value.items())) for key, value in sorted(phase_status.items())},
        "phase_failure_rates": {
            key: (sum(count for status, count in statuses.items() if status in TERMINAL_FAILURES)
                  / sum(statuses.values()))
            for key, statuses in sorted(phase_status.items())
        },
        "phase_runtime_seconds": dict(sorted(phase_runtime.items())),
        "phase_peak_rss_kb": {key: max(value) for key, value in sorted(phase_rss.items())},
        "phase_storage_bytes": dict(sorted(phase_storage.items())),
        "total_storage_bytes": sum(phase_storage.values()),
        "elapsed_phase_seconds": elapsed,
        "projected_remaining_phase_seconds": remaining,
    }


def validate_clean_content(records: Iterable[APKCheckpointRecord]) -> dict[str, object]:
    """Find identity and semantic-content leakage across train/evaluation splits."""

    values = tuple(records)
    apk_splits: dict[str, set[str]] = defaultdict(set)
    content: dict[str, list[tuple[str, str]]] = defaultdict(list)
    for item in values:
        apk_splits[item.apk_sha256].add(item.split)
        for semantic_hash in set(item.artifact_hashes):
            content[semantic_hash].append((item.apk_sha256, item.split))
    identity_leaks = sorted(apk for apk, splits in apk_splits.items() if len(splits) > 1)
    content_leaks = sorted(
        semantic_hash for semantic_hash, owners in content.items()
        if len({split for _, split in owners}) > 1
    )
    return {
        "clean": not identity_leaks and not content_leaks,
        "apk_identity_leaks": tuple(identity_leaks),
        "semantic_content_leaks": tuple(content_leaks),
    }


def apk_mil_metrics(
    expected: Mapping[str, int], predicted_scores: Mapping[str, float], *, threshold: float = 0.5,
) -> dict[str, float | int]:
    """Binary metrics at the APK (bag) level, never at artifact-instance level."""

    if set(expected) != set(predicted_scores):
        raise ValueError("expected labels and predictions must cover the same APK identities")
    if any(label not in (0, 1) for label in expected.values()):
        raise ValueError("APK labels must be 0 or 1")
    if not 0.0 <= threshold <= 1.0:
        raise ValueError("threshold must be between 0 and 1")
    if any(not 0.0 <= score <= 1.0 for score in predicted_scores.values()):
        raise ValueError("prediction scores must be between 0 and 1")
    pairs = [(expected[key], int(predicted_scores[key] >= threshold)) for key in sorted(expected)]
    tn = sum(actual == 0 and predicted == 0 for actual, predicted in pairs)
    fp = sum(actual == 0 and predicted == 1 for actual, predicted in pairs)
    fn = sum(actual == 1 and predicted == 0 for actual, predicted in pairs)
    tp = sum(actual == 1 and predicted == 1 for actual, predicted in pairs)
    ratio = lambda numerator, denominator: numerator / denominator if denominator else 0.0
    precision, recall = ratio(tp, tp + fp), ratio(tp, tp + fn)
    return {
        "apk_count": len(pairs), "accuracy": ratio(tp + tn, len(pairs)),
        "precision": precision, "recall": recall,
        "f1": ratio(2 * precision * recall, precision + recall),
        "tn": tn, "fp": fp, "fn": fn, "tp": tp,
    }
