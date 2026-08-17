"""Non-destructive Stage-1B duplication and leakage audit helpers.

The audit is disabled by default. It reports candidate groups and clean validation
views; it never removes, rewrites, or reweights BehaviorArtifacts.
"""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable

from kavach_ai.backend.pipeline.stage2_static.v2_artifacts import BehaviorArtifact
from kavach_ai.backend.pipeline.stage2_static.v2_canonical import write_json_atomic


AUDIT_SCHEMA = "stage1b-audit-v2alpha1"
AUDIT_STORAGE_VERSION = "v2/stage1b"
_TOKEN = re.compile(r"[A-Za-z_$][A-Za-z0-9_.$<>:/-]*")


@dataclass(frozen=True)
class AuditConfig:
    enabled: bool = False
    near_duplicates_enabled: bool = False
    near_duplicate_jaccard: float = 0.85
    max_near_duplicate_artifacts: int = 5_000


@dataclass(frozen=True)
class ArtifactAssignment:
    artifact: BehaviorArtifact
    label: str
    split: str


@dataclass(frozen=True)
class ExactGroup:
    semantic_sha256: str
    artifact_ids: tuple[str, ...]
    apk_sha256s: tuple[str, ...]
    labels: tuple[str, ...]
    splits: tuple[str, ...]
    source_categories: tuple[str, ...]
    sink_categories: tuple[str, ...]
    behavior_categories: tuple[str, ...]


@dataclass(frozen=True)
class NearDuplicatePair:
    left_artifact_id: str
    right_artifact_id: str
    token_jaccard: float


@dataclass(frozen=True)
class AuditReport:
    status: str
    artifact_count: int
    apk_count: int
    exact_duplicate_group_count: int
    exact_duplicate_artifacts_beyond_first: int
    cross_apk_group_count: int
    cross_split_group_count: int
    label_counts: tuple[tuple[str, int], ...]
    split_counts: tuple[tuple[str, int], ...]
    exact_groups: tuple[ExactGroup, ...]
    clean_validation_artifact_ids: tuple[str, ...]
    near_duplicate_pairs: tuple[NearDuplicatePair, ...] = ()
    notes: tuple[str, ...] = ()
    schema_version: str = AUDIT_SCHEMA

    def to_dict(self) -> dict:
        return asdict(self)


def _flow_tokens(artifact: BehaviorArtifact) -> frozenset[str]:
    parts = [
        artifact.source_category, artifact.sink_category, artifact.behavior_category,
        artifact.flow.source.definition, artifact.flow.sink.definition,
    ]
    parts.extend(statement.jimple for statement in artifact.flow.statements)
    parts.extend(control.predicate.jimple for control in artifact.flow.controls)
    return frozenset(token.lower() for token in _TOKEN.findall("\n".join(parts)))


def _near_duplicate_pairs(
    assignments: tuple[ArtifactAssignment, ...], config: AuditConfig,
) -> tuple[NearDuplicatePair, ...]:
    if not config.near_duplicates_enabled:
        return ()
    if len(assignments) > config.max_near_duplicate_artifacts:
        raise ValueError(
            "near-duplicate audit exceeds max_near_duplicate_artifacts; "
            "use an indexed implementation or raise the explicit audit cap"
        )
    tokens = [(item.artifact.artifact_id, _flow_tokens(item.artifact)) for item in assignments]
    pairs = []
    for index, (left_id, left) in enumerate(tokens):
        for right_id, right in tokens[index + 1:]:
            union = left | right
            score = len(left & right) / len(union) if union else 1.0
            if score >= config.near_duplicate_jaccard:
                pairs.append(NearDuplicatePair(left_id, right_id, round(score, 6)))
    return tuple(sorted(pairs, key=lambda item: (item.left_artifact_id, item.right_artifact_id)))


def build_audit_report(
    assignments: Iterable[ArtifactAssignment], *, config: AuditConfig = AuditConfig(),
) -> AuditReport:
    """Build a read-only audit report from already collapsed APK-scoped artifacts."""

    values = tuple(assignments)
    if not config.enabled:
        return AuditReport(
            status="DISABLED", artifact_count=0, apk_count=0,
            exact_duplicate_group_count=0, exact_duplicate_artifacts_beyond_first=0,
            cross_apk_group_count=0, cross_split_group_count=0,
            label_counts=(), split_counts=(), exact_groups=(),
            clean_validation_artifact_ids=(),
            notes=("Stage-1B audit is disabled by configuration",),
        )

    grouped: dict[str, list[ArtifactAssignment]] = defaultdict(list)
    for item in values:
        grouped[item.artifact.semantic_sha256].append(item)
    exact_groups = []
    for semantic_hash, members in sorted(grouped.items()):
        if len(members) < 2:
            continue
        exact_groups.append(ExactGroup(
            semantic_sha256=semantic_hash,
            artifact_ids=tuple(sorted(item.artifact.artifact_id for item in members)),
            apk_sha256s=tuple(sorted({item.artifact.apk_sha256 for item in members})),
            labels=tuple(sorted({item.label for item in members})),
            splits=tuple(sorted({item.split for item in members})),
            source_categories=tuple(sorted({item.artifact.source_category for item in members})),
            sink_categories=tuple(sorted({item.artifact.sink_category for item in members})),
            behavior_categories=tuple(sorted({item.artifact.behavior_category for item in members})),
        ))

    train_hashes = {
        item.artifact.semantic_sha256 for item in values if item.split == "train"
    }
    clean_validation = tuple(sorted(
        item.artifact.artifact_id for item in values
        if item.split in {"validation", "val"}
        and item.artifact.semantic_sha256 not in train_hashes
    ))
    label_counts = Counter(item.label for item in values)
    split_counts = Counter(item.split for item in values)
    return AuditReport(
        status="SUCCESS",
        artifact_count=len(values),
        apk_count=len({item.artifact.apk_sha256 for item in values}),
        exact_duplicate_group_count=len(exact_groups),
        exact_duplicate_artifacts_beyond_first=sum(len(group.artifact_ids) - 1 for group in exact_groups),
        cross_apk_group_count=sum(len(group.apk_sha256s) > 1 for group in exact_groups),
        cross_split_group_count=sum(len(group.splits) > 1 for group in exact_groups),
        label_counts=tuple(sorted(label_counts.items())),
        split_counts=tuple(sorted(split_counts.items())),
        exact_groups=tuple(exact_groups),
        clean_validation_artifact_ids=clean_validation,
        near_duplicate_pairs=_near_duplicate_pairs(values, config),
    )


def audit_report_path(root: str | Path, report_name: str = "corpus") -> Path:
    if not report_name or "/" in report_name or "\\" in report_name:
        raise ValueError("report_name must be one path-safe segment")
    return Path(root) / AUDIT_STORAGE_VERSION / f"{report_name}.json"


def write_audit_report(
    root: str | Path, report: AuditReport, *, report_name: str = "corpus",
) -> Path:
    destination = audit_report_path(root, report_name)
    write_json_atomic(destination, report)
    return destination
