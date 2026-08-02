"""Deterministic APK-level controls for offline sink-slice preprocessing."""

from __future__ import annotations

import multiprocessing
from collections import Counter, defaultdict, deque
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Iterable

from kavach_ai.backend.pipeline.stage2_static.decompile import ExtractedMethod
from kavach_ai.backend.pipeline.stage3_ml.slicing import (
    SinkMatch,
    SliceLimits,
    SlicingResult,
    find_sinks,
    slice_sinks,
)


PREPROCESSING_VERSION = "offline-preprocessing-v1"
SELECTION_VERSION = "category-round-robin-v1"
TERMINAL_STATUSES = frozenset(
    {"completed", "completed_with_truncation", "capped", "zero_sink"}
)


class ApkProcessingStatus(str, Enum):
    COMPLETED = "completed"
    COMPLETED_WITH_TRUNCATION = "completed_with_truncation"
    CAPPED = "capped"
    TIMED_OUT = "timed_out"
    ZERO_SINK = "zero_sink"
    EXTRACTION_PARTIAL = "extraction_partial"
    FAILED = "failed"


@dataclass(frozen=True)
class PreprocessingBudgets:
    max_slicing_seconds_per_apk: float = 300.0
    max_slices_per_apk: int = 256
    max_total_slice_instructions: int = 65_536

    def __post_init__(self) -> None:
        if self.max_slicing_seconds_per_apk <= 0:
            raise ValueError("max_slicing_seconds_per_apk must be positive")
        if self.max_slices_per_apk <= 0:
            raise ValueError("max_slices_per_apk must be positive")
        if self.max_total_slice_instructions <= 0:
            raise ValueError("max_total_slice_instructions must be positive")


@dataclass(frozen=True)
class BoundedSlicingResult:
    slicing: SlicingResult
    total_sinks: tuple[SinkMatch, ...]
    candidate_sinks: tuple[SinkMatch, ...]
    cap_reason: str | None
    rejected_sink: SinkMatch | None

    @property
    def omitted_sinks(self) -> tuple[SinkMatch, ...]:
        published = set(self.slicing.sinks)
        return tuple(item for item in self.total_sinks if item not in published)


@dataclass(frozen=True)
class ProcessRunResult:
    timed_out: bool
    exit_code: int | None


def sink_record(sink: SinkMatch | None) -> dict[str, Any] | None:
    if sink is None:
        return None
    return {
        "rule_id": sink.rule_id,
        "category": sink.category,
        "dex_name": sink.method.dex_name,
        "source_method": sink.method.full_signature,
        "instruction_index": sink.instruction_index,
        "invoked_signature": sink.invoked_signature,
    }


def category_counts(sinks: Iterable[SinkMatch]) -> dict[str, int]:
    return dict(sorted(Counter(item.category for item in sinks).items()))


def select_sinks_by_category(
    sinks: Iterable[SinkMatch], max_sinks: int
) -> tuple[SinkMatch, ...]:
    """Round-robin sorted categories without inventing an unsupported risk ranking."""

    if max_sinks <= 0:
        raise ValueError("max_sinks must be positive")
    grouped: dict[str, deque[SinkMatch]] = defaultdict(deque)
    for sink in sorted(set(sinks)):
        grouped[sink.category].append(sink)
    selected: list[SinkMatch] = []
    categories = sorted(grouped)
    while len(selected) < max_sinks:
        progressed = False
        for category in categories:
            if grouped[category] and len(selected) < max_sinks:
                selected.append(grouped[category].popleft())
                progressed = True
        if not progressed:
            break
    return tuple(selected)


def build_bounded_slices(
    methods: Iterable[ExtractedMethod],
    budgets: PreprocessingBudgets,
    *,
    limits: SliceLimits | None = None,
) -> BoundedSlicingResult:
    method_tuple = tuple(methods)
    all_sinks = find_sinks(method_tuple)
    candidates = select_sinks_by_category(all_sinks, budgets.max_slices_per_apk)
    slicing = slice_sinks(
        method_tuple,
        candidates,
        limits=limits,
        max_total_instructions=budgets.max_total_slice_instructions,
    )
    instruction_rejected = len(slicing.slices) < len(candidates)
    rejected = candidates[len(slicing.slices)] if instruction_rejected else None
    cap_reason = None
    if instruction_rejected:
        cap_reason = "max_total_slice_instructions"
    elif len(candidates) < len(all_sinks):
        cap_reason = "max_slices_per_apk"
    return BoundedSlicingResult(slicing, all_sinks, candidates, cap_reason, rejected)


def run_interruptible_process(
    target: Callable[..., None],
    args: tuple[Any, ...],
    *,
    timeout_seconds: float,
) -> ProcessRunResult:
    """Run a spawn-safe worker and forcibly stop it at the configured deadline."""

    context = multiprocessing.get_context("spawn")
    process = context.Process(target=target, args=args)
    process.start()
    process.join(timeout_seconds)
    if process.is_alive():
        process.terminate()
        process.join(5)
        if process.is_alive():
            process.kill()
            process.join()
        return ProcessRunResult(True, process.exitcode)
    return ProcessRunResult(False, process.exitcode)


def remove_worker_output(path: Path) -> None:
    path.unlink(missing_ok=True)
    for temporary in path.parent.glob(f".{path.name}.*.tmp"):
        temporary.unlink(missing_ok=True)


__all__ = [
    "ApkProcessingStatus",
    "BoundedSlicingResult",
    "PREPROCESSING_VERSION",
    "PreprocessingBudgets",
    "ProcessRunResult",
    "SELECTION_VERSION",
    "TERMINAL_STATUSES",
    "build_bounded_slices",
    "category_counts",
    "remove_worker_output",
    "run_interruptible_process",
    "select_sinks_by_category",
    "sink_record",
]
