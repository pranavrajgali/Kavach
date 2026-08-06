from __future__ import annotations

import pytest

from training.analyze_corpus import (
    ExampleRecord,
    assign_quartiles,
    context_impact,
    duplicate_summary,
    hash_token_ids,
    selected_category_counts,
    simulate_epoch,
)


def _example(
    example_id: str,
    apk_hash: str,
    label: str,
    category: str = "reflection",
) -> ExampleRecord:
    return ExampleRecord(
        example_id=example_id,
        apk_hash=apk_hash,
        label=label,
        split="train",
        apk_status="completed",
        sink_category=category,
        is_truncated=False,
        retained_instruction_count=4,
        involved_method_count=1,
        unresolved_boundary_count=0,
        raw_character_count=20,
        normalized_character_count=40,
        reasons=(),
        slice_path=f"training/data/slices/v1/{apk_hash}.jsonl.gz",
        slice_line=1,
        sink_instruction_index=2,
        normalized_sha256="0" * 64,
        token_sha256="1" * 64,
        token_count=8,
    )


def test_assign_quartiles_is_deterministic_and_tie_broken_by_hash() -> None:
    values = {"d": 10, "b": 10, "a": 1, "c": 5, "e": 20}
    assert assign_quartiles(values) == {
        "a": "Q1",
        "c": "Q1",
        "b": "Q2",
        "d": "Q3",
        "e": "Q4",
    }
    assert assign_quartiles({}) == {}


def test_selected_category_counts_reconstructs_round_robin() -> None:
    assert selected_category_counts({"reflection": 5, "sms": 1}, 4) == {
        "reflection": 3,
        "sms": 1,
    }
    assert selected_category_counts({"reflection": 5, "sms": 1}, 0) == {}
    with pytest.raises(ValueError, match="outside"):
        selected_category_counts({"reflection": 1}, 2)


def test_context_impact_uses_strict_limit_and_affected_only_loss() -> None:
    result = context_impact([512, 1024, 1025, 2048], 1024)
    assert result["affected_count"] == 2
    assert result["affected_percentage"] == 50.0
    assert result["mean_tokens_discarded_affected"] == 512.5
    assert result["median_tokens_discarded_affected"] == 512.5
    assert result["mean_fraction_retained_affected"] == pytest.approx(
        (1024 / 1025 + 1024 / 2048) / 2
    )
    assert context_impact([], 1024)["affected_percentage"] is None


def test_duplicate_summary_distinguishes_apk_and_split_crossing() -> None:
    groups = {
        "a": [
            {"example_id": "e1", "apk_hash": "apk1", "split": "train"},
            {"example_id": "e2", "apk_hash": "apk1", "split": "train"},
        ],
        "b": [
            {"example_id": "e3", "apk_hash": "apk2", "split": "train"},
            {"example_id": "e4", "apk_hash": "apk3", "split": "validation"},
            {"example_id": "e5", "apk_hash": "apk4", "split": "validation"},
        ],
        "unique": [
            {"example_id": "e6", "apk_hash": "apk5", "split": "test"},
        ],
    }
    result = duplicate_summary(groups)
    assert result["exact_duplicate_records_beyond_first"] == 3
    assert result["duplicate_group_count"] == 2
    assert result["within_apk_group_count"] == 1
    assert result["across_apk_group_count"] == 1
    assert result["cross_split_group_count"] == 1


def test_token_hash_is_sequence_sensitive_and_validates_ids() -> None:
    assert hash_token_ids([1, 2, 3]) == hash_token_ids((1, 2, 3))
    assert hash_token_ids([1, 2, 3]) != hash_token_ids([1, 3, 2])
    assert hash_token_ids([1, 2]) != hash_token_ids([1, 2, 0])
    with pytest.raises(ValueError, match="non-negative"):
        hash_token_ids([1, -1])


def test_sampler_is_deterministic_balanced_and_apk_uniform() -> None:
    examples = [
        _example("b1", "benign-a", "Benign", "reflection"),
        _example("b2", "benign-a", "Benign", "class_loader"),
        _example("b3", "benign-b", "Benign", "sms"),
        _example("m1", "malicious-a", "Malicious", "execution"),
        _example("m2", "malicious-b", "Malicious", "reflection"),
    ]
    first = simulate_epoch(examples, epoch_size=12, seed=42)
    second = simulate_epoch(examples, epoch_size=12, seed=42)
    assert first == second
    assert first["class_counts"] == {"Benign": 6, "Malicious": 6}
    assert first["unique_apks_represented"] == 4
    assert first["slices_per_apk"]["max"] == 3
    assert first["duplicate_draws"] > 0


def test_sampler_requires_both_classes() -> None:
    with pytest.raises(ValueError, match="both classes"):
        simulate_epoch([_example("b1", "benign-a", "Benign")], epoch_size=2)
