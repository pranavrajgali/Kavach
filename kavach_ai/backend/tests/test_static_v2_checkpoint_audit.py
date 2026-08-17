from __future__ import annotations

from dataclasses import replace

import pytest

from kavach_ai.backend.pipeline.stage3_ml.checkpoint_audit import (
    APKCheckpointRecord, PhaseMeasure, apk_mil_metrics, build_checkpoint_metrics,
    validate_clean_content,
)


def _record(digit: str, label: str, split: str, hashes=(), raw=0, tokens=()):
    return APKCheckpointRecord(
        apk_sha256=digit * 64, label=label, split=split,
        raw_occurrences=raw, artifact_hashes=tuple(hashes),
        artifact_token_counts=tuple(tokens),
        lane_counts=(("FLOWDROID_TAINT", len(hashes)),),
        behavior_counts=(("EXTERNAL_DATA_TRANSFER", len(hashes)),),
        phase_measures=(PhaseMeasure("managed", "SUCCESS", 2.0, 100, 20),),
    )


def test_checkpoint_metrics_cover_composition_dedup_tokens_cost_and_projection():
    records = (
        replace(
            _record("1", "benign", "train", ("a",), 2, (400,)),
            source_endpoint_counts=(("LOCATION_INFORMATION->NETWORK", 1),),
            endpoint_definition_counts=(("<net: void send(java.lang.String)>", 1),),
        ),
        _record("2", "malicious", "validation", ("a", "b"), 2, (600, 3000)),
        _record("3", "benign", "test"),
    )
    report = build_checkpoint_metrics(records, total_planned_apks=6, token_thresholds=(512, 2048))
    assert report["class_counts"] == {"benign": 2, "malicious": 1}
    assert report["class_split_counts"]["malicious/validation"] == 1
    assert report["class_coverage"]["benign"]["zero_artifact_apks"] == 1
    assert report["class_coverage"]["malicious"]["artifact_count"] == 2
    assert report["zero_artifact_apks"] == 1
    assert report["raw_occurrences"] == 4
    assert report["collapsed_artifacts"] == 3
    assert report["within_apk_duplicate_rate"] == 0.25
    assert report["cross_apk_exact_group_count"] == 1
    assert report["cross_split_exact_group_count"] == 1
    assert report["token_thresholds"]["512"]["count"] == 2
    assert report["source_endpoint_counts"] == {"LOCATION_INFORMATION->NETWORK": 1}
    assert report["endpoint_definition_counts"] == {"<net: void send(java.lang.String)>": 1}
    assert report["endpoint_definition_apk_coverage"] == {"<net: void send(java.lang.String)>": 1}
    assert report["phase_peak_rss_kb"] == {"managed": 100}
    assert report["phase_failure_rates"] == {"managed": 0.0}
    assert report["total_storage_bytes"] == 60
    assert report["projected_remaining_phase_seconds"] == 6.0


def test_checkpoint_validation_rejects_misaligned_counts_and_duplicate_apks():
    with pytest.raises(ValueError, match="smaller"):
        _record("1", "benign", "train", ("a",), 0)
    record = _record("1", "benign", "train")
    with pytest.raises(ValueError, match="duplicate APK"):
        build_checkpoint_metrics((record, record))


def test_clean_content_validation_reports_cross_split_semantic_leakage():
    records = (
        _record("1", "benign", "train", ("shared",), 1, (10,)),
        _record("2", "malicious", "test", ("shared",), 1, (10,)),
    )
    result = validate_clean_content(records)
    assert result["clean"] is False
    assert result["semantic_content_leaks"] == ("shared",)
    assert result["apk_identity_leaks"] == ()


def test_apk_mil_metrics_are_bag_level_and_validate_identity_sets():
    result = apk_mil_metrics(
        {"a": 0, "b": 0, "c": 1, "d": 1},
        {"a": 0.1, "b": 0.8, "c": 0.4, "d": 0.9},
    )
    assert result == {
        "apk_count": 4, "accuracy": 0.5, "precision": 0.5,
        "recall": 0.5, "f1": 0.5, "tn": 1, "fp": 1, "fn": 1, "tp": 1,
    }
    with pytest.raises(ValueError, match="same APK"):
        apk_mil_metrics({"a": 0}, {"b": 0.1})
