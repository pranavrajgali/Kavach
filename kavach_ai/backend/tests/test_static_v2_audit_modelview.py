from __future__ import annotations

from dataclasses import replace

from kavach_ai.backend.pipeline.stage2_static.flowdroid import parse_flowdroid_output
from kavach_ai.backend.pipeline.stage3_ml.audit import (
    AuditConfig, ArtifactAssignment, audit_report_path, build_audit_report,
    write_audit_report,
)
from kavach_ai.backend.pipeline.stage3_ml.behavior_artifacts import build_behavior_artifact
from training.utils.model_view import (
    MODEL_VIEW_SCHEMA, candidate_path, read_candidate, write_candidate,
)


APK = "a" * 64
CONFIG = "b" * 64


def _behavior(*, apk: str = APK, suffix: str = "one"):
    managed = parse_flowdroid_output({
        "schema_version": "flowdroid-sidecar-v1", "apk_sha256": apk,
        "status": "SUCCESS",
        "provenance": {"version": "2.15.1", "config_sha256": CONFIG},
        "flows": [{
            "source": {"definition": "<Device: String id()>", "category": "UNIQUE_IDENTIFIER", "statement_id": "s1"},
            "sink": {"definition": "<Writer: void write(String)>", "category": "NETWORK", "statement_id": "s2"},
            "statements": [
                {"statement_id": "s1", "method_signature": "<C: void send()>", "jimple": "id = virtualinvoke device.id()"},
                {"statement_id": "s2", "method_signature": "<C: void send()>", "jimple": f"virtualinvoke writer.write(id) // {suffix}"},
            ],
        }],
    })
    return build_behavior_artifact(
        apk_sha256=apk, flow=managed.flows[0], managed_provenance=managed.provenance,
    )


def test_model_view_round_trip_uses_versioned_v2_path(tmp_path) -> None:
    artifact = _behavior()
    path = write_candidate(tmp_path, artifact)
    assert path == candidate_path(
        tmp_path, apk_sha256=artifact.apk_sha256, artifact_id=artifact.artifact_id,
    )
    assert "/v2/candidate1/" in path.as_posix()
    restored = read_candidate(path)
    assert restored.schema_version == MODEL_VIEW_SCHEMA
    assert restored.artifact_id == artifact.artifact_id
    assert restored.text.startswith("[BEHAVIOR]\n")


def test_stage1b_audit_is_disabled_by_default() -> None:
    report = build_audit_report((ArtifactAssignment(_behavior(), "benign", "train"),))
    assert report.status == "DISABLED"
    assert report.artifact_count == 0


def test_exact_audit_retains_cross_apk_records_and_builds_clean_validation(tmp_path) -> None:
    train = _behavior(apk="1" * 64)
    duplicate = replace(
        train, apk_sha256="2" * 64, artifact_id="duplicate-apk-artifact",
    )
    clean = _behavior(apk="3" * 64, suffix="different")
    assignments = (
        ArtifactAssignment(train, "benign", "train"),
        ArtifactAssignment(duplicate, "malicious", "validation"),
        ArtifactAssignment(clean, "malicious", "validation"),
    )
    report = build_audit_report(assignments, config=AuditConfig(enabled=True))
    assert report.artifact_count == 3
    assert report.exact_duplicate_group_count == 1
    assert report.cross_apk_group_count == 1
    assert report.cross_split_group_count == 1
    assert report.exact_duplicate_artifacts_beyond_first == 1
    assert report.clean_validation_artifact_ids == (clean.artifact_id,)
    assert len(report.exact_groups[0].artifact_ids) == 2
    path = write_audit_report(tmp_path, report, report_name="subset")
    assert path == audit_report_path(tmp_path, "subset")
    assert "/v2/stage1b/" in path.as_posix()


def test_near_duplicate_audit_is_separately_opt_in() -> None:
    left = _behavior(apk="1" * 64, suffix="one")
    right = _behavior(apk="2" * 64, suffix="two")
    assignments = (
        ArtifactAssignment(left, "benign", "train"),
        ArtifactAssignment(right, "malicious", "test"),
    )
    exact_only = build_audit_report(assignments, config=AuditConfig(enabled=True))
    assert exact_only.near_duplicate_pairs == ()
    with_near = build_audit_report(assignments, config=AuditConfig(
        enabled=True, near_duplicates_enabled=True, near_duplicate_jaccard=0.5,
    ))
    assert len(with_near.near_duplicate_pairs) == 1
