from __future__ import annotations

import json
import subprocess
from argparse import Namespace
from pathlib import Path

from kavach_ai.backend.pipeline.stage2_static.flowdroid import (
    flowdroid_output_diagnostics, run_flowdroid,
)
from training.run_corpus_v2 import (
    balanced_selection, completed, load_or_create_selection, merge_managed,
    taint_group_fingerprint,
)
from kavach_ai.backend.pipeline.stage2_static.v2_artifacts import (
    ManagedAnalysisArtifact, ToolProvenance,
)


APK = "a" * 64


def _sidecar_payload() -> dict:
    return {
        "schema_version": "flowdroid-sidecar-v1", "apk_sha256": APK,
        "status": "SUCCESS", "provenance": {
            "version": "2.15.1", "config_sha256": "b" * 64,
        },
        "flows": [],
        "diagnostics": {
            "raw_result_count": 3, "accepted_result_count": 0,
            "rejected_result_count": 3,
            "rejection_reason_counts": {"UNKNOWN_SINK_CATEGORY": 3},
            "path_null_count": 1, "termination_state": "SUCCESS",
        },
    }


def test_successful_run_persists_logs_and_diagnostic_counters(tmp_path, monkeypatch) -> None:
    apk = tmp_path / "sample.apk"
    apk.write_bytes(b"apk")
    output = tmp_path / "result.json"

    def fake_run(*args, **kwargs):
        output.write_text(json.dumps(_sidecar_payload()), encoding="utf-8")
        return subprocess.CompletedProcess(args[0], 0, "phase timing", "warning")

    monkeypatch.setattr(subprocess, "run", fake_run)
    result = run_flowdroid(
        command=("java", "-jar", "sidecar.jar"), apk_path=apk, output_path=output,
        config={"group": "sensitive"}, timeout_seconds=12,
    )
    assert result.status == "SUCCESS"
    log = Path(f"{output}.log").read_text(encoding="utf-8")
    assert "phase timing" in log and "warning" in log
    process = json.loads(Path(f"{output}.diagnostics.json").read_text(encoding="utf-8"))
    assert process["sidecar"]["raw_result_count"] == 3
    assert process["sidecar"]["rejection_reason_counts"] == {"UNKNOWN_SINK_CATEGORY": 3}


def test_old_sidecar_output_gets_backward_compatible_counts(tmp_path) -> None:
    output = tmp_path / "old.json"
    payload = _sidecar_payload()
    payload.pop("diagnostics")
    output.write_text(json.dumps(payload), encoding="utf-8")
    assert flowdroid_output_diagnostics(output)["raw_result_count"] == 0


def test_taint_fingerprint_changes_with_timeout_and_tool_bytes(tmp_path) -> None:
    java = tmp_path / "java"
    sidecar = tmp_path / "sidecar.jar"
    definitions = tmp_path / "defs.txt"
    platforms = tmp_path / "platforms" / "android-35"
    platforms.mkdir(parents=True)
    java.write_bytes(b"jdk-17")
    sidecar.write_bytes(b"sidecar-one")
    definitions.write_text("source -> sink", encoding="utf-8")
    (platforms / "android.jar").write_bytes(b"android-35")
    args = Namespace(
        java=java, sidecar_jar=sidecar, android_platforms=platforms.parent,
        taint_group_timeout=180,
    )
    config = {"flowdroid_version": "2.15.1", "soot_version": "4.7.1", "jdk_major": 17}
    first, identity = taint_group_fingerprint(
        args=args, group_name="sensitive", definitions=definitions, config=config,
    )
    args.taint_group_timeout = 181
    second, _ = taint_group_fingerprint(
        args=args, group_name="sensitive", definitions=definitions, config=config,
    )
    assert first != second
    assert identity["sidecar"]["sha256"]
    assert identity["android_platforms"]["android_jars"][0]["sha256"]


def test_merge_provenance_is_not_action_provenance() -> None:
    actions = ManagedAnalysisArtifact(
        APK, "SUCCESS", (), ToolProvenance("FlowDroid", "2.15.1", "a", APK), actions=(),
    )
    group = ManagedAnalysisArtifact(
        APK, "SUCCESS", (), ToolProvenance("FlowDroid", "2.15.1", "g", APK),
    )
    merged = merge_managed(APK, actions, [group])
    assert merged.provenance.tool == "Kavach managed merge"
    assert merged.provenance.config_sha256 not in {"a", "g"}


def test_failed_phase_retries_when_output_is_absent(tmp_path) -> None:
    status = {"phases": {"manifest": {"status": "FAILED", "output": str(tmp_path / "missing.json")}}}
    assert not completed(status, "manifest", True)
    output = tmp_path / "timeout.json"
    output.write_text("{}", encoding="utf-8")
    status["phases"]["managed_taint"] = {"status": "TIMEOUT", "output": str(output)}
    assert completed(status, "managed_taint", True)


def test_balanced_selection_is_deterministic_unique_and_persisted(tmp_path) -> None:
    records = []
    for label, prefix in (("Benign", "b"), ("Malicious", "m")):
        for index in range(3):
            records.append({
                "apk_hash": f"{index:064x}" if label == "Benign" else f"{index + 100:064x}",
                "label": label, "split": ("train", "validation", "test")[index],
                "source_path": f"data/{label}/{prefix}{index}.apk",
            })
    selected = balanced_selection(list(reversed(records)), per_label=2)
    assert [item["label"] for item in selected].count("Benign") == 2
    assert [item["label"] for item in selected].count("Malicious") == 2
    assert len({item["apk_hash"] for item in selected}) == 4

    # Exercise durable reload with a production-sized synthetic inventory.
    full = []
    for label, offset in (("Benign", 0), ("Malicious", 1000)):
        for index in range(251):
            full.append({"apk_hash": f"{index + offset:064x}", "label": label,
                         "split": "train", "source_path": f"{label}/{index}.apk"})
    manifest = tmp_path / "selection.json"
    first = load_or_create_selection(manifest, full)
    second = load_or_create_selection(manifest, list(reversed(full)))
    assert [item["apk_hash"] for item in first] == [item["apk_hash"] for item in second]
