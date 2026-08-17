from __future__ import annotations

from kavach_ai.backend.pipeline.stage2_static.flowdroid import parse_flowdroid_output
from kavach_ai.backend.pipeline.stage2_static.v2_artifacts import (
    Endpoint, ManagedAction, NativeContext, NativeFunctionEvidence, StatementRef, ToolProvenance,
)
from kavach_ai.backend.pipeline.stage3_ml.behavior_artifacts import build_action_artifact, build_behavior_artifact
from training.utils.model_view import (
    ModelViewOptions, PhaseCompletion, build_apk_index, read_apk_index,
    serialize_candidate, write_apk_index,
)


APK = "a" * 64
CONFIG = "b" * 64


def _artifact():
    managed = parse_flowdroid_output({
        "schema_version": "flowdroid-sidecar-v1", "apk_sha256": APK, "status": "SUCCESS",
        "provenance": {"version": "2.15.1", "config_sha256": CONFIG},
        "flows": [{
            "source": {"definition": "<Device: String id()>", "category": "UNIQUE_IDENTIFIER", "statement_id": "s1"},
            "sink": {"definition": "<Writer: void write(String)>", "category": "NETWORK", "statement_id": "s2"},
            "statements": [
                {"statement_id": "s1", "method_signature": "<C: void send()>", "jimple": "id = device.id()"},
                {"statement_id": "s2", "method_signature": "<C: void send()>", "jimple": "writer.write(id)"},
            ],
        }],
    })
    return build_behavior_artifact(apk_sha256=APK, flow=managed.flows[0], managed_provenance=managed.provenance)


def test_model_view_is_reproducible_and_records_representation_config() -> None:
    artifact = _artifact()
    first = serialize_candidate(artifact)
    second = serialize_candidate(artifact)
    assert first == second
    assert first.apk_sha256 == APK
    assert first.analysis_lane == "FLOWDROID_TAINT"
    assert first.content_sha256 and first.config_sha256
    assert "[ENDPOINT]" in first.text


def test_optional_sections_change_config_and_content_deterministically() -> None:
    artifact = _artifact()
    full = serialize_candidate(artifact)
    reduced = serialize_candidate(artifact, options=ModelViewOptions(include_controls=False, include_native_context=False))
    assert full.config_sha256 != reduced.config_sha256
    # This fixture has neither section, so its text remains equal while the
    # representation policy is still explicitly distinguishable.
    assert full.text == reduced.text


def test_zero_artifact_apk_round_trip_uses_status_not_fake_view(tmp_path) -> None:
    index = build_apk_index(
        apk_sha256=APK, views=(),
        phases=(
            PhaseCompletion("managed", "SUCCESS", True),
            PhaseCompletion("native", "PARTIAL", False, ("UNSUPPORTED_ABI",)),
        ),
    )
    assert index.artifact_ids == ()
    path = write_apk_index(tmp_path, index)
    restored = read_apk_index(path)
    assert restored == index
    assert restored.phases[1].complete is False


def test_index_sorts_artifacts_and_phases() -> None:
    artifact = _artifact()
    view = serialize_candidate(artifact)
    index = build_apk_index(
        apk_sha256=APK, views=(view,),
        phases=(PhaseCompletion("native", "SKIPPED", True), PhaseCompletion("managed", "SUCCESS", True)),
    )
    assert index.artifact_ids == (artifact.artifact_id,)
    assert tuple(item.phase for item in index.phases) == ("managed", "native")


def _action_artifact(*, native: bool = False):
    statement = StatementRef("a1", "<C: void act()>", "runtime.exec(command)")
    action = ManagedAction(
        Endpoint("<Runtime: Process exec(String)>", "PROCESS_EXECUTION", statement),
        "COMMAND_EXECUTION", (StatementRef("d1", "<C: void act()>", "command = input"),),
    )
    native_context = NativeContext(False)
    if native:
        native_context = NativeContext(True, None, (
            NativeFunctionEvidence("native_exec", "system(command);", ("system",), (), ("sh",)),
        ))
    provenance = ToolProvenance("test", "1", CONFIG, APK)
    return build_action_artifact(
        apk_sha256=APK, action=action, managed_provenance=provenance,
        native_context=native_context,
    )


def test_action_and_native_artifacts_use_their_actual_analysis_lanes() -> None:
    action_view = serialize_candidate(_action_artifact())
    native_view = serialize_candidate(_action_artifact(native=True))
    assert action_view.analysis_lane == "ACTION_DEPENDENCY"
    assert "analysis_lane=ACTION_DEPENDENCY" in action_view.text
    assert native_view.analysis_lane == "NATIVE_ACTION"
    assert "[NATIVE_CONTEXT]" in native_view.text
    assert "raw_pcode" not in native_view.text


def test_representation_fingerprint_includes_schema_version() -> None:
    options = ModelViewOptions()
    assert options.config_sha256 != CONFIG
    assert options.config_sha256 == ModelViewOptions().config_sha256
