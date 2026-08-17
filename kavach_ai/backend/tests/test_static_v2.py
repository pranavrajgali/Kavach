from __future__ import annotations

from dataclasses import replace

import pytest

from kavach_ai.backend.pipeline.stage1_triage.triage import (
    IntentFilter, ManifestComponent, TriageResult,
)
from kavach_ai.backend.pipeline.stage3_ml.behavior_artifacts import (
    attach_manifest_context, build_behavior_artifact, collapse_within_apk,
)
from kavach_ai.backend.pipeline.stage2_static.v2_canonical import canonical_json, canonical_sha256
from kavach_ai.backend.pipeline.stage2_static.flowdroid import FlowDroidOutputError, parse_flowdroid_output
from kavach_ai.backend.pipeline.stage2_static.ghidra import (
    link_jni_evidence, normalize_decompiled_code, parse_ghidra_output,
)
from kavach_ai.backend.pipeline.stage1_triage.manifest_context import from_triage
from kavach_ai.backend.pipeline.stage2_static.v2_artifacts import NativeContext, ToolProvenance
from training.utils.model_view import serialize_candidate


APK_HASH = "a" * 64
CONFIG_HASH = "b" * 64


def flow_output(*, sink_definition: str = "<java.net.URLConnection: void connect()>") -> dict:
    return {
        "schema_version": "flowdroid-sidecar-v1",
        "apk_sha256": APK_HASH,
        "status": "SUCCESS",
        "provenance": {"version": "2.15.1", "config_sha256": CONFIG_HASH},
        "flows": [{
            "source": {
                "definition": "<android.location.Location: double getLatitude()>",
                "category": "LOCATION_INFORMATION", "statement_id": "s1",
                "access_path": "location.latitude",
            },
            "sink": {"definition": sink_definition, "category": "NETWORK", "statement_id": "s3"},
            "statements": [
                {"statement_id": "s1", "method_signature": "<p.C: void send()>", "jimple": "$d0 = virtualinvoke r0.<android.location.Location: double getLatitude()>()", "dex_offset": 8},
                {"statement_id": "s2", "method_signature": "<p.C: void send()>", "jimple": "$z0 = cmd == \"UPLOAD\"", "dex_offset": 12},
                {"statement_id": "s3", "method_signature": "<p.C: void send()>", "jimple": "virtualinvoke r1.<java.net.URLConnection: void connect()>()", "dex_offset": 20},
            ],
            "controls": [{
                "predicate": {"statement_id": "c1", "method_signature": "<p.C: void send()>", "jimple": "if $z0 == 0 goto return"},
                "controls_statement_ids": ["s3"],
                "operand_definitions": [{"statement_id": "c0", "method_signature": "<p.C: void send()>", "jimple": "$z0 = cmd == \"UPLOAD\""}],
            }],
            "component": {"component_type": "receiver", "component_name": "p.Boot", "callback": "onReceive", "exported": True},
        }],
    }


def test_flow_parser_preserves_ordered_jimple_and_direct_control() -> None:
    artifact = parse_flowdroid_output(flow_output())
    flow = artifact.flows[0]
    assert [item.statement_id for item in flow.statements] == ["s1", "s2", "s3"]
    assert flow.controls[0].controls_statement_ids == ("s3",)
    assert flow.component and flow.component.callback == "onReceive"
    assert flow.source.category == "LOCATION_INFORMATION"
    assert flow.sink.category == "NETWORK"


def test_flow_parser_rejects_control_reference_outside_path() -> None:
    value = flow_output()
    value["flows"][0]["controls"][0]["controls_statement_ids"] = ["missing"]
    with pytest.raises(FlowDroidOutputError, match="unknown flow statement"):
        parse_flowdroid_output(value)


def test_manifest_is_context_and_filters_are_retained() -> None:
    receiver = ManifestComponent(
        "receiver", "p.Boot", True, True, True, None,
        (IntentFilter(("android.intent.action.BOOT_COMPLETED",), (), ({"scheme": "content"},)),),
    )
    triage = TriageResult(
        "x.apk", APK_HASH, "p", ("android.permission.ACCESS_FINE_LOCATION", "android.permission.INTERNET"),
        (), (), (receiver,), (), None, ("p.Boot",), ("p.Boot",), 23, 35,
        (), (), (), (), 0.0, False, (),
    )
    manifest = from_triage(triage)
    assert manifest.components[0].intent_filters[0].actions == ("android.intent.action.BOOT_COMPLETED",)
    assert manifest.permissions == tuple(sorted(triage.permissions))
    managed = parse_flowdroid_output(flow_output())
    enriched = attach_manifest_context(managed.flows[0], manifest)
    assert enriched.component and enriched.component.exported is True
    assert enriched.component.intent_filters[0].actions == ("android.intent.action.BOOT_COMPLETED",)


def test_behavior_identity_dedup_and_endpoint_separation() -> None:
    managed = parse_flowdroid_output(flow_output())
    first = build_behavior_artifact(
        apk_sha256=APK_HASH, flow=managed.flows[0], managed_provenance=managed.provenance,
    )
    duplicate = replace(first, occurrence_statement_ids=("another-site",))
    collapsed = collapse_within_apk((first, duplicate))
    assert collapsed[0].occurrence_count == 2
    assert collapsed[0].occurrence_statement_ids == ("another-site", "s3")

    other_managed = parse_flowdroid_output(flow_output(sink_definition="<okhttp3.Call: okhttp3.Response execute()>"))
    other = build_behavior_artifact(
        apk_sha256=APK_HASH, flow=other_managed.flows[0], managed_provenance=other_managed.provenance,
    )
    assert other.semantic_sha256 != first.semantic_sha256
    assert len(collapse_within_apk((first, other))) == 2


def test_native_debug_pcode_and_addresses_do_not_drive_semantic_identity() -> None:
    native = parse_ghidra_output({
        "schema_version": "ghidra-sidecar-v1", "library_sha256": "c" * 64,
        "abi": "arm64-v8a", "status": "SUCCESS",
        "provenance": {"version": "12.1.2", "config_sha256": CONFIG_HASH},
        "functions": [{
            "function_id": "Java_p_C_send", "decompiled_code": "x = *(long *)0x1234abcd;\n send(x);",
            "calls": ["send"], "imports": ["send"], "strings": ["/api"],
            "raw_pcode_debug_ref": "sha256:raw-one",
        }],
    })
    assert "0x1234abcd" not in native.functions[0].normalized_decompiled_code
    assert "<ADDR>" in native.functions[0].normalized_decompiled_code
    assert native.functions[0].raw_pcode_debug_ref == "sha256:raw-one"
    linked = link_jni_evidence(
        managed_method="<p.C: native void send()>",
        expected_short_symbol="Java_p_C_send", expected_long_symbol="Java_p_C_send__",
        library_archive_path="lib/arm64-v8a/libx.so", analysis=native,
    )
    assert linked.mapping and linked.mapping.mapping_kind == "exact_short_name"
    assert linked.selected_evidence[0].function_id == "Java_p_C_send"


def test_unresolved_dynamic_jni_is_explicit() -> None:
    native = parse_ghidra_output({
        "schema_version": "ghidra-sidecar-v1", "library_sha256": "c" * 64,
        "abi": "arm64-v8a", "status": "SUCCESS",
        "provenance": {"version": "12.1.2", "config_sha256": CONFIG_HASH},
        "functions": [],
    })
    linked = link_jni_evidence(
        managed_method="<p.C: native void hidden()>", expected_short_symbol="Java_p_C_hidden",
        expected_long_symbol="Java_p_C_hidden__", library_archive_path="lib/x.so",
        analysis=native, dynamic_registration_seen=True,
    )
    assert linked.mapping and linked.mapping.mapping_kind == "unresolved_dynamic"
    assert "RegisterNatives" in linked.mapping.unresolved_reason


def test_canonical_schema_roundtrip_is_deterministic() -> None:
    managed = parse_flowdroid_output(flow_output())
    behavior = build_behavior_artifact(
        apk_sha256=APK_HASH, flow=managed.flows[0], managed_provenance=managed.provenance,
        native_context=NativeContext(False),
    )
    encoded = canonical_json(behavior)
    assert canonical_sha256(behavior) == canonical_sha256(behavior.to_dict())
    assert encoded == canonical_json(behavior)
    assert '"schema_version":"behavior-artifact-v2alpha1"' in encoded


def test_unapproved_source_sink_pair_does_not_create_behavior() -> None:
    value = flow_output()
    value["flows"][0]["source"]["category"] = "LOCATION_INFORMATION"
    value["flows"][0]["sink"]["category"] = "FILE"
    managed = parse_flowdroid_output(value)
    with pytest.raises(ValueError, match="unapproved"):
        build_behavior_artifact(
            apk_sha256=APK_HASH, flow=managed.flows[0], managed_provenance=managed.provenance,
        )


def test_model_view_uses_jimple_not_smali_or_raw_pcode() -> None:
    managed = parse_flowdroid_output(flow_output())
    behavior = build_behavior_artifact(
        apk_sha256=APK_HASH, flow=managed.flows[0], managed_provenance=managed.provenance,
    )
    view = serialize_candidate(behavior)
    assert "[FLOW]" in view.text and "virtualinvoke" in view.text
    assert "raw_pcode" not in view.text and "smali_debug_ref" not in view.text


def test_tool_failure_provenance_is_stable() -> None:
    provenance = ToolProvenance("FlowDroid", "2.15.1", CONFIG_HASH, APK_HASH)
    assert canonical_sha256(provenance) == canonical_sha256(provenance)


def test_native_code_normalization_is_whitespace_stable() -> None:
    assert normalize_decompiled_code(" a   = 1;\r\n\r\n send(a); ") == "a = 1;\nsend(a);"
