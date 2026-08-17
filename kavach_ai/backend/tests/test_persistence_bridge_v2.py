from __future__ import annotations

from kavach_ai.backend.pipeline.stage2_static.v2_artifacts import (
    Endpoint,
    ManagedFlow,
    StatementRef,
    ToolProvenance,
)
from kavach_ai.backend.pipeline.stage3_ml.persistence_bridge import (
    PersistenceFlowSegment,
    build_exact_key_persistence_bridges,
)
from training.run_corpus_v2 import persistence_segment


APK = "a" * 64


def _statement(identifier: str, jimple: str) -> StatementRef:
    return StatementRef(identifier, "<Fixture: void run()>", jimple)


def _flow(source_category: str, sink_category: str, prefix: str) -> ManagedFlow:
    source_statement = _statement(f"{prefix}-source", f"{prefix} source")
    sink_statement = _statement(f"{prefix}-sink", f"{prefix} sink")
    return ManagedFlow(
        source=Endpoint("fixture-source", source_category, source_statement),
        sink=Endpoint("fixture-sink", sink_category, sink_statement),
        statements=(source_statement, sink_statement),
    )


def _segment(
    role: str,
    key: str,
    flow: ManagedFlow,
    *,
    apk: str = APK,
    kind: str = "CONFIG_FILE",
    namespace: str = "bot.cfg",
) -> PersistenceFlowSegment:
    return PersistenceFlowSegment(
        apk_sha256=apk,
        role=role,
        storage_kind=kind,
        namespace=namespace,
        constant_keys=(key,) if key else (),
        flow=flow,
        provenance=ToolProvenance("flowdroid", "2.15.1", role.lower(), apk),
    )


def test_exact_key_persistence_bridge_preserves_segments_and_uncertainty() -> None:
    store_flow = _flow("UNIQUE_IDENTIFIER", "PERSISTENT_STORE", "store")
    load_flow = _flow("PERSISTENT_LOAD", "NETWORK", "load")

    artifacts = build_exact_key_persistence_bridges(
        stores=(_segment("STORE", "BotID", store_flow),),
        loads=(_segment("LOAD", "BotID", load_flow),),
    )

    assert len(artifacts) == 1
    artifact = artifacts[0]
    assert artifact.source_category == "UNIQUE_IDENTIFIER"
    assert artifact.sink_category == "NETWORK"
    assert artifact.flow is not None and not artifact.flow.complete
    assert "EXACT_KEY_PERSISTENCE_ORDER" in artifact.flow.unresolved_calls
    assert artifact.persistence_bridge is not None
    assert artifact.persistence_bridge.source_segment == store_flow
    assert artifact.persistence_bridge.load_segment == load_flow
    assert artifact.persistence_bridge.normalized_key == "BotID"
    assert artifact.persistence_bridge.ordering_uncertainty == "OVER_APPROXIMATED"
    assert artifact.persistence_bridge.precision == "EXACT_CONSTANT_KEY"
    assert len(artifact.provenance) == 2
    assert artifact.to_dict()["persistence_bridge"]["bridge_kind"] == "EXACT_KEY_PERSISTENCE"


def test_persistence_bridge_rejects_mismatched_key() -> None:
    store = _segment("STORE", "BotID", _flow("UNIQUE_IDENTIFIER", "PERSISTENT_STORE", "s"))
    load = _segment("LOAD", "theme", _flow("PERSISTENT_LOAD", "NETWORK", "l"))
    assert build_exact_key_persistence_bridges(stores=(store,), loads=(load,)) == ()


def test_persistence_bridge_rejects_unknown_identity_and_cross_apk() -> None:
    store_flow = _flow("UNIQUE_IDENTIFIER", "PERSISTENT_STORE", "s")
    load_flow = _flow("PERSISTENT_LOAD", "NETWORK", "l")
    store = _segment("STORE", "", store_flow)
    load = _segment("LOAD", "", load_flow)
    assert build_exact_key_persistence_bridges(stores=(store,), loads=(load,)) == ()

    store = _segment("STORE", "BotID", store_flow)
    other_apk_load = _segment("LOAD", "BotID", load_flow, apk="b" * 64)
    assert build_exact_key_persistence_bridges(stores=(store,), loads=(other_apk_load,)) == ()


def test_persistence_bridge_rejects_kind_or_namespace_mismatch() -> None:
    store_flow = _flow("UNIQUE_IDENTIFIER", "PERSISTENT_STORE", "s")
    load_flow = _flow("PERSISTENT_LOAD", "NETWORK", "l")
    store = _segment("STORE", "BotID", store_flow)

    wrong_kind = _segment("LOAD", "BotID", load_flow, kind="SHARED_PREFERENCES")
    wrong_namespace = _segment("LOAD", "BotID", load_flow, namespace="other.cfg")
    assert build_exact_key_persistence_bridges(stores=(store,), loads=(wrong_kind,)) == ()
    assert build_exact_key_persistence_bridges(stores=(store,), loads=(wrong_namespace,)) == ()


def test_runner_recovers_only_constant_key_helper_segments() -> None:
    provenance = ToolProvenance("FlowDroid", "2.15.1", "cfg", APK)
    source = _statement("source", "id = getDeviceId()")
    store_call = StatementRef(
        "store", "<com.android.system.Init: void onCreate()>",
        'virtualinvoke r0.<com.android.system.Init: void writeCfg(java.lang.String,java.lang.String)>("BotID", id)',
    )
    store_flow = ManagedFlow(
        Endpoint("device", "UNIQUE_IDENTIFIER", source),
        Endpoint("<com.android.system.Init: void writeCfg(java.lang.String,java.lang.String)>",
                 "PERSISTENCE_STORE", store_call),
        (source, store_call),
    )
    segment = persistence_segment(APK, store_flow, provenance)
    assert segment is not None
    assert segment.namespace == "com.android.system"
    assert segment.constant_keys == ("BotID",)

    dynamic_call = StatementRef(
        "dynamic", store_call.method_signature,
        "virtualinvoke r0.<com.android.system.Init: void writeCfg(java.lang.String,java.lang.String)>(key, id)",
    )
    dynamic_flow = ManagedFlow(
        store_flow.source,
        Endpoint(store_flow.sink.definition, "PERSISTENCE_STORE", dynamic_call),
        (source, dynamic_call),
    )
    assert persistence_segment(APK, dynamic_flow, provenance) is None
