"""Pure BehaviorArtifact classification, construction, and within-APK dedup."""

from __future__ import annotations

from dataclasses import replace
from typing import Iterable, Mapping

from kavach_ai.backend.pipeline.stage2_static.v2_canonical import canonical_sha256
from kavach_ai.backend.pipeline.stage2_static.v2_artifacts import (
    BehaviorArtifact, ManagedAction, ManagedFlow, ManifestArtifact, NativeContext, ToolProvenance,
    semantic_hash,
)


BEHAVIOR_RULES: Mapping[tuple[str, str], tuple[str, tuple[str, ...], str]] = {
    ("LOCATION_INFORMATION", "NETWORK"): ("DATA_EXFILTRATION", ("T1430",), "medium"),
    ("CONTACT_INFORMATION", "NETWORK"): ("DATA_EXFILTRATION", ("T1636.003",), "medium"),
    ("SMS_MMS", "NETWORK"): ("DATA_EXFILTRATION", ("T1636.004",), "medium"),
    ("UNIQUE_IDENTIFIER", "NETWORK"): ("DATA_EXFILTRATION", (), "medium"),
    ("ACCOUNT_INFORMATION", "NETWORK"): ("EXTERNAL_DATA_TRANSFER", (), "medium"),
    ("CLIPBOARD_INFORMATION", "NETWORK"): ("EXTERNAL_DATA_TRANSFER", (), "medium"),
    ("FILE_INFORMATION", "NETWORK"): ("DATA_EXFILTRATION", ("T1533",), "medium"),
    ("NETWORK", "DYNAMIC_CODE_LOAD"): ("RUNTIME_CODE_LOADING", ("T1407",), "high"),
    ("FILE_INFORMATION", "DYNAMIC_CODE_LOAD"): ("RUNTIME_CODE_LOADING", ("T1407",), "medium"),
    ("COMMAND_INPUT", "PROCESS_EXECUTION"): ("COMMAND_EXECUTION", (), "high"),
    ("SMS_MMS", "SMS"): ("SMS_TELEPHONY_ABUSE", (), "medium"),
    ("UNIQUE_IDENTIFIER", "SMS"): ("EXTERNAL_DATA_TRANSFER", (), "medium"),
    ("ACCOUNT_INFORMATION", "SMS"): ("EXTERNAL_DATA_TRANSFER", (), "medium"),
    ("CLIPBOARD_INFORMATION", "SMS"): ("EXTERNAL_DATA_TRANSFER", (), "medium"),
    ("LOCATION_INFORMATION", "EXTERNAL_IPC"): ("EXTERNAL_IPC_TRANSFER", (), "medium"),
    ("UNIQUE_IDENTIFIER", "EXTERNAL_IPC"): ("EXTERNAL_IPC_TRANSFER", (), "medium"),
    ("ACCOUNT_INFORMATION", "EXTERNAL_IPC"): ("EXTERNAL_IPC_TRANSFER", (), "medium"),
    ("CLIPBOARD_INFORMATION", "EXTERNAL_IPC"): ("EXTERNAL_IPC_TRANSFER", (), "medium"),
    ("SMS_MMS", "EXTERNAL_IPC"): ("EXTERNAL_IPC_TRANSFER", (), "medium"),
}

SENSITIVE_SOURCES = frozenset({
    "LOCATION_INFORMATION", "UNIQUE_IDENTIFIER", "ADVERTISING_IDENTIFIER", "APP_IDENTIFIER",
    "ACCOUNT_INFORMATION", "AUTH_CREDENTIAL", "AUTH_TOKEN", "CONTACT_INFORMATION", "SMS_MMS",
    "CALL_LOG_INFORMATION", "CALENDAR_INFORMATION", "CLIPBOARD_INFORMATION", "MEDIA_INFORMATION",
    "AUDIO_INFORMATION", "SCREEN_INFORMATION", "SENSOR_INFORMATION", "HEALTH_INFORMATION",
    "LOCAL_FILE_INFORMATION", "LOCAL_DATABASE_INFORMATION",
})


def behavior_rule(source: str, sink: str) -> tuple[str, tuple[str, ...], str] | None:
    direct = BEHAVIOR_RULES.get((source, sink))
    if direct is not None:
        return direct
    if source in SENSITIVE_SOURCES:
        behavior = {
            "NETWORK": "EXTERNAL_DATA_TRANSFER", "SMS": "EXTERNAL_DATA_TRANSFER",
            "EXTERNAL_IPC": "EXTERNAL_IPC_TRANSFER", "SHARED_FILE": "EXTERNAL_FILE_EXPOSURE",
            "LOG": "SENSITIVE_DATA_EXPOSURE",
        }.get(sink)
        if behavior:
            return behavior, (), "medium"
    if source in {"NETWORK_INPUT", "EXTERNAL_IPC_INPUT"}:
        behavior = {
            "PROCESS_EXECUTION": "REMOTE_COMMAND_DISPATCH",
            "DYNAMIC_CODE_LOAD": "DYNAMIC_CODE_EXECUTION",
            "PACKAGE_INSTALLATION": "SOFTWARE_INSTALLATION",
        }.get(sink)
        if behavior:
            return behavior, (), "high"
    return None


def relevant_permissions(manifest: ManifestArtifact | None, source: str, sink: str) -> tuple[str, ...]:
    if manifest is None:
        return ()
    needles = {
        "LOCATION_INFORMATION": ("LOCATION",),
        "CONTACT_INFORMATION": ("CONTACTS",),
        "SMS_MMS": ("SMS",),
        "NETWORK": ("INTERNET", "NETWORK_STATE"),
        "PROCESS_EXECUTION": (),
    }
    wanted = needles.get(source, ()) + needles.get(sink, ())
    return tuple(permission for permission in manifest.permissions if any(token in permission for token in wanted))


def attach_manifest_context(flow: ManagedFlow, manifest: ManifestArtifact | None) -> ManagedFlow:
    """Enrich FlowDroid ownership without gating or changing the recovered flow."""

    if manifest is None or flow.component is None:
        return flow
    owner = flow.component.component_name.replace("/", ".").lstrip("L").rstrip(";")
    for component in manifest.components:
        if component.component_name == owner:
            return replace(
                flow,
                component=replace(component, callback=flow.component.callback),
            )
    return flow


def build_behavior_artifact(
    *, apk_sha256: str, flow: ManagedFlow, managed_provenance: ToolProvenance,
    manifest: ManifestArtifact | None = None, native_context: NativeContext | None = None,
    semantic_context: tuple[str, ...] = (),
) -> BehaviorArtifact:
    flow = attach_manifest_context(flow, manifest)
    rule = behavior_rule(flow.source.category, flow.sink.category)
    if rule is None:
        raise ValueError(f"unapproved source/sink behavior pair: {(flow.source.category, flow.sink.category)!r}")
    behavior, mitre, confidence = rule
    native = native_context or NativeContext(False)
    digest = semantic_hash(
        source_category=flow.source.category, sink_category=flow.sink.category,
        behavior_category=behavior, flow=flow, native_context=native,
    )
    provenance = [managed_provenance]
    artifact_id = canonical_sha256({"apk_sha256": apk_sha256, "semantic_sha256": digest})
    return BehaviorArtifact(
        apk_sha256, artifact_id, digest, 1, flow.source.category, flow.sink.category,
        behavior, mitre, confidence, flow.component,
        relevant_permissions(manifest, flow.source.category, flow.sink.category),
        flow, tuple(sorted(set(semantic_context))), native, tuple(provenance), (),
        (flow.sink.statement.statement_id,),
    )


def build_action_artifact(
    *, apk_sha256: str, action: ManagedAction, managed_provenance: ToolProvenance,
    manifest: ManifestArtifact | None = None, native_context: NativeContext | None = None,
    semantic_context: tuple[str, ...] = (), source_category: str = "NONE",
) -> BehaviorArtifact:
    native = native_context or NativeContext(False)
    digest = semantic_hash(
        source_category=source_category, sink_category=action.endpoint.category,
        behavior_category=action.behavior_category, flow=None, action=action,
        native_context=native,
    )
    artifact_id = canonical_sha256({"apk_sha256": apk_sha256, "semantic_sha256": digest})
    component = action.component
    if component and manifest:
        owner = component.component_name.replace("/", ".").lstrip("L").rstrip(";")
        for candidate in manifest.components:
            if candidate.component_name == owner:
                component = replace(candidate, callback=component.callback)
                break
    return BehaviorArtifact(
        apk_sha256, artifact_id, digest, 1, source_category, action.endpoint.category,
        action.behavior_category, (), "medium", component,
        relevant_permissions(manifest, source_category, action.endpoint.category), None,
        tuple(sorted(set(semantic_context))), native, (managed_provenance,), (),
        (action.endpoint.statement.statement_id,), action=action,
    )


def collapse_within_apk(artifacts: Iterable[BehaviorArtifact]) -> tuple[BehaviorArtifact, ...]:
    grouped: dict[tuple[str, str], BehaviorArtifact] = {}
    for artifact in artifacts:
        key = (artifact.apk_sha256, artifact.semantic_sha256)
        previous = grouped.get(key)
        if previous is None:
            grouped[key] = artifact
            continue
        occurrences = tuple(sorted(set(previous.occurrence_statement_ids + artifact.occurrence_statement_ids)))
        grouped[key] = replace(
            previous, occurrence_count=previous.occurrence_count + artifact.occurrence_count,
            occurrence_statement_ids=occurrences,
        )
    return tuple(grouped[key] for key in sorted(grouped))
