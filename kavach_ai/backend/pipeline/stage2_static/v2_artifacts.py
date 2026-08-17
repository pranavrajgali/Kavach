"""Tool-neutral, deterministic Stage-1 static-analysis contracts."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from .v2_canonical import canonical_sha256


BEHAVIOR_ARTIFACT_SCHEMA = "behavior-artifact-v2alpha1"
MANAGED_ARTIFACT_SCHEMA = "managed-flow-v2alpha1"
NATIVE_ARTIFACT_SCHEMA = "native-evidence-v2alpha1"
MANIFEST_ARTIFACT_SCHEMA = "manifest-context-v2alpha1"


@dataclass(frozen=True, order=True)
class ToolIssue:
    code: str
    message: str
    phase: str
    severity: str = "warning"


@dataclass(frozen=True)
class ToolProvenance:
    tool: str
    version: str
    config_sha256: str
    input_sha256: str
    command: tuple[str, ...] = ()
    runtime_seconds: float | None = None
    max_rss_kb: int | None = None


@dataclass(frozen=True, order=True)
class IntentFilterContext:
    actions: tuple[str, ...] = ()
    categories: tuple[str, ...] = ()
    data: tuple[tuple[tuple[str, str], ...], ...] = ()


@dataclass(frozen=True, order=True)
class ComponentContext:
    component_type: str
    component_name: str
    callback: str | None = None
    exported: bool | None = None
    intent_filters: tuple[IntentFilterContext, ...] = ()


@dataclass(frozen=True)
class ManifestArtifact:
    apk_sha256: str
    package_name: str
    permissions: tuple[str, ...]
    components: tuple[ComponentContext, ...]
    min_sdk: int | None
    target_sdk: int | None
    warnings: tuple[str, ...] = ()
    schema_version: str = MANIFEST_ARTIFACT_SCHEMA


@dataclass(frozen=True, order=True)
class StatementRef:
    statement_id: str
    method_signature: str
    jimple: str
    dex_offset: int | None = None
    line_number: int | None = None
    tags: tuple[str, ...] = ()
    exception_context: tuple[str, ...] = ()
    monitor_context: str | None = None
    smali_debug_ref: str | None = field(default=None, compare=False)


@dataclass(frozen=True)
class Endpoint:
    definition: str
    category: str
    statement: StatementRef
    access_path: str | None = None


@dataclass(frozen=True, order=True)
class ControlPredicate:
    predicate: StatementRef
    controls_statement_ids: tuple[str, ...]
    operand_definitions: tuple[StatementRef, ...] = ()


@dataclass(frozen=True)
class ManagedFlow:
    source: Endpoint
    sink: Endpoint
    statements: tuple[StatementRef, ...]
    controls: tuple[ControlPredicate, ...] = ()
    component: ComponentContext | None = None
    call_sites: tuple[StatementRef, ...] = ()
    complete: bool = True
    unresolved_calls: tuple[str, ...] = ()


@dataclass(frozen=True)
class PersistenceBridge:
    """Explicit evidence joining two independently proven persistence segments."""

    bridge_kind: str
    storage_kind: str
    namespace: str
    normalized_key: str
    source_segment: ManagedFlow
    load_segment: ManagedFlow
    ordering_uncertainty: str
    precision: str


@dataclass(frozen=True)
class ManagedAction:
    endpoint: Endpoint
    behavior_category: str
    argument_dependencies: tuple[StatementRef, ...]
    controls: tuple[ControlPredicate, ...] = ()
    component: ComponentContext | None = None
    complete: bool = True
    unresolved_calls: tuple[str, ...] = ()


@dataclass(frozen=True)
class ManagedAnalysisArtifact:
    apk_sha256: str
    status: str
    flows: tuple[ManagedFlow, ...]
    provenance: ToolProvenance
    issues: tuple[ToolIssue, ...] = ()
    actions: tuple[ManagedAction, ...] = ()
    schema_version: str = MANAGED_ARTIFACT_SCHEMA


@dataclass(frozen=True, order=True)
class JniMappingEvidence:
    managed_method: str
    library_sha256: str | None
    library_archive_path: str | None
    native_function: str | None
    mapping_kind: str
    confidence: float
    unresolved_reason: str | None = None


@dataclass(frozen=True)
class NativeFunctionEvidence:
    function_id: str
    normalized_decompiled_code: str | None = None
    calls: tuple[str, ...] = ()
    imports: tuple[str, ...] = ()
    strings: tuple[str, ...] = ()
    raw_pcode_debug_ref: str | None = field(default=None, compare=False)
    full_analysis_debug_ref: str | None = field(default=None, compare=False)


@dataclass(frozen=True)
class NativeAnalysisArtifact:
    library_sha256: str
    abi: str
    status: str
    functions: tuple[NativeFunctionEvidence, ...]
    provenance: ToolProvenance
    issues: tuple[ToolIssue, ...] = ()
    schema_version: str = NATIVE_ARTIFACT_SCHEMA


@dataclass(frozen=True)
class NativeContext:
    crossed: bool
    mapping: JniMappingEvidence | None = None
    selected_evidence: tuple[NativeFunctionEvidence, ...] = ()


@dataclass(frozen=True)
class BehaviorArtifact:
    apk_sha256: str
    artifact_id: str
    semantic_sha256: str
    occurrence_count: int
    source_category: str
    sink_category: str
    behavior_category: str
    mitre_ids: tuple[str, ...]
    classification_confidence: str
    android_context: ComponentContext | None
    relevant_permissions: tuple[str, ...]
    flow: ManagedFlow | None
    semantic_context: tuple[str, ...]
    native_context: NativeContext
    provenance: tuple[ToolProvenance, ...]
    issues: tuple[ToolIssue, ...] = ()
    occurrence_statement_ids: tuple[str, ...] = ()
    action: ManagedAction | None = None
    persistence_bridge: PersistenceBridge | None = None
    schema_version: str = BEHAVIOR_ARTIFACT_SCHEMA

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def behavior_semantic_identity(
    *, source_category: str, sink_category: str, behavior_category: str,
    flow: ManagedFlow | None, native_context: NativeContext,
    action: ManagedAction | None = None,
    persistence_bridge: PersistenceBridge | None = None,
) -> dict[str, Any]:
    """Identity excludes APK, volatile addresses, debug refs and tool runtime."""

    statements = [
        {
            "method": item.method_signature,
            "jimple": item.jimple,
            "exception_context": item.exception_context,
            "monitor_context": item.monitor_context,
        }
        for item in (flow.statements if flow else action.argument_dependencies if action else ())
    ]
    controls = [
        {
            "predicate": item.predicate.jimple,
            "method": item.predicate.method_signature,
            "controls": item.controls_statement_ids,
            "operands": tuple(definition.jimple for definition in item.operand_definitions),
        }
        for item in (flow.controls if flow else action.controls if action else ())
    ]
    native = None
    if native_context.mapping:
        native = {
            "managed_method": native_context.mapping.managed_method,
            "library_sha256": native_context.mapping.library_sha256,
            "native_function": native_context.mapping.native_function,
            "mapping_kind": native_context.mapping.mapping_kind,
            "evidence": [
                {
                    "function_id": item.function_id,
                    "code": item.normalized_decompiled_code,
                    "calls": item.calls,
                    "imports": item.imports,
                    "strings": item.strings,
                }
                for item in native_context.selected_evidence
            ],
        }
    bridge = None
    if persistence_bridge is not None:
        bridge = {
            "bridge_kind": persistence_bridge.bridge_kind,
            "storage_kind": persistence_bridge.storage_kind,
            "namespace": persistence_bridge.namespace,
            "normalized_key": persistence_bridge.normalized_key,
            "ordering_uncertainty": persistence_bridge.ordering_uncertainty,
            "precision": persistence_bridge.precision,
            "source_segment": tuple(
                (item.method_signature, item.jimple)
                for item in persistence_bridge.source_segment.statements
            ),
            "load_segment": tuple(
                (item.method_signature, item.jimple)
                for item in persistence_bridge.load_segment.statements
            ),
        }
    identity = {
        "source": {"category": source_category, "definition": flow.source.definition if flow else None},
        "sink": {"category": sink_category, "definition": flow.sink.definition if flow else action.endpoint.definition if action else None},
        "behavior_category": behavior_category,
        "statements": statements,
        "controls": controls,
        "native": native,
    }
    if bridge is not None:
        identity["persistence_bridge"] = bridge
    return identity


def semantic_hash(**kwargs: Any) -> str:
    return canonical_sha256(behavior_semantic_identity(**kwargs))
