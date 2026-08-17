"""Conservative exact-key joins for independently proven persistence flows."""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Iterable

from kavach_ai.backend.pipeline.stage2_static.v2_artifacts import (
    BehaviorArtifact,
    ManagedFlow,
    ManifestArtifact,
    PersistenceBridge,
    ToolIssue,
    ToolProvenance,
    semantic_hash,
)
from kavach_ai.backend.pipeline.stage2_static.v2_canonical import canonical_sha256

from .behavior_artifacts import build_behavior_artifact


@dataclass(frozen=True)
class PersistenceFlowSegment:
    """One FlowDroid-proven segment terminating at or starting from storage."""

    apk_sha256: str
    role: str
    storage_kind: str
    namespace: str
    constant_keys: tuple[str, ...]
    flow: ManagedFlow
    provenance: ToolProvenance

    def __post_init__(self) -> None:
        if self.role not in {"STORE", "LOAD"}:
            raise ValueError("persistence segment role must be STORE or LOAD")


def _normalized_identity(segment: PersistenceFlowSegment) -> tuple[str, str, tuple[str, ...]] | None:
    kind = segment.storage_kind.strip().upper()
    namespace = segment.namespace.strip()
    keys = tuple(sorted({key.strip() for key in segment.constant_keys if key.strip()}))
    # Unresolved namespaces and keys are deliberately not joinable.
    if not kind or not namespace or not keys:
        return None
    return kind, namespace, keys


def _combine_flow(store: ManagedFlow, load: ManagedFlow) -> ManagedFlow:
    statements = tuple(dict.fromkeys(store.statements + load.statements))
    controls = tuple(dict.fromkeys(store.controls + load.controls))
    call_sites = tuple(dict.fromkeys(store.call_sites + load.call_sites))
    unresolved = tuple(dict.fromkeys(
        store.unresolved_calls + ("EXACT_KEY_PERSISTENCE_ORDER",) + load.unresolved_calls
    ))
    return ManagedFlow(
        source=store.source,
        sink=load.sink,
        statements=statements,
        controls=controls,
        component=load.component or store.component,
        call_sites=call_sites,
        complete=False,
        unresolved_calls=unresolved,
    )


def build_exact_key_persistence_bridges(
    *,
    stores: Iterable[PersistenceFlowSegment],
    loads: Iterable[PersistenceFlowSegment],
    manifest: ManifestArtifact | None = None,
) -> tuple[BehaviorArtifact, ...]:
    """Join only same-APK, same-kind, same-namespace, intersecting constant keys."""

    artifacts: list[BehaviorArtifact] = []
    valid_stores = [(item, _normalized_identity(item)) for item in stores if item.role == "STORE"]
    valid_loads = [(item, _normalized_identity(item)) for item in loads if item.role == "LOAD"]
    for store, store_identity in valid_stores:
        if store_identity is None:
            continue
        store_kind, store_namespace, store_keys = store_identity
        for load, load_identity in valid_loads:
            if load_identity is None or store.apk_sha256 != load.apk_sha256:
                continue
            load_kind, load_namespace, load_keys = load_identity
            if (store_kind, store_namespace) != (load_kind, load_namespace):
                continue
            for key in sorted(set(store_keys).intersection(load_keys)):
                flow = _combine_flow(store.flow, load.flow)
                bridge = PersistenceBridge(
                    bridge_kind="EXACT_KEY_PERSISTENCE",
                    storage_kind=store_kind,
                    namespace=store_namespace,
                    normalized_key=key,
                    source_segment=store.flow,
                    load_segment=load.flow,
                    ordering_uncertainty="OVER_APPROXIMATED",
                    precision="EXACT_CONSTANT_KEY",
                )
                artifact = build_behavior_artifact(
                    apk_sha256=store.apk_sha256,
                    flow=flow,
                    managed_provenance=store.provenance,
                    manifest=manifest,
                    semantic_context=(
                        "persistence_bridge=EXACT_KEY_PERSISTENCE",
                        f"storage_kind={store_kind}",
                        f"storage_namespace={store_namespace}",
                        f"storage_key={key}",
                        "persistence_ordering=OVER_APPROXIMATED",
                    ),
                )
                digest = semantic_hash(
                    source_category=artifact.source_category,
                    sink_category=artifact.sink_category,
                    behavior_category=artifact.behavior_category,
                    flow=flow,
                    native_context=artifact.native_context,
                    persistence_bridge=bridge,
                )
                artifact = replace(
                    artifact,
                    artifact_id=canonical_sha256({
                        "apk_sha256": store.apk_sha256,
                        "semantic_sha256": digest,
                    }),
                    semantic_sha256=digest,
                    provenance=tuple(dict.fromkeys((store.provenance, load.provenance))),
                    issues=(ToolIssue(
                        code="PERSISTENCE_ORDER_OVER_APPROXIMATED",
                        message="Exact-key store/load identity matched; lifecycle ordering is not proven",
                        phase="behavior",
                    ),),
                    persistence_bridge=bridge,
                )
                artifacts.append(artifact)
    return tuple(sorted(artifacts, key=lambda item: item.artifact_id))
