"""Deterministic, versioned ModelView serialization for V2 artifacts.

An APK with no BehaviorArtifacts is represented by an empty APKModelViewIndex,
never by a fabricated suspicious artifact.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

from kavach_ai.backend.pipeline.stage2_static.v2_artifacts import BehaviorArtifact
from kavach_ai.backend.pipeline.stage2_static.v2_canonical import canonical_sha256, read_json, write_json_atomic


MODEL_VIEW_SCHEMA = "model-view-v2-candidate1"
MODEL_VIEW_INDEX_SCHEMA = "model-view-index-v2-candidate1"
MODEL_VIEW_STORAGE_VERSION = "v2/candidate1"


@dataclass(frozen=True)
class ModelViewOptions:
    """Auditable switches; compression and truncation are deliberately absent."""

    include_android_context: bool = True
    include_manifest_context: bool = True
    include_controls: bool = True
    include_semantic_context: bool = True
    include_native_context: bool = True

    @property
    def config_sha256(self) -> str:
        # Include the format version so a serializer revision cannot silently
        # reuse ModelViews produced by an older text contract.
        return canonical_sha256({"schema_version": MODEL_VIEW_SCHEMA, "options": asdict(self)})


@dataclass(frozen=True)
class ModelView:
    # First two fields stay compatible with existing synthetic MIL fixtures.
    artifact_id: str
    text: str
    apk_sha256: str | None = None
    behavior_category: str | None = None
    analysis_lane: str | None = None
    content_sha256: str | None = None
    config_sha256: str | None = None
    schema_version: str = MODEL_VIEW_SCHEMA

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ModelView":
        schema = value.get("schema_version")
        if schema != MODEL_VIEW_SCHEMA:
            raise ValueError(f"unsupported ModelView schema: {schema!r}")
        artifact_id, text = value.get("artifact_id"), value.get("text")
        if not isinstance(artifact_id, str) or not artifact_id:
            raise ValueError("ModelView artifact_id must be a non-empty string")
        if not isinstance(text, str):
            raise ValueError("ModelView text must be a string")
        view = cls(
            artifact_id, text, _optional_string(value, "apk_sha256"),
            _optional_string(value, "behavior_category"), _optional_string(value, "analysis_lane"),
            _optional_string(value, "content_sha256"), _optional_string(value, "config_sha256"), schema,
        )
        if view.content_sha256 is not None and view.content_sha256 != canonical_sha256(text):
            raise ValueError("ModelView content_sha256 does not match text")
        return view


@dataclass(frozen=True, order=True)
class PhaseCompletion:
    phase: str
    status: str
    complete: bool
    issue_codes: tuple[str, ...] = ()


@dataclass(frozen=True)
class APKModelViewIndex:
    """Per-APK bag membership and extraction state, including empty bags."""

    apk_sha256: str
    artifact_ids: tuple[str, ...]
    phases: tuple[PhaseCompletion, ...]
    model_view_config_sha256: str
    schema_version: str = MODEL_VIEW_INDEX_SCHEMA

    def __post_init__(self) -> None:
        if len(self.apk_sha256) != 64:
            raise ValueError("apk_sha256 must contain 64 characters")
        if self.artifact_ids != tuple(sorted(set(self.artifact_ids))):
            raise ValueError("artifact_ids must be sorted and unique")
        names = tuple(item.phase for item in self.phases)
        if names != tuple(sorted(set(names))):
            raise ValueError("phases must be sorted and unique by phase name")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "APKModelViewIndex":
        if value.get("schema_version") != MODEL_VIEW_INDEX_SCHEMA:
            raise ValueError(f"unsupported ModelView index schema: {value.get('schema_version')!r}")
        phases = tuple(PhaseCompletion(
            str(item["phase"]), str(item["status"]), bool(item["complete"]),
            tuple(sorted(set(str(code) for code in item.get("issue_codes", ())))),
        ) for item in value.get("phases", ()))
        return cls(str(value["apk_sha256"]), tuple(str(x) for x in value.get("artifact_ids", ())), phases,
                   str(value["model_view_config_sha256"]), MODEL_VIEW_INDEX_SCHEMA)


def _optional_string(value: Mapping[str, Any], key: str) -> str | None:
    item = value.get(key)
    if item is not None and not isinstance(item, str):
        raise ValueError(f"ModelView {key} must be a string or null")
    return item


def _clean(value: object) -> str:
    return " ".join(str(value).replace("\r", " ").replace("\n", " ").split())


def _analysis_lane(artifact: BehaviorArtifact) -> str:
    if artifact.native_context.crossed:
        return "NATIVE_ACTION"
    if artifact.action is not None:
        return "ACTION_DEPENDENCY"
    return "FLOWDROID_TAINT"


def serialize_candidate(artifact: BehaviorArtifact, *, options: ModelViewOptions | None = None) -> ModelView:
    """Build an uncompressed candidate view from a flow or future action artifact."""

    selected, lane = options or ModelViewOptions(), _analysis_lane(artifact)
    sections = ["[BEHAVIOR]", " ".join((
        f"category={_clean(artifact.behavior_category)}",
        f"source_category={_clean(artifact.source_category or 'NONE')}",
        f"sink_category={_clean(artifact.sink_category)}", f"analysis_lane={lane}",
    ))]
    if selected.include_android_context and artifact.android_context:
        context = artifact.android_context
        sections.extend(["[ANDROID_CONTEXT]", " ".join((
            f"component_type={_clean(context.component_type)}", f"component={_clean(context.component_name)}",
            f"callback={_clean(context.callback or 'unknown')}", f"exported={context.exported}",
        ))])
    if selected.include_manifest_context and artifact.relevant_permissions:
        sections.extend(["[MANIFEST_CONTEXT]", "permissions=" + ",".join(sorted(set(artifact.relevant_permissions)))])

    flow, action = getattr(artifact, "flow", None), getattr(artifact, "action", None)
    if flow is not None:
        sections.extend(["[SOURCE]", _clean(flow.source.definition), "[FLOW]"])
        sections.extend(_clean(item.jimple) for item in flow.statements)
        if selected.include_controls and flow.controls:
            sections.append("[CONTROL]")
            for control in sorted(flow.controls, key=lambda item: item.predicate.statement_id):
                sections.append(_clean(control.predicate.jimple))
                sections.extend("depends_on=" + _clean(item.jimple)
                                for item in sorted(control.operand_definitions, key=lambda item: item.statement_id))
        sections.extend(["[ENDPOINT]", _clean(flow.sink.definition)])
    elif action is not None:
        endpoint = getattr(action, "endpoint", None)
        definition = getattr(endpoint, "definition", getattr(action, "definition", action))
        sections.extend(["[ACTION]", _clean(definition)])
        arguments = getattr(action, "argument_dependencies", ())
        if arguments:
            sections.append("[ARGUMENT_DEPENDENCIES]")
            sections.extend(_clean(getattr(item, "jimple", item)) for item in arguments)
        controls = getattr(action, "controls", ())
        if selected.include_controls and controls:
            sections.append("[CONTROL]")
            for control in sorted(controls, key=lambda item: item.predicate.statement_id):
                sections.append(_clean(control.predicate.jimple))
                sections.extend("depends_on=" + _clean(item.jimple)
                                for item in sorted(control.operand_definitions, key=lambda item: item.statement_id))
        sections.extend(["[ENDPOINT]", _clean(definition)])
    else:
        raise ValueError("BehaviorArtifact must contain a managed flow or action")

    if selected.include_semantic_context and artifact.semantic_context:
        sections.extend(["[SEMANTIC_CONTEXT]", ",".join(sorted(set(artifact.semantic_context)))])
    if selected.include_native_context and artifact.native_context.crossed:
        mapping = artifact.native_context.mapping
        sections.extend(["[NATIVE_CONTEXT]",
                         f"mapping={_clean(mapping.mapping_kind if mapping else 'unresolved')} "
                         f"function={_clean(mapping.native_function if mapping and mapping.native_function else 'unknown')}"])
        for evidence in sorted(artifact.native_context.selected_evidence, key=lambda item: item.function_id):
            if evidence.normalized_decompiled_code:
                sections.append(evidence.normalized_decompiled_code.strip())
            if evidence.calls:
                sections.append("calls=" + ",".join(sorted(set(evidence.calls))))
            if evidence.imports:
                sections.append("imports=" + ",".join(sorted(set(evidence.imports))))
            if evidence.strings:
                sections.append("strings=" + ",".join(sorted(set(evidence.strings))))
    text = "\n".join(sections)
    return ModelView(artifact.artifact_id, text, artifact.apk_sha256, artifact.behavior_category, lane,
                     canonical_sha256(text), selected.config_sha256)


def candidate_path(root: str | Path, *, apk_sha256: str, artifact_id: str) -> Path:
    if not apk_sha256 or not artifact_id:
        raise ValueError("apk_sha256 and artifact_id are required")
    return Path(root) / MODEL_VIEW_STORAGE_VERSION / apk_sha256 / f"{artifact_id}.json"


def index_path(root: str | Path, *, apk_sha256: str) -> Path:
    if not apk_sha256:
        raise ValueError("apk_sha256 is required")
    return Path(root) / MODEL_VIEW_STORAGE_VERSION / apk_sha256 / "index.json"


def build_apk_index(*, apk_sha256: str, views: Sequence[ModelView], phases: Sequence[PhaseCompletion],
                    options: ModelViewOptions | None = None) -> APKModelViewIndex:
    if any(view.apk_sha256 is not None and view.apk_sha256 != apk_sha256 for view in views):
        raise ValueError("ModelView belongs to a different APK")
    return APKModelViewIndex(apk_sha256, tuple(sorted({view.artifact_id for view in views})),
                             tuple(sorted(phases, key=lambda item: item.phase)),
                             (options or ModelViewOptions()).config_sha256)


def write_candidate(root: str | Path, artifact: BehaviorArtifact, *, options: ModelViewOptions | None = None) -> Path:
    destination = candidate_path(root, apk_sha256=artifact.apk_sha256, artifact_id=artifact.artifact_id)
    write_json_atomic(destination, serialize_candidate(artifact, options=options))
    return destination


def write_apk_index(root: str | Path, index: APKModelViewIndex) -> Path:
    destination = index_path(root, apk_sha256=index.apk_sha256)
    write_json_atomic(destination, index)
    return destination


def read_candidate(path: str | Path) -> ModelView:
    return ModelView.from_dict(read_json(path))


def read_apk_index(path: str | Path) -> APKModelViewIndex:
    return APKModelViewIndex.from_dict(read_json(path))
