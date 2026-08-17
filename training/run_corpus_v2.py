"""Resumable Plan-2 V2 extraction over immutable APK identities.

This runner never reads or writes V1 generated artifacts.  Every phase has an
independent atomic output and status so a larger --limit resumes the same order.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import time
from collections import Counter
from dataclasses import asdict, replace
from functools import lru_cache
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from kavach_ai.backend.pipeline.stage1_triage.manifest_context import extract_manifest_artifact
from kavach_ai.backend.pipeline.stage2_static.decompile import extract_native_libraries, validate_apk
from kavach_ai.backend.pipeline.stage2_static.flowdroid import (
    FLOWDROID_VERSION, flowdroid_output_diagnostics, load_flowdroid_output, run_flowdroid,
)
from kavach_ai.backend.pipeline.stage2_static.ghidra import load_ghidra_output
from kavach_ai.backend.pipeline.stage2_static.v2_artifacts import (
    ComponentContext, Endpoint, IntentFilterContext, ManagedAction, ManifestArtifact,
    ManagedAnalysisArtifact, NativeContext, StatementRef, ToolProvenance,
)
from kavach_ai.backend.pipeline.stage2_static.v2_canonical import (
    canonical_sha256, file_sha256, read_json, write_json_atomic,
)
from kavach_ai.backend.pipeline.stage3_ml.behavior_artifacts import (
    build_action_artifact, build_behavior_artifact, collapse_within_apk,
)
from kavach_ai.backend.pipeline.stage3_ml.persistence_bridge import (
    PersistenceFlowSegment, build_exact_key_persistence_bridges,
)
from training.utils.dataset import load_apk_metadata, load_apk_splits
from training.utils.model_view import (
    ModelViewOptions, PhaseCompletion, build_apk_index, serialize_candidate, write_apk_index,
    write_candidate,
)

V2_ROOT = ROOT / "training/data/v2"
DEFAULT_SELECTION = V2_ROOT / "corpus" / "balanced_500_v1.json"
METADATA = ROOT / "training/data/manifests/apk_metadata.jsonl"
SPLITS = ROOT / "training/data/manifests/apk_splits_v1.json"
FLOW_CONFIG = ROOT / "configs/static_v2/flowdroid_stage1.json"
GHIDRA_CONFIG = ROOT / "configs/static_v2/ghidra_stage1.json"
CATEGORIES = ROOT / "configs/static_v2/categories_stage1.json"
ACTIONS = ROOT / "configs/static_v2/actions_stage1.json"
TAINT_GROUPS = {
    "sensitive_external": ROOT / "configs/static_v2/sources_sinks_taint_sensitive_stage1.txt",
    "storage_external": ROOT / "configs/static_v2/sources_sinks_taint_storage_stage1.txt",
    "input_privileged": ROOT / "configs/static_v2/sources_sinks_taint_privileged_stage1.txt",
}
TERMINAL = {"SUCCESS", "PARTIAL", "PARTIAL_TIMEOUT", "PARTIAL_OOM", "NOT_APPLICABLE", "TIMEOUT", "OOM", "FAILED"}
_QUOTED_JIMPLE = re.compile(r'"([^"\\]*(?:\\.[^"\\]*)*)"')


def inventory() -> list[dict]:
    metadata = load_apk_metadata(METADATA)
    splits = load_apk_splits(SPLITS, set(metadata))
    return [dict(metadata[digest], split=splits[digest]) for digest in sorted(metadata)]


def balanced_selection(records: list[dict], *, per_label: int = 250) -> list[dict]:
    """Select a deterministic label-balanced subset without altering split identity."""

    selected = []
    for label in ("Benign", "Malicious"):
        members = sorted((item for item in records if item["label"] == label),
                         key=lambda item: item["apk_hash"])
        if len(members) < per_label:
            raise ValueError(f"need {per_label} {label} APKs, found {len(members)}")
        selected.extend(members[:per_label])
    return sorted(selected, key=lambda item: item["apk_hash"])


def load_or_create_selection(path: Path, records: list[dict]) -> list[dict]:
    by_hash = {item["apk_hash"]: item for item in records}
    if path.exists():
        value = read_json(path)
        if value.get("schema_version") != "v2-corpus-selection-v1":
            raise ValueError(f"unsupported corpus selection schema: {path}")
        hashes = value.get("apk_sha256", ())
        if len(hashes) != 500 or len(set(hashes)) != 500:
            raise ValueError("balanced corpus manifest must contain 500 unique APK hashes")
        selected = []
        for digest in hashes:
            if digest not in by_hash:
                raise ValueError(f"selected APK is absent from immutable inventory: {digest}")
            selected.append(by_hash[digest])
    else:
        selected = balanced_selection(records)
        write_json_atomic(path, {
            "schema_version": "v2-corpus-selection-v1",
            "selection_policy": "lowest_sha256_per_label",
            "per_label": 250,
            "apk_sha256": [item["apk_hash"] for item in selected],
            "composition": dict(sorted(Counter(
                f"{item['label']}/{item['split']}" for item in selected
            ).items())),
        })
    labels = Counter(item["label"] for item in selected)
    if labels != {"Benign": 250, "Malicious": 250}:
        raise ValueError(f"selection is not balanced: {dict(labels)}")
    return selected


def phase_status(apk_hash: str) -> dict:
    path = V2_ROOT / "status" / f"{apk_hash}.json"
    if path.exists():
        return read_json(path)
    return {"schema_version": "apk-extraction-status-v2alpha1", "apk_sha256": apk_hash, "phases": {}}


def save_status(value: dict) -> None:
    write_json_atomic(V2_ROOT / "status" / f"{value['apk_sha256']}.json", value)


def record_phase(status: dict, phase: str, state: str, started: float, **extra: object) -> None:
    status["phases"][phase] = {"status": state, "runtime_seconds": time.monotonic() - started, **extra}
    save_status(status)


def completed(status: dict, phase: str, resume: bool, config_sha256: str | None = None) -> bool:
    phase_value = status.get("phases", {}).get(phase, {})
    if not resume or phase_value.get("status") not in TERMINAL:
        return False
    if config_sha256 is not None and phase_value.get("config_sha256") != config_sha256:
        return False
    # A failed phase without its promised output is not a completed cache entry.
    # Timeout artifacts are deliberately reusable when the adapter persisted one.
    if phase_value.get("status") in {"FAILED", "TIMEOUT", "OOM"}:
        output = phase_value.get("output")
        if not output or not Path(output).exists():
            return False
    if phase == "native":
        index = V2_ROOT / "native" / "apk" / f"{status['apk_sha256']}.json"
        try:
            for item in read_json(index).get("libraries", ()):
                load_ghidra_output(item["analysis"])
        except Exception:
            return False
    return True


def flow_command(args: argparse.Namespace, definitions: Path) -> tuple[str, ...]:
    config = json.loads(FLOW_CONFIG.read_text())
    return (
        str(args.java), "-Xmx8g", "-jar", str(args.sidecar_jar),
        "--platforms", str(args.android_platforms), "--sources-sinks", str(definitions),
        "--categories", str(CATEGORIES), "--actions", str(ACTIONS),
        "--data-timeout", str(config["data_timeout_seconds"]),
        "--callback-timeout", str(config["callback_timeout_seconds"]),
        "--path-timeout", str(config["path_timeout_seconds"]),
    )


def action_command(args: argparse.Namespace) -> tuple[str, ...]:
    return (
        str(args.java), "-Xmx8g", "-jar", str(args.sidecar_jar),
        "--mode", "actions", "--platforms", str(args.android_platforms),
        "--actions", str(ACTIONS),
    )


def merge_managed(apk_hash: str, actions: ManagedAnalysisArtifact,
                  groups: list[ManagedAnalysisArtifact]) -> ManagedAnalysisArtifact:
    flows = {canonical_sha256(asdict(item)): item for group in groups for item in group.flows}
    action_values = {canonical_sha256(asdict(item)): item for item in actions.actions}
    issues = tuple(actions.issues) + tuple(issue for group in groups for issue in group.issues)
    states = [actions.status, *(group.status for group in groups)]
    status = "SUCCESS" if all(item == "SUCCESS" for item in states) else "PARTIAL"
    provenance = ToolProvenance(
        "Kavach managed merge", FLOWDROID_VERSION,
        canonical_sha256({"actions": asdict(actions.provenance),
                          "groups": [asdict(group.provenance) for group in groups]}),
        apk_hash,
    )
    return ManagedAnalysisArtifact(
        apk_hash, status, tuple(flows[key] for key in sorted(flows)), provenance,
        issues, tuple(action_values[key] for key in sorted(action_values)),
    )


def _file_identity(path: Path) -> dict[str, object]:
    resolved = path.resolve()
    return {
        "path": str(resolved),
        "sha256": file_sha256(resolved) if resolved.is_file() else None,
        "missing": not resolved.exists(),
    }


@lru_cache(maxsize=4)
def _android_platform_identity(path_text: str) -> dict[str, object]:
    root = Path(path_text).resolve()
    jars = sorted(root.glob("*/android.jar")) if root.is_dir() else []
    return {"path": str(root), "android_jars": [
        {"relative_path": str(item.relative_to(root)), "sha256": file_sha256(item)} for item in jars
    ]}


def taint_group_fingerprint(
    *, args: argparse.Namespace, group_name: str, definitions: Path, config: dict,
) -> tuple[str, dict[str, object]]:
    """Fingerprint every input that can materially change a taint-group result."""

    identity: dict[str, object] = {
        "schema": "taint-group-cache-v2",
        "group": group_name,
        "flowdroid_config": config,
        "outer_timeout_seconds": args.taint_group_timeout,
        "definitions_sha256": file_sha256(definitions),
        "categories_sha256": file_sha256(CATEGORIES),
        "actions_sha256": file_sha256(ACTIONS),
        "sidecar": _file_identity(args.sidecar_jar),
        "java": _file_identity(args.java),
        "android_platforms": _android_platform_identity(str(args.android_platforms)),
        "flowdroid_version": config.get("flowdroid_version", FLOWDROID_VERSION),
        "soot_version": config.get("soot_version"),
        "jdk_major": config.get("jdk_major"),
    }
    return canonical_sha256(identity), identity


def run_ghidra_library(args: argparse.Namespace, library: Path, output: Path, debug: Path) -> str:
    config = json.loads(GHIDRA_CONFIG.read_text())
    project = f"v2_{library.stem}_{canonical_sha256(str(library))[:8]}_{time.time_ns()}"
    command = (
        str(args.ghidra_headless), str(args.ghidra_projects), project,
        "-import", str(library), "-scriptPath", str(ROOT / "tools/ghidra_scripts"),
        "-postScript", "KavachNativeEvidence.java", str(output), str(debug),
        canonical_sha256(config), "-analysisTimeoutPerFile", str(config["analysis_timeout_seconds"]),
    )
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=args.native_timeout)
    except subprocess.TimeoutExpired:
        return "TIMEOUT"
    return "SUCCESS" if result.returncode == 0 and output.exists() else "FAILED"


def native_action(function) -> tuple[str, str] | None:
    names = {item.lower() for item in function.calls + function.imports}
    if names & {"execve", "execv", "execvp", "execl", "system", "popen", "posix_spawn"}:
        return "PROCESS_EXECUTION", "COMMAND_EXECUTION"
    if names & {"unlink", "remove", "truncate", "reboot", "mount", "setuid", "ptrace"}:
        return "NATIVE_SYSTEM_MODIFICATION", "DEVICE_POLICY_OR_SECURITY_MODIFICATION"
    if names & {"dlopen", "android_dlopen_ext", "mprotect", "memfd_create"}:
        return "DYNAMIC_CODE_LOAD", "DYNAMIC_CODE_EXECUTION"
    return None


def manifest_from_json(value: dict) -> ManifestArtifact:
    components = tuple(ComponentContext(
        item["component_type"], item["component_name"], item.get("callback"), item.get("exported"),
        tuple(IntentFilterContext(
            tuple(rule.get("actions", ())), tuple(rule.get("categories", ())),
            tuple(tuple(tuple(pair) for pair in data) for data in rule.get("data", ())),
        ) for rule in item.get("intent_filters", ())),
    ) for item in value.get("components", ()))
    return ManifestArtifact(value["apk_sha256"], value["package_name"], tuple(value.get("permissions", ())),
                            components, value.get("min_sdk"), value.get("target_sdk"),
                            tuple(value.get("warnings", ())))


def persistence_segment(apk_hash: str, flow, provenance) -> PersistenceFlowSegment | None:
    """Recognize only the diagnosed exact-key config-helper boundary."""

    if flow.sink.category == "PERSISTENCE_STORE":
        role, endpoint = "STORE", flow.sink
    elif flow.source.category == "PERSISTENCE_LOAD":
        role, endpoint = "LOAD", flow.source
    else:
        return None
    owner_match = re.match(r"<([^:]+):", endpoint.definition)
    owner = owner_match.group(1) if owner_match else ""
    namespace = owner.rpartition(".")[0]
    keys = tuple(sorted(set(_QUOTED_JIMPLE.findall(endpoint.statement.jimple))))
    if not namespace or not keys:
        return None
    return PersistenceFlowSegment(
        apk_sha256=apk_hash, role=role, storage_kind="CONFIG_HELPER",
        namespace=namespace, constant_keys=keys, flow=flow, provenance=provenance,
    )


def analyze(record: dict, args: argparse.Namespace) -> dict:
    apk_hash = record["apk_hash"]
    apk = ROOT / record["source_path"]
    status = phase_status(apk_hash)
    validated = validate_apk(apk)
    if validated.apk_hash != apk_hash:
        raise ValueError(f"APK identity mismatch: {apk}")

    manifest_path = V2_ROOT / "manifests" / f"{apk_hash}.json"
    if not completed(status, "manifest", args.resume):
        started = time.monotonic()
        try:
            write_json_atomic(manifest_path, extract_manifest_artifact(apk))
            record_phase(status, "manifest", "SUCCESS", started, output=str(manifest_path))
        except Exception as exc:
            record_phase(status, "manifest", "FAILED", started, error=str(exc))

    config = json.loads(FLOW_CONFIG.read_text())
    action_identity = {
        "schema": "action-cache-v2", "actions_sha256": file_sha256(ACTIONS),
        "outer_timeout_seconds": args.action_timeout,
        "sidecar": _file_identity(args.sidecar_jar), "java": _file_identity(args.java),
        "android_platforms": _android_platform_identity(str(args.android_platforms)),
        "flowdroid_version": config.get("flowdroid_version", FLOWDROID_VERSION),
        "soot_version": config.get("soot_version"), "jdk_major": config.get("jdk_major"),
    }
    action_fingerprint = canonical_sha256(action_identity)
    action_path = V2_ROOT / "managed" / "actions" / action_fingerprint / f"{apk_hash}.json"
    if not completed(status, "managed_actions", args.resume, action_fingerprint):
        started = time.monotonic()
        actions_result = run_flowdroid(
            command=action_command(args), apk_path=apk, output_path=action_path,
            config={"actions": read_json(ACTIONS), "mode": "actions-only-v1"},
            timeout_seconds=args.action_timeout,
        )
        if not action_path.exists(): write_json_atomic(action_path, actions_result)
        record_phase(status, "managed_actions", actions_result.status, started, output=str(action_path),
                     action_count=len(actions_result.actions), config_sha256=action_fingerprint,
                     config_identity=action_identity,
                     diagnostic_log=str(action_path) + ".log",
                     diagnostics=str(action_path) + ".diagnostics.json")

    group_results = []
    group_fingerprints = {}
    for group_name, definitions in TAINT_GROUPS.items():
        fingerprint, config_identity = taint_group_fingerprint(
            args=args, group_name=group_name, definitions=definitions, config=config,
        )
        group_fingerprints[group_name] = fingerprint
        phase = f"managed_taint_{group_name}"
        output = V2_ROOT / "managed" / "taint" / group_name / fingerprint / f"{apk_hash}.json"
        if not completed(status, phase, args.resume, fingerprint):
            started = time.monotonic()
            result = run_flowdroid(
                command=flow_command(args, definitions), apk_path=apk, output_path=output,
                config={"flowdroid": config, "group": group_name, "definitions": definitions.read_text()},
                timeout_seconds=args.taint_group_timeout,
            )
            if not output.exists(): write_json_atomic(output, result)
            try:
                diagnostic_counts = flowdroid_output_diagnostics(output)
            except (OSError, ValueError, TypeError, json.JSONDecodeError):
                diagnostic_counts = {
                    "raw_result_count": 0, "accepted_result_count": len(result.flows),
                    "rejected_result_count": 0, "termination_state": result.status,
                }
            record_phase(status, phase, result.status, started, output=str(output),
                         flow_count=len(result.flows), config_sha256=fingerprint,
                         config_identity=config_identity, diagnostics=diagnostic_counts,
                         diagnostic_log=str(output) + ".log",
                         process_diagnostics=str(output) + ".diagnostics.json")
        cached_group = load_flowdroid_output(output)
        group_results.append(replace(
            cached_group,
            provenance=replace(cached_group.provenance, config_sha256=fingerprint),
        ))
        phase_value = status["phases"][phase]
        if "diagnostics" not in phase_value:
            try:
                phase_value["diagnostics"] = flowdroid_output_diagnostics(output)
            except (OSError, ValueError, TypeError, json.JSONDecodeError):
                phase_value["diagnostics"] = {
                    "raw_result_count": len(cached_group.flows),
                    "accepted_result_count": len(cached_group.flows),
                    "rejected_result_count": 0,
                    "termination_state": cached_group.status,
                }
            phase_value["config_identity"] = config_identity
            phase_value["diagnostic_log"] = str(output) + ".log"
            phase_value["process_diagnostics"] = str(output) + ".diagnostics.json"
            save_status(status)

    actions_result = load_flowdroid_output(action_path)
    actions_result = replace(
        actions_result,
        provenance=replace(actions_result.provenance, config_sha256=action_fingerprint),
    )
    managed = merge_managed(apk_hash, actions_result, group_results)
    all_states = [status["phases"][f"managed_taint_{name}"]["status"] for name in TAINT_GROUPS]
    action_state = status["phases"]["managed_actions"]["status"]
    aggregate_fingerprint = canonical_sha256({"actions": action_fingerprint, "groups": group_fingerprints})
    started = time.monotonic()
    aggregate_state = "SUCCESS" if action_state == "SUCCESS" and all(x == "SUCCESS" for x in all_states) else "PARTIAL"
    record_phase(status, "managed", aggregate_state, started, action_count=len(managed.actions),
                 flow_count=len(managed.flows), action_status=action_state,
                 taint_status=dict(zip(TAINT_GROUPS, all_states)), config_sha256=aggregate_fingerprint)

    native_index = V2_ROOT / "native" / "apk" / f"{apk_hash}.json"
    if not completed(status, "native", args.resume):
        started = time.monotonic()
        extracted, issues = extract_native_libraries(validated, V2_ROOT / "native" / "extracted" / apk_hash)
        # One preferred ABI/library first; content hashes provide cross-APK reuse.
        order = {"arm64-v8a": 0, "armeabi-v7a": 1, "x86_64": 2, "x86": 3, "armeabi": 4, "mips": 5}
        selected = sorted(extracted, key=lambda item: (order.get(item.abi, 99), item.archive_path))[:1]
        entries = []
        states = []
        for item in selected:
            output = V2_ROOT / "native" / "libraries" / f"{item.sha256}.json"
            debug = V2_ROOT / "native" / "debug" / item.sha256
            if output.exists():
                try:
                    state = load_ghidra_output(output).status
                except Exception:
                    state = run_ghidra_library(args, Path(item.extracted_path), output, debug)
            else:
                state = run_ghidra_library(args, Path(item.extracted_path), output, debug)
            states.append(state)
            entries.append({"library_sha256": item.sha256, "abi": item.abi,
                            "archive_path": item.archive_path, "analysis": str(output), "status": state})
        write_json_atomic(native_index, {"apk_sha256": apk_hash, "libraries": entries,
                                         "inventory_issue_count": len(issues)})
        state = "NOT_APPLICABLE" if not selected else "SUCCESS" if all(x == "SUCCESS" for x in states) else "PARTIAL"
        record_phase(status, "native", state, started, output=str(native_index), library_count=len(selected))

    behavior_path = V2_ROOT / "behavior_artifacts" / f"{apk_hash}.json"
    behavior_fingerprint = canonical_sha256({"managed": aggregate_fingerprint, "rules": "approved-taxonomy-v2-20260816"})
    modelview_fingerprint = ModelViewOptions().config_sha256
    if (not completed(status, "behavior", args.resume, behavior_fingerprint)
            or not completed(status, "modelview", args.resume, modelview_fingerprint)):
        started = time.monotonic()
        manifest = manifest_from_json(read_json(manifest_path)) if manifest_path.exists() else None
        raw = []
        rejection_reasons = Counter()
        stores, loads = [], []
        for group_name, group in zip(TAINT_GROUPS, group_results):
            for flow in group.flows:
                segment = persistence_segment(apk_hash, flow, group.provenance)
                if segment is not None:
                    (stores if segment.role == "STORE" else loads).append(segment)
                    continue
                try:
                    raw.append(build_behavior_artifact(
                        apk_sha256=apk_hash, flow=flow,
                        managed_provenance=group.provenance, manifest=manifest,
                    ))
                except ValueError as exc:
                    rejection_reasons[str(exc)] += 1
        bridges = build_exact_key_persistence_bridges(
            stores=stores, loads=loads, manifest=manifest,
        )
        raw.extend(bridges)
        for action in actions_result.actions:
            raw.append(build_action_artifact(apk_sha256=apk_hash, action=action,
                                             managed_provenance=actions_result.provenance, manifest=manifest))
        if native_index.exists():
            for entry in read_json(native_index).get("libraries", ()):
                path = Path(entry["analysis"])
                if not path.exists(): continue
                try:
                    analysis = load_ghidra_output(path)
                except Exception:
                    continue
                for function in analysis.functions:
                    classified = native_action(function)
                    if not classified: continue
                    endpoint_category, behavior_category = classified
                    statement = StatementRef(canonical_sha256((function.function_id, classified))[:24],
                                             f"<native:{function.function_id}>", function.function_id)
                    action = ManagedAction(Endpoint(function.function_id, endpoint_category, statement),
                                           behavior_category, ())
                    raw.append(build_action_artifact(
                        apk_sha256=apk_hash, action=action, managed_provenance=analysis.provenance,
                        native_context=NativeContext(True, None, (function,)),
                    ))
        collapsed = collapse_within_apk(raw)
        write_json_atomic(behavior_path, {"schema_version": "behavior-artifact-set-v2alpha1",
                                          "apk_sha256": apk_hash, "raw_occurrences": len(raw),
                                          "artifacts": [item.to_dict() for item in collapsed]})
        record_phase(status, "behavior", "SUCCESS", started, output=str(behavior_path),
                     raw_occurrences=len(raw), artifact_count=len(collapsed),
                     persistence_bridge_count=len(bridges),
                     rejection_reason_counts=dict(rejection_reasons),
                     config_sha256=behavior_fingerprint)
        started = time.monotonic()
        views = [serialize_candidate(item) for item in collapsed]
        for item in collapsed:
            write_candidate(V2_ROOT / "modelviews", item)
        phases = [PhaseCompletion(name, value["status"], value["status"] in TERMINAL)
                  for name, value in status["phases"].items() if name != "modelview"]
        write_apk_index(V2_ROOT / "modelviews", build_apk_index(
            apk_sha256=apk_hash, views=views, phases=phases,
        ))
        record_phase(status, "modelview", "SUCCESS", started, artifact_count=len(views),
                     config_sha256=modelview_fingerprint)
    return status


def main() -> None:
    try:
        from loguru import logger
        logger.remove()
    except ImportError:
        pass
    parser = argparse.ArgumentParser()
    parser.add_argument("--limit", type=int, required=True)
    parser.add_argument("--selection-manifest", type=Path, default=DEFAULT_SELECTION)
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--java", type=Path, default=Path("/opt/homebrew/opt/openjdk@17/bin/java"))
    parser.add_argument("--sidecar-jar", type=Path, default=ROOT / "tools/flowdroid-sidecar/target/flowdroid-sidecar-0.1.0.jar")
    parser.add_argument("--android-platforms", type=Path, default=Path("/opt/homebrew/share/android-commandlinetools/platforms"))
    parser.add_argument("--ghidra-headless", type=Path, default=Path("/opt/homebrew/opt/ghidra/libexec/support/analyzeHeadless"))
    parser.add_argument("--ghidra-projects", type=Path, default=Path("/private/tmp/kavach_ghidra_projects"))
    parser.add_argument("--managed-timeout", type=float, default=600)
    parser.add_argument("--action-timeout", type=float, default=180)
    parser.add_argument("--taint-group-timeout", type=float, default=180)
    parser.add_argument("--native-timeout", type=float, default=600)
    args = parser.parse_args()
    records = load_or_create_selection(args.selection_manifest, inventory())
    if args.limit < 1 or args.limit > len(records):
        raise SystemExit(f"--limit must be between 1 and {len(records)}")
    selected = records[:args.limit]
    print(json.dumps({"checkpoint": args.limit, "composition": dict(Counter(
        f"{item['label']}/{item['split']}" for item in selected))}, sort_keys=True), flush=True)
    for index, record in enumerate(selected, 1):
        print(f"[{index}/{args.limit}] {record['apk_hash']} {record['label']} {record['split']}", flush=True)
        analyze(record, args)


if __name__ == "__main__":
    main()
