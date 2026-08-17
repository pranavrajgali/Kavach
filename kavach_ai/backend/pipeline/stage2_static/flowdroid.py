"""External FlowDroid process adapter and stable JSON parser."""

from __future__ import annotations

import json
import subprocess
import time
from pathlib import Path
from typing import Any

from .v2_canonical import canonical_sha256, file_sha256
from .v2_artifacts import (
    ComponentContext, ControlPredicate, Endpoint, ManagedAction, ManagedAnalysisArtifact,
    ManagedFlow, StatementRef, ToolIssue, ToolProvenance,
)


FLOWDROID_VERSION = "2.15.1"


class FlowDroidOutputError(ValueError):
    pass


def _statement(value: dict[str, Any]) -> StatementRef:
    required = ("statement_id", "method_signature", "jimple")
    if any(not isinstance(value.get(key), str) or not value[key] for key in required):
        raise FlowDroidOutputError("statement lacks a stable id, method signature, or Jimple text")
    return StatementRef(
        value["statement_id"], value["method_signature"], value["jimple"],
        value.get("dex_offset"), value.get("line_number"), tuple(value.get("tags", ())),
        tuple(value.get("exception_context", ())), value.get("monitor_context"),
        value.get("smali_debug_ref"),
    )


def _component(value: dict[str, Any] | None) -> ComponentContext | None:
    if not value:
        return None
    return ComponentContext(
        value["component_type"], value["component_name"], value.get("callback"),
        value.get("exported"), (),
    )


def parse_flowdroid_output(value: dict[str, Any]) -> ManagedAnalysisArtifact:
    if value.get("schema_version") == "managed-flow-v2alpha1":
        raw = value["provenance"]
        return ManagedAnalysisArtifact(
            value["apk_sha256"], value["status"], (),
            ToolProvenance(raw["tool"], raw["version"], raw["config_sha256"], raw["input_sha256"],
                           tuple(raw.get("command", ())), raw.get("runtime_seconds"), raw.get("max_rss_kb")),
            tuple(ToolIssue(**item) for item in value.get("issues", ())), actions=(),
        )
    if value.get("schema_version") != "flowdroid-sidecar-v1":
        raise FlowDroidOutputError(f"unsupported FlowDroid sidecar schema: {value.get('schema_version')!r}")
    flows: list[ManagedFlow] = []
    for raw in value.get("flows", ()):
        statements = tuple(_statement(item) for item in raw.get("statements", ()))
        by_id = {item.statement_id: item for item in statements}
        if len(by_id) != len(statements):
            raise FlowDroidOutputError("duplicate statement_id in flow")
        try:
            source_statement = by_id[raw["source"]["statement_id"]]
            sink_statement = by_id[raw["sink"]["statement_id"]]
        except (KeyError, TypeError) as exc:
            raise FlowDroidOutputError("source/sink statement is absent from reconstructed path") from exc
        controls = []
        for control in raw.get("controls", ()):
            predicate = _statement(control["predicate"])
            controlled = tuple(control.get("controls_statement_ids", ()))
            if any(item not in by_id for item in controlled):
                raise FlowDroidOutputError("control predicate references an unknown flow statement")
            controls.append(
                ControlPredicate(
                    predicate, controlled,
                    tuple(_statement(item) for item in control.get("operand_definitions", ())),
                )
            )
        source = Endpoint(
            raw["source"]["definition"], raw["source"]["category"], source_statement,
            raw["source"].get("access_path"),
        )
        sink = Endpoint(
            raw["sink"]["definition"], raw["sink"]["category"], sink_statement,
            raw["sink"].get("access_path"),
        )
        flows.append(
            ManagedFlow(
                source, sink, statements, tuple(controls), _component(raw.get("component")),
                tuple(_statement(item) for item in raw.get("call_sites", ())),
                bool(raw.get("complete", True)), tuple(raw.get("unresolved_calls", ())),
            )
        )
    actions: list[ManagedAction] = []
    for raw in value.get("actions", ()):
        endpoint_raw = raw["endpoint"]
        endpoint_statement = _statement(endpoint_raw["statement"])
        endpoint = Endpoint(
            endpoint_raw["definition"], endpoint_raw["category"], endpoint_statement,
            endpoint_raw.get("access_path"),
        )
        controls = tuple(
            ControlPredicate(
                _statement(item["predicate"]), tuple(item.get("controls_statement_ids", ())),
                tuple(_statement(value) for value in item.get("operand_definitions", ())),
            ) for item in raw.get("controls", ())
        )
        actions.append(ManagedAction(
            endpoint, raw["behavior_category"],
            tuple(_statement(item) for item in raw.get("argument_dependencies", ())),
            controls, _component(raw.get("component")), bool(raw.get("complete", True)),
            tuple(raw.get("unresolved_calls", ())),
        ))
    provenance_raw = value["provenance"]
    provenance = ToolProvenance(
        "FlowDroid", provenance_raw["version"], provenance_raw["config_sha256"],
        value["apk_sha256"], tuple(provenance_raw.get("command", ())),
        provenance_raw.get("runtime_seconds"), provenance_raw.get("max_rss_kb"),
    )
    return ManagedAnalysisArtifact(
        value["apk_sha256"], value["status"], tuple(flows), provenance,
        tuple(ToolIssue(**item) for item in value.get("issues", ())), actions=tuple(actions),
    )


def load_flowdroid_output(path: str | Path) -> ManagedAnalysisArtifact:
    try:
        with Path(path).open("r", encoding="utf-8") as stream:
            value = json.load(stream)
    except (OSError, json.JSONDecodeError) as exc:
        raise FlowDroidOutputError(f"unable to read FlowDroid output: {exc}") from exc
    return parse_flowdroid_output(value)


def flowdroid_output_diagnostics(path: str | Path) -> dict[str, Any]:
    """Return stable, status-friendly diagnostics from either sidecar schema.

    Newer sidecars may provide detailed filtering counters.  Older cached output
    remains readable and gets conservative counters derived from its payload.
    """

    value = json.loads(Path(path).read_text(encoding="utf-8"))
    diagnostic = dict(value.get("diagnostics") or {})
    raw_count = diagnostic.get("raw_result_count", value.get("raw_result_count"))
    accepted = diagnostic.get("accepted_result_count", len(value.get("flows", ())))
    rejected = diagnostic.get("rejected_result_count")
    if raw_count is None:
        raw_count = accepted + (rejected or 0)
    if rejected is None:
        rejected = max(0, raw_count - accepted)
    return {
        "raw_result_count": int(raw_count),
        "accepted_result_count": int(accepted),
        "rejected_result_count": int(rejected),
        "rejection_reason_counts": dict(diagnostic.get("rejection_reason_counts") or {}),
        "path_null_count": int(diagnostic.get("path_null_count", 0)),
        "path_reconstruction_failure_count": int(
            diagnostic.get("path_reconstruction_failure_count", 0)
        ),
        "source_occurrence_counts": dict(diagnostic.get("source_occurrence_counts") or {}),
        "sink_occurrence_counts": dict(diagnostic.get("sink_occurrence_counts") or {}),
        "termination_state": diagnostic.get("termination_state", value.get("status", "UNKNOWN")),
        "performance": dict(diagnostic.get("performance") or {}),
    }


def _diagnostic_paths(output_path: str | Path) -> tuple[Path, Path]:
    output = Path(output_path)
    return Path(f"{output}.log"), Path(f"{output}.diagnostics.json")


def _persist_process_diagnostics(
    output_path: str | Path, *, command: tuple[str, ...], status: str,
    runtime_seconds: float, stdout: str | None, stderr: str | None,
    returncode: int | None, timeout_seconds: float,
) -> tuple[Path, Path]:
    log_path, diagnostic_path = _diagnostic_paths(output_path)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_path.write_text(
        "[stdout]\n" + (stdout or "") + "\n[stderr]\n" + (stderr or ""),
        encoding="utf-8",
    )
    payload = {
        "schema_version": "flowdroid-process-diagnostics-v1",
        "status": status,
        "termination_state": status,
        "runtime_seconds": runtime_seconds,
        "timeout_seconds": timeout_seconds,
        "returncode": returncode,
        "command": list(command),
        "log_ref": str(log_path),
    }
    if Path(output_path).exists():
        try:
            payload["sidecar"] = flowdroid_output_diagnostics(output_path)
        except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
            payload["sidecar_diagnostics_error"] = str(exc)
    diagnostic_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return log_path, diagnostic_path


def _get_ru_maxrss() -> int:
    try:
        import resource
        return resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
    except Exception:
        return 0


def run_flowdroid(
    *, command: tuple[str, ...], apk_path: str | Path, output_path: str | Path,
    config: dict[str, Any], timeout_seconds: float,
) -> ManagedAnalysisArtifact:
    """Run an external pinned sidecar; no FlowDroid binary is vendored."""

    started = time.monotonic()
    rss_before = _get_ru_maxrss()
    try:
        result = subprocess.run(
            (*command, "--apk", str(apk_path), "--output", str(output_path)),
            check=False, capture_output=True, text=True, timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired as exc:
        runtime = time.monotonic() - started
        log_path, diagnostic_path = _persist_process_diagnostics(
            output_path, command=command, status="TIMEOUT", runtime_seconds=runtime,
            stdout=exc.stdout.decode(errors="replace") if isinstance(exc.stdout, bytes) else exc.stdout,
            stderr=exc.stderr.decode(errors="replace") if isinstance(exc.stderr, bytes) else exc.stderr,
            returncode=None, timeout_seconds=timeout_seconds,
        )
        provenance = ToolProvenance(
            "FlowDroid", FLOWDROID_VERSION, canonical_sha256(config), file_sha256(apk_path),
            command, runtime,
            _get_ru_maxrss() - rss_before,
        )
        return ManagedAnalysisArtifact(
            provenance.input_sha256, "TIMEOUT", (), provenance,
            (ToolIssue("FLOWDROID_PROCESS_TIMEOUT", f"{exc}; diagnostics={diagnostic_path}; log={log_path}", "managed", "error"),),
        )
    runtime = time.monotonic() - started
    combined_log = (result.stderr or "") + "\n" + (result.stdout or "")
    process_state = (
        "SUCCESS" if result.returncode == 0 else
        "OOM" if result.returncode in {-9, 137} or "OutOfMemoryError" in combined_log else
        "FAILED"
    )
    log_path, diagnostic_path = _persist_process_diagnostics(
        output_path, command=command, status=process_state,
        runtime_seconds=runtime, stdout=result.stdout, stderr=result.stderr,
        returncode=result.returncode, timeout_seconds=timeout_seconds,
    )
    if result.returncode != 0:
        provenance = ToolProvenance(
            "FlowDroid", FLOWDROID_VERSION, canonical_sha256(config), file_sha256(apk_path),
            command, runtime,
            _get_ru_maxrss() - rss_before,
        )
        message = (result.stderr or result.stdout or "FlowDroid failed")[-4000:]
        issue_code = "FLOWDROID_PROCESS_OOM" if process_state == "OOM" else "FLOWDROID_PROCESS_FAILED"
        return ManagedAnalysisArtifact(
            provenance.input_sha256, process_state, (), provenance,
            (ToolIssue(issue_code, f"{message}; diagnostics={diagnostic_path}; log={log_path}", "managed", "error"),),
        )
    return load_flowdroid_output(output_path)
