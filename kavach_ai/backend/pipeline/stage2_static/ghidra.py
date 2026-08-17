"""External Ghidra E2 adapter and address-free semantic evidence parser."""

from __future__ import annotations

import json
import re
import subprocess
import time
from pathlib import Path
from typing import Any

from .v2_canonical import canonical_sha256, file_sha256
from .v2_artifacts import (
    JniMappingEvidence, NativeAnalysisArtifact, NativeContext,
    NativeFunctionEvidence, ToolIssue, ToolProvenance,
)


class GhidraOutputError(ValueError):
    pass


_VOLATILE_ADDRESS = re.compile(r"\b(?:0x)?[0-9a-fA-F]{8,16}\b")


def normalize_decompiled_code(value: str | None) -> str | None:
    if value is None:
        return None
    lines = []
    for line in value.replace("\r\n", "\n").splitlines():
        normalized = " ".join(line.strip().split())
        if normalized:
            lines.append(_VOLATILE_ADDRESS.sub("<ADDR>", normalized))
    return "\n".join(lines)


def parse_ghidra_output(value: dict[str, Any]) -> NativeAnalysisArtifact:
    if value.get("schema_version") != "ghidra-sidecar-v1":
        raise GhidraOutputError(f"unsupported Ghidra schema: {value.get('schema_version')!r}")
    functions = tuple(
        NativeFunctionEvidence(
            item["function_id"], normalize_decompiled_code(item.get("decompiled_code")),
            tuple(sorted(set(item.get("calls", ())))),
            tuple(sorted(set(item.get("imports", ())))),
            tuple(sorted(set(item.get("strings", ())))),
            item.get("raw_pcode_debug_ref"), item.get("full_analysis_debug_ref"),
        )
        for item in value.get("functions", ())
    )
    raw = value["provenance"]
    provenance = ToolProvenance(
        "Ghidra", raw["version"], raw["config_sha256"], value["library_sha256"],
        tuple(raw.get("command", ())), raw.get("runtime_seconds"), raw.get("max_rss_kb"),
    )
    return NativeAnalysisArtifact(
        value["library_sha256"], value["abi"], value["status"], functions, provenance,
        tuple(ToolIssue(**item) for item in value.get("issues", ())),
    )


def load_ghidra_output(path: str | Path) -> NativeAnalysisArtifact:
    try:
        with Path(path).open("r", encoding="utf-8") as stream:
            return parse_ghidra_output(json.load(stream))
    except (OSError, json.JSONDecodeError) as exc:
        raise GhidraOutputError(f"unable to read Ghidra output: {exc}") from exc


def run_ghidra(
    *, command: tuple[str, ...], library_path: str | Path, output_path: str | Path,
    abi: str, config: dict[str, Any], timeout_seconds: float,
) -> NativeAnalysisArtifact:
    started = time.monotonic()
    digest = file_sha256(library_path)
    provenance = lambda runtime: ToolProvenance(
        "Ghidra", str(config.get("version", "external")), canonical_sha256(config), digest,
        command, runtime, resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss,
    )
    try:
        result = subprocess.run(
            (*command, str(library_path), str(output_path)), check=False,
            capture_output=True, text=True, timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired as exc:
        return NativeAnalysisArtifact(
            digest, abi, "TIMEOUT", (), provenance(time.monotonic() - started),
            (ToolIssue("GHIDRA_PROCESS_TIMEOUT", str(exc), "native", "error"),),
        )
    if result.returncode != 0:
        message = (result.stderr or result.stdout or "Ghidra failed")[-4000:]
        return NativeAnalysisArtifact(
            digest, abi, "FAILED", (), provenance(time.monotonic() - started),
            (ToolIssue("GHIDRA_PROCESS_FAILED", message, "native", "error"),),
        )
    return load_ghidra_output(output_path)


def link_jni_evidence(
    *, managed_method: str, expected_short_symbol: str, expected_long_symbol: str,
    library_archive_path: str | None, analysis: NativeAnalysisArtifact | None,
    dynamic_registration_seen: bool = False,
) -> NativeContext:
    """Join one managed native boundary without pretending unresolved JNI was followed."""

    if analysis is None:
        mapping = JniMappingEvidence(
            managed_method, None, library_archive_path, None, "unresolved", 0.0,
            "native library analysis unavailable",
        )
        return NativeContext(True, mapping, ())
    by_name = {item.function_id: item for item in analysis.functions}
    matched = by_name.get(expected_long_symbol) or by_name.get(expected_short_symbol)
    if matched is not None:
        kind = "exact_long_name" if matched.function_id == expected_long_symbol else "exact_short_name"
        mapping = JniMappingEvidence(
            managed_method, analysis.library_sha256, library_archive_path,
            matched.function_id, kind, 1.0, None,
        )
        return NativeContext(True, mapping, (matched,))
    reason = "RegisterNatives observed but table could not be resolved" if dynamic_registration_seen else "no exported JNI symbol or resolved RegisterNatives entry"
    mapping = JniMappingEvidence(
        managed_method, analysis.library_sha256, library_archive_path, None,
        "unresolved_dynamic" if dynamic_registration_seen else "unresolved", 0.25 if dynamic_registration_seen else 0.0,
        reason,
    )
    return NativeContext(True, mapping, ())
