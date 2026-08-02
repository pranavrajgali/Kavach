"""Compact, versioned serialization for rebuildable static-analysis IR."""

from __future__ import annotations

import gzip
import json
from dataclasses import asdict, dataclass, is_dataclass
from enum import Enum
from pathlib import Path
from typing import Any

from kavach_ai.backend.pipeline.stage2_static.decompile import (
    DataPayload,
    ExceptionHandler,
    ExtractedMethod,
    ExtractionBackend,
    Instruction,
    Label,
    MethodParameter,
    NativeLibrary,
    PayloadEntry,
    PayloadKind,
)
from kavach_ai.backend.pipeline.stage2_static.jni_bridge import (
    ExportedSymbol,
    JniBridgeResult,
    LibraryLoadEvidence,
    NativeIssue,
    NativeIssueSeverity,
    NativeLibraryAnalysis,
    NativeMethodIdentity,
    NativeSignal,
    NativeSignalCategory,
    NativeToolBackend,
    recompute_cached_jni_bridges,
)


STATIC_IR_VERSION = "static-ir-v1"
EXTRACTOR_VERSION = "decompile-v1"


@dataclass(frozen=True)
class StaticIR:
    apk_hash: str
    methods: tuple[ExtractedMethod, ...]
    jni_result: JniBridgeResult
    extraction_status: str
    extraction_issues: tuple[dict[str, Any], ...]


def _jsonable(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if is_dataclass(value):
        return {key: _jsonable(item) for key, item in asdict(value).items()}
    if isinstance(value, dict):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_jsonable(item) for item in value]
    return value


def static_ir_record(
    apk_hash: str,
    methods: tuple[ExtractedMethod, ...],
    jni_result: JniBridgeResult,
    extraction_status: str,
    extraction_issues: tuple[object, ...],
) -> dict[str, Any]:
    return {
        "schema_version": STATIC_IR_VERSION,
        "extractor_version": EXTRACTOR_VERSION,
        "apk_hash": apk_hash,
        "extraction_status": extraction_status,
        "extraction_issues": [_extraction_issue_record(issue) for issue in extraction_issues],
        "methods": [_method_record(method) for method in methods],
        "jni": _jni_record(jni_result),
    }


def _extraction_issue_record(issue: object) -> dict[str, Any]:
    stage = getattr(issue, "stage", None)
    severity = getattr(issue, "severity", None)
    return {
        "stage": getattr(stage, "value", stage),
        "code": getattr(issue, "code", "UNKNOWN"),
        "message": getattr(issue, "message", str(issue)),
        "severity": getattr(severity, "value", severity),
        "dex_name": getattr(issue, "dex_name", None),
        "class_name": getattr(issue, "class_name", None),
        "method_signature": getattr(issue, "method_signature", None),
        "byte_offset": getattr(issue, "byte_offset", None),
    }


def _method_record(method: ExtractedMethod) -> dict[str, Any]:
    value = _jsonable(method)
    value.pop("source_path", None)
    value.pop("declared_source_file", None)
    for payload in value.get("payloads", ()):
        payload.pop("source_path", None)
    return value


def _jni_record(result: JniBridgeResult) -> dict[str, Any]:
    value = _jsonable(result)
    for analysis in value.get("library_analyses", ()):
        library = analysis["library"]
        analysis["library"] = {
            key: library[key]
            for key in ("filename", "abi", "archive_path", "sha256")
        }
        for symbol in analysis.get("exported_symbols", ()):
            symbol.pop("address", None)
    return value


def write_static_ir(path: Path, record: dict[str, Any]) -> None:
    with gzip.open(path, "wt", encoding="utf-8") as file:
        json.dump(record, file, sort_keys=True, separators=(",", ":"))


def _method(value: dict[str, Any]) -> ExtractedMethod:
    return ExtractedMethod(
        dex_name=value["dex_name"],
        class_name=value["class_name"],
        method_name=value["method_name"],
        descriptor=value["descriptor"],
        full_signature=value["full_signature"],
        access_flags=tuple(value["access_flags"]),
        parameters=tuple(MethodParameter(**item) for item in value["parameters"]),
        register_count=value.get("register_count"),
        local_count=value.get("local_count"),
        instructions=tuple(
            Instruction(
                item["index"], item.get("offset"), item["opcode"],
                tuple(item["operands"]), item["raw_text"],
            )
            for item in value["instructions"]
        ),
        labels=tuple(Label(**item) for item in value["labels"]),
        exception_handlers=tuple(ExceptionHandler(**item) for item in value["exception_handlers"]),
        declared_source_file=value.get("declared_source_file"),
        source_path="",
        backend=ExtractionBackend(value["backend"]),
        payloads=tuple(
            DataPayload(
                item["label"], PayloadKind(item["kind"]),
                tuple(PayloadEntry(**entry) for entry in item["entries"]),
                item["raw_text"], "", item.get("start_line"), item.get("end_line"),
                item.get("start_offset"), item.get("end_offset"),
            )
            for item in value.get("payloads", ())
        ),
    )


def _method_identity(value: dict[str, Any]) -> NativeMethodIdentity:
    return NativeMethodIdentity(value["dex_name"], value["full_signature"])


def _symbol(value: dict[str, Any]) -> ExportedSymbol:
    return ExportedSymbol(
        value["library_archive_path"], value["abi"], value["name"],
        value.get("symbol_type"), value.get("address"), NativeToolBackend(value["backend"]),
    )


def _native_issue(value: dict[str, Any]) -> NativeIssue:
    return NativeIssue(
        value["code"], value["message"], NativeIssueSeverity(value["severity"]),
        value.get("library_archive_path"),
        _method_identity(value["method"]) if value.get("method") else None,
    )


def _cached_jni(value: dict[str, Any], methods: tuple[ExtractedMethod, ...]) -> JniBridgeResult:
    loads = tuple(
        LibraryLoadEvidence(
            _method_identity(item["method"]), item["instruction_index"],
            item.get("requested_name"), tuple(item["resolved_library_archive_paths"]),
            item["dynamic_name"],
        )
        for item in value.get("load_evidence", ())
    )
    analyses: list[NativeLibraryAnalysis] = []
    for item in value.get("library_analyses", ()):
        library_value = item["library"]
        library = NativeLibrary(
            library_value["filename"], library_value["abi"], library_value["archive_path"],
            "", library_value["sha256"], library_value.get("size_bytes", 0),
        )
        signals = tuple(
            NativeSignal(
                signal["library_archive_path"], signal["abi"],
                NativeSignalCategory(signal["category"]), signal["signature"],
                signal["evidence_kind"], signal["occurrence_count"],
            )
            for signal in item.get("sensitive_signals", ())
        )
        analyses.append(
            NativeLibraryAnalysis(
                library,
                NativeToolBackend(item["backend"]),
                tuple(_symbol(symbol) for symbol in item.get("exported_symbols", ())),
                signals,
                tuple(_native_issue(issue) for issue in item.get("issues", ())),
            )
        )
    return recompute_cached_jni_bridges(methods, loads, analyses)


def read_static_ir(path: Path) -> StaticIR:
    with gzip.open(path, "rt", encoding="utf-8") as file:
        value = json.load(file)
    if value.get("schema_version") != STATIC_IR_VERSION:
        raise ValueError(f"Unsupported static IR schema: {value.get('schema_version')!r}")
    if value.get("extractor_version") != EXTRACTOR_VERSION:
        raise ValueError(f"Unsupported extractor version: {value.get('extractor_version')!r}")
    methods = tuple(_method(item) for item in value["methods"])
    return StaticIR(
        value["apk_hash"], methods, _cached_jni(value.get("jni", {}), methods),
        value["extraction_status"], tuple(value.get("extraction_issues", ())),
    )


__all__ = [
    "STATIC_IR_VERSION",
    "EXTRACTOR_VERSION",
    "StaticIR",
    "read_static_ir",
    "static_ir_record",
    "write_static_ir",
]
