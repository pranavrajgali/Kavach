"""Versioned, deterministic serialization of structured program slices."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Iterable, Mapping

from kavach_ai.backend.pipeline.stage2_static.decompile import ExtractedMethod
from kavach_ai.backend.pipeline.stage3_ml.slicing import (
    MethodIdentity,
    ProgramSlice,
    UnresolvedBoundary,
)


NORMALIZATION_VERSION = "structural-v1"
NORMALIZATION_CONFIG = {
    "local_registers": "first_appearance_per_full_method",
    "parameter_registers": "preserved",
    "labels": "first_appearance_per_full_method",
    "quoted_literals": "preserved",
    "method_marker": "[METHOD] <full_signature>",
    "boundary_marker": "[BOUNDARY] kind=<kind> target=<signature-or-NONE>",
}
_TOKEN_PATTERN = re.compile(r"(?<![A-Za-z0-9_$])(?:v\d+|:[A-Za-z0-9_$.-]+)(?![A-Za-z0-9_$])")


@dataclass(frozen=True)
class SliceText:
    raw_slice_text: str
    normalized_slice_text: str
    normalization_version: str = NORMALIZATION_VERSION


def canonical_sink_identity(apk_hash: str, program_slice: ProgramSlice) -> dict[str, object]:
    sink = program_slice.sink
    return {
        "apk_hash": apk_hash,
        "rule_id": sink.rule_id,
        "dex_name": sink.method.dex_name,
        "source_method": sink.method.full_signature,
        "instruction_index": sink.instruction_index,
        "invoked_signature": sink.invoked_signature,
    }


def stable_example_id(apk_hash: str, program_slice: ProgramSlice) -> str:
    identity = canonical_sink_identity(apk_hash, program_slice)
    encoded = json.dumps(identity, sort_keys=True, separators=(",", ":")).encode()
    return f"{apk_hash}:{hashlib.sha256(encoded).hexdigest()}"


def register_example_identity(
    identities: dict[str, dict[str, object]],
    example_id: str,
    identity: dict[str, object],
) -> None:
    existing = identities.get(example_id)
    if existing is not None:
        raise ValueError(
            "Duplicate example_id encountered; conflicting canonical sink identities: "
            f"first={existing!r}, second={identity!r}"
        )
    identities[example_id] = identity


def _outside_quotes(text: str) -> Iterable[tuple[bool, str]]:
    start = 0
    quoted = False
    escaped = False
    for index, character in enumerate(text):
        if escaped:
            escaped = False
            continue
        if quoted and character == "\\":
            escaped = True
            continue
        if character == '"':
            if index > start:
                yield quoted, text[start:index]
            yield True, character
            quoted = not quoted
            start = index + 1
    if start < len(text):
        yield quoted, text[start:]


def _tokens_outside_quotes(text: str) -> Iterable[str]:
    for quoted, section in _outside_quotes(text):
        if not quoted:
            yield from (match.group(0) for match in _TOKEN_PATTERN.finditer(section))


def _method_maps(method: ExtractedMethod) -> tuple[dict[str, str], dict[str, str]]:
    registers: dict[str, str] = {}
    labels: dict[str, str] = {}
    for instruction in method.instructions:
        for token in _tokens_outside_quotes(instruction.raw_text):
            if token.startswith("v") and token not in registers:
                registers[token] = f"v{len(registers)}"
            elif token.startswith(":") and token not in labels:
                labels[token] = f":label_{len(labels)}"
    for label in method.labels:
        if label.name not in labels:
            labels[label.name] = f":label_{len(labels)}"
    for payload in method.payloads:
        if payload.label not in labels:
            labels[payload.label] = f":label_{len(labels)}"
        for entry in payload.entries:
            if entry.target_label and entry.target_label not in labels:
                labels[entry.target_label] = f":label_{len(labels)}"
    return registers, labels


def build_method_normalization_maps(
    methods: Iterable[ExtractedMethod],
) -> dict[MethodIdentity, tuple[dict[str, str], dict[str, str]]]:
    """Build deterministic full-method mappings once for all slices in an APK."""

    return {
        MethodIdentity(method.dex_name, method.full_signature): _method_maps(method)
        for method in methods
    }


def _replace_tokens(text: str, replacements: Mapping[str, str]) -> str:
    sections: list[str] = []
    for quoted, section in _outside_quotes(text):
        if quoted:
            sections.append(section)
        else:
            sections.append(_TOKEN_PATTERN.sub(lambda match: replacements.get(match.group(0), match.group(0)), section))
    return "".join(sections)


def _normalize_instruction(raw_text: str, replacements: Mapping[str, str]) -> str:
    normalized = _replace_tokens(raw_text.strip(), replacements)
    sections: list[str] = []
    for quoted, section in _outside_quotes(normalized):
        if quoted:
            sections.append(section)
        else:
            section = re.sub(r"\s+", " ", section)
            section = re.sub(r",\s*", ", ", section)
            sections.append(section)
    return "".join(sections).strip()


def _boundary_line(boundary: UnresolvedBoundary) -> str:
    return f"[BOUNDARY] kind={boundary.kind.value} target={boundary.target_signature or 'NONE'}"


def serialize_program_slice(
    program_slice: ProgramSlice,
    methods: Iterable[ExtractedMethod],
    *,
    method_maps: Mapping[
        MethodIdentity, tuple[Mapping[str, str], Mapping[str, str]]
    ] | None = None,
) -> SliceText:
    """Return unchanged raw text and structural-v1 normalized model text."""

    method_index = {
        MethodIdentity(method.dex_name, method.full_signature): method for method in methods
    }
    maps = method_maps or {
        identity: _method_maps(method) for identity, method in method_index.items()
    }
    raw_lines = [item.instruction.raw_text for item in program_slice.retained_instructions]
    boundaries: dict[tuple[MethodIdentity, int], list[UnresolvedBoundary]] = {}
    for boundary in program_slice.unresolved_boundaries:
        boundaries.setdefault((boundary.method, boundary.instruction_index), []).append(boundary)

    normalized_lines: list[str] = []
    active_method: MethodIdentity | None = None
    for retained in program_slice.retained_instructions:
        if retained.method != active_method:
            normalized_lines.append(f"[METHOD] {retained.method.full_signature}")
            active_method = retained.method
        register_map, label_map = maps.get(retained.method, ({}, {}))
        normalized_lines.append(
            _normalize_instruction(
                retained.instruction.raw_text,
                {**register_map, **label_map},
            )
        )
        for boundary in sorted(
            boundaries.pop((retained.method, retained.instruction_index), ()),
            key=lambda item: (item.kind.value, item.target_signature or ""),
        ):
            normalized_lines.append(_boundary_line(boundary))

    # Preserve boundary evidence even if its source instruction was not retained.
    for key in sorted(boundaries, key=lambda item: (item[0], item[1])):
        for boundary in sorted(
            boundaries[key], key=lambda item: (item.kind.value, item.target_signature or "")
        ):
            normalized_lines.append(_boundary_line(boundary))

    return SliceText("\n".join(raw_lines), "\n".join(normalized_lines))


__all__ = [
    "build_method_normalization_maps",
    "NORMALIZATION_VERSION",
    "NORMALIZATION_CONFIG",
    "SliceText",
    "canonical_sink_identity",
    "register_example_identity",
    "serialize_program_slice",
    "stable_example_id",
]
