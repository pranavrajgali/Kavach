"""Bounded, deterministic JNI and native-library static analysis.

The stage consumes structured extraction output only.  It never reopens an APK,
executes native code, disassembles instructions, or assigns an APK verdict.
String and symbol matches are evidence for later stages, not proof of malicious
behaviour.
"""

from __future__ import annotations

import hashlib
import io
import json
import re
import shutil
import stat
import subprocess
from collections import Counter, defaultdict
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from types import MappingProxyType
from typing import Iterable, Mapping, Sequence

from kavach_ai.backend.pipeline.stage2_static.decompile import (
    ExtractedMethod,
    ExtractionResult,
    Instruction,
    NativeLibrary,
)


class NativeIssueSeverity(str, Enum):
    WARNING = "warning"
    ERROR = "error"


class NativeAnalysisStatus(str, Enum):
    SUCCESS = "SUCCESS"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class NativeToolBackend(str, Enum):
    LLVM_NM = "llvm-nm"
    NM = "nm"
    READELF = "readelf"
    PYTHON_ELF = "python_elf"
    NONE = "none"


class JniMappingKind(str, Enum):
    EXACT_SHORT_NAME = "exact_short_name"
    EXACT_LONG_NAME = "exact_long_name"
    AMBIGUOUS_OVERLOAD = "ambiguous_overload"
    UNRESOLVED = "unresolved"


class NativeSignalCategory(str, Enum):
    PROCESS_EXECUTION = "process_execution"
    NETWORK = "network"
    FILESYSTEM = "filesystem"
    DYNAMIC_LOADING = "dynamic_loading"
    ANTI_ANALYSIS = "anti_analysis"
    CRYPTOGRAPHY = "cryptography"
    PRIVILEGE_SYSTEM = "privilege_system"


@dataclass(frozen=True, order=True)
class NativeMethodIdentity:
    dex_name: str
    full_signature: str


@dataclass(frozen=True, order=True)
class ExportedSymbol:
    library_archive_path: str
    abi: str
    name: str
    symbol_type: str | None
    address: str | None
    backend: NativeToolBackend


@dataclass(frozen=True, order=True)
class LibraryLoadEvidence:
    method: NativeMethodIdentity
    instruction_index: int
    requested_name: str | None
    resolved_library_archive_paths: tuple[str, ...]
    dynamic_name: bool


@dataclass(frozen=True, order=True)
class JniMapping:
    method: NativeMethodIdentity
    expected_short_symbol: str
    expected_long_symbol: str
    matched_symbols: tuple[ExportedSymbol, ...]
    matched_libraries: tuple[str, ...]
    mapping_kind: JniMappingKind
    confidence: float


@dataclass(frozen=True, order=True)
class NativeSignal:
    library_archive_path: str
    abi: str
    category: NativeSignalCategory
    signature: str
    evidence_kind: str
    occurrence_count: int


@dataclass(frozen=True)
class NativeIssue:
    code: str
    message: str
    severity: NativeIssueSeverity
    library_archive_path: str | None = None
    method: NativeMethodIdentity | None = None


@dataclass(frozen=True)
class NativeLibraryAnalysis:
    library: NativeLibrary
    backend: NativeToolBackend
    exported_symbols: tuple[ExportedSymbol, ...]
    sensitive_signals: tuple[NativeSignal, ...]
    issues: tuple[NativeIssue, ...]


@dataclass(frozen=True)
class JniBridgeMetrics:
    native_declarations: int
    libraries_scanned: int
    symbols_recovered: int
    exact_mappings: int
    ambiguous_mappings: int
    unresolved_native_methods: int
    sensitive_signals: int


@dataclass(frozen=True)
class JniBridgeResult:
    status: NativeAnalysisStatus
    native_methods: tuple[NativeMethodIdentity, ...]
    load_evidence: tuple[LibraryLoadEvidence, ...]
    library_analyses: tuple[NativeLibraryAnalysis, ...]
    mappings: tuple[JniMapping, ...]
    metrics: JniBridgeMetrics
    issues: tuple[NativeIssue, ...]


NATIVE_SIGNAL_SIGNATURES: Mapping[
    NativeSignalCategory, tuple[str, ...]
] = MappingProxyType(
    {
        NativeSignalCategory.PROCESS_EXECUTION: (
            "execl",
            "execve",
            "execvp",
            "fork",
            "popen",
            "system",
        ),
        NativeSignalCategory.NETWORK: (
            "SSL_read",
            "SSL_write",
            "connect",
            "getaddrinfo",
            "inet_addr",
            "recv",
            "send",
            "socket",
        ),
        NativeSignalCategory.FILESYSTEM: (
            "chmod",
            "open",
            "openat",
            "read",
            "unlink",
            "write",
        ),
        NativeSignalCategory.DYNAMIC_LOADING: (
            "JNI_OnLoad",
            "RegisterNatives",
            "System.loadLibrary",
            "android_dlopen_ext",
            "dlopen",
            "dlsym",
        ),
        NativeSignalCategory.ANTI_ANALYSIS: (
            "/proc/self/maps",
            "TracerPid",
            "frida",
            "gum-js-loop",
            "ptrace",
        ),
        NativeSignalCategory.PRIVILEGE_SYSTEM: (
            "mount",
            "setgid",
            "setuid",
            "su",
        ),
        NativeSignalCategory.CRYPTOGRAPHY: (
            "AES",
            "EVP_Decrypt",
            "EVP_Encrypt",
            "RSA",
        ),
    }
)

_LOAD_LIBRARY_SIGNATURE = (
    "Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V"
)
_LOAD_SIGNATURE = "Ljava/lang/System;->load(Ljava/lang/String;)V"
_METHOD_REFERENCE_PATTERN = re.compile(
    r"(L[^;\s]+;->[^\s(]+\([^)]*\)(?:V|[ZBSCIJFD]|L[^;]+;|"
    r"\[+(?:[ZBSCIJFD]|L[^;]+;)))"
)
_REGISTER_PATTERN = re.compile(r"\b[vp]\d+\b")
_NM_TYPE_PATTERN = re.compile(r"^[A-Za-z?]$")
_GENERIC_SIGNATURES = frozenset({"open", "read", "write", "send", "recv"})


@dataclass(frozen=True)
class _LibraryOutcome:
    analysis: NativeLibraryAnalysis
    validation_succeeded: bool
    symbol_succeeded: bool
    scan_succeeded: bool


def _method_identity(method: ExtractedMethod) -> NativeMethodIdentity:
    return NativeMethodIdentity(method.dex_name, method.full_signature)


def _issue_key(issue: NativeIssue) -> tuple[object, ...]:
    return (
        issue.code,
        issue.library_archive_path or "",
        issue.method or NativeMethodIdentity("", ""),
        issue.message,
        issue.severity.value,
    )


def _library_key(library: NativeLibrary) -> tuple[str, str, str]:
    return library.archive_path, library.abi, library.filename


def _jni_encode(value: str) -> str:
    encoded: list[str] = []
    for character in value:
        if character == "/":
            encoded.append("_")
        elif character == "_":
            encoded.append("_1")
        elif character == ";":
            encoded.append("_2")
        elif character == "[":
            encoded.append("_3")
        elif character.isascii() and character.isalnum():
            encoded.append(character)
        else:
            units = character.encode("utf-16-be")
            encoded.extend(
                f"_0{int.from_bytes(units[index:index + 2], 'big'):04X}"
                for index in range(0, len(units), 2)
            )
    return "".join(encoded)


def _validate_method_for_encoding(method: ExtractedMethod) -> str:
    if (
        not method.class_name.startswith("L")
        or not method.class_name.endswith(";")
        or len(method.class_name) <= 2
    ):
        raise ValueError(f"Invalid JNI class descriptor: {method.class_name}")
    if not method.method_name or method.method_name.startswith("<"):
        raise ValueError(f"Invalid JNI native method name: {method.method_name}")
    descriptor = method.descriptor
    if not descriptor.startswith("(") or ")" not in descriptor:
        raise ValueError(f"Invalid JNI method descriptor: {descriptor}")
    closing = descriptor.index(")")
    parameters = descriptor[1:closing]
    return_type = descriptor[closing + 1 :]
    if not _valid_descriptor_sequence(parameters, allow_void=False):
        raise ValueError(f"Invalid JNI parameter descriptor: {descriptor}")
    if not _valid_descriptor_sequence(
        return_type, allow_void=True, require_single=True
    ):
        raise ValueError(f"JNI descriptor has no return type: {descriptor}")
    return parameters


def _valid_descriptor_sequence(
    value: str,
    *,
    allow_void: bool,
    require_single: bool = False,
) -> bool:
    if not value:
        return not require_single
    position = 0
    count = 0
    while position < len(value):
        start = position
        while position < len(value) and value[position] == "[":
            position += 1
        if position >= len(value):
            return False
        kind = value[position]
        if kind == "L":
            terminator = value.find(";", position)
            if terminator < 0 or terminator == position + 1:
                return False
            position = terminator + 1
        elif kind in "ZBSCIJFD":
            position += 1
        elif kind == "V" and allow_void and position == start:
            position += 1
        else:
            return False
        count += 1
        if require_single and count > 1:
            return False
    return count == 1 if require_single else True


def encode_jni_short_name(method: ExtractedMethod) -> str:
    """Return the standard short JNI export name for a native declaration."""

    _validate_method_for_encoding(method)
    class_name = method.class_name[1:-1]
    return f"Java_{_jni_encode(class_name)}_{_jni_encode(method.method_name)}"


def encode_jni_long_name(method: ExtractedMethod) -> str:
    """Return the parameter-qualified long JNI export name."""

    parameters = _validate_method_for_encoding(method)
    return f"{encode_jni_short_name(method)}__{_jni_encode(parameters)}"


def _read_validated_library(
    library: NativeLibrary,
) -> tuple[bytes | None, NativeIssue | None]:
    path = Path(library.extracted_path)
    try:
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode):
            raise OSError("library path is a symlink")
        if not stat.S_ISREG(metadata.st_mode):
            raise OSError("library path is not a regular file")
        if metadata.st_size != library.size_bytes:
            raise OSError(
                f"size mismatch: expected {library.size_bytes}, got {metadata.st_size}"
            )
        data = path.read_bytes()
        digest = hashlib.sha256(data).hexdigest()
        if digest != library.sha256:
            raise OSError(
                f"SHA-256 mismatch: expected {library.sha256}, got {digest}"
            )
    except (OSError, ValueError) as exc:
        return None, NativeIssue(
            code="NATIVE_LIBRARY_VALIDATION_FAILED",
            message=f"Native library validation failed: {exc}",
            severity=NativeIssueSeverity.ERROR,
            library_archive_path=library.archive_path,
        )
    return data, None


def _parse_nm_output(
    output: str,
    library: NativeLibrary,
    backend: NativeToolBackend,
) -> tuple[tuple[ExportedSymbol, ...], bool]:
    symbols: set[ExportedSymbol] = set()
    malformed = False
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) < 2:
            malformed = True
            continue
        name = parts[0]
        symbol_type = parts[1] if _NM_TYPE_PATTERN.fullmatch(parts[1]) else None
        if symbol_type is None:
            malformed = True
            continue
        if symbol_type.upper() == "U":
            continue
        address = parts[2] if len(parts) >= 3 and _looks_hex(parts[2]) else None
        symbols.add(
            ExportedSymbol(
                library.archive_path,
                library.abi,
                name,
                symbol_type,
                address,
                backend,
            )
        )
    return tuple(sorted(symbols)), malformed


def _parse_readelf_output(
    output: str,
    library: NativeLibrary,
) -> tuple[tuple[ExportedSymbol, ...], bool]:
    symbols: set[ExportedSymbol] = set()
    saw_candidate = False
    malformed = False
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not re.match(r"^\d+:", line):
            continue
        saw_candidate = True
        parts = line.split(maxsplit=7)
        if len(parts) < 8:
            malformed = True
            continue
        _, value, _, symbol_type, binding, visibility, section, name = parts
        if (
            binding not in {"GLOBAL", "WEAK"}
            or section == "UND"
            or visibility not in {"DEFAULT", "PROTECTED"}
            or not name
        ):
            continue
        symbols.add(
            ExportedSymbol(
                library.archive_path,
                library.abi,
                name.split("@", 1)[0],
                symbol_type,
                value if _looks_hex(value) else None,
                NativeToolBackend.READELF,
            )
        )
    if output.strip() and not saw_candidate and "Symbol table" not in output:
        malformed = True
    return tuple(sorted(symbols)), malformed


def _looks_hex(value: str) -> bool:
    try:
        int(value, 16)
    except ValueError:
        return False
    return True


def _symbol_command(
    executable: str,
    backend: NativeToolBackend,
    library: NativeLibrary,
) -> tuple[str, ...]:
    if backend in {NativeToolBackend.LLVM_NM, NativeToolBackend.NM}:
        return (
            executable,
            "--dynamic",
            "--defined-only",
            "--extern-only",
            "--format=posix",
            library.extracted_path,
        )
    return (executable, "--dyn-syms", "--wide", library.extracted_path)


def _extract_python_symbols(
    library: NativeLibrary,
    data: bytes,
) -> tuple[tuple[ExportedSymbol, ...], bool, str | None]:
    try:
        from elftools.elf.elffile import ELFFile
    except ImportError:
        return (), False, "pyelftools is not installed"
    try:
        elf = ELFFile(io.BytesIO(data))
        section = elf.get_section_by_name(".dynsym")
        if section is None:
            return (), True, None
        symbols: set[ExportedSymbol] = set()
        for symbol in section.iter_symbols():
            binding = symbol.entry["st_info"]["bind"]
            visibility = symbol.entry["st_other"]["visibility"]
            section_index = symbol.entry["st_shndx"]
            if (
                binding not in {"STB_GLOBAL", "STB_WEAK"}
                or visibility not in {"STV_DEFAULT", "STV_PROTECTED"}
                or section_index == "SHN_UNDEF"
                or not symbol.name
            ):
                continue
            symbols.add(
                ExportedSymbol(
                    library.archive_path,
                    library.abi,
                    symbol.name,
                    symbol.entry["st_info"]["type"],
                    f"{int(symbol.entry['st_value']):x}",
                    NativeToolBackend.PYTHON_ELF,
                )
            )
        return tuple(sorted(symbols)), True, None
    except Exception as exc:
        return (), False, str(exc)


def _extract_symbols_from_validated(
    library: NativeLibrary,
    data: bytes,
    *,
    timeout: float,
) -> tuple[
    tuple[ExportedSymbol, ...],
    NativeToolBackend,
    tuple[NativeIssue, ...],
    bool,
]:
    issues: list[NativeIssue] = []
    candidates = (
        ("llvm-nm", NativeToolBackend.LLVM_NM),
        ("nm", NativeToolBackend.NM),
        ("readelf", NativeToolBackend.READELF),
    )
    for tool_name, backend in candidates:
        executable = shutil.which(tool_name)
        if executable is None:
            issues.append(
                NativeIssue(
                    "NATIVE_SYMBOL_TOOL_MISSING",
                    f"{tool_name} is not installed; trying the next backend.",
                    NativeIssueSeverity.WARNING,
                    library.archive_path,
                )
            )
            continue
        command = _symbol_command(executable, backend, library)
        try:
            completed = subprocess.run(
                command,
                check=False,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            issues.append(
                NativeIssue(
                    "NATIVE_SYMBOL_TOOL_TIMEOUT",
                    f"{tool_name} exceeded the {timeout:g}s timeout.",
                    NativeIssueSeverity.WARNING,
                    library.archive_path,
                )
            )
            continue
        except OSError as exc:
            issues.append(
                NativeIssue(
                    "NATIVE_SYMBOL_TOOL_PROCESS_ERROR",
                    f"{tool_name} could not run: {exc}",
                    NativeIssueSeverity.WARNING,
                    library.archive_path,
                )
            )
            continue
        if completed.returncode != 0:
            issues.append(
                NativeIssue(
                    "NATIVE_SYMBOL_TOOL_NONZERO_EXIT",
                    (
                        f"{tool_name} exited with {completed.returncode}: "
                        f"{completed.stderr.strip()}"
                    ),
                    NativeIssueSeverity.WARNING,
                    library.archive_path,
                )
            )
            continue
        if backend in {NativeToolBackend.LLVM_NM, NativeToolBackend.NM}:
            symbols, malformed = _parse_nm_output(
                completed.stdout, library, backend
            )
        else:
            symbols, malformed = _parse_readelf_output(
                completed.stdout, library
            )
        if malformed:
            issues.append(
                NativeIssue(
                    "NATIVE_SYMBOL_OUTPUT_MALFORMED",
                    f"{tool_name} produced malformed symbol output.",
                    NativeIssueSeverity.WARNING,
                    library.archive_path,
                )
            )
            continue
        return symbols, backend, tuple(sorted(issues, key=_issue_key)), True

    symbols, succeeded, error = _extract_python_symbols(library, data)
    if succeeded:
        return (
            symbols,
            NativeToolBackend.PYTHON_ELF,
            tuple(sorted(issues, key=_issue_key)),
            True,
        )
    issues.append(
        NativeIssue(
            "NATIVE_SYMBOL_BACKEND_UNAVAILABLE",
            f"No symbol backend completed successfully: {error}",
            NativeIssueSeverity.WARNING,
            library.archive_path,
        )
    )
    return (
        (),
        NativeToolBackend.NONE,
        tuple(sorted(issues, key=_issue_key)),
        False,
    )


def extract_exported_symbols(
    library: NativeLibrary,
    *,
    timeout: float = 30.0,
) -> tuple[
    tuple[ExportedSymbol, ...],
    NativeToolBackend,
    tuple[NativeIssue, ...],
]:
    """Recover defined global dynamic symbols from one validated library."""

    if timeout <= 0:
        raise ValueError("timeout must be positive")
    data, validation_issue = _read_validated_library(library)
    if validation_issue is not None or data is None:
        return (), NativeToolBackend.NONE, (validation_issue,)  # type: ignore[arg-type]
    symbols, backend, issues, _ = _extract_symbols_from_validated(
        library, data, timeout=timeout
    )
    return symbols, backend, issues


def _signature_pattern(signature: str) -> re.Pattern[bytes]:
    encoded = re.escape(signature.encode("utf-8"))
    return re.compile(rb"(?<![A-Za-z0-9_])" + encoded + rb"(?![A-Za-z0-9_])")


def _scan_bytes(
    library: NativeLibrary,
    data: bytes,
) -> tuple[NativeSignal, ...]:
    signals: list[NativeSignal] = []
    for category in NativeSignalCategory:
        for signature in NATIVE_SIGNAL_SIGNATURES[category]:
            count = len(_signature_pattern(signature).findall(data))
            if count:
                signals.append(
                    NativeSignal(
                        library.archive_path,
                        library.abi,
                        category,
                        signature,
                        "binary_string",
                        count,
                    )
                )
    return tuple(sorted(signals))


def scan_native_signals(
    library: NativeLibrary,
) -> tuple[tuple[NativeSignal, ...], tuple[NativeIssue, ...]]:
    """Scan validated bytes for bounded sensitive native signatures."""

    data, validation_issue = _read_validated_library(library)
    if validation_issue is not None or data is None:
        return (), (validation_issue,)  # type: ignore[arg-type]
    return _scan_bytes(library, data), ()


def _symbol_signal(
    symbol: ExportedSymbol,
) -> tuple[NativeSignalCategory, str] | None:
    base_name = symbol.name.split("@", 1)[0]
    for category in NativeSignalCategory:
        for signature in NATIVE_SIGNAL_SIGNATURES[category]:
            if base_name == signature:
                return category, signature
    return None


def _merge_signal_evidence(
    library: NativeLibrary,
    raw_signals: Sequence[NativeSignal],
    symbols: Sequence[ExportedSymbol],
) -> tuple[NativeSignal, ...]:
    by_key = {
        (signal.category, signal.signature): signal for signal in raw_signals
    }
    counts: Counter[tuple[NativeSignalCategory, str]] = Counter()
    for symbol in symbols:
        matched = _symbol_signal(symbol)
        if matched is not None:
            counts[matched] += 1
    for (category, signature), count in counts.items():
        by_key[(category, signature)] = NativeSignal(
            library.archive_path,
            library.abi,
            category,
            signature,
            "exported_symbol",
            count,
        )
    return tuple(sorted(by_key.values()))


def _instruction_registers(instruction: Instruction) -> tuple[str, ...]:
    text = " ".join(instruction.operands)
    range_match = re.search(r"\b([vp])(\d+)\s*\.\.\s*([vp])(\d+)\b", text)
    registers: list[str] = []
    if range_match and range_match.group(1) == range_match.group(3):
        registers.extend(
            f"{range_match.group(1)}{number}"
            for number in range(
                int(range_match.group(2)), int(range_match.group(4)) + 1
            )
        )
        text = text[: range_match.start()] + text[range_match.end() :]
    registers.extend(_REGISTER_PATTERN.findall(text))
    return tuple(dict.fromkeys(registers))


def _method_reference(instruction: Instruction) -> str | None:
    for value in (*instruction.operands, instruction.raw_text):
        match = _METHOD_REFERENCE_PATTERN.search(value)
        if match:
            return match.group(1)
    return None


def _const_string_value(instruction: Instruction) -> str | None:
    if not instruction.opcode.startswith("const-string") or len(
        instruction.operands
    ) < 2:
        return None
    literal = instruction.operands[1].strip()
    try:
        decoded = json.loads(literal)
    except (json.JSONDecodeError, TypeError):
        return None
    return decoded if isinstance(decoded, str) else None


def _defines_register(instruction: Instruction, register: str) -> bool:
    registers = _instruction_registers(instruction)
    if not registers or registers[0] != register:
        return False
    return instruction.opcode.startswith(
        (
            "move",
            "const",
            "new-",
            "iget",
            "sget",
            "aget",
            "array-length",
            "instance-of",
            "check-cast",
            "add-",
            "sub-",
            "rsub-",
            "mul-",
            "div-",
            "rem-",
            "and-",
            "or-",
            "xor-",
            "shl-",
            "shr-",
            "ushr-",
            "neg-",
            "not-",
            "cmp",
        )
    ) or "-to-" in instruction.opcode


def _resolve_local_string(
    method: ExtractedMethod,
    instruction_position: int,
    register: str,
    *,
    limit: int = 64,
) -> str | None:
    current = register
    lower = max(-1, instruction_position - limit - 1)
    for position in range(instruction_position - 1, lower, -1):
        instruction = method.instructions[position]
        registers = _instruction_registers(instruction)
        if instruction.opcode.startswith("const-string") and registers:
            if registers[0] == current:
                return _const_string_value(instruction)
            continue
        if instruction.opcode.startswith("move") and not instruction.opcode.startswith(
            ("move-result", "move-exception")
        ):
            if len(registers) >= 2 and registers[0] == current:
                current = registers[1]
            continue
        if _defines_register(instruction, current):
            return None
    return None


def find_library_load_evidence(
    methods: Sequence[ExtractedMethod],
    libraries: Sequence[NativeLibrary],
) -> tuple[LibraryLoadEvidence, ...]:
    """Find direct System.load/loadLibrary calls and bounded literal evidence."""

    libraries_by_name: dict[str, list[NativeLibrary]] = defaultdict(list)
    for library in sorted(libraries, key=_library_key):
        libraries_by_name[library.filename].append(library)
    evidence: list[LibraryLoadEvidence] = []
    for method in sorted(
        (candidate for candidate in methods if candidate.is_usable),
        key=lambda candidate: (candidate.dex_name, candidate.full_signature),
    ):
        identity = _method_identity(method)
        for position, instruction in enumerate(method.instructions):
            reference = _method_reference(instruction)
            if reference not in {_LOAD_LIBRARY_SIGNATURE, _LOAD_SIGNATURE}:
                continue
            registers = _instruction_registers(instruction)
            requested = (
                _resolve_local_string(method, position, registers[0])
                if registers
                else None
            )
            matches: list[NativeLibrary] = []
            if requested is not None:
                if reference == _LOAD_LIBRARY_SIGNATURE:
                    candidate_names = {
                        requested,
                        (
                            requested
                            if requested.startswith("lib") and requested.endswith(".so")
                            else f"lib{requested}.so"
                        ),
                    }
                else:
                    candidate_names = {Path(requested).name}
                for name in candidate_names:
                    matches.extend(libraries_by_name.get(name, ()))
                if reference == _LOAD_SIGNATURE:
                    matches.extend(
                        library
                        for library in libraries
                        if library.extracted_path == requested
                    )
            evidence.append(
                LibraryLoadEvidence(
                    identity,
                    instruction.index,
                    requested,
                    tuple(
                        sorted(
                            {library.archive_path for library in matches}
                        )
                    ),
                    requested is None,
                )
            )
    return tuple(sorted(set(evidence)))


def _discover_native_methods(
    methods: Sequence[ExtractedMethod],
) -> tuple[tuple[NativeMethodIdentity, ExtractedMethod], ...]:
    representatives: dict[NativeMethodIdentity, ExtractedMethod] = {}
    for method in sorted(
        (candidate for candidate in methods if candidate.is_native),
        key=lambda candidate: (
            candidate.dex_name,
            candidate.full_signature,
            candidate.backend.value,
            candidate.source_path,
        ),
    ):
        representatives.setdefault(_method_identity(method), method)
    return tuple(sorted(representatives.items()))


def _build_mappings(
    native_methods: Sequence[tuple[NativeMethodIdentity, ExtractedMethod]],
    symbols: Sequence[ExportedSymbol],
) -> tuple[tuple[JniMapping, ...], tuple[NativeIssue, ...]]:
    by_name: dict[str, list[ExportedSymbol]] = defaultdict(list)
    for symbol in sorted(symbols):
        by_name[symbol.name].append(symbol)

    encoded: dict[
        NativeMethodIdentity, tuple[str, str] | None
    ] = {}
    issues: list[NativeIssue] = []
    short_groups: Counter[str] = Counter()
    for identity, method in native_methods:
        try:
            names = encode_jni_short_name(method), encode_jni_long_name(method)
        except ValueError as exc:
            encoded[identity] = None
            issues.append(
                NativeIssue(
                    "JNI_SYMBOL_ENCODING_FAILED",
                    str(exc),
                    NativeIssueSeverity.WARNING,
                    method=identity,
                )
            )
        else:
            encoded[identity] = names
            short_groups[names[0]] += 1

    mappings: list[JniMapping] = []
    for identity, _ in native_methods:
        names = encoded[identity]
        if names is None:
            mappings.append(
                JniMapping(
                    identity, "", "", (), (), JniMappingKind.UNRESOLVED, 0.0
                )
            )
            continue
        short_name, long_name = names
        long_matches = tuple(sorted(by_name.get(long_name, ())))
        short_matches = tuple(sorted(by_name.get(short_name, ())))
        if long_matches:
            matched = long_matches
            kind = JniMappingKind.EXACT_LONG_NAME
            confidence = 1.0
        elif short_matches and short_groups[short_name] == 1:
            matched = short_matches
            kind = JniMappingKind.EXACT_SHORT_NAME
            confidence = 0.9
        elif short_matches:
            matched = short_matches
            kind = JniMappingKind.AMBIGUOUS_OVERLOAD
            confidence = 0.5
            issues.append(
                NativeIssue(
                    "JNI_SHORT_NAME_AMBIGUOUS",
                    (
                        f"{short_name} is shared by "
                        f"{short_groups[short_name]} native declarations."
                    ),
                    NativeIssueSeverity.WARNING,
                    method=identity,
                )
            )
        else:
            matched = ()
            kind = JniMappingKind.UNRESOLVED
            confidence = 0.0
            issues.append(
                NativeIssue(
                    "JNI_MAPPING_UNRESOLVED",
                    (
                        "No static JNI export matched; the implementation may "
                        "be stripped, hidden, absent, or dynamically registered."
                    ),
                    NativeIssueSeverity.WARNING,
                    method=identity,
                )
            )
        mappings.append(
            JniMapping(
                identity,
                short_name,
                long_name,
                matched,
                tuple(
                    sorted({symbol.library_archive_path for symbol in matched})
                ),
                kind,
                confidence,
            )
        )
    return tuple(sorted(mappings)), tuple(sorted(issues, key=_issue_key))


def _analyze_library(
    library: NativeLibrary,
    *,
    timeout: float,
) -> _LibraryOutcome:
    data, validation_issue = _read_validated_library(library)
    if validation_issue is not None or data is None:
        analysis = NativeLibraryAnalysis(
            library,
            NativeToolBackend.NONE,
            (),
            (),
            (validation_issue,),  # type: ignore[arg-type]
        )
        return _LibraryOutcome(analysis, False, False, False)

    symbols, backend, symbol_issues, symbol_succeeded = (
        _extract_symbols_from_validated(library, data, timeout=timeout)
    )
    raw_signals = _scan_bytes(library, data)
    signals = _merge_signal_evidence(library, raw_signals, symbols)
    analysis = NativeLibraryAnalysis(
        library,
        backend,
        symbols,
        signals,
        symbol_issues,
    )
    return _LibraryOutcome(analysis, True, symbol_succeeded, True)


def analyze_jni_bridges(
    extraction_result: ExtractionResult,
    *,
    symbol_timeout: float = 30.0,
) -> JniBridgeResult:
    """Analyze native declarations, library loads, exports, and byte signals."""

    if symbol_timeout <= 0:
        raise ValueError("symbol_timeout must be positive")
    native_pairs = _discover_native_methods(extraction_result.methods)
    native_identities = tuple(identity for identity, _ in native_pairs)
    libraries = tuple(sorted(extraction_result.native_libraries, key=_library_key))
    load_evidence = find_library_load_evidence(
        extraction_result.methods, libraries
    )

    if not native_pairs and not libraries:
        metrics = JniBridgeMetrics(0, 0, 0, 0, 0, 0, 0)
        return JniBridgeResult(
            NativeAnalysisStatus.NOT_APPLICABLE,
            (),
            load_evidence,
            (),
            (),
            metrics,
            (),
        )

    outcomes = tuple(
        _analyze_library(library, timeout=symbol_timeout)
        for library in libraries
    )
    analyses = tuple(outcome.analysis for outcome in outcomes)
    symbols = tuple(
        sorted(
            symbol
            for analysis in analyses
            for symbol in analysis.exported_symbols
        )
    )
    mappings, mapping_issues = _build_mappings(native_pairs, symbols)
    issues: list[NativeIssue] = [
        issue for analysis in analyses for issue in analysis.issues
    ]
    issues.extend(mapping_issues)

    for item in load_evidence:
        if item.dynamic_name:
            issues.append(
                NativeIssue(
                    "DYNAMIC_LIBRARY_LOAD_NAME",
                    "System library load name could not be resolved locally.",
                    NativeIssueSeverity.WARNING,
                    method=item.method,
                )
            )
        elif not item.resolved_library_archive_paths:
            issues.append(
                NativeIssue(
                    "LOADED_LIBRARY_NOT_IN_APK",
                    (
                        f"Requested library {item.requested_name!r} does not "
                        "match an extracted native library."
                    ),
                    NativeIssueSeverity.WARNING,
                    method=item.method,
                )
            )

    dynamic_registration = any(
        signal.signature in {"RegisterNatives", "JNI_OnLoad"}
        for analysis in analyses
        for signal in analysis.sensitive_signals
    )
    if dynamic_registration and any(
        mapping.mapping_kind is JniMappingKind.UNRESOLVED for mapping in mappings
    ):
        issues.append(
            NativeIssue(
                "DYNAMIC_JNI_REGISTRATION_POSSIBLE",
                (
                    "Unresolved native declarations coexist with RegisterNatives "
                    "or JNI_OnLoad evidence; no static mapping was fabricated."
                ),
                NativeIssueSeverity.WARNING,
            )
        )

    complete = all(
        outcome.validation_succeeded
        and outcome.symbol_succeeded
        and outcome.scan_succeeded
        for outcome in outcomes
    )
    if complete:
        status = NativeAnalysisStatus.SUCCESS
    else:
        useful = bool(
            native_identities
            or load_evidence
            or symbols
            or any(analysis.sensitive_signals for analysis in analyses)
            or any(outcome.validation_succeeded for outcome in outcomes)
        )
        status = (
            NativeAnalysisStatus.PARTIAL
            if useful
            else NativeAnalysisStatus.FAILED
        )

    exact_count = sum(
        mapping.mapping_kind
        in {JniMappingKind.EXACT_LONG_NAME, JniMappingKind.EXACT_SHORT_NAME}
        for mapping in mappings
    )
    ambiguous_count = sum(
        mapping.mapping_kind is JniMappingKind.AMBIGUOUS_OVERLOAD
        for mapping in mappings
    )
    unresolved_count = sum(
        mapping.mapping_kind is JniMappingKind.UNRESOLVED
        for mapping in mappings
    )
    signal_count = sum(
        len(analysis.sensitive_signals) for analysis in analyses
    )
    metrics = JniBridgeMetrics(
        len(native_identities),
        sum(outcome.scan_succeeded for outcome in outcomes),
        len(symbols),
        exact_count,
        ambiguous_count,
        unresolved_count,
        signal_count,
    )
    return JniBridgeResult(
        status,
        native_identities,
        load_evidence,
        analyses,
        mappings,
        metrics,
        tuple(sorted(set(issues), key=_issue_key)),
    )


__all__ = [
    "ExportedSymbol",
    "JniBridgeMetrics",
    "JniBridgeResult",
    "JniMapping",
    "JniMappingKind",
    "LibraryLoadEvidence",
    "NATIVE_SIGNAL_SIGNATURES",
    "NativeAnalysisStatus",
    "NativeIssue",
    "NativeIssueSeverity",
    "NativeLibraryAnalysis",
    "NativeMethodIdentity",
    "NativeSignal",
    "NativeSignalCategory",
    "NativeToolBackend",
    "analyze_jni_bridges",
    "encode_jni_long_name",
    "encode_jni_short_name",
    "extract_exported_symbols",
    "find_library_load_evidence",
    "scan_native_signals",
]
