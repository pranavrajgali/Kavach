

from __future__ import annotations

import hashlib
import re
import shutil
import stat
import subprocess
import time
from dataclasses import dataclass, replace
from enum import Enum
from pathlib import Path, PurePosixPath
from zipfile import BadZipFile, ZipFile


PROJECT_ROOT = Path(__file__).resolve().parents[4]
DEFAULT_ARTIFACT_ROOT = PROJECT_ROOT / "artifacts" / "decompile"
APK_HASH_PATTERN = re.compile(r"^[0-9a-f]{64}$")
DEX_NAME_PATTERN = re.compile(r"^classes(?P<number>\d*)\.dex$")
CLASS_DESCRIPTOR_PATTERN = re.compile(r"^L[^;\s]+;$")
CLASS_DECLARATION_PATTERN = re.compile(
    r"^\.class(?:\s+(?P<flags>.*?))?\s+(?P<class_name>L[^;]+;)$"
)
SOURCE_DECLARATION_PATTERN = re.compile(r'^\.source\s+"(?P<source>.*)"$')
PARAM_PATTERN = re.compile(
    r'^\.param\s+(?P<register>p\d+)(?:\s*,\s*"(?P<name>(?:[^"\\]|\\.)*)")?'
)
CATCH_PATTERN = re.compile(
    r"^\.(?P<kind>catch|catchall)"
    r"(?:\s+(?P<exception>L[^;]+;))?\s+"
    r"\{(?P<start>:[^\s.]+)\s+\.\.\s+(?P<end>:[^\s}]+)\}\s+"
    r"(?P<handler>:\S+)$"
)
PAYLOAD_START_PATTERN = re.compile(
    r"^\.(?P<kind>packed-switch|sparse-switch|array-data)"
    r"(?:\s+(?P<argument>\S+))?$"
)
BLOCK_DIRECTIVE_PATTERN = re.compile(
    r"^\.(?P<name>annotation|subannotation|array-data|packed-switch|sparse-switch)"
    r"(?:\s+.*)?$"
)
INCOMPLETE_APKTOOL_MARKERS = (
    "error occurred while disassembling class",
    "error while processing method",
    "skipping class",
    "last instruction in method",
    " is truncated",
)


class ExtractionBackend(str, Enum):
    SMALI = "smali"
    RAW_DEX = "raw_dex"
    MIXED = "mixed"


class ExtractionStatus(str, Enum):
    SUCCESS = "SUCCESS"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"


class IssueSeverity(str, Enum):
    WARNING = "warning"
    ERROR = "error"


class ExtractionStage(str, Enum):
    VALIDATION = "validation"
    WORKSPACE = "workspace"
    APKTOOL = "apktool"
    SMALI_PARSE = "smali_parse"
    JADX = "jadx"
    RAW_DEX = "raw_dex"
    NATIVE_INVENTORY = "native_inventory"
    ORCHESTRATION = "orchestration"


@dataclass(frozen=True)
class ExtractionIssue:
    stage: ExtractionStage
    code: str
    message: str
    severity: IssueSeverity
    dex_name: str | None = None
    source_path: str | None = None
    class_name: str | None = None
    method_signature: str | None = None
    byte_offset: int | None = None


class ExtractionError(RuntimeError):
    """Raised when validation or workspace setup cannot safely continue."""

    def __init__(self, issue: ExtractionIssue):
        self.issue = issue
        super().__init__(f"{issue.code}: {issue.message}")


@dataclass(frozen=True)
class ToolExecution:
    tool: str
    command: tuple[str, ...]
    installed: bool
    return_code: int | None
    timed_out: bool
    stdout: str
    stderr: str
    output_path: str | None
    duration_seconds: float

    @property
    def success(self) -> bool:
        """Whether the process itself completed successfully.

        A successful process is not proof that its extraction output is usable.
        """

        return self.installed and not self.timed_out and self.return_code == 0


@dataclass(frozen=True)
class DexArtifact:
    dex_name: str
    archive_path: str
    extracted_path: str | None
    sha256: str
    size_bytes: int
    expected_smali_directory: str


@dataclass(frozen=True)
class NativeLibrary:
    filename: str
    abi: str
    archive_path: str
    extracted_path: str
    sha256: str
    size_bytes: int


@dataclass(frozen=True)
class MethodParameter:
    position: int
    type_descriptor: str
    register: str | None = None
    name: str | None = None


@dataclass(frozen=True)
class Instruction:
    index: int
    offset: int | None
    opcode: str
    operands: tuple[str, ...]
    raw_text: str

    @property
    def is_parsed(self) -> bool:
        return self.index >= 0 and bool(self.opcode.strip())


@dataclass(frozen=True)
class Label:
    name: str
    instruction_index: int | None
    offset: int | None = None


@dataclass(frozen=True)
class ExceptionHandler:
    exception_type: str | None
    try_start_label: str
    try_end_label: str
    handler_label: str
    raw_text: str


class PayloadKind(str, Enum):
    PACKED_SWITCH = "packed_switch"
    SPARSE_SWITCH = "sparse_switch"
    ARRAY_DATA = "array_data"


@dataclass(frozen=True)
class PayloadEntry:
    key: int | None
    target_label: str | None
    value: str | None
    raw_text: str


@dataclass(frozen=True)
class DataPayload:
    label: str
    kind: PayloadKind
    entries: tuple[PayloadEntry, ...]
    raw_text: str
    source_path: str
    start_line: int | None = None
    end_line: int | None = None
    start_offset: int | None = None
    end_offset: int | None = None


@dataclass(frozen=True)
class ExtractedMethod:
    dex_name: str
    class_name: str
    method_name: str
    descriptor: str
    full_signature: str
    access_flags: tuple[str, ...]
    parameters: tuple[MethodParameter, ...]
    register_count: int | None
    local_count: int | None
    instructions: tuple[Instruction, ...]
    labels: tuple[Label, ...]
    exception_handlers: tuple[ExceptionHandler, ...]
    declared_source_file: str | None
    source_path: str
    backend: ExtractionBackend
    payloads: tuple[DataPayload, ...] = ()

    def __post_init__(self) -> None:
        normalized_flags = tuple(
            sorted(
                {
                    flag.strip().lower()
                    for flag in self.access_flags
                    if flag and flag.strip()
                }
            )
        )
        object.__setattr__(self, "access_flags", normalized_flags)

    @property
    def is_native(self) -> bool:
        return "native" in self.access_flags

    @property
    def is_abstract(self) -> bool:
        return "abstract" in self.access_flags

    @property
    def canonical_signature(self) -> str:
        return f"{self.class_name}->{self.method_name}{self.descriptor}"

    @property
    def has_valid_identity(self) -> bool:
        return (
            bool(CLASS_DESCRIPTOR_PATTERN.fullmatch(self.class_name))
            and _is_valid_method_name(self.method_name)
            and _is_valid_method_descriptor(self.descriptor)
            and self.full_signature == self.canonical_signature
        )

    @property
    def is_usable(self) -> bool:
        return (
            not self.is_native
            and not self.is_abstract
            and self.has_valid_identity
            and any(instruction.is_parsed for instruction in self.instructions)
        )


@dataclass(frozen=True)
class ExtractionWorkspace:
    artifact_path: Path
    apktool_path: Path
    jadx_path: Path
    raw_dex_path: Path
    native_path: Path


@dataclass(frozen=True)
class ValidatedApk:
    apk_path: Path
    apk_hash: str
    dex_files: tuple[DexArtifact, ...]
    native_archive_paths: tuple[str, ...]
    issues: tuple[ExtractionIssue, ...]


@dataclass(frozen=True)
class RawDexExtraction:
    dex_files: tuple[DexArtifact, ...]
    methods: tuple[ExtractedMethod, ...]
    issues: tuple[ExtractionIssue, ...]
    complete_coverage: bool


@dataclass(frozen=True)
class ExtractionResult:
    apk_path: str
    apk_hash: str
    artifact_path: str
    dex_files: tuple[DexArtifact, ...]
    methods: tuple[ExtractedMethod, ...]
    native_libraries: tuple[NativeLibrary, ...]
    apktool_output_path: str
    jadx_output_path: str
    raw_dex_output_path: str
    native_output_path: str
    backend_used: ExtractionBackend | None
    apktool_execution: ToolExecution | None
    jadx_execution: ToolExecution | None
    raw_dex_fallback_used: bool
    status: ExtractionStatus
    issues: tuple[ExtractionIssue, ...]

    @property
    def warnings(self) -> tuple[ExtractionIssue, ...]:
        return tuple(
            issue for issue in self.issues if issue.severity is IssueSeverity.WARNING
        )

    @property
    def errors(self) -> tuple[ExtractionIssue, ...]:
        return tuple(
            issue for issue in self.issues if issue.severity is IssueSeverity.ERROR
        )

    @property
    def apktool_success(self) -> bool:
        return bool(self.apktool_execution and self.apktool_execution.success)

    @property
    def jadx_success(self) -> bool:
        return bool(self.jadx_execution and self.jadx_execution.success)

    @property
    def usable_methods(self) -> tuple[ExtractedMethod, ...]:
        return tuple(method for method in self.methods if method.is_usable)

    @property
    def native_method_signatures(self) -> tuple[str, ...]:
        return tuple(
            method.full_signature for method in self.methods if method.is_native
        )


def validate_apk(apk_path: str | Path) -> ValidatedApk:
    """Validate an APK and collect archive-level DEX/native provenance.

    APKs without DEX files are valid inputs.  They receive a ``NO_DEX_FILES``
    issue so later native inventory can still run.
    """

    path = Path(apk_path).expanduser().resolve()
    if not path.exists():
        _raise_validation("APK_NOT_FOUND", f"APK path does not exist: {path}")
    if not path.is_file():
        _raise_validation("APK_NOT_FILE", f"APK path is not a file: {path}")
    if path.suffix.lower() != ".apk":
        _raise_validation(
            "INVALID_APK_EXTENSION", f"Expected an .apk file: {path.name}"
        )

    apk_hash = _sha256_file(path)
    try:
        with ZipFile(path) as archive:
            archive_names = tuple(archive.namelist())
            if "AndroidManifest.xml" not in archive_names:
                _raise_validation(
                    "MISSING_ANDROID_MANIFEST",
                    "APK archive does not contain AndroidManifest.xml.",
                )
            _assert_readable_member(archive, "AndroidManifest.xml")

            dex_names = tuple(
                sorted(
                    (name for name in archive_names if DEX_NAME_PATTERN.fullmatch(name)),
                    key=_dex_sort_key,
                )
            )
            dex_files = tuple(_build_dex_artifact(archive, name) for name in dex_names)
            native_paths = tuple(
                sorted(
                    name
                    for name in archive_names
                    if name.startswith("lib/")
                    and name.endswith(".so")
                    and len(Path(name).parts) >= 3
                )
            )
    except ExtractionError:
        raise
    except BadZipFile as exc:
        raise ExtractionError(
            ExtractionIssue(
                stage=ExtractionStage.VALIDATION,
                code="INVALID_APK_ZIP",
                message="File is not a readable ZIP/APK archive.",
                severity=IssueSeverity.ERROR,
                source_path=str(path),
            )
        ) from exc
    except (OSError, RuntimeError, ValueError) as exc:
        raise ExtractionError(
            ExtractionIssue(
                stage=ExtractionStage.VALIDATION,
                code="APK_ARCHIVE_READ_FAILED",
                message=f"Unable to read APK archive: {exc}",
                severity=IssueSeverity.ERROR,
                source_path=str(path),
            )
        ) from exc

    issues: tuple[ExtractionIssue, ...] = ()
    if not dex_files:
        issues = (
            ExtractionIssue(
                stage=ExtractionStage.VALIDATION,
                code="NO_DEX_FILES",
                message=(
                    "APK contains no root-level classes*.dex files; code methods "
                    "cannot be recovered, but native inventory may still proceed."
                ),
                severity=IssueSeverity.ERROR,
                source_path=str(path),
            ),
        )

    return ValidatedApk(
        apk_path=path,
        apk_hash=apk_hash,
        dex_files=dex_files,
        native_archive_paths=native_paths,
        issues=issues,
    )


def prepare_workspace(
    apk_hash: str,
    artifact_root: str | Path | None = None,
) -> ExtractionWorkspace:
    """Create a clean, hash-scoped extraction workspace."""

    normalized_hash = apk_hash.strip().lower()
    if not APK_HASH_PATTERN.fullmatch(normalized_hash):
        _raise_workspace(
            "INVALID_APK_HASH",
            "Workspace requires a lowercase 64-character SHA-256 digest.",
        )

    root = (
        Path(artifact_root).expanduser()
        if artifact_root is not None
        else DEFAULT_ARTIFACT_ROOT
    )
    try:
        root.mkdir(parents=True, exist_ok=True)
        resolved_root = root.resolve(strict=True)
        target = resolved_root / normalized_hash

        if target.is_symlink():
            _raise_workspace(
                "UNSAFE_WORKSPACE_SYMLINK",
                f"Refusing to clear symlinked workspace: {target}",
            )
        if target.parent != resolved_root or target.name != normalized_hash:
            _raise_workspace(
                "UNSAFE_WORKSPACE_PATH",
                f"Workspace escaped the configured artifact root: {target}",
            )

        if target.exists():
            if not target.is_dir():
                _raise_workspace(
                    "WORKSPACE_NOT_DIRECTORY",
                    f"Existing workspace target is not a directory: {target}",
                )
            shutil.rmtree(target)

        apktool_path = target / "apktool"
        jadx_path = target / "jadx"
        raw_dex_path = target / "raw_dex"
        native_path = target / "native"
        for directory in (apktool_path, jadx_path, raw_dex_path, native_path):
            directory.mkdir(parents=True, exist_ok=False)
    except ExtractionError:
        raise
    except OSError as exc:
        raise ExtractionError(
            ExtractionIssue(
                stage=ExtractionStage.WORKSPACE,
                code="WORKSPACE_PREPARATION_FAILED",
                message=f"Unable to prepare extraction workspace: {exc}",
                severity=IssueSeverity.ERROR,
                source_path=str(root),
            )
        ) from exc

    return ExtractionWorkspace(
        artifact_path=target,
        apktool_path=apktool_path,
        jadx_path=jadx_path,
        raw_dex_path=raw_dex_path,
        native_path=native_path,
    )


def raw_dex_source_path(apk_hash: str, dex_name: str) -> str:
    """Return stable provenance for a method parsed directly from an APK DEX."""

    normalized_hash = apk_hash.strip().lower()
    if not APK_HASH_PATTERN.fullmatch(normalized_hash):
        raise ValueError("apk_hash must be a lowercase SHA-256 digest")
    if not DEX_NAME_PATTERN.fullmatch(dex_name):
        raise ValueError("dex_name must be a root-level classes*.dex filename")
    return f"apk://{normalized_hash}!/{dex_name}"


def extract_raw_dex(
    validated_apk: ValidatedApk,
    raw_dex_path: str | Path,
) -> RawDexExtraction:
    """Copy, verify, and parse every validated root-level DEX with Androguard."""

    output = Path(raw_dex_path).expanduser()
    issues: list[ExtractionIssue] = []
    methods: list[ExtractedMethod] = []
    updated_dex_files: list[DexArtifact] = []
    complete_coverage = bool(validated_apk.dex_files)

    try:
        if output.is_symlink():
            raise OSError(f"refusing symlinked raw DEX directory: {output}")
        output.mkdir(parents=True, exist_ok=True)
        output = output.resolve(strict=True)
    except OSError as exc:
        issue = _raw_dex_issue(
            code="RAW_DEX_WORKSPACE_INVALID",
            message=f"Unable to prepare raw DEX output directory: {exc}",
            source_path=str(output),
        )
        return RawDexExtraction(
            dex_files=validated_apk.dex_files,
            methods=(),
            issues=(issue,),
            complete_coverage=False,
        )

    if not validated_apk.dex_files:
        return RawDexExtraction(
            dex_files=(),
            methods=(),
            issues=(
                _raw_dex_issue(
                    code="RAW_DEX_NO_FILES",
                    message="APK contains no validated root-level DEX files.",
                    source_path=str(validated_apk.apk_path),
                ),
            ),
            complete_coverage=False,
        )

    try:
        archive = ZipFile(validated_apk.apk_path)
    except (BadZipFile, OSError) as exc:
        return RawDexExtraction(
            dex_files=validated_apk.dex_files,
            methods=(),
            issues=(
                _raw_dex_issue(
                    code="RAW_DEX_ARCHIVE_OPEN_FAILED",
                    message=f"Unable to reopen APK archive for raw DEX fallback: {exc}",
                    source_path=str(validated_apk.apk_path),
                ),
            ),
            complete_coverage=False,
        )

    with archive:
        for dex_file in sorted(
            validated_apk.dex_files,
            key=lambda artifact: _dex_sort_key(artifact.dex_name),
        ):
            copied, copy_issue = _copy_validated_dex(archive, dex_file, output)
            if copy_issue is not None:
                issues.append(copy_issue)
                updated_dex_files.append(dex_file)
                complete_coverage = False
                continue

            updated = replace(dex_file, extracted_path=str(copied))
            updated_dex_files.append(updated)
            provenance = raw_dex_source_path(
                validated_apk.apk_hash,
                dex_file.dex_name,
            )
            try:
                dex_object = _load_androguard_dex(copied.read_bytes())
            except ImportError as exc:
                issues.append(
                    _raw_dex_issue(
                        code="RAW_DEX_DEPENDENCY_UNAVAILABLE",
                        message=(
                            "Androguard 4.1.x is required for raw DEX fallback: "
                            f"{exc}"
                        ),
                        dex_name=dex_file.dex_name,
                        source_path=provenance,
                    )
                )
                complete_coverage = False
                continue
            except Exception as exc:
                issues.append(
                    _raw_dex_issue(
                        code="RAW_DEX_PARSE_FAILED",
                        message=f"Androguard could not parse {dex_file.dex_name}: {exc}",
                        dex_name=dex_file.dex_name,
                        source_path=provenance,
                    )
                )
                complete_coverage = False
                continue

            parsed_methods, parse_issues, dex_complete = _parse_raw_dex_object(
                dex_object,
                dex_name=dex_file.dex_name,
                source_path=provenance,
            )
            methods.extend(parsed_methods)
            issues.extend(parse_issues)
            complete_coverage = complete_coverage and dex_complete

    ordered_methods = tuple(sorted(methods, key=_method_sort_key))
    if not any(method.is_usable for method in ordered_methods):
        issues.append(
            _raw_dex_issue(
                code="RAW_DEX_NO_USABLE_METHODS",
                message="Raw DEX fallback produced no usable methods.",
                source_path=str(validated_apk.apk_path),
            )
        )

    return RawDexExtraction(
        dex_files=tuple(updated_dex_files),
        methods=ordered_methods,
        issues=tuple(issues),
        complete_coverage=complete_coverage,
    )


def extract_native_libraries(
    validated_apk: ValidatedApk,
    native_path: str | Path,
) -> tuple[
    tuple[NativeLibrary, ...],
    tuple[ExtractionIssue, ...],
]:
    """Safely extract and inventory validated native-library archive entries."""

    archive_paths = tuple(sorted(set(validated_apk.native_archive_paths)))
    if not archive_paths:
        return (), ()

    output = Path(native_path).expanduser()
    try:
        if output.is_symlink():
            raise OSError(f"refusing symlinked native output directory: {output}")
        output.mkdir(parents=True, exist_ok=True)
        output = output.resolve(strict=True)
    except OSError as exc:
        return (), tuple(
            _native_issue(
                code="NATIVE_OUTPUT_INVALID",
                message=f"Unable to prepare native output directory: {exc}",
                archive_path=archive_path,
                source_path=str(output),
            )
            for archive_path in archive_paths
        )

    try:
        archive = ZipFile(validated_apk.apk_path)
    except (BadZipFile, OSError) as exc:
        return (), tuple(
            _native_issue(
                code="NATIVE_ARCHIVE_OPEN_FAILED",
                message=f"Unable to reopen APK archive: {exc}",
                archive_path=archive_path,
                source_path=str(validated_apk.apk_path),
            )
            for archive_path in archive_paths
        )

    libraries: list[NativeLibrary] = []
    issues: list[ExtractionIssue] = []
    with archive:
        for archive_path in archive_paths:
            library, issue = _extract_native_library(
                archive,
                archive_path=archive_path,
                output=output,
            )
            if issue is not None:
                issues.append(issue)
            elif library is not None:
                libraries.append(library)

    return tuple(libraries), tuple(issues)


def run_apktool(
    apk_path: str | Path,
    output_path: str | Path,
    *,
    timeout: float,
) -> ToolExecution:
    """Run APKTool without a shell and capture process metadata."""

    apk = Path(apk_path).resolve()
    output = Path(output_path).resolve()
    executable = shutil.which("apktool")
    command = (
        executable or "apktool",
        "d",
        "-f",
        "-r",
        "-a",
        "-o",
        str(output),
        str(apk),
    )
    if executable is None:
        return ToolExecution(
            tool="apktool",
            command=command,
            installed=False,
            return_code=None,
            timed_out=False,
            stdout="",
            stderr="APKTool executable was not found on PATH.",
            output_path=str(output),
            duration_seconds=0.0,
        )

    started_at = time.monotonic()
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return ToolExecution(
            tool="apktool",
            command=command,
            installed=True,
            return_code=completed.returncode,
            timed_out=False,
            stdout=completed.stdout,
            stderr=completed.stderr,
            output_path=str(output),
            duration_seconds=round(time.monotonic() - started_at, 6),
        )
    except subprocess.TimeoutExpired as exc:
        return ToolExecution(
            tool="apktool",
            command=command,
            installed=True,
            return_code=None,
            timed_out=True,
            stdout=_coerce_process_text(exc.stdout),
            stderr=_coerce_process_text(exc.stderr),
            output_path=str(output),
            duration_seconds=round(time.monotonic() - started_at, 6),
        )
    except OSError as exc:
        return ToolExecution(
            tool="apktool",
            command=command,
            installed=True,
            return_code=None,
            timed_out=False,
            stdout="",
            stderr=str(exc),
            output_path=str(output),
            duration_seconds=round(time.monotonic() - started_at, 6),
        )


def run_jadx(
    apk_path: str | Path,
    output_path: str | Path,
    *,
    timeout: float,
) -> ToolExecution:
    """Run JADX for human-readable Java-like source without affecting analysis."""

    apk = Path(apk_path).resolve()
    output = Path(output_path).resolve()
    executable = shutil.which("jadx")
    command = (
        executable or "jadx",
        "--no-res",
        "-d",
        str(output),
        str(apk),
    )
    if executable is None:
        return ToolExecution(
            tool="jadx",
            command=command,
            installed=False,
            return_code=None,
            timed_out=False,
            stdout="",
            stderr="JADX executable was not found on PATH.",
            output_path=str(output),
            duration_seconds=0.0,
        )

    started_at = time.monotonic()
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return ToolExecution(
            tool="jadx",
            command=command,
            installed=True,
            return_code=completed.returncode,
            timed_out=False,
            stdout=completed.stdout,
            stderr=completed.stderr,
            output_path=str(output),
            duration_seconds=round(time.monotonic() - started_at, 6),
        )
    except subprocess.TimeoutExpired as exc:
        return ToolExecution(
            tool="jadx",
            command=command,
            installed=True,
            return_code=None,
            timed_out=True,
            stdout=_coerce_process_text(exc.stdout),
            stderr=_coerce_process_text(exc.stderr),
            output_path=str(output),
            duration_seconds=round(time.monotonic() - started_at, 6),
        )
    except OSError as exc:
        return ToolExecution(
            tool="jadx",
            command=command,
            installed=True,
            return_code=None,
            timed_out=False,
            stdout="",
            stderr=str(exc),
            output_path=str(output),
            duration_seconds=round(time.monotonic() - started_at, 6),
        )


def parse_smali_file(
    smali_path: str | Path,
    dex_name: str,
) -> tuple[tuple[ExtractedMethod, ...], tuple[ExtractionIssue, ...]]:
    """Parse all method declarations from one APKTool-generated Smali file."""

    path = Path(smali_path).resolve()
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as exc:
        return (), (
            ExtractionIssue(
                stage=ExtractionStage.SMALI_PARSE,
                code="SMALI_FILE_READ_FAILED",
                message=f"Unable to read Smali file: {exc}",
                severity=IssueSeverity.ERROR,
                dex_name=dex_name,
                source_path=str(path),
            ),
        )

    class_name: str | None = None
    declared_source_file: str | None = None
    for line in lines:
        stripped = line.strip()
        if class_name is None:
            class_match = CLASS_DECLARATION_PATTERN.fullmatch(stripped)
            if class_match:
                class_name = class_match.group("class_name")
        if declared_source_file is None:
            source_match = SOURCE_DECLARATION_PATTERN.fullmatch(stripped)
            if source_match:
                declared_source_file = source_match.group("source")
        if class_name is not None and declared_source_file is not None:
            break

    if class_name is None:
        return (), (
            ExtractionIssue(
                stage=ExtractionStage.SMALI_PARSE,
                code="SMALI_CLASS_DECLARATION_MISSING",
                message="Smali file does not contain a valid .class declaration.",
                severity=IssueSeverity.ERROR,
                dex_name=dex_name,
                source_path=str(path),
            ),
        )

    methods: list[ExtractedMethod] = []
    issues: list[ExtractionIssue] = []
    line_index = 0
    while line_index < len(lines):
        if not lines[line_index].strip().startswith(".method "):
            line_index += 1
            continue
        end_index = next(
            (
                candidate
                for candidate in range(line_index + 1, len(lines))
                if lines[candidate].strip() == ".end method"
            ),
            None,
        )
        if end_index is None:
            issues.append(
                ExtractionIssue(
                    stage=ExtractionStage.SMALI_PARSE,
                    code="SMALI_METHOD_BLOCK_UNTERMINATED",
                    message=f"Method starting on line {line_index + 1} has no .end method.",
                    severity=IssueSeverity.ERROR,
                    dex_name=dex_name,
                    source_path=str(path),
                )
            )
            break

        method, method_issues = _parse_smali_method(
            lines[line_index : end_index + 1],
            class_name=class_name,
            declared_source_file=declared_source_file,
            source_path=str(path),
            dex_name=dex_name,
            start_line=line_index + 1,
        )
        issues.extend(method_issues)
        if method is not None:
            methods.append(method)
        line_index = end_index + 1

    return tuple(methods), tuple(issues)


def extract_apk(
    apk_path: str | Path,
    artifact_root: str | Path | None = None,
    *,
    apktool_timeout: float = 120.0,
    jadx_timeout: float = 180.0,
    run_jadx_analysis: bool = True,
) -> ExtractionResult:
    """Extract APKTool Smali into backend-neutral method objects."""

    if apktool_timeout <= 0 or jadx_timeout <= 0:
        raise ValueError("Tool timeouts must be greater than zero.")

    validated = validate_apk(apk_path)
    workspace = prepare_workspace(validated.apk_hash, artifact_root)
    issues = list(validated.issues)
    native_libraries, native_issues = extract_native_libraries(
        validated,
        workspace.native_path,
    )
    issues.extend(native_issues)
    methods: list[ExtractedMethod] = []
    result_dex_files = validated.dex_files
    apktool_execution: ToolExecution | None = None
    jadx_execution: ToolExecution | None = None
    smali_complete = False
    raw_dex_fallback_used = False

    if validated.dex_files:
        apktool_execution = run_apktool(
            validated.apk_path,
            workspace.apktool_path,
            timeout=apktool_timeout,
        )
        issues.extend(_apktool_execution_issues(apktool_execution))
        output_methods, output_issues, complete_coverage = _parse_apktool_output(
            workspace.apktool_path,
            validated.dex_files,
        )
        methods.extend(output_methods)
        issues.extend(output_issues)

        combined_output = (
            f"{apktool_execution.stdout}\n{apktool_execution.stderr}".lower()
        )
        if any(marker in combined_output for marker in INCOMPLETE_APKTOOL_MARKERS):
            complete_coverage = False
            issues.append(
                ExtractionIssue(
                    stage=ExtractionStage.APKTOOL,
                    code="APKTOOL_INCOMPLETE_DISASSEMBLY",
                    message=(
                        "APKTool reported skipped, truncated, or otherwise "
                        "incompletely disassembled code."
                    ),
                    severity=IssueSeverity.ERROR,
                    source_path=str(validated.apk_path),
                )
            )
        smali_complete = apktool_execution.success and complete_coverage
        if not smali_complete:
            raw_dex_fallback_used = True
            raw_extraction = extract_raw_dex(
                validated,
                workspace.raw_dex_path,
            )
            result_dex_files = raw_extraction.dex_files
            methods = list(_merge_extracted_methods(methods, raw_extraction.methods))
            issues.extend(raw_extraction.issues)

        if run_jadx_analysis:
            jadx_execution = run_jadx(
                validated.apk_path,
                workspace.jadx_path,
                timeout=jadx_timeout,
            )
            issues.extend(_jadx_execution_issues(jadx_execution))

    methods = list(sorted(methods, key=_method_sort_key))
    usable_methods = tuple(method for method in methods if method.is_usable)
    native_extraction_failed = bool(native_issues)
    if usable_methods and (
        not smali_complete
        or raw_dex_fallback_used
        or native_extraction_failed
    ):
        status = ExtractionStatus.PARTIAL
    elif usable_methods:
        status = ExtractionStatus.SUCCESS
    elif native_libraries:
        status = ExtractionStatus.PARTIAL
    else:
        status = ExtractionStatus.FAILED

    return ExtractionResult(
        apk_path=str(validated.apk_path),
        apk_hash=validated.apk_hash,
        artifact_path=str(workspace.artifact_path),
        dex_files=result_dex_files,
        methods=tuple(methods),
        native_libraries=native_libraries,
        apktool_output_path=str(workspace.apktool_path),
        jadx_output_path=str(workspace.jadx_path),
        raw_dex_output_path=str(workspace.raw_dex_path),
        native_output_path=str(workspace.native_path),
        backend_used=_backend_for_methods(usable_methods),
        apktool_execution=apktool_execution,
        jadx_execution=jadx_execution,
        raw_dex_fallback_used=raw_dex_fallback_used,
        status=status,
        issues=tuple(issues),
    )


def _parse_apktool_output(
    apktool_path: Path,
    dex_files: tuple[DexArtifact, ...],
) -> tuple[
    tuple[ExtractedMethod, ...],
    tuple[ExtractionIssue, ...],
    bool,
]:
    methods: list[ExtractedMethod] = []
    issues: list[ExtractionIssue] = []
    complete_coverage = True

    for dex_file in dex_files:
        smali_directory = apktool_path / dex_file.expected_smali_directory
        if not smali_directory.is_dir():
            complete_coverage = False
            issues.append(
                ExtractionIssue(
                    stage=ExtractionStage.APKTOOL,
                    code="APKTOOL_SMALI_DIRECTORY_MISSING",
                    message=(
                        f"Expected {dex_file.expected_smali_directory}/ for "
                        f"{dex_file.dex_name}, but it was not produced."
                    ),
                    severity=IssueSeverity.ERROR,
                    dex_name=dex_file.dex_name,
                    source_path=str(smali_directory),
                )
            )
            continue

        smali_files = tuple(sorted(smali_directory.rglob("*.smali")))
        if not smali_files:
            complete_coverage = False
            issues.append(
                ExtractionIssue(
                    stage=ExtractionStage.APKTOOL,
                    code="APKTOOL_SMALI_DIRECTORY_EMPTY",
                    message=(
                        f"{dex_file.expected_smali_directory}/ contains no "
                        f"Smali files for {dex_file.dex_name}."
                    ),
                    severity=IssueSeverity.ERROR,
                    dex_name=dex_file.dex_name,
                    source_path=str(smali_directory),
                )
            )
            continue

        for smali_file in smali_files:
            parsed_methods, parse_issues = parse_smali_file(
                smali_file,
                dex_file.dex_name,
            )
            methods.extend(parsed_methods)
            issues.extend(parse_issues)
            if any(issue.severity is IssueSeverity.ERROR for issue in parse_issues):
                complete_coverage = False

    if not any(method.is_usable for method in methods):
        complete_coverage = False
        issues.append(
            ExtractionIssue(
                stage=ExtractionStage.SMALI_PARSE,
                code="APKTOOL_NO_USABLE_METHODS",
                message="APKTool output produced no usable parsed Smali methods.",
                severity=IssueSeverity.ERROR,
                source_path=str(apktool_path),
            )
        )

    return tuple(methods), tuple(issues), complete_coverage


def _apktool_execution_issues(
    execution: ToolExecution,
) -> tuple[ExtractionIssue, ...]:
    if not execution.installed:
        return (
            ExtractionIssue(
                stage=ExtractionStage.APKTOOL,
                code="APKTOOL_NOT_INSTALLED",
                message="APKTool executable was not found on PATH.",
                severity=IssueSeverity.ERROR,
                source_path=execution.output_path,
            ),
        )
    if execution.timed_out:
        return (
            ExtractionIssue(
                stage=ExtractionStage.APKTOOL,
                code="APKTOOL_TIMEOUT",
                message="APKTool exceeded its configured timeout.",
                severity=IssueSeverity.ERROR,
                source_path=execution.output_path,
            ),
        )
    if execution.return_code != 0:
        return (
            ExtractionIssue(
                stage=ExtractionStage.APKTOOL,
                code="APKTOOL_NONZERO_EXIT",
                message=f"APKTool exited with return code {execution.return_code}.",
                severity=IssueSeverity.ERROR,
                source_path=execution.output_path,
            ),
        )
    return ()


def _jadx_execution_issues(
    execution: ToolExecution,
) -> tuple[ExtractionIssue, ...]:
    code: str | None = None
    message: str | None = None
    if not execution.installed:
        code = "JADX_NOT_INSTALLED"
        message = "JADX executable was not found on PATH."
    elif execution.timed_out:
        code = "JADX_TIMEOUT"
        message = "JADX exceeded its configured timeout."
    elif execution.return_code is None:
        code = "JADX_PROCESS_ERROR"
        message = f"JADX could not be executed: {execution.stderr}"
    elif execution.return_code != 0:
        code = "JADX_NONZERO_EXIT"
        message = f"JADX exited with return code {execution.return_code}."
    elif execution.output_path is not None:
        try:
            has_java_source = any(
                path.is_file()
                for path in Path(execution.output_path).rglob("*.java")
            )
        except OSError as exc:
            code = "JADX_OUTPUT_CHECK_FAILED"
            message = f"Unable to inspect JADX output: {exc}"
        else:
            if not has_java_source:
                code = "JADX_NO_SOURCE_FILES"
                message = "JADX exited successfully but produced no Java source files."

    if code is None or message is None:
        return ()
    return (
        ExtractionIssue(
            stage=ExtractionStage.JADX,
            code=code,
            message=message,
            severity=IssueSeverity.WARNING,
            source_path=execution.output_path,
        ),
    )


def _extract_native_library(
    archive: ZipFile,
    *,
    archive_path: str,
    output: Path,
) -> tuple[NativeLibrary | None, ExtractionIssue | None]:
    path_parts = archive_path.split("/")
    if (
        archive_path.startswith("/")
        or "\\" in archive_path
        or len(path_parts) < 3
        or path_parts[0] != "lib"
        or any(part in {"", ".", ".."} for part in path_parts)
        or not path_parts[-1].endswith(".so")
    ):
        return None, _native_issue(
            code="NATIVE_ARCHIVE_PATH_INVALID",
            message=f"Malformed or unsafe native archive path: {archive_path}",
            archive_path=archive_path,
            source_path=archive_path,
        )

    pure_path = PurePosixPath(archive_path)
    abi = path_parts[1]
    relative_path = PurePosixPath(*pure_path.parts[1:])
    target = output.joinpath(*relative_path.parts)
    try:
        _prepare_safe_native_parent(output, target.parent)
        if target.is_symlink():
            raise OSError(f"refusing symlinked native output target: {target}")
        if target.exists() and not target.is_file():
            raise OSError(f"native output target is not a regular file: {target}")
        resolved_parent = target.parent.resolve(strict=True)
        if not resolved_parent.is_relative_to(output):
            raise OSError(f"native output target escapes output directory: {target}")
        target = resolved_parent / target.name

        archive_info = archive.getinfo(archive_path)
        archive_mode = (archive_info.external_attr >> 16) & 0o170000
        if archive_mode == stat.S_IFLNK:
            raise OSError(f"refusing symlinked native archive member: {archive_path}")

        archive_digest = hashlib.sha256()
        copied_size = 0
        with archive.open(archive_info) as source, target.open("wb") as sink:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                archive_digest.update(chunk)
                copied_size += len(chunk)
                sink.write(chunk)

        extracted_size = target.stat().st_size
        extracted_hash = _sha256_regular_file(target)
        archive_hash = archive_digest.hexdigest()
        verification_error = _native_verification_error(
            archive_size=archive_info.file_size,
            copied_size=copied_size,
            extracted_size=extracted_size,
            archive_hash=archive_hash,
            extracted_hash=extracted_hash,
        )
        if verification_error is not None:
            raise OSError(verification_error)
    except (KeyError, OSError, RuntimeError, ValueError) as exc:
        try:
            if target.is_file() or target.is_symlink():
                target.unlink()
        except OSError:
            pass
        return None, _native_issue(
            code="NATIVE_LIBRARY_EXTRACTION_FAILED",
            message=f"Unable to extract {archive_path}: {exc}",
            archive_path=archive_path,
            source_path=archive_path,
        )

    return NativeLibrary(
        filename=pure_path.name,
        abi=abi,
        archive_path=archive_path,
        extracted_path=str(target),
        sha256=archive_hash,
        size_bytes=extracted_size,
    ), None


def _prepare_safe_native_parent(output: Path, parent: Path) -> None:
    if not parent.is_relative_to(output):
        raise OSError(f"native output parent escapes output directory: {parent}")
    relative = parent.relative_to(output)
    current = output
    for component in relative.parts:
        current = current / component
        if current.is_symlink():
            raise OSError(f"refusing symlinked native output component: {current}")
        current.mkdir(exist_ok=True)
        if not current.resolve(strict=True).is_relative_to(output):
            raise OSError(f"native output component escapes output directory: {current}")


def _sha256_regular_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _native_verification_error(
    *,
    archive_size: int,
    copied_size: int,
    extracted_size: int,
    archive_hash: str,
    extracted_hash: str,
) -> str | None:
    if copied_size != archive_size or extracted_size != archive_size:
        return (
            f"size mismatch: ZIP={archive_size}, copied={copied_size}, "
            f"extracted={extracted_size}"
        )
    if extracted_hash != archive_hash:
        return (
            f"SHA-256 mismatch: archive={archive_hash}, "
            f"extracted={extracted_hash}"
        )
    return None


def _native_issue(
    *,
    code: str,
    message: str,
    archive_path: str,
    source_path: str,
) -> ExtractionIssue:
    return ExtractionIssue(
        stage=ExtractionStage.NATIVE_INVENTORY,
        code=code,
        message=message,
        severity=IssueSeverity.ERROR,
        source_path=source_path,
    )


def _copy_validated_dex(
    archive: ZipFile,
    dex_file: DexArtifact,
    output: Path,
) -> tuple[Path, ExtractionIssue | None]:
    if not DEX_NAME_PATTERN.fullmatch(dex_file.dex_name):
        return output / dex_file.dex_name, _raw_dex_issue(
            code="RAW_DEX_NAME_INVALID",
            message=f"Refusing unsafe DEX archive name: {dex_file.dex_name}",
            dex_name=dex_file.dex_name,
            source_path=dex_file.archive_path,
        )

    target = output / dex_file.dex_name
    if target.parent != output or target.is_symlink():
        return target, _raw_dex_issue(
            code="RAW_DEX_TARGET_UNSAFE",
            message=f"Refusing unsafe raw DEX output target: {target}",
            dex_name=dex_file.dex_name,
            source_path=str(target),
        )

    digest = hashlib.sha256()
    try:
        with archive.open(dex_file.archive_path) as source, target.open("wb") as sink:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(chunk)
                sink.write(chunk)
    except (KeyError, OSError, RuntimeError, ValueError) as exc:
        try:
            target.unlink()
        except OSError:
            pass
        return target, _raw_dex_issue(
            code="RAW_DEX_COPY_FAILED",
            message=f"Unable to copy {dex_file.dex_name}: {exc}",
            dex_name=dex_file.dex_name,
            source_path=dex_file.archive_path,
        )

    copied_hash = digest.hexdigest()
    if copied_hash != dex_file.sha256:
        try:
            target.unlink()
        except OSError:
            pass
        return target, _raw_dex_issue(
            code="RAW_DEX_HASH_MISMATCH",
            message=(
                f"Copied {dex_file.dex_name} SHA-256 {copied_hash} does not "
                f"match validated SHA-256 {dex_file.sha256}."
            ),
            dex_name=dex_file.dex_name,
            source_path=str(target),
        )
    return target, None


def _load_androguard_dex(raw_dex: bytes) -> object:
    from androguard.core.dex import DEX

    return DEX(raw_dex)


def _parse_raw_dex_object(
    dex_object: object,
    *,
    dex_name: str,
    source_path: str,
) -> tuple[
    tuple[ExtractedMethod, ...],
    tuple[ExtractionIssue, ...],
    bool,
]:
    methods: list[ExtractedMethod] = []
    issues: list[ExtractionIssue] = []
    complete_coverage = True

    try:
        classes = list(dex_object.get_classes())
    except Exception as exc:
        return (), (
            _raw_dex_issue(
                code="RAW_DEX_CLASS_LIST_FAILED",
                message=f"Unable to enumerate classes: {exc}",
                dex_name=dex_name,
                source_path=source_path,
            ),
        ), False

    sortable_classes: list[tuple[str, int, object]] = []
    for class_index, class_object in enumerate(classes):
        try:
            class_name = class_object.get_name()
            if not isinstance(class_name, str) or not class_name:
                raise ValueError("class name is empty")
        except Exception as exc:
            issues.append(
                _raw_dex_issue(
                    code="RAW_DEX_CLASS_METADATA_FAILED",
                    message=f"Unable to read class metadata: {exc}",
                    dex_name=dex_name,
                    source_path=source_path,
                )
            )
            complete_coverage = False
            continue
        sortable_classes.append((class_name, class_index, class_object))

    for class_name, _, class_object in sorted(sortable_classes):
        declared_source_file: str | None = None
        try:
            source_index = class_object.get_source_file_idx()
            if source_index != 0xFFFFFFFF:
                declared_source_file = dex_object.get_cm_string(source_index)
        except Exception as exc:
            issues.append(
                _raw_dex_issue(
                    code="RAW_DEX_CLASS_SOURCE_FAILED",
                    message=f"Unable to read source-file metadata: {exc}",
                    dex_name=dex_name,
                    class_name=class_name,
                    source_path=source_path,
                )
            )
            complete_coverage = False

        try:
            class_methods = list(class_object.get_methods())
        except Exception as exc:
            issues.append(
                _raw_dex_issue(
                    code="RAW_DEX_CLASS_METHODS_FAILED",
                    message=f"Unable to enumerate class methods: {exc}",
                    dex_name=dex_name,
                    class_name=class_name,
                    source_path=source_path,
                )
            )
            complete_coverage = False
            continue

        sortable_methods: list[tuple[str, str, int, object]] = []
        for method_index, method_object in enumerate(class_methods):
            try:
                name = method_object.get_name()
                descriptor = method_object.get_descriptor()
            except Exception:
                name = ""
                descriptor = ""
            sortable_methods.append((name, descriptor, method_index, method_object))

        for _, _, _, method_object in sorted(sortable_methods):
            parsed, issue = _parse_raw_method(
                dex_object,
                method_object,
                dex_name=dex_name,
                class_name=class_name,
                declared_source_file=declared_source_file,
                source_path=source_path,
            )
            if issue is not None:
                issues.append(issue)
                complete_coverage = False
                continue
            if parsed is not None:
                methods.append(parsed)

    return tuple(methods), tuple(issues), complete_coverage


def _parse_raw_method(
    dex_object: object,
    method_object: object,
    *,
    dex_name: str,
    class_name: str,
    declared_source_file: str | None,
    source_path: str,
) -> tuple[ExtractedMethod | None, ExtractionIssue | None]:
    method_name: str | None = None
    descriptor: str | None = None
    full_signature: str | None = None
    try:
        method_name = method_object.get_name()
        descriptor = "".join(method_object.get_descriptor().split())
        full_signature = f"{class_name}->{method_name}{descriptor}"
        access_flags = tuple(method_object.get_access_flags_string().split())
        code = method_object.get_code()
    except Exception as exc:
        return None, _raw_dex_issue(
            code="RAW_DEX_METHOD_METADATA_FAILED",
            message=f"Unable to read method metadata: {exc}",
            dex_name=dex_name,
            class_name=class_name,
            method_signature=full_signature,
            source_path=source_path,
        )

    is_static = any(flag.lower() == "static" for flag in access_flags)
    parameter_types = _method_parameter_types(descriptor)
    if parameter_types is None:
        parameter_types = ()

    if code is None:
        normalized_flags = {flag.lower() for flag in access_flags}
        if not normalized_flags.intersection({"native", "abstract"}):
            return None, _raw_dex_issue(
                code="RAW_DEX_CONCRETE_METHOD_NO_CODE",
                message="Concrete method declaration has no DEX code item.",
                dex_name=dex_name,
                class_name=class_name,
                method_signature=full_signature,
                source_path=source_path,
            )
        return ExtractedMethod(
            dex_name=dex_name,
            class_name=class_name,
            method_name=method_name,
            descriptor=descriptor,
            full_signature=full_signature,
            access_flags=access_flags,
            parameters=_build_method_parameters(
                parameter_types,
                is_static=is_static,
                parameter_names={},
                legacy_parameter_names=[],
            ),
            register_count=None,
            local_count=None,
            instructions=(),
            labels=(),
            exception_handlers=(),
            declared_source_file=declared_source_file,
            source_path=source_path,
            backend=ExtractionBackend.RAW_DEX,
        ), None

    last_offset: int | None = None
    try:
        register_count = code.get_registers_size()
        incoming_count = code.get_ins_size()
        local_count = register_count - incoming_count
        if local_count < 0:
            raise ValueError(
                f"register count {register_count} is smaller than incoming "
                f"register count {incoming_count}"
            )

        instruction_rows: list[tuple[int, object]] = []
        for offset, instruction in method_object.get_instructions_idx():
            last_offset = offset
            instruction.get_name()
            instruction.get_output(offset)
            instruction.get_operands(offset)
            instruction.get_length()
            instruction_rows.append((offset, instruction))

        (
            instructions,
            labels,
            payloads,
            exception_handlers,
        ) = _convert_raw_code(
            dex_object,
            code,
            instruction_rows,
            local_count=local_count,
            source_path=source_path,
        )
        if not instructions:
            raise ValueError("concrete method contains no executable instructions")
    except Exception as exc:
        return None, _raw_dex_issue(
            code="RAW_DEX_METHOD_PARSE_FAILED",
            message=f"Unable to parse concrete method: {exc}",
            dex_name=dex_name,
            class_name=class_name,
            method_signature=full_signature,
            source_path=source_path,
            byte_offset=(
                last_offset
                if last_offset is not None
                else _androguard_error_offset(exc)
            ),
        )

    return ExtractedMethod(
        dex_name=dex_name,
        class_name=class_name,
        method_name=method_name,
        descriptor=descriptor,
        full_signature=full_signature,
        access_flags=access_flags,
        parameters=_build_method_parameters(
            parameter_types,
            is_static=is_static,
            parameter_names={},
            legacy_parameter_names=[],
        ),
        register_count=register_count,
        local_count=local_count,
        instructions=instructions,
        labels=labels,
        exception_handlers=exception_handlers,
        declared_source_file=declared_source_file,
        source_path=source_path,
        backend=ExtractionBackend.RAW_DEX,
        payloads=payloads,
    ), None


def _convert_raw_code(
    dex_object: object,
    code: object,
    instruction_rows: list[tuple[int, object]],
    *,
    local_count: int,
    source_path: str,
) -> tuple[
    tuple[Instruction, ...],
    tuple[Label, ...],
    tuple[DataPayload, ...],
    tuple[ExceptionHandler, ...],
]:
    payload_rows = {
        offset: instruction
        for offset, instruction in instruction_rows
        if instruction.get_name().endswith("-payload")
    }
    executable_rows = [
        (offset, instruction)
        for offset, instruction in instruction_rows
        if offset not in payload_rows
    ]
    executable_offsets = {
        offset: index for index, (offset, _) in enumerate(executable_rows)
    }

    target_offsets: set[int] = set()
    payload_references: dict[int, list[int]] = {}
    instruction_targets: dict[int, int] = {}
    for offset, instruction in executable_rows:
        relative_targets = _raw_relative_offsets(instruction, offset)
        if not relative_targets:
            continue
        if len(relative_targets) != 1:
            raise ValueError(
                f"instruction at byte offset {offset} has ambiguous targets"
            )
        target = offset + relative_targets[0] * 2
        instruction_targets[offset] = target
        target_offsets.add(target)
        if instruction.get_name() in {
            "packed-switch",
            "sparse-switch",
            "fill-array-data",
        }:
            payload_references.setdefault(target, []).append(offset)

    payloads: list[DataPayload] = []
    for payload_offset, payload_instruction in sorted(payload_rows.items()):
        references = payload_references.get(payload_offset, [])
        payload_name = payload_instruction.get_name()
        if payload_name in {"packed-switch-payload", "sparse-switch-payload"}:
            if len(set(references)) != 1:
                raise ValueError(
                    f"switch payload at byte offset {payload_offset} does not "
                    "have exactly one referencing instruction"
                )
            switch_offset = references[0]
            for relative_target in payload_instruction.get_targets():
                target_offsets.add(switch_offset + relative_target * 2)
        payload = _build_raw_payload(
            payload_instruction,
            payload_offset=payload_offset,
            reference_offset=references[0] if references else None,
            source_path=source_path,
        )
        payloads.append(payload)

    exception_specs, exception_offsets = _raw_exception_specs(dex_object, code)
    target_offsets.update(exception_offsets)
    label_names = {
        offset: _raw_label(offset)
        for offset in sorted(target_offsets | set(payload_rows))
    }

    normalized_payloads = tuple(
        _replace_payload_targets(payload, label_names) for payload in payloads
    )
    instructions = tuple(
        Instruction(
            index=index,
            offset=offset,
            opcode=instruction.get_name(),
            operands=_raw_instruction_operands(
                instruction,
                offset=offset,
                local_count=local_count,
                target_offset=instruction_targets.get(offset),
                label_names=label_names,
            ),
            raw_text=_raw_instruction_text(instruction, offset),
        )
        for index, (offset, instruction) in enumerate(executable_rows)
    )
    labels = tuple(
        Label(
            name=label_names[offset],
            instruction_index=(
                None if offset in payload_rows else executable_offsets.get(offset)
            ),
            offset=offset,
        )
        for offset in sorted(label_names)
    )
    exception_handlers = tuple(
        ExceptionHandler(
            exception_type=exception_type,
            try_start_label=label_names[start],
            try_end_label=label_names[end],
            handler_label=label_names[handler],
            raw_text=(
                f".catchall {{{label_names[start]} .. {label_names[end]}}} "
                f"{label_names[handler]}"
                if exception_type is None
                else (
                    f".catch {exception_type} "
                    f"{{{label_names[start]} .. {label_names[end]}}} "
                    f"{label_names[handler]}"
                )
            ),
        )
        for start, end, exception_type, handler in exception_specs
    )
    return instructions, labels, normalized_payloads, exception_handlers


def _raw_relative_offsets(instruction: object, offset: int) -> tuple[int, ...]:
    offsets: list[int] = []
    for operand in instruction.get_operands(offset):
        if not operand:
            continue
        kind = operand[0]
        kind_name = getattr(kind, "name", "")
        if kind_name == "OFFSET" and len(operand) >= 2:
            offsets.append(int(operand[1]))
    return tuple(offsets)


def _build_raw_payload(
    payload_instruction: object,
    *,
    payload_offset: int,
    reference_offset: int | None,
    source_path: str,
) -> DataPayload:
    name = payload_instruction.get_name()
    label = _raw_label(payload_offset)
    length = payload_instruction.get_length()
    entries: list[PayloadEntry] = []

    if name == "packed-switch-payload":
        kind = PayloadKind.PACKED_SWITCH
        keys = payload_instruction.get_keys()
        targets = payload_instruction.get_targets()
        lines = [label, f".packed-switch {hex(keys[0]) if keys else '0x0'}"]
        for key, relative_target in zip(keys, targets, strict=True):
            target_offset = (
                reference_offset + relative_target * 2
                if reference_offset is not None
                else None
            )
            raw_entry = (
                _raw_label(target_offset)
                if target_offset is not None
                else "<unresolved>"
            )
            entries.append(
                PayloadEntry(
                    key=int(key),
                    target_label=raw_entry if target_offset is not None else None,
                    value=None,
                    raw_text=raw_entry,
                )
            )
            lines.append(f"    {raw_entry}")
        lines.append(".end packed-switch")
    elif name == "sparse-switch-payload":
        kind = PayloadKind.SPARSE_SWITCH
        keys = payload_instruction.get_keys()
        targets = payload_instruction.get_targets()
        lines = [label, ".sparse-switch"]
        for key, relative_target in zip(keys, targets, strict=True):
            target_offset = (
                reference_offset + relative_target * 2
                if reference_offset is not None
                else None
            )
            target = (
                _raw_label(target_offset)
                if target_offset is not None
                else "<unresolved>"
            )
            raw_entry = f"{hex(int(key))} -> {target}"
            entries.append(
                PayloadEntry(
                    key=int(key),
                    target_label=target if target_offset is not None else None,
                    value=None,
                    raw_text=raw_entry,
                )
            )
            lines.append(f"    {raw_entry}")
        lines.append(".end sparse-switch")
    elif name == "fill-array-data-payload":
        kind = PayloadKind.ARRAY_DATA
        width = int(payload_instruction.element_width)
        size = int(payload_instruction.size)
        raw_data = bytes(payload_instruction.get_data())
        lines = [label, f".array-data {hex(width)}"]
        for index in range(size):
            chunk = raw_data[index * width : (index + 1) * width]
            value = hex(int.from_bytes(chunk, byteorder="little", signed=False))
            entries.append(
                PayloadEntry(
                    key=None,
                    target_label=None,
                    value=value,
                    raw_text=value,
                )
            )
            lines.append(f"    {value}")
        lines.append(".end array-data")
    else:
        raise ValueError(f"unsupported raw payload instruction: {name}")

    return DataPayload(
        label=label,
        kind=kind,
        entries=tuple(entries),
        raw_text="\n".join(lines),
        source_path=source_path,
        start_line=None,
        end_line=None,
        start_offset=payload_offset,
        end_offset=payload_offset + length,
    )


def _replace_payload_targets(
    payload: DataPayload,
    label_names: dict[int, str],
) -> DataPayload:
    if payload.kind is PayloadKind.ARRAY_DATA:
        return payload
    entries = tuple(
        replace(
            entry,
            target_label=(
                label_names.get(_raw_label_offset(entry.target_label))
                if entry.target_label is not None
                else None
            ),
        )
        for entry in payload.entries
    )
    return replace(payload, entries=entries)


def _raw_label_offset(label: str) -> int:
    return int(label.removeprefix(":raw_"), 16)


def _raw_exception_specs(
    dex_object: object,
    code: object,
) -> tuple[
    tuple[tuple[int, int, str | None, int], ...],
    set[int],
]:
    if code.get_tries_size() <= 0:
        return (), set()

    handler_list = code.get_handlers()
    handlers_by_offset = {
        handler.get_off(): handler for handler in handler_list.get_list()
    }
    specs: list[tuple[int, int, str | None, int]] = []
    offsets: set[int] = set()
    for try_item in code.get_tries():
        start = try_item.get_start_addr() * 2
        end = start + try_item.get_insn_count() * 2
        handler_offset = try_item.get_handler_off() + handler_list.get_off()
        handler = handlers_by_offset.get(handler_offset)
        if handler is None:
            raise ValueError(
                f"try range at byte offset {start} references a missing handler"
            )
        offsets.update((start, end))
        for typed_handler in handler.get_handlers():
            target = typed_handler.get_addr() * 2
            exception_type = dex_object.get_cm_type(
                typed_handler.get_type_idx()
            )
            specs.append((start, end, exception_type, target))
            offsets.add(target)
        if handler.get_size() <= 0:
            target = handler.get_catch_all_addr() * 2
            specs.append((start, end, None, target))
            offsets.add(target)
    return tuple(specs), offsets


def _raw_instruction_operands(
    instruction: object,
    *,
    offset: int,
    local_count: int,
    target_offset: int | None,
    label_names: dict[int, str],
) -> tuple[str, ...]:
    rendered = _split_operands(instruction.get_output(offset).strip())
    normalized = tuple(
        _normalize_raw_registers(operand, local_count) for operand in rendered
    )
    if target_offset is not None:
        if not normalized:
            return (label_names[target_offset],)
        normalized = (*normalized[:-1], label_names[target_offset])
    return normalized


def _normalize_raw_registers(value: str, local_count: int) -> str:
    def replace_register(match: re.Match[str]) -> str:
        register = int(match.group("number"))
        if register >= local_count:
            return f"p{register - local_count}"
        return f"v{register}"

    return re.sub(r"\bv(?P<number>\d+)\b", replace_register, value)


def _raw_instruction_text(instruction: object, offset: int) -> str:
    output = instruction.get_output(offset).strip()
    return f"{instruction.get_name()} {output}".rstrip()


def _androguard_error_offset(error: BaseException) -> int | None:
    for argument in error.args:
        if isinstance(argument, int) and argument >= 0:
            return argument
        if isinstance(argument, BaseException):
            nested = _androguard_error_offset(argument)
            if nested is not None:
                return nested
    return None


def _raw_label(offset: int) -> str:
    if offset < 0:
        raise ValueError(f"raw DEX label offset cannot be negative: {offset}")
    return f":raw_{offset:08x}"


def _method_sort_key(method: ExtractedMethod) -> tuple[int, str, str, str]:
    backend_order = {
        ExtractionBackend.SMALI: "0",
        ExtractionBackend.RAW_DEX: "1",
        ExtractionBackend.MIXED: "2",
    }
    dex_number, _ = _dex_sort_key(method.dex_name)
    return (
        dex_number,
        method.class_name,
        method.full_signature,
        backend_order[method.backend],
    )


def _merge_extracted_methods(
    smali_methods: list[ExtractedMethod] | tuple[ExtractedMethod, ...],
    raw_methods: list[ExtractedMethod] | tuple[ExtractedMethod, ...],
) -> tuple[ExtractedMethod, ...]:
    def priority(method: ExtractedMethod) -> int:
        if method.backend is ExtractionBackend.SMALI:
            return 0 if method.is_usable else 2
        return 1 if method.is_usable else 3

    selected: dict[tuple[str, str], ExtractedMethod] = {}
    candidates = sorted(
        (*smali_methods, *raw_methods),
        key=lambda method: (
            priority(method),
            _method_sort_key(method),
            method.source_path,
        ),
    )
    for method in candidates:
        selected.setdefault((method.dex_name, method.full_signature), method)
    return tuple(sorted(selected.values(), key=_method_sort_key))


def _backend_for_methods(
    methods: tuple[ExtractedMethod, ...],
) -> ExtractionBackend | None:
    backends = {method.backend for method in methods if method.is_usable}
    if not backends:
        return None
    if backends == {ExtractionBackend.SMALI}:
        return ExtractionBackend.SMALI
    if backends == {ExtractionBackend.RAW_DEX}:
        return ExtractionBackend.RAW_DEX
    return ExtractionBackend.MIXED


def _raw_dex_issue(
    *,
    code: str,
    message: str,
    source_path: str,
    dex_name: str | None = None,
    class_name: str | None = None,
    method_signature: str | None = None,
    byte_offset: int | None = None,
) -> ExtractionIssue:
    return ExtractionIssue(
        stage=ExtractionStage.RAW_DEX,
        code=code,
        message=message,
        severity=IssueSeverity.ERROR,
        dex_name=dex_name,
        source_path=source_path,
        class_name=class_name,
        method_signature=method_signature,
        byte_offset=byte_offset,
    )


def _parse_smali_method(
    block_lines: list[str],
    *,
    class_name: str,
    declared_source_file: str | None,
    source_path: str,
    dex_name: str,
    start_line: int,
) -> tuple[ExtractedMethod | None, tuple[ExtractionIssue, ...]]:
    issues: list[ExtractionIssue] = []
    header = block_lines[0].strip().removeprefix(".method").strip()
    header_parts = header.split()
    if not header_parts:
        return None, (
            _smali_issue(
                "SMALI_METHOD_HEADER_INVALID",
                f"Invalid method declaration on line {start_line}.",
                dex_name,
                source_path,
            ),
        )

    signature_token = header_parts[-1]
    descriptor_start = signature_token.find("(")
    if descriptor_start <= 0:
        return None, (
            _smali_issue(
                "SMALI_METHOD_HEADER_INVALID",
                f"Invalid method signature on line {start_line}: {signature_token}",
                dex_name,
                source_path,
            ),
        )

    method_name = signature_token[:descriptor_start]
    descriptor = signature_token[descriptor_start:]
    access_flags = tuple(header_parts[:-1])
    is_static = any(flag.lower() == "static" for flag in access_flags)
    parameter_types = _method_parameter_types(descriptor)
    if parameter_types is None:
        issues.append(
            _smali_issue(
                "SMALI_METHOD_DESCRIPTOR_INVALID",
                f"Invalid method descriptor on line {start_line}: {descriptor}",
                dex_name,
                source_path,
            )
        )
        parameter_types = ()

    local_count: int | None = None
    register_count: int | None = None
    parameter_names: dict[str, str] = {}
    legacy_parameter_names: list[str] = []
    instructions: list[Instruction] = []
    labels: list[Label] = []
    exception_handlers: list[ExceptionHandler] = []
    payloads: list[DataPayload] = []

    body_index = 1
    while body_index < len(block_lines) - 1:
        raw_line = block_lines[body_index]
        stripped = raw_line.strip()
        absolute_line = start_line + body_index
        if not stripped or stripped.startswith("#"):
            body_index += 1
            continue

        if stripped == ".locals" or stripped.startswith(".locals "):
            value = stripped.removeprefix(".locals").strip()
            local_count = _parse_nonnegative_int(value)
            if local_count is None:
                issues.append(
                    _smali_issue(
                        "SMALI_LOCALS_DIRECTIVE_INVALID",
                        f"Invalid .locals directive on line {absolute_line}.",
                        dex_name,
                        source_path,
                    )
                )
            body_index += 1
            continue
        if stripped == ".registers" or stripped.startswith(".registers "):
            value = stripped.removeprefix(".registers").strip()
            register_count = _parse_nonnegative_int(value)
            if register_count is None:
                issues.append(
                    _smali_issue(
                        "SMALI_REGISTERS_DIRECTIVE_INVALID",
                        f"Invalid .registers directive on line {absolute_line}.",
                        dex_name,
                        source_path,
                    )
                )
            body_index += 1
            continue

        parameter_match = PARAM_PATTERN.match(stripped)
        if parameter_match:
            name = parameter_match.group("name")
            if name is not None:
                parameter_names[parameter_match.group("register")] = name
            body_index += 1
            continue
        if stripped.startswith(".parameter "):
            legacy_name = _quoted_directive_value(stripped)
            if legacy_name is not None:
                legacy_parameter_names.append(legacy_name)
            body_index += 1
            continue

        if stripped.startswith(":"):
            payload_directive_index = _next_content_line(block_lines, body_index + 1)
            payload_start = (
                PAYLOAD_START_PATTERN.fullmatch(
                    block_lines[payload_directive_index].strip()
                )
                if payload_directive_index is not None
                and payload_directive_index < len(block_lines) - 1
                else None
            )
            if payload_start is not None:
                payload, payload_end, payload_issues = _parse_payload(
                    block_lines,
                    label_index=body_index,
                    directive_index=payload_directive_index,
                    start_line=start_line,
                    source_path=source_path,
                    dex_name=dex_name,
                )
                labels.append(Label(stripped, None, None))
                issues.extend(payload_issues)
                if payload is not None:
                    payloads.append(payload)
                body_index = payload_end + 1
                continue

            labels.append(Label(stripped, len(instructions), None))
            body_index += 1
            continue

        catch_match = CATCH_PATTERN.fullmatch(stripped)
        if catch_match:
            exception_handlers.append(
                ExceptionHandler(
                    exception_type=catch_match.group("exception"),
                    try_start_label=catch_match.group("start"),
                    try_end_label=catch_match.group("end"),
                    handler_label=catch_match.group("handler"),
                    raw_text=raw_line,
                )
            )
            body_index += 1
            continue

        if stripped.startswith("."):
            directive_end, directive_issue = _non_executable_directive_end(
                block_lines,
                body_index,
                start_line=start_line,
                dex_name=dex_name,
                source_path=source_path,
            )
            if directive_issue is not None:
                issues.append(directive_issue)
            if directive_end is not None:
                body_index = directive_end + 1
                continue
            body_index += 1
            continue

        opcode, operands = _parse_instruction_text(stripped)
        instructions.append(
            Instruction(
                index=len(instructions),
                offset=None,
                opcode=opcode,
                operands=operands,
                raw_text=raw_line,
            )
        )
        body_index += 1

    incoming_register_count = _incoming_register_count(parameter_types, is_static)
    if local_count is not None:
        register_count = local_count + incoming_register_count
    elif register_count is not None:
        computed_locals = register_count - incoming_register_count
        local_count = computed_locals if computed_locals >= 0 else None

    parameters = _build_method_parameters(
        parameter_types,
        is_static=is_static,
        parameter_names=parameter_names,
        legacy_parameter_names=legacy_parameter_names,
    )
    method = ExtractedMethod(
        dex_name=dex_name,
        class_name=class_name,
        method_name=method_name,
        descriptor=descriptor,
        full_signature=f"{class_name}->{method_name}{descriptor}",
        access_flags=access_flags,
        parameters=parameters,
        register_count=register_count,
        local_count=local_count,
        instructions=tuple(instructions),
        labels=tuple(labels),
        exception_handlers=tuple(exception_handlers),
        declared_source_file=declared_source_file,
        source_path=source_path,
        backend=ExtractionBackend.SMALI,
        payloads=tuple(payloads),
    )
    return method, tuple(issues)


def _non_executable_directive_end(
    method_lines: list[str],
    directive_index: int,
    *,
    start_line: int,
    dex_name: str,
    source_path: str,
) -> tuple[int | None, ExtractionIssue | None]:
    """Find the end of a non-executable Smali directive block.

    Known multiline directives are treated as blocks even when malformed.
    Other directives are skipped as blocks only when a matching ``.end`` is
    present, avoiding broad suppression of otherwise unknown method text.
    """

    stripped = method_lines[directive_index].strip()
    known_match = BLOCK_DIRECTIVE_PATTERN.fullmatch(stripped)
    directive_name = (
        known_match.group("name")
        if known_match is not None
        else stripped.removeprefix(".").split(maxsplit=1)[0]
    )
    if not directive_name or directive_name == "end":
        return None, None

    end_directive = f".end {directive_name}"
    end_index = next(
        (
            candidate
            for candidate in range(directive_index + 1, len(method_lines) - 1)
            if method_lines[candidate].strip() == end_directive
        ),
        None,
    )
    if end_index is not None:
        return end_index, None
    if known_match is None:
        return None, None
    absolute_line = start_line + directive_index
    return len(method_lines) - 2, _smali_issue(
        "SMALI_DIRECTIVE_BLOCK_UNTERMINATED",
        (
            f"Non-executable .{directive_name} block starting on line "
            f"{absolute_line} has no {end_directive}."
        ),
        dex_name,
        source_path,
    )


def _parse_payload(
    method_lines: list[str],
    *,
    label_index: int,
    directive_index: int,
    start_line: int,
    source_path: str,
    dex_name: str,
) -> tuple[DataPayload | None, int, tuple[ExtractionIssue, ...]]:
    label = method_lines[label_index].strip()
    directive = method_lines[directive_index].strip()
    match = PAYLOAD_START_PATTERN.fullmatch(directive)
    if match is None:
        return None, directive_index, ()

    kind_name = match.group("kind")
    end_directive = f".end {kind_name}"
    end_index = next(
        (
            candidate
            for candidate in range(directive_index + 1, len(method_lines))
            if method_lines[candidate].strip() == end_directive
        ),
        None,
    )
    if end_index is None:
        return None, len(method_lines) - 2, (
            _smali_issue(
                "SMALI_PAYLOAD_UNTERMINATED",
                f"Payload {label} has no {end_directive}.",
                dex_name,
                source_path,
            ),
        )

    payload_kind = {
        "packed-switch": PayloadKind.PACKED_SWITCH,
        "sparse-switch": PayloadKind.SPARSE_SWITCH,
        "array-data": PayloadKind.ARRAY_DATA,
    }[kind_name]
    issues: list[ExtractionIssue] = []
    entries: list[PayloadEntry] = []
    content = [
        line
        for line in method_lines[directive_index + 1 : end_index]
        if line.strip() and not line.strip().startswith("#")
    ]

    if payload_kind is PayloadKind.PACKED_SWITCH:
        first_key = _parse_smali_int(match.group("argument") or "")
        if first_key is None:
            issues.append(
                _smali_issue(
                    "SMALI_PAYLOAD_KEY_INVALID",
                    f"Packed-switch {label} has an invalid first key.",
                    dex_name,
                    source_path,
                )
            )
        for position, raw_entry in enumerate(content):
            target = raw_entry.strip()
            entries.append(
                PayloadEntry(
                    key=first_key + position if first_key is not None else None,
                    target_label=target if target.startswith(":") else None,
                    value=None,
                    raw_text=raw_entry,
                )
            )
    elif payload_kind is PayloadKind.SPARSE_SWITCH:
        for raw_entry in content:
            key_text, separator, target_text = raw_entry.strip().partition("->")
            key = _parse_smali_int(key_text.strip()) if separator else None
            target = target_text.strip() if separator else ""
            if key is None or not target.startswith(":"):
                issues.append(
                    _smali_issue(
                        "SMALI_PAYLOAD_ENTRY_INVALID",
                        f"Sparse-switch {label} contains an invalid entry.",
                        dex_name,
                        source_path,
                    )
                )
            entries.append(
                PayloadEntry(
                    key=key,
                    target_label=target if target.startswith(":") else None,
                    value=None,
                    raw_text=raw_entry,
                )
            )
    else:
        for raw_entry in content:
            entries.append(
                PayloadEntry(
                    key=None,
                    target_label=None,
                    value=raw_entry.strip(),
                    raw_text=raw_entry,
                )
            )

    payload = DataPayload(
        label=label,
        kind=payload_kind,
        entries=tuple(entries),
        raw_text="\n".join(method_lines[label_index : end_index + 1]),
        source_path=source_path,
        start_line=start_line + label_index,
        end_line=start_line + end_index,
        start_offset=None,
        end_offset=None,
    )
    return payload, end_index, tuple(issues)


def _method_parameter_types(descriptor: str) -> tuple[str, ...] | None:
    if not _is_valid_method_descriptor(descriptor):
        return None
    closing = descriptor.index(")")
    parameters: list[str] = []
    position = 1
    while position < closing:
        next_position = _consume_descriptor_type(
            descriptor,
            position,
            limit=closing,
            allow_void=False,
        )
        if next_position is None:
            return None
        parameters.append(descriptor[position:next_position])
        position = next_position
    return tuple(parameters)


def _build_method_parameters(
    parameter_types: tuple[str, ...],
    *,
    is_static: bool,
    parameter_names: dict[str, str],
    legacy_parameter_names: list[str],
) -> tuple[MethodParameter, ...]:
    parameters: list[MethodParameter] = []
    register_index = 0 if is_static else 1
    for position, type_descriptor in enumerate(parameter_types):
        register = f"p{register_index}"
        name = parameter_names.get(register)
        if name is None and position < len(legacy_parameter_names):
            name = legacy_parameter_names[position]
        parameters.append(
            MethodParameter(
                position=position,
                type_descriptor=type_descriptor,
                register=register,
                name=name,
            )
        )
        register_index += 2 if type_descriptor in {"J", "D"} else 1
    return tuple(parameters)


def _incoming_register_count(
    parameter_types: tuple[str, ...],
    is_static: bool,
) -> int:
    return (0 if is_static else 1) + sum(
        2 if parameter_type in {"J", "D"} else 1
        for parameter_type in parameter_types
    )


def _parse_instruction_text(instruction: str) -> tuple[str, tuple[str, ...]]:
    opcode, separator, operand_text = instruction.partition(" ")
    return opcode, _split_operands(operand_text.strip()) if separator else ()


def _split_operands(operand_text: str) -> tuple[str, ...]:
    if not operand_text:
        return ()
    operands: list[str] = []
    current: list[str] = []
    brace_depth = 0
    in_quote = False
    escaped = False
    for character in operand_text:
        if escaped:
            current.append(character)
            escaped = False
            continue
        if character == "\\" and in_quote:
            current.append(character)
            escaped = True
            continue
        if character == '"':
            in_quote = not in_quote
            current.append(character)
            continue
        if not in_quote:
            if character == "{":
                brace_depth += 1
            elif character == "}":
                brace_depth = max(0, brace_depth - 1)
            elif character == "," and brace_depth == 0:
                operands.append("".join(current).strip())
                current = []
                continue
        current.append(character)
    if current:
        operands.append("".join(current).strip())
    return tuple(operand for operand in operands if operand)


def _next_content_line(lines: list[str], start: int) -> int | None:
    for index in range(start, len(lines)):
        stripped = lines[index].strip()
        if stripped and not stripped.startswith("#"):
            return index
    return None


def _parse_nonnegative_int(value: str) -> int | None:
    try:
        parsed = int(value, 0)
    except ValueError:
        return None
    return parsed if parsed >= 0 else None


def _parse_smali_int(value: str) -> int | None:
    normalized = value.strip()
    if normalized and normalized[-1] in "tTsSlL":
        normalized = normalized[:-1]
    try:
        return int(normalized, 0)
    except ValueError:
        return None


def _quoted_directive_value(directive: str) -> str | None:
    match = re.search(r'"(?P<value>(?:[^"\\]|\\.)*)"', directive)
    return match.group("value") if match else None


def _coerce_process_text(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode(errors="replace")
    return value


def _smali_issue(
    code: str,
    message: str,
    dex_name: str,
    source_path: str,
) -> ExtractionIssue:
    return ExtractionIssue(
        stage=ExtractionStage.SMALI_PARSE,
        code=code,
        message=message,
        severity=IssueSeverity.ERROR,
        dex_name=dex_name,
        source_path=source_path,
    )


def _build_dex_artifact(archive: ZipFile, dex_name: str) -> DexArtifact:
    digest = hashlib.sha256()
    size_bytes = 0
    try:
        with archive.open(dex_name) as dex_file:
            for chunk in iter(lambda: dex_file.read(1024 * 1024), b""):
                digest.update(chunk)
                size_bytes += len(chunk)
    except (OSError, RuntimeError, ValueError) as exc:
        raise ExtractionError(
            ExtractionIssue(
                stage=ExtractionStage.VALIDATION,
                code="DEX_ENTRY_READ_FAILED",
                message=f"Unable to read {dex_name}: {exc}",
                severity=IssueSeverity.ERROR,
                dex_name=dex_name,
                source_path=dex_name,
            )
        ) from exc

    return DexArtifact(
        dex_name=dex_name,
        archive_path=dex_name,
        extracted_path=None,
        sha256=digest.hexdigest(),
        size_bytes=size_bytes,
        expected_smali_directory=_expected_smali_directory(dex_name),
    )


def _expected_smali_directory(dex_name: str) -> str:
    match = DEX_NAME_PATTERN.fullmatch(dex_name)
    if match is None:
        raise ValueError(f"Unsupported DEX filename: {dex_name}")
    number = match.group("number")
    return "smali" if not number else f"smali_classes{number}"


def _dex_sort_key(dex_name: str) -> tuple[int, str]:
    match = DEX_NAME_PATTERN.fullmatch(dex_name)
    if match is None:
        return (2**31 - 1, dex_name)
    number = match.group("number")
    return (1 if not number else int(number), dex_name)


def _assert_readable_member(archive: ZipFile, member_name: str) -> None:
    try:
        with archive.open(member_name) as member:
            member.read(1)
    except (OSError, RuntimeError, ValueError) as exc:
        raise ExtractionError(
            ExtractionIssue(
                stage=ExtractionStage.VALIDATION,
                code="APK_ENTRY_READ_FAILED",
                message=f"Unable to read {member_name}: {exc}",
                severity=IssueSeverity.ERROR,
                source_path=member_name,
            )
        ) from exc


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as apk_file:
            for chunk in iter(lambda: apk_file.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as exc:
        raise ExtractionError(
            ExtractionIssue(
                stage=ExtractionStage.VALIDATION,
                code="APK_HASH_FAILED",
                message=f"Unable to calculate APK SHA-256: {exc}",
                severity=IssueSeverity.ERROR,
                source_path=str(path),
            )
        ) from exc
    return digest.hexdigest()


def _is_valid_method_name(method_name: str) -> bool:
    if method_name in {"<init>", "<clinit>"}:
        return True
    return bool(method_name) and not any(
        character.isspace() or character in ".;[/<>(" for character in method_name
    )


def _is_valid_method_descriptor(descriptor: str) -> bool:
    if not descriptor.startswith("("):
        return False
    closing = descriptor.find(")")
    if closing < 1:
        return False

    position = 1
    while position < closing:
        next_position = _consume_descriptor_type(
            descriptor, position, limit=closing, allow_void=False
        )
        if next_position is None:
            return False
        position = next_position
    if position != closing:
        return False

    return_position = _consume_descriptor_type(
        descriptor, closing + 1, limit=len(descriptor), allow_void=True
    )
    return return_position == len(descriptor)


def _consume_descriptor_type(
    descriptor: str,
    position: int,
    *,
    limit: int,
    allow_void: bool,
) -> int | None:
    if position >= limit:
        return None

    current = descriptor[position]
    if current == "V":
        return position + 1 if allow_void else None
    if current in "ZBSCIJFD":
        return position + 1
    if current == "L":
        end = descriptor.find(";", position + 1, limit)
        if end == -1 or end == position + 1:
            return None
        class_body = descriptor[position + 1 : end]
        if any(character.isspace() or character in ".;[" for character in class_body):
            return None
        return end + 1
    if current == "[":
        element_position = position
        while element_position < limit and descriptor[element_position] == "[":
            element_position += 1
        return _consume_descriptor_type(
            descriptor,
            element_position,
            limit=limit,
            allow_void=False,
        )
    return None


def _raise_validation(code: str, message: str) -> None:
    raise ExtractionError(
        ExtractionIssue(
            stage=ExtractionStage.VALIDATION,
            code=code,
            message=message,
            severity=IssueSeverity.ERROR,
        )
    )


def _raise_workspace(code: str, message: str) -> None:
    raise ExtractionError(
        ExtractionIssue(
            stage=ExtractionStage.WORKSPACE,
            code=code,
            message=message,
            severity=IssueSeverity.ERROR,
        )
    )


__all__ = [
    "DEFAULT_ARTIFACT_ROOT",
    "DataPayload",
    "DexArtifact",
    "ExceptionHandler",
    "ExtractedMethod",
    "ExtractionBackend",
    "ExtractionError",
    "ExtractionIssue",
    "ExtractionResult",
    "ExtractionStage",
    "ExtractionStatus",
    "ExtractionWorkspace",
    "Instruction",
    "IssueSeverity",
    "Label",
    "MethodParameter",
    "NativeLibrary",
    "PayloadEntry",
    "PayloadKind",
    "RawDexExtraction",
    "ToolExecution",
    "ValidatedApk",
    "extract_apk",
    "extract_native_libraries",
    "extract_raw_dex",
    "parse_smali_file",
    "prepare_workspace",
    "raw_dex_source_path",
    "run_apktool",
    "run_jadx",
    "validate_apk",
]
