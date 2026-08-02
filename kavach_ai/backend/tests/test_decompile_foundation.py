from __future__ import annotations

import hashlib
import stat
import subprocess
from dataclasses import FrozenInstanceError, replace
from pathlib import Path
from zipfile import ZipFile

import pytest

from kavach_ai.backend.pipeline.stage2_static import decompile
from kavach_ai.backend.pipeline.stage2_static.decompile import (
    DEFAULT_ARTIFACT_ROOT,
    PROJECT_ROOT,
    DataPayload,
    DexArtifact,
    ExceptionHandler,
    ExtractedMethod,
    ExtractionBackend,
    ExtractionError,
    ExtractionIssue,
    ExtractionResult,
    ExtractionStage,
    ExtractionStatus,
    ExtractionWorkspace,
    Instruction,
    IssueSeverity,
    Label,
    MethodParameter,
    NativeLibrary,
    PayloadEntry,
    PayloadKind,
    RawDexExtraction,
    ToolExecution,
    extract_apk,
    extract_native_libraries,
    extract_raw_dex,
    parse_smali_file,
    prepare_workspace,
    raw_dex_source_path,
    run_apktool,
    run_jadx,
    validate_apk,
)


APK_HASH = "a" * 64


def _write_apk(
    path: Path,
    *,
    dex_entries: tuple[str, ...] = ("classes.dex",),
    native_entries: tuple[str, ...] = (),
    include_manifest: bool = True,
) -> Path:
    with ZipFile(path, "w") as archive:
        if include_manifest:
            archive.writestr("AndroidManifest.xml", b"manifest")
        for index, dex_name in enumerate(dex_entries):
            archive.writestr(dex_name, f"dex-{index}-{dex_name}".encode())
        for native_path in native_entries:
            archive.writestr(native_path, f"native-{native_path}".encode())
    return path


def _instruction() -> Instruction:
    return Instruction(
        index=0,
        offset=None,
        opcode="return-void",
        operands=(),
        raw_text="return-void",
    )


def _method(
    *,
    class_name: str = "Lcom/example/Test;",
    method_name: str = "run",
    descriptor: str = "()V",
    full_signature: str | None = None,
    access_flags: tuple[str, ...] = ("public",),
    instructions: tuple[Instruction, ...] | None = None,
    backend: ExtractionBackend = ExtractionBackend.SMALI,
) -> ExtractedMethod:
    signature = (
        full_signature
        if full_signature is not None
        else f"{class_name}->{method_name}{descriptor}"
    )
    return ExtractedMethod(
        dex_name="classes.dex",
        class_name=class_name,
        method_name=method_name,
        descriptor=descriptor,
        full_signature=signature,
        access_flags=access_flags,
        parameters=(),
        register_count=1,
        local_count=1,
        instructions=(_instruction(),) if instructions is None else instructions,
        labels=(),
        exception_handlers=(),
        declared_source_file="Test.java",
        source_path="smali/com/example/Test.smali",
        backend=backend,
    )


def _result(
    tmp_path: Path,
    *,
    methods: tuple[ExtractedMethod, ...] = (),
    status: ExtractionStatus = ExtractionStatus.SUCCESS,
    issues: tuple[ExtractionIssue, ...] = (),
    apktool_execution: ToolExecution | None = None,
    jadx_execution: ToolExecution | None = None,
) -> ExtractionResult:
    artifact_path = tmp_path / APK_HASH
    return ExtractionResult(
        apk_path="/fixtures/sample.apk",
        apk_hash=APK_HASH,
        artifact_path=str(artifact_path),
        dex_files=(),
        methods=methods,
        native_libraries=(),
        apktool_output_path=str(artifact_path / "apktool"),
        jadx_output_path=str(artifact_path / "jadx"),
        raw_dex_output_path=str(artifact_path / "raw_dex"),
        native_output_path=str(artifact_path / "native"),
        backend_used=ExtractionBackend.SMALI if methods else None,
        apktool_execution=apktool_execution,
        jadx_execution=jadx_execution,
        raw_dex_fallback_used=False,
        status=status,
        issues=issues,
    )


def _tool_execution(
    *,
    installed: bool = True,
    return_code: int | None = 0,
    timed_out: bool = False,
) -> ToolExecution:
    return ToolExecution(
        tool="fixture-tool",
        command=("fixture-tool", "--version"),
        installed=installed,
        return_code=return_code,
        timed_out=timed_out,
        stdout="",
        stderr="",
        output_path=None,
        duration_seconds=0.01,
    )


def test_enum_values_and_dataclasses_are_immutable() -> None:
    assert ExtractionBackend.SMALI.value == "smali"
    assert ExtractionBackend.RAW_DEX.value == "raw_dex"
    assert ExtractionBackend.MIXED.value == "mixed"
    assert [status.value for status in ExtractionStatus] == [
        "SUCCESS",
        "PARTIAL",
        "FAILED",
    ]
    assert IssueSeverity.WARNING.value == "warning"
    assert ExtractionStage.SMALI_PARSE.value == "smali_parse"

    instances = (
        ExtractionIssue(
            ExtractionStage.VALIDATION,
            "CODE",
            "message",
            IssueSeverity.WARNING,
        ),
        DexArtifact(
            "classes.dex",
            "classes.dex",
            None,
            APK_HASH,
            3,
            "smali",
        ),
        NativeLibrary(
            "libx.so",
            "arm64-v8a",
            "lib/arm64-v8a/libx.so",
            "/tmp/libx.so",
            APK_HASH,
            3,
        ),
        MethodParameter(0, "Ljava/lang/String;", "p0", "value"),
        _instruction(),
        Label(":start", 0, None),
        ExceptionHandler(
            "Ljava/lang/Exception;",
            ":try_start",
            ":try_end",
            ":handler",
            ".catch ...",
        ),
        PayloadEntry(1, ":case_1", None, "    :case_1"),
        DataPayload(
            ":payload",
            PayloadKind.PACKED_SWITCH,
            (PayloadEntry(1, ":case_1", None, "    :case_1"),),
            ":payload\n.packed-switch 0x1\n    :case_1\n.end packed-switch",
            "/tmp/Test.smali",
            10,
            13,
        ),
        _method(),
        ExtractionWorkspace(
            Path("/tmp/artifact"),
            Path("/tmp/artifact/apktool"),
            Path("/tmp/artifact/jadx"),
            Path("/tmp/artifact/raw_dex"),
            Path("/tmp/artifact/native"),
        ),
        RawDexExtraction((), (), (), False),
    )
    for instance in instances:
        with pytest.raises(FrozenInstanceError):
            instance.__setattr__("unexpected", True)


@pytest.mark.parametrize(
    ("installed", "return_code", "timed_out", "expected"),
    [
        (True, 0, False, True),
        (True, 0, True, False),
        (False, 0, False, False),
        (True, 1, False, False),
        (True, None, False, False),
    ],
)
def test_tool_execution_success(
    installed: bool,
    return_code: int | None,
    timed_out: bool,
    expected: bool,
) -> None:
    execution = _tool_execution(
        installed=installed,
        return_code=return_code,
        timed_out=timed_out,
    )
    assert execution.success is expected


def test_method_usability_rules() -> None:
    concrete = _method(access_flags=("PUBLIC", "public"))
    native = _method(access_flags=("public", "native"), instructions=())
    abstract = _method(access_flags=("ABSTRACT", "public"), instructions=())
    empty = _method(instructions=())

    assert concrete.access_flags == ("public",)
    assert concrete.is_usable
    assert not concrete.is_native
    assert not concrete.is_abstract

    assert native.is_native
    assert not native.is_usable
    assert abstract.is_abstract
    assert not abstract.is_usable
    assert not empty.is_usable


@pytest.mark.parametrize(
    ("method_name", "descriptor"),
    [
        ("<init>", "()V"),
        ("<clinit>", "()V"),
        ("primitives", "(ZBSCIJFD)V"),
        ("objects", "(Ljava/lang/String;Lcom/example/Input;)Ljava/lang/Object;"),
        ("array", "([I)[Ljava/lang/String;"),
        ("multiArray", "([[Ljava/lang/String;[[I)V"),
        ("returnsVoid", "(I)V"),
    ],
)
def test_valid_method_descriptors(method_name: str, descriptor: str) -> None:
    assert _method(method_name=method_name, descriptor=descriptor).has_valid_identity


@pytest.mark.parametrize(
    "descriptor",
    [
        "I)V",
        "(I",
        "(V)V",
        "(Ljava/lang/String)V",
        "([V)V",
        "([[)V",
        "(Ljava.lang.String;)V",
        "()Vtrailing",
        "()",
        "",
    ],
)
def test_invalid_method_descriptors(descriptor: str) -> None:
    assert not _method(descriptor=descriptor).has_valid_identity


@pytest.mark.parametrize(
    "method",
    [
        _method(class_name="com/example/Test"),
        _method(class_name="Lcom/example/Test"),
        _method(method_name="bad name"),
        _method(method_name="bad/name"),
        _method(full_signature="Lcom/example/Test;->other()V"),
    ],
)
def test_invalid_method_identity_is_not_usable(method: ExtractedMethod) -> None:
    assert not method.has_valid_identity
    assert not method.is_usable


def test_extraction_result_derived_properties_and_jadx_warning(
    tmp_path: Path,
) -> None:
    concrete = _method()
    native = _method(
        method_name="nativeCall",
        full_signature="Lcom/example/Test;->nativeCall()V",
        access_flags=("native", "public"),
        instructions=(),
    )
    warning = ExtractionIssue(
        stage=ExtractionStage.JADX,
        code="JADX_FAILED",
        message="Readable source was not generated.",
        severity=IssueSeverity.WARNING,
    )
    error = ExtractionIssue(
        stage=ExtractionStage.SMALI_PARSE,
        code="FIXTURE_ERROR",
        message="Fixture error.",
        severity=IssueSeverity.ERROR,
    )
    result = _result(
        tmp_path,
        methods=(concrete, native),
        status=ExtractionStatus.SUCCESS,
        issues=(warning, error),
        apktool_execution=_tool_execution(),
        jadx_execution=_tool_execution(return_code=1),
    )

    assert result.status is ExtractionStatus.SUCCESS
    assert result.apktool_success
    assert not result.jadx_success
    assert result.warnings == (warning,)
    assert result.errors == (error,)
    assert result.usable_methods == (concrete,)
    assert result.native_method_signatures == (native.full_signature,)


def test_validate_single_dex_apk(tmp_path: Path) -> None:
    apk = _write_apk(tmp_path / "single.apk")
    validated = validate_apk(apk)

    assert validated.apk_hash == hashlib.sha256(apk.read_bytes()).hexdigest()
    assert [dex.dex_name for dex in validated.dex_files] == ["classes.dex"]
    assert validated.dex_files[0].expected_smali_directory == "smali"
    assert validated.dex_files[0].extracted_path is None
    assert validated.issues == ()
    assert validated.native_archive_paths == ()


def test_validate_multidex_uses_natural_order(tmp_path: Path) -> None:
    apk = _write_apk(
        tmp_path / "multidex.apk",
        dex_entries=("classes10.dex", "classes3.dex", "classes.dex", "classes2.dex"),
    )
    validated = validate_apk(apk)

    assert [dex.dex_name for dex in validated.dex_files] == [
        "classes.dex",
        "classes2.dex",
        "classes3.dex",
        "classes10.dex",
    ]
    assert [dex.expected_smali_directory for dex in validated.dex_files] == [
        "smali",
        "smali_classes2",
        "smali_classes3",
        "smali_classes10",
    ]


def test_validate_no_dex_and_native_entries(tmp_path: Path) -> None:
    apk = _write_apk(
        tmp_path / "native.apk",
        dex_entries=(),
        native_entries=(
            "lib/x86/libsample.so",
            "lib/arm64-v8a/libsample.so",
        ),
    )
    validated = validate_apk(apk)

    assert validated.dex_files == ()
    assert [issue.code for issue in validated.issues] == ["NO_DEX_FILES"]
    assert validated.native_archive_paths == (
        "lib/arm64-v8a/libsample.so",
        "lib/x86/libsample.so",
    )


def test_native_library_absence_is_not_an_issue(tmp_path: Path) -> None:
    validated = validate_apk(_write_apk(tmp_path / "no-native.apk"))
    assert validated.native_archive_paths == ()
    assert validated.issues == ()
    libraries, issues = extract_native_libraries(validated, tmp_path / "native")
    assert libraries == ()
    assert issues == ()


def test_extract_native_libraries_preserves_paths_and_metadata(
    tmp_path: Path,
) -> None:
    native_entries = (
        "lib/x86/libz.so",
        "lib/arm64-v8a/sub/libx.so",
        "lib/armeabi-v7a/liba.so",
    )
    apk = _write_apk(
        tmp_path / "native.apk",
        native_entries=native_entries,
    )
    validated = validate_apk(apk)

    libraries, issues = extract_native_libraries(validated, tmp_path / "native")

    assert issues == ()
    assert [library.archive_path for library in libraries] == sorted(native_entries)
    assert [library.abi for library in libraries] == [
        "arm64-v8a",
        "armeabi-v7a",
        "x86",
    ]
    nested = libraries[0]
    expected = f"native-{nested.archive_path}".encode()
    assert nested.filename == "libx.so"
    assert Path(nested.extracted_path).relative_to(tmp_path / "native") == Path(
        "arm64-v8a/sub/libx.so"
    )
    assert Path(nested.extracted_path).read_bytes() == expected
    assert nested.size_bytes == len(expected)
    assert nested.sha256 == hashlib.sha256(expected).hexdigest()


def test_native_invalid_path_does_not_stop_later_library(tmp_path: Path) -> None:
    apk = _write_apk(
        tmp_path / "unsafe-native.apk",
        native_entries=(
            "lib/arm64-v8a/../escape.so",
            "lib/x86/libgood.so",
        ),
    )
    validated = validate_apk(apk)

    libraries, issues = extract_native_libraries(validated, tmp_path / "native")

    assert [library.archive_path for library in libraries] == [
        "lib/x86/libgood.so"
    ]
    assert [issue.code for issue in issues] == ["NATIVE_ARCHIVE_PATH_INVALID"]
    assert not (tmp_path / "native" / "escape.so").exists()


@pytest.mark.parametrize(
    "unsafe_path",
    [
        "/lib/arm64-v8a/libx.so",
        "lib//libx.so",
        "lib/arm64-v8a/../../libx.so",
        r"lib\\arm64-v8a\\libx.so",
        "assets/arm64-v8a/libx.so",
    ],
)
def test_native_archive_path_validation_rejects_unsafe_entries(
    tmp_path: Path,
    unsafe_path: str,
) -> None:
    apk = _write_apk(tmp_path / "sample.apk")
    validated = validate_apk(apk)
    unsafe = replace(validated, native_archive_paths=(unsafe_path,))

    libraries, issues = extract_native_libraries(unsafe, tmp_path / "native")

    assert libraries == ()
    assert [issue.code for issue in issues] == ["NATIVE_ARCHIVE_PATH_INVALID"]


def test_native_output_symlink_is_rejected(tmp_path: Path) -> None:
    apk = _write_apk(
        tmp_path / "native.apk",
        native_entries=("lib/arm64-v8a/libx.so",),
    )
    validated = validate_apk(apk)
    output = tmp_path / "native"
    outside = tmp_path / "outside"
    output.mkdir()
    outside.mkdir()
    (output / "arm64-v8a").symlink_to(outside, target_is_directory=True)

    libraries, issues = extract_native_libraries(validated, output)

    assert libraries == ()
    assert [issue.code for issue in issues] == [
        "NATIVE_LIBRARY_EXTRACTION_FAILED"
    ]
    assert not (outside / "libx.so").exists()


def test_native_archive_symlink_member_is_rejected(tmp_path: Path) -> None:
    from zipfile import ZipInfo

    apk = tmp_path / "native-link.apk"
    link = ZipInfo("lib/arm64-v8a/liblink.so")
    link.create_system = 3
    link.external_attr = (stat.S_IFLNK | 0o777) << 16
    with ZipFile(apk, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"manifest")
        archive.writestr("classes.dex", b"dex")
        archive.writestr(link, b"libtarget.so")
    validated = validate_apk(apk)

    libraries, issues = extract_native_libraries(validated, tmp_path / "native")

    assert libraries == ()
    assert [issue.code for issue in issues] == [
        "NATIVE_LIBRARY_EXTRACTION_FAILED"
    ]


@pytest.mark.parametrize(
    ("values", "expected_fragment"),
    [
        ((2, 1, 2, "a", "a"), "size mismatch"),
        ((1, 1, 1, "a", "b"), "SHA-256 mismatch"),
        ((1, 1, 1, "a", "a"), None),
    ],
)
def test_native_size_and_hash_verification(
    values: tuple[int, int, int, str, str],
    expected_fragment: str | None,
) -> None:
    result = decompile._native_verification_error(
        archive_size=values[0],
        copied_size=values[1],
        extracted_size=values[2],
        archive_hash=values[3],
        extracted_hash=values[4],
    )
    if expected_fragment is None:
        assert result is None
    else:
        assert expected_fragment in result


def test_native_hash_mismatch_is_structured(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    apk = _write_apk(
        tmp_path / "native.apk",
        native_entries=("lib/x86/libx.so",),
    )
    validated = validate_apk(apk)
    monkeypatch.setattr(decompile, "_sha256_regular_file", lambda path: "0" * 64)

    libraries, issues = extract_native_libraries(validated, tmp_path / "native")

    assert libraries == ()
    assert [issue.code for issue in issues] == [
        "NATIVE_LIBRARY_EXTRACTION_FAILED"
    ]
    assert not (tmp_path / "native" / "x86" / "libx.so").exists()


@pytest.mark.parametrize(
    ("fixture_name", "expected_code"),
    [
        ("missing", "APK_NOT_FOUND"),
        ("wrong_extension", "INVALID_APK_EXTENSION"),
        ("invalid_zip", "INVALID_APK_ZIP"),
        ("missing_manifest", "MISSING_ANDROID_MANIFEST"),
    ],
)
def test_validation_errors_are_structured(
    tmp_path: Path,
    fixture_name: str,
    expected_code: str,
) -> None:
    if fixture_name == "missing":
        path = tmp_path / "missing.apk"
    elif fixture_name == "wrong_extension":
        path = tmp_path / "sample.zip"
        path.write_bytes(b"zip")
    elif fixture_name == "invalid_zip":
        path = tmp_path / "sample.apk"
        path.write_bytes(b"not a zip")
    else:
        path = _write_apk(
            tmp_path / "sample.apk",
            include_manifest=False,
        )

    with pytest.raises(ExtractionError) as raised:
        validate_apk(path)

    assert raised.value.issue.stage is ExtractionStage.VALIDATION
    assert raised.value.issue.severity is IssueSeverity.ERROR
    assert raised.value.issue.code == expected_code


def test_prepare_workspace_creates_expected_directories(tmp_path: Path) -> None:
    workspace = prepare_workspace(APK_HASH, tmp_path / "artifacts" / "decompile")

    assert workspace.artifact_path.name == APK_HASH
    assert workspace.apktool_path.is_dir()
    assert workspace.jadx_path.is_dir()
    assert workspace.raw_dex_path.is_dir()
    assert workspace.native_path.is_dir()
    assert {path.name for path in workspace.artifact_path.iterdir()} == {
        "apktool",
        "jadx",
        "raw_dex",
        "native",
    }


def test_repeated_workspace_cleanup_preserves_unrelated_files(
    tmp_path: Path,
) -> None:
    root = tmp_path / "artifacts" / "decompile"
    first = prepare_workspace(APK_HASH, root)
    stale_file = first.apktool_path / "stale.txt"
    stale_file.write_text("stale")
    unrelated_file = root / "unrelated.txt"
    unrelated_file.write_text("keep")

    second = prepare_workspace(APK_HASH, root)

    assert not stale_file.exists()
    assert unrelated_file.read_text() == "keep"
    assert second.apktool_path.is_dir()


@pytest.mark.parametrize("invalid_hash", ["", "abc", "g" * 64, "a" * 63])
def test_prepare_workspace_rejects_invalid_hashes(
    tmp_path: Path,
    invalid_hash: str,
) -> None:
    with pytest.raises(ExtractionError) as raised:
        prepare_workspace(invalid_hash, tmp_path)
    assert raised.value.issue.code == "INVALID_APK_HASH"


def test_prepare_workspace_rejects_symlink_target(tmp_path: Path) -> None:
    root = tmp_path / "artifacts" / "decompile"
    outside = tmp_path / "outside"
    root.mkdir(parents=True)
    outside.mkdir()
    (root / APK_HASH).symlink_to(outside, target_is_directory=True)

    with pytest.raises(ExtractionError) as raised:
        prepare_workspace(APK_HASH, root)

    assert raised.value.issue.code == "UNSAFE_WORKSPACE_SYMLINK"
    assert outside.is_dir()


def test_raw_dex_source_path_is_stable() -> None:
    assert (
        raw_dex_source_path(APK_HASH, "classes2.dex")
        == f"apk://{APK_HASH}!/classes2.dex"
    )
    with pytest.raises(ValueError):
        raw_dex_source_path("invalid", "classes.dex")
    with pytest.raises(ValueError):
        raw_dex_source_path(APK_HASH, "nested/classes.dex")


class _OperandKind:
    def __init__(self, name: str):
        self.name = name


REGISTER = _OperandKind("REGISTER")
OFFSET = _OperandKind("OFFSET")


class _FakeInstruction:
    def __init__(
        self,
        name: str,
        output: str = "",
        operands: tuple[tuple[object, ...], ...] = (),
        length: int = 2,
    ):
        self.name = name
        self.output = output
        self.operands = operands
        self.length = length

    def get_name(self) -> str:
        return self.name

    def get_output(self, offset: int) -> str:
        return self.output

    def get_operands(self, offset: int) -> tuple[tuple[object, ...], ...]:
        return self.operands

    def get_length(self) -> int:
        return self.length


class _FakeSwitchPayload(_FakeInstruction):
    def __init__(
        self,
        name: str,
        keys: tuple[int, ...],
        targets: tuple[int, ...],
        *,
        length: int,
    ):
        super().__init__(name, length=length)
        self.keys = keys
        self.targets = targets

    def get_keys(self) -> tuple[int, ...]:
        return self.keys

    def get_targets(self) -> tuple[int, ...]:
        return self.targets


class _FakeArrayPayload(_FakeInstruction):
    def __init__(self, data: bytes, element_width: int):
        super().__init__(
            "fill-array-data-payload",
            length=8 + len(data),
        )
        self.data = data
        self.element_width = element_width
        self.size = len(data) // element_width

    def get_data(self) -> bytes:
        return self.data


class _FakeTypedHandler:
    def get_type_idx(self) -> int:
        return 1

    def get_addr(self) -> int:
        return 2


class _FakeHandler:
    def get_off(self) -> int:
        return 104

    def get_handlers(self) -> list[_FakeTypedHandler]:
        return [_FakeTypedHandler()]

    def get_size(self) -> int:
        return -1

    def get_catch_all_addr(self) -> int:
        return 2


class _FakeHandlerList:
    def get_off(self) -> int:
        return 100

    def get_list(self) -> list[_FakeHandler]:
        return [_FakeHandler()]


class _FakeTry:
    def get_start_addr(self) -> int:
        return 0

    def get_insn_count(self) -> int:
        return 2

    def get_handler_off(self) -> int:
        return 4


class _FakeCode:
    def __init__(
        self,
        registers: int,
        incoming: int,
        *,
        with_handlers: bool = False,
    ):
        self.registers = registers
        self.incoming = incoming
        self.with_handlers = with_handlers

    def get_registers_size(self) -> int:
        return self.registers

    def get_ins_size(self) -> int:
        return self.incoming

    def get_tries_size(self) -> int:
        return 1 if self.with_handlers else 0

    def get_handlers(self) -> _FakeHandlerList:
        return _FakeHandlerList()

    def get_tries(self) -> list[_FakeTry]:
        return [_FakeTry()]


class _FakeMethod:
    def __init__(
        self,
        name: str,
        descriptor: str,
        access_flags: str,
        code: _FakeCode | None,
        rows: tuple[tuple[int, _FakeInstruction], ...] = (),
        *,
        fail_instructions: bool = False,
    ):
        self.name = name
        self.descriptor = descriptor
        self.access_flags = access_flags
        self.code = code
        self.rows = rows
        self.fail_instructions = fail_instructions

    def get_name(self) -> str:
        return self.name

    def get_descriptor(self) -> str:
        return self.descriptor

    def get_access_flags_string(self) -> str:
        return self.access_flags

    def get_code(self) -> _FakeCode | None:
        return self.code

    def get_instructions_idx(self) -> object:
        if self.fail_instructions:
            def broken() -> object:
                yield 0, _FakeInstruction("const/4", "v0, 0x0")
                raise ValueError("invalid instruction stream at byte 2")

            return broken()
        return iter(self.rows)


class _FakeClass:
    def __init__(
        self,
        name: str,
        methods: tuple[_FakeMethod, ...],
        *,
        fail_methods: bool = False,
    ):
        self.name = name
        self.methods = methods
        self.fail_methods = fail_methods

    def get_name(self) -> str:
        return self.name

    def get_source_file_idx(self) -> int:
        return 7

    def get_methods(self) -> list[_FakeMethod]:
        if self.fail_methods:
            raise ValueError("corrupted class data")
        return list(self.methods)


class _FakeDex:
    def __init__(
        self,
        classes: tuple[_FakeClass, ...],
        *,
        fail_classes: bool = False,
    ):
        self.classes = classes
        self.fail_classes = fail_classes

    def get_classes(self) -> list[_FakeClass]:
        if self.fail_classes:
            raise ValueError("corrupted class table")
        return list(self.classes)

    def get_cm_string(self, index: int) -> str:
        return "RawSource.java"

    def get_cm_type(self, index: int) -> str:
        return "Ljava/lang/Exception;"


def _rich_fake_dex(class_name: str = "Lx/Raw;") -> _FakeDex:
    constructor = _FakeMethod(
        "<init>",
        "(J)V",
        "public constructor",
        _FakeCode(4, 3),
        (
            (
                0,
                _FakeInstruction(
                    "invoke-direct",
                    "v1, Ljava/lang/Object;-><init>()V",
                    ((REGISTER, 1),),
                    6,
                ),
            ),
            (6, _FakeInstruction("return-void")),
        ),
    )
    choose = _FakeMethod(
        "choose",
        "(I J)V",
        "public static",
        _FakeCode(5, 3, with_handlers=True),
        (
            (
                0,
                _FakeInstruction(
                    "if-eqz",
                    "v2, +000002h",
                    ((REGISTER, 2), (OFFSET, 2)),
                ),
            ),
            (4, _FakeInstruction("return-void")),
        ),
    )
    payload_method = _FakeMethod(
        "payloads",
        "()V",
        "public",
        _FakeCode(2, 1),
        (
            (
                0,
                _FakeInstruction(
                    "packed-switch",
                    "v0, +00000ah",
                    ((REGISTER, 0), (OFFSET, 10)),
                    6,
                ),
            ),
            (
                6,
                _FakeInstruction(
                    "sparse-switch",
                    "v0, +000011h",
                    ((REGISTER, 0), (OFFSET, 17)),
                    6,
                ),
            ),
            (
                12,
                _FakeInstruction(
                    "fill-array-data",
                    "v0, +000018h",
                    ((REGISTER, 0), (OFFSET, 24)),
                    6,
                ),
            ),
            (18, _FakeInstruction("return-void")),
            (
                20,
                _FakeSwitchPayload(
                    "packed-switch-payload",
                    (1, 2),
                    (3, 6),
                    length=12,
                ),
            ),
            (
                40,
                _FakeSwitchPayload(
                    "sparse-switch-payload",
                    (5, 9),
                    (3, 6),
                    length=20,
                ),
            ),
            (60, _FakeArrayPayload(b"\x01\x02", 1)),
        ),
    )
    native = _FakeMethod("nativeCall", "()V", "public native", None)
    abstract = _FakeMethod("abstractCall", "()V", "public abstract", None)
    return _FakeDex(
        (
            _FakeClass(
                class_name,
                (payload_method, native, constructor, abstract, choose),
            ),
        )
    )


def test_extract_raw_dex_copies_verifies_and_converts_methods(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    apk = _write_apk(tmp_path / "sample.apk")
    validated = validate_apk(apk)
    monkeypatch.setattr(
        decompile,
        "_load_androguard_dex",
        lambda raw: _rich_fake_dex(),
    )

    result = extract_raw_dex(validated, tmp_path / "raw_dex")

    assert result.complete_coverage
    assert result.issues == ()
    assert result.dex_files[0].extracted_path is not None
    copied = Path(result.dex_files[0].extracted_path)
    assert copied.read_bytes() == b"dex-0-classes.dex"
    assert [method.method_name for method in result.methods] == [
        "<init>",
        "abstractCall",
        "choose",
        "nativeCall",
        "payloads",
    ]

    constructor = next(method for method in result.methods if method.method_name == "<init>")
    assert constructor.register_count == 4
    assert constructor.local_count == 1
    assert constructor.parameters == (MethodParameter(0, "J", "p1", None),)
    assert constructor.instructions[0].operands[0] == "p0"
    assert constructor.declared_source_file == "RawSource.java"
    assert constructor.source_path == f"apk://{validated.apk_hash}!/classes.dex"

    choose = next(method for method in result.methods if method.method_name == "choose")
    assert choose.descriptor == "(IJ)V"
    assert [parameter.register for parameter in choose.parameters] == ["p0", "p1"]
    assert [instruction.index for instruction in choose.instructions] == [0, 1]
    assert [instruction.offset for instruction in choose.instructions] == [0, 4]
    assert choose.instructions[0].operands == ("p0", ":raw_00000004")
    assert choose.labels == (
        Label(":raw_00000000", 0, 0),
        Label(":raw_00000004", 1, 4),
    )
    assert [handler.exception_type for handler in choose.exception_handlers] == [
        "Ljava/lang/Exception;",
        None,
    ]

    native = next(method for method in result.methods if method.method_name == "nativeCall")
    abstract = next(
        method for method in result.methods if method.method_name == "abstractCall"
    )
    assert native.is_native and not native.is_usable
    assert abstract.is_abstract and not abstract.is_usable


def test_raw_dex_payloads_use_offsets_and_no_instruction_indexes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    validated = validate_apk(_write_apk(tmp_path / "sample.apk"))
    monkeypatch.setattr(
        decompile,
        "_load_androguard_dex",
        lambda raw: _rich_fake_dex(),
    )
    result = extract_raw_dex(validated, tmp_path / "raw")
    method = next(method for method in result.methods if method.method_name == "payloads")

    assert [instruction.offset for instruction in method.instructions] == [0, 6, 12, 18]
    assert [payload.kind for payload in method.payloads] == [
        PayloadKind.PACKED_SWITCH,
        PayloadKind.SPARSE_SWITCH,
        PayloadKind.ARRAY_DATA,
    ]
    packed, sparse, array = method.payloads
    assert (packed.start_line, packed.end_line) == (None, None)
    assert (packed.start_offset, packed.end_offset) == (20, 32)
    assert [(entry.key, entry.target_label) for entry in packed.entries] == [
        (1, ":raw_00000006"),
        (2, ":raw_0000000c"),
    ]
    assert [(entry.key, entry.target_label) for entry in sparse.entries] == [
        (5, ":raw_0000000c"),
        (9, ":raw_00000012"),
    ]
    assert [entry.value for entry in array.entries] == ["0x1", "0x2"]
    assert packed.raw_text.startswith(":raw_00000014\n.packed-switch")
    assert {
        label.offset: label.instruction_index
        for label in method.labels
        if label.offset in {20, 40, 60}
    } == {20: None, 40: None, 60: None}


def test_extract_raw_dex_multidex_order_and_failure_isolation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    validated = validate_apk(
        _write_apk(
            tmp_path / "multidex.apk",
            dex_entries=("classes2.dex", "classes.dex", "classes3.dex"),
        )
    )
    loaded = iter(
        (
            _FakeDex(
                (
                    _FakeClass(
                        "Lx/First;",
                        (
                            _FakeMethod(
                                "broken",
                                "()V",
                                "public",
                                _FakeCode(1, 1),
                                fail_instructions=True,
                            ),
                            _FakeMethod(
                                "later",
                                "()V",
                                "public static",
                                _FakeCode(0, 0),
                                ((0, _FakeInstruction("return-void")),),
                            ),
                        ),
                    ),
                )
            ),
            _FakeDex(
                (
                    _FakeClass("Lx/Corrupt;", (), fail_methods=True),
                    _FakeClass(
                        "Lx/Second;",
                        (
                            _FakeMethod(
                                "run",
                                "()V",
                                "public static",
                                _FakeCode(0, 0),
                                ((0, _FakeInstruction("return-void")),),
                            ),
                        ),
                    ),
                )
            ),
            _FakeDex((), fail_classes=True),
        )
    )
    monkeypatch.setattr(
        decompile,
        "_load_androguard_dex",
        lambda raw: next(loaded),
    )

    result = extract_raw_dex(validated, tmp_path / "raw")

    assert [dex.dex_name for dex in result.dex_files] == [
        "classes.dex",
        "classes2.dex",
        "classes3.dex",
    ]
    assert not result.complete_coverage
    assert [method.method_name for method in result.methods] == ["later", "run"]
    codes = {issue.code for issue in result.issues}
    assert "RAW_DEX_METHOD_PARSE_FAILED" in codes
    assert "RAW_DEX_CLASS_METHODS_FAILED" in codes
    assert "RAW_DEX_CLASS_LIST_FAILED" in codes
    method_issue = next(
        issue for issue in result.issues
        if issue.code == "RAW_DEX_METHOD_PARSE_FAILED"
    )
    assert method_issue.class_name == "Lx/First;"
    assert method_issue.method_signature == "Lx/First;->broken()V"
    assert method_issue.byte_offset == 0


def test_extract_raw_dex_reports_corrupted_dex_and_hash_mismatch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    validated = validate_apk(_write_apk(tmp_path / "sample.apk"))
    monkeypatch.setattr(
        decompile,
        "_load_androguard_dex",
        lambda raw: (_ for _ in ()).throw(ValueError("bad DEX")),
    )
    corrupted = extract_raw_dex(validated, tmp_path / "raw-corrupt")
    assert not corrupted.complete_coverage
    assert "RAW_DEX_PARSE_FAILED" in {issue.code for issue in corrupted.issues}

    wrong_hash = (
        replace(validated.dex_files[0], sha256="0" * 64),
    )
    mismatched = extract_raw_dex(
        replace(validated, dex_files=wrong_hash),
        tmp_path / "raw-hash",
    )
    assert "RAW_DEX_HASH_MISMATCH" in {
        issue.code for issue in mismatched.issues
    }
    assert mismatched.dex_files[0].extracted_path is None


def test_raw_no_code_declarations_preserve_complete_coverage(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    validated = validate_apk(_write_apk(tmp_path / "declarations.apk"))
    declarations = _FakeDex(
        (
            _FakeClass(
                "Lx/Declarations;",
                (
                    _FakeMethod("nativeCall", "()V", "public native", None),
                    _FakeMethod("abstractCall", "()V", "public abstract", None),
                ),
            ),
        )
    )
    monkeypatch.setattr(
        decompile,
        "_load_androguard_dex",
        lambda raw: declarations,
    )

    result = extract_raw_dex(validated, tmp_path / "raw")

    assert result.complete_coverage
    assert len(result.methods) == 2
    assert not any(method.is_usable for method in result.methods)
    assert "RAW_DEX_NO_USABLE_METHODS" in {
        issue.code for issue in result.issues
    }


def test_raw_concrete_method_without_code_is_corruption(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    validated = validate_apk(_write_apk(tmp_path / "missing-code.apk"))
    dex = _FakeDex(
        (
            _FakeClass(
                "Lx/MissingCode;",
                (_FakeMethod("run", "()V", "public", None),),
            ),
        )
    )
    monkeypatch.setattr(decompile, "_load_androguard_dex", lambda raw: dex)

    result = extract_raw_dex(validated, tmp_path / "raw")

    assert not result.complete_coverage
    assert result.methods == ()
    assert "RAW_DEX_CONCRETE_METHOD_NO_CODE" in {
        issue.code for issue in result.issues
    }


def test_run_apktool_uses_exact_command_and_captures_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    apk = tmp_path / "sample.apk"
    apk.write_bytes(b"apk")
    output = tmp_path / "apktool"
    captured: dict[str, object] = {}

    monkeypatch.setattr(decompile.shutil, "which", lambda name: "/tools/apktool")

    def fake_run(command: tuple[str, ...], **kwargs: object) -> subprocess.CompletedProcess[str]:
        captured["command"] = command
        captured["kwargs"] = kwargs
        return subprocess.CompletedProcess(command, 0, "apktool stdout", "apktool stderr")

    monkeypatch.setattr(decompile.subprocess, "run", fake_run)
    execution = run_apktool(apk, output, timeout=12.5)

    assert captured["command"] == (
        "/tools/apktool",
        "d",
        "-f",
        "-r",
        "-a",
        "-o",
        str(output.resolve()),
        str(apk.resolve()),
    )
    assert captured["kwargs"] == {
        "capture_output": True,
        "text": True,
        "timeout": 12.5,
        "check": False,
    }
    assert execution.success
    assert execution.stdout == "apktool stdout"
    assert execution.stderr == "apktool stderr"
    assert execution.output_path == str(output.resolve())
    assert execution.duration_seconds >= 0


def test_run_apktool_missing_executable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(decompile.shutil, "which", lambda name: None)
    execution = run_apktool(tmp_path / "sample.apk", tmp_path / "out", timeout=1)
    assert not execution.installed
    assert not execution.success
    assert execution.return_code is None
    assert execution.command[0] == "apktool"


def test_run_apktool_timeout_preserves_streams(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(decompile.shutil, "which", lambda name: "/tools/apktool")

    def timeout(*args: object, **kwargs: object) -> None:
        raise subprocess.TimeoutExpired(
            cmd=("apktool",),
            timeout=1,
            output=b"partial stdout",
            stderr=b"partial stderr",
        )

    monkeypatch.setattr(decompile.subprocess, "run", timeout)
    execution = run_apktool(tmp_path / "sample.apk", tmp_path / "out", timeout=1)
    assert execution.timed_out
    assert not execution.success
    assert execution.stdout == "partial stdout"
    assert execution.stderr == "partial stderr"


def test_run_jadx_uses_exact_command_and_captures_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    apk = tmp_path / "sample.apk"
    apk.write_bytes(b"apk")
    output = tmp_path / "jadx"
    output.mkdir()
    captured: dict[str, object] = {}
    monkeypatch.setattr(decompile.shutil, "which", lambda name: "/tools/jadx")

    def fake_run(
        command: tuple[str, ...],
        **kwargs: object,
    ) -> subprocess.CompletedProcess[str]:
        captured["command"] = command
        captured["kwargs"] = kwargs
        source = output / "sources" / "x" / "Example.java"
        source.parent.mkdir(parents=True)
        source.write_text("package x; class Example {}")
        return subprocess.CompletedProcess(command, 0, "jadx stdout", "jadx stderr")

    monkeypatch.setattr(decompile.subprocess, "run", fake_run)
    execution = run_jadx(apk, output, timeout=17.5)

    assert captured["command"] == (
        "/tools/jadx",
        "--no-res",
        "-d",
        str(output.resolve()),
        str(apk.resolve()),
    )
    assert captured["kwargs"] == {
        "capture_output": True,
        "text": True,
        "timeout": 17.5,
        "check": False,
    }
    assert execution.success
    assert execution.stdout == "jadx stdout"
    assert execution.stderr == "jadx stderr"
    assert execution.output_path == str(output.resolve())
    assert execution.duration_seconds >= 0
    assert decompile._jadx_execution_issues(execution) == ()


def test_run_jadx_missing_executable_is_warning(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(decompile.shutil, "which", lambda name: None)
    execution = run_jadx(tmp_path / "sample.apk", tmp_path / "jadx", timeout=1)
    issues = decompile._jadx_execution_issues(execution)

    assert not execution.installed
    assert not execution.success
    assert execution.command[0] == "jadx"
    assert [issue.code for issue in issues] == ["JADX_NOT_INSTALLED"]
    assert all(issue.severity is IssueSeverity.WARNING for issue in issues)


def test_run_jadx_timeout_preserves_streams_and_warns(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(decompile.shutil, "which", lambda name: "/tools/jadx")

    def timeout(*args: object, **kwargs: object) -> None:
        raise subprocess.TimeoutExpired(
            cmd=("jadx",),
            timeout=1,
            output=b"partial stdout",
            stderr=b"partial stderr",
        )

    monkeypatch.setattr(decompile.subprocess, "run", timeout)
    execution = run_jadx(tmp_path / "sample.apk", tmp_path / "jadx", timeout=1)
    issues = decompile._jadx_execution_issues(execution)

    assert execution.timed_out
    assert execution.stdout == "partial stdout"
    assert execution.stderr == "partial stderr"
    assert [issue.code for issue in issues] == ["JADX_TIMEOUT"]
    assert issues[0].severity is IssueSeverity.WARNING


@pytest.mark.parametrize(
    ("failure", "expected_code"),
    [
        ("nonzero", "JADX_NONZERO_EXIT"),
        ("process", "JADX_PROCESS_ERROR"),
    ],
)
def test_run_jadx_process_failures_are_warnings(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure: str,
    expected_code: str,
) -> None:
    monkeypatch.setattr(decompile.shutil, "which", lambda name: "/tools/jadx")

    def fail(
        command: tuple[str, ...],
        **kwargs: object,
    ) -> subprocess.CompletedProcess[str]:
        if failure == "process":
            raise OSError("unable to execute Java")
        return subprocess.CompletedProcess(command, 2, "partial", "failed")

    monkeypatch.setattr(decompile.subprocess, "run", fail)
    execution = run_jadx(tmp_path / "sample.apk", tmp_path / "jadx", timeout=1)
    issues = decompile._jadx_execution_issues(execution)

    assert not execution.success
    assert [issue.code for issue in issues] == [expected_code]
    assert issues[0].severity is IssueSeverity.WARNING


def test_successful_jadx_without_java_source_warns(tmp_path: Path) -> None:
    output = tmp_path / "jadx"
    output.mkdir()
    execution = ToolExecution(
        tool="jadx",
        command=("jadx",),
        installed=True,
        return_code=0,
        timed_out=False,
        stdout="",
        stderr="",
        output_path=str(output),
        duration_seconds=0.1,
    )
    issues = decompile._jadx_execution_issues(execution)
    assert [issue.code for issue in issues] == ["JADX_NO_SOURCE_FILES"]
    assert issues[0].severity is IssueSeverity.WARNING


def test_parse_smali_methods_registers_exceptions_and_payloads(
    tmp_path: Path,
) -> None:
    smali = tmp_path / "Example.smali"
    smali.write_text(
        """.class public final Lcom/example/Example;
.super Ljava/lang/Object;
.source "Example.java"

.method public constructor <init>(J)V
    .locals 2
    .param p1, "identifier"
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V
    return-void
.end method

.method public static choose(IJLjava/lang/String;)V
    .registers 8
    .param p0, "choice"
    .param p1, "wide"
    .param p3, "name"
    :try_start_0
    packed-switch p0, :pswitch_data_0
    sparse-switch p0, :sswitch_data_0
    fill-array-data p0, :array_data_0
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0
    return-void
    :catch_0
    return-void
    :catchall_0
    return-void
    :case_1
    return-void
    :case_2
    return-void
    :pswitch_data_0
    .packed-switch 0x1
        :case_1
        :case_2
    .end packed-switch
    :sswitch_data_0
    .sparse-switch
        0x5 -> :case_1
        0x9 -> :case_2
    .end sparse-switch
    :array_data_0
    .array-data 0x1
        0x1t
        0x2t
    .end array-data
.end method

.method public native nativeCall()V
.end method

.method public abstract abstractCall()V
.end method
"""
    )

    methods, issues = parse_smali_file(smali, "classes2.dex")
    assert issues == ()
    assert [method.method_name for method in methods] == [
        "<init>",
        "choose",
        "nativeCall",
        "abstractCall",
    ]

    constructor, choose, native, abstract = methods
    assert constructor.dex_name == "classes2.dex"
    assert constructor.register_count == 5
    assert constructor.local_count == 2
    assert constructor.parameters == (
        MethodParameter(0, "J", "p1", "identifier"),
    )
    assert [instruction.index for instruction in choose.instructions] == list(
        range(len(choose.instructions))
    )
    assert choose.instructions[0].opcode == "packed-switch"
    assert choose.instructions[0].operands == ("p0", ":pswitch_data_0")
    assert choose.register_count == 8
    assert choose.local_count == 4
    assert [parameter.register for parameter in choose.parameters] == [
        "p0",
        "p1",
        "p3",
    ]
    assert [parameter.name for parameter in choose.parameters] == [
        "choice",
        "wide",
        "name",
    ]
    assert choose.exception_handlers == (
        ExceptionHandler(
            "Ljava/lang/Exception;",
            ":try_start_0",
            ":try_end_0",
            ":catch_0",
            "    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0",
        ),
        ExceptionHandler(
            None,
            ":try_start_0",
            ":try_end_0",
            ":catchall_0",
            "    .catchall {:try_start_0 .. :try_end_0} :catchall_0",
        ),
    )

    assert [payload.kind for payload in choose.payloads] == [
        PayloadKind.PACKED_SWITCH,
        PayloadKind.SPARSE_SWITCH,
        PayloadKind.ARRAY_DATA,
    ]
    packed, sparse, array = choose.payloads
    assert [(entry.key, entry.target_label) for entry in packed.entries] == [
        (1, ":case_1"),
        (2, ":case_2"),
    ]
    assert [(entry.key, entry.target_label) for entry in sparse.entries] == [
        (5, ":case_1"),
        (9, ":case_2"),
    ]
    assert [entry.value for entry in array.entries] == ["0x1t", "0x2t"]
    assert packed.raw_text.startswith("    :pswitch_data_0\n")
    assert packed.raw_text.endswith(".end packed-switch")
    assert packed.source_path == str(smali.resolve())
    assert packed.start_line > 0
    assert packed.end_line >= packed.start_line
    assert packed.start_offset is None
    assert packed.end_offset is None
    payload_labels = {
        label.name: label.instruction_index
        for label in choose.labels
        if label.name.endswith("_data_0")
    }
    assert payload_labels == {
        ":pswitch_data_0": None,
        ":sswitch_data_0": None,
        ":array_data_0": None,
    }
    assert native.is_native and not native.is_usable
    assert abstract.is_abstract and not abstract.is_usable


def test_parse_smali_reports_malformed_blocks(tmp_path: Path) -> None:
    missing_class = tmp_path / "MissingClass.smali"
    missing_class.write_text(".method public run()V\n.end method\n")
    methods, issues = parse_smali_file(missing_class, "classes.dex")
    assert methods == ()
    assert [issue.code for issue in issues] == ["SMALI_CLASS_DECLARATION_MISSING"]

    unterminated = tmp_path / "Unterminated.smali"
    unterminated.write_text(
        ".class public Lx/Test;\n.method public run()V\n    return-void\n"
    )
    methods, issues = parse_smali_file(unterminated, "classes.dex")
    assert methods == ()
    assert [issue.code for issue in issues] == ["SMALI_METHOD_BLOCK_UNTERMINATED"]


def test_parse_smali_skips_annotation_and_directive_bodies(tmp_path: Path) -> None:
    smali = tmp_path / "Annotated.smali"
    smali.write_text(
        """.class public Lx/Annotated;
.super Ljava/lang/Object;

.method public run()V
    const/4 v0, 0x1
    .annotation runtime Landroid/annotation/TargetApi;
        value = {
            Landroid/os/Build$VERSION_CODES;->N:I
        }
    .end annotation
    .annotation runtime Lx/Nested;
        value = .subannotation Lx/Value;
            name = "NewApi"
        .end subannotation
    .end annotation
    const/4 v1, 0x2
    return-void
.end method
"""
    )

    methods, issues = parse_smali_file(smali, "classes.dex")
    assert issues == ()
    assert [instruction.opcode for instruction in methods[0].instructions] == [
        "const/4",
        "const/4",
        "return-void",
    ]
    executable_text = "\n".join(
        instruction.raw_text for instruction in methods[0].instructions
    )
    for fake_opcode in ("NewApi", "value", "}", "VERSION_CODES"):
        assert fake_opcode not in executable_text


def test_parse_smali_unterminated_directive_is_structured_and_recovers_later_method(
    tmp_path: Path,
) -> None:
    smali = tmp_path / "BrokenAnnotation.smali"
    smali.write_text(
        """.class public Lx/BrokenAnnotation;
.method public broken()V
    .annotation runtime Lx/Broken;
        value = "unterminated"
    return-void
.end method
.method public later()V
    return-void
.end method
"""
    )

    methods, issues = parse_smali_file(smali, "classes.dex")
    assert [method.method_name for method in methods] == ["broken", "later"]
    assert [issue.code for issue in issues] == [
        "SMALI_DIRECTIVE_BLOCK_UNTERMINATED"
    ]
    assert methods[0].instructions == ()
    assert [instruction.opcode for instruction in methods[1].instructions] == [
        "return-void"
    ]


@pytest.mark.parametrize(
    ("directive", "expected_code"),
    [
        (".locals nope", "SMALI_LOCALS_DIRECTIVE_INVALID"),
        (".locals -1", "SMALI_LOCALS_DIRECTIVE_INVALID"),
        (".registers", "SMALI_REGISTERS_DIRECTIVE_INVALID"),
        (".registers invalid", "SMALI_REGISTERS_DIRECTIVE_INVALID"),
    ],
)
def test_parse_smali_reports_invalid_register_directives(
    tmp_path: Path,
    directive: str,
    expected_code: str,
) -> None:
    smali = tmp_path / "InvalidRegisters.smali"
    smali.write_text(
        f""".class public Lx/InvalidRegisters;
.method public run()V
    {directive}
    return-void
.end method
"""
    )
    methods, issues = parse_smali_file(smali, "classes.dex")
    assert len(methods) == 1
    assert methods[0].register_count is None
    assert expected_code in {issue.code for issue in issues}


def _mock_apktool_with_smali(
    monkeypatch: pytest.MonkeyPatch,
    smali_files: dict[str, str],
    *,
    return_code: int = 0,
    stderr: str = "",
    timed_out: bool = False,
) -> None:
    def fake_run(
        apk_path: str | Path,
        output_path: str | Path,
        *,
        timeout: float,
    ) -> ToolExecution:
        output = Path(output_path)
        for relative_path, content in smali_files.items():
            target = output / relative_path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content)
        return ToolExecution(
            tool="apktool",
            command=("apktool",),
            installed=True,
            return_code=None if timed_out else return_code,
            timed_out=timed_out,
            stdout="",
            stderr=stderr,
            output_path=str(output),
            duration_seconds=0.01,
        )

    monkeypatch.setattr(decompile, "run_apktool", fake_run)

    def fake_raw_fallback(
        validated_apk: object,
        raw_dex_path: str | Path,
    ) -> RawDexExtraction:
        return RawDexExtraction(
            dex_files=validated_apk.dex_files,
            methods=(),
            issues=(
                ExtractionIssue(
                    stage=ExtractionStage.RAW_DEX,
                    code="RAW_DEX_FIXTURE_FAILED",
                    message="Synthetic fallback did not recover methods.",
                    severity=IssueSeverity.ERROR,
                    source_path=str(raw_dex_path),
                ),
            ),
            complete_coverage=False,
        )

    monkeypatch.setattr(decompile, "extract_raw_dex", fake_raw_fallback)

    def fake_jadx(
        apk_path: str | Path,
        output_path: str | Path,
        *,
        timeout: float,
    ) -> ToolExecution:
        output = Path(output_path)
        source = output / "sources" / "x" / "Test.java"
        source.parent.mkdir(parents=True, exist_ok=True)
        source.write_text("package x; class Test {}")
        return ToolExecution(
            tool="jadx",
            command=("jadx", "--no-res", "-d", str(output), str(apk_path)),
            installed=True,
            return_code=0,
            timed_out=False,
            stdout="",
            stderr="",
            output_path=str(output),
            duration_seconds=0.01,
        )

    monkeypatch.setattr(decompile, "run_jadx", fake_jadx)


SIMPLE_SMALI = """.class public Lx/Test;
.source "Test.java"
.method public run()V
    .locals 0
    return-void
.end method
"""


def test_extract_apk_success_with_complete_smali(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    apk = _write_apk(tmp_path / "sample.apk")
    _mock_apktool_with_smali(
        monkeypatch,
        {
            "smali/z/Second.smali": SIMPLE_SMALI.replace(
                "Lx/Test;", "Lz/Second;"
            ),
            "smali/a/First.smali": SIMPLE_SMALI.replace("Lx/Test;", "La/First;"),
        },
    )
    result = extract_apk(apk, tmp_path / "artifacts" / "decompile")
    assert result.status is ExtractionStatus.SUCCESS
    assert result.backend_used is ExtractionBackend.SMALI
    assert not result.raw_dex_fallback_used
    assert result.apktool_success
    assert [method.class_name for method in result.methods] == [
        "La/First;",
        "Lz/Second;",
    ]
    assert result.errors == ()


def test_extract_apk_can_skip_jadx_for_offline_dataset_build(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    apk = _write_apk(tmp_path / "sample.apk")
    _mock_apktool_with_smali(monkeypatch, {"smali/x/Test.smali": SIMPLE_SMALI})

    def unexpected_jadx(*args, **kwargs):
        raise AssertionError("JADX must remain inspection-only in this mode")

    monkeypatch.setattr(decompile, "run_jadx", unexpected_jadx)
    result = extract_apk(
        apk,
        tmp_path / "artifacts" / "decompile",
        run_jadx_analysis=False,
    )
    assert result.status is ExtractionStatus.SUCCESS
    assert result.jadx_execution is None


def test_extract_apk_partial_for_incomplete_multidex(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    apk = _write_apk(
        tmp_path / "multidex.apk",
        dex_entries=("classes.dex", "classes2.dex"),
    )
    _mock_apktool_with_smali(
        monkeypatch,
        {"smali/x/Test.smali": SIMPLE_SMALI},
    )
    result = extract_apk(apk, tmp_path / "artifacts" / "decompile")
    assert result.status is ExtractionStatus.PARTIAL
    assert result.backend_used is ExtractionBackend.SMALI
    assert result.raw_dex_fallback_used
    assert "APKTOOL_SMALI_DIRECTORY_MISSING" in {
        issue.code for issue in result.errors
    }


@pytest.mark.parametrize(
    ("return_code", "timed_out", "stderr", "expected_code"),
    [
        (1, False, "", "APKTOOL_NONZERO_EXIT"),
        (0, True, "", "APKTOOL_TIMEOUT"),
        (
            0,
            False,
            "Error occurred while disassembling class Lx/Bad; - skipping class",
            "APKTOOL_INCOMPLETE_DISASSEMBLY",
        ),
    ],
)
def test_extract_apk_partial_when_usable_output_has_tool_problem(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    return_code: int,
    timed_out: bool,
    stderr: str,
    expected_code: str,
) -> None:
    apk = _write_apk(tmp_path / "sample.apk")
    _mock_apktool_with_smali(
        monkeypatch,
        {"smali/x/Test.smali": SIMPLE_SMALI},
        return_code=return_code,
        timed_out=timed_out,
        stderr=stderr,
    )
    result = extract_apk(apk, tmp_path / "artifacts" / "decompile")
    assert result.status is ExtractionStatus.PARTIAL
    assert result.usable_methods
    assert result.raw_dex_fallback_used
    assert expected_code in {issue.code for issue in result.errors}


def test_extract_apk_failed_without_usable_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    apk = _write_apk(tmp_path / "sample.apk")
    _mock_apktool_with_smali(monkeypatch, {})
    result = extract_apk(apk, tmp_path / "artifacts" / "decompile")
    assert result.status is ExtractionStatus.FAILED
    assert result.backend_used is None
    assert not result.usable_methods
    assert result.raw_dex_fallback_used
    assert "RAW_DEX_FIXTURE_FAILED" in {
        issue.code for issue in result.errors
    }


def test_extract_apk_failed_with_empty_smali_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    apk = _write_apk(tmp_path / "sample.apk")
    _mock_apktool_with_smali(
        monkeypatch,
        {"smali/README.txt": "APKTool produced no Smali classes."},
    )
    result = extract_apk(apk, tmp_path / "artifacts" / "decompile")
    assert result.status is ExtractionStatus.FAILED
    assert "APKTOOL_SMALI_DIRECTORY_EMPTY" in {
        issue.code for issue in result.errors
    }
    assert result.raw_dex_fallback_used
    assert "RAW_DEX_FIXTURE_FAILED" in {
        issue.code for issue in result.errors
    }


def test_method_merge_uses_approved_four_level_priority() -> None:
    usable_smali = _method(method_name="first")
    usable_raw_duplicate = _method(
        method_name="first",
        backend=ExtractionBackend.RAW_DEX,
    )
    unusable_smali = _method(
        method_name="second",
        access_flags=("native",),
        instructions=(),
    )
    usable_raw = _method(
        method_name="second",
        backend=ExtractionBackend.RAW_DEX,
    )
    unusable_smali_third = _method(
        method_name="third",
        access_flags=("abstract",),
        instructions=(),
    )
    unusable_raw_third = _method(
        method_name="third",
        access_flags=("native",),
        instructions=(),
        backend=ExtractionBackend.RAW_DEX,
    )
    unusable_raw_fourth = _method(
        method_name="fourth",
        access_flags=("native",),
        instructions=(),
        backend=ExtractionBackend.RAW_DEX,
    )

    merged = decompile._merge_extracted_methods(
        (usable_smali, unusable_smali, unusable_smali_third),
        (
            usable_raw_duplicate,
            usable_raw,
            unusable_raw_third,
            unusable_raw_fourth,
        ),
    )
    by_name = {method.method_name: method for method in merged}

    assert by_name["first"] is usable_smali
    assert by_name["second"] is usable_raw
    assert by_name["third"] is unusable_smali_third
    assert by_name["fourth"] is unusable_raw_fourth


def test_backend_selection_uses_final_usable_methods() -> None:
    smali = _method(method_name="smali")
    raw = _method(method_name="raw", backend=ExtractionBackend.RAW_DEX)
    raw_declaration = _method(
        method_name="rawDeclaration",
        access_flags=("native",),
        instructions=(),
        backend=ExtractionBackend.RAW_DEX,
    )

    assert decompile._backend_for_methods((smali,)) is ExtractionBackend.SMALI
    assert decompile._backend_for_methods((raw,)) is ExtractionBackend.RAW_DEX
    assert (
        decompile._backend_for_methods((smali, raw))
        is ExtractionBackend.MIXED
    )
    assert (
        decompile._backend_for_methods((smali, raw_declaration))
        is ExtractionBackend.SMALI
    )
    assert decompile._backend_for_methods(()) is None


def test_extract_apk_raw_only_fallback_is_partial(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    apk = _write_apk(tmp_path / "sample.apk")
    _mock_apktool_with_smali(monkeypatch, {})
    raw = _method(method_name="rawRecovered", backend=ExtractionBackend.RAW_DEX)

    def recover_raw(
        validated_apk: object,
        raw_dex_path: str | Path,
    ) -> RawDexExtraction:
        return RawDexExtraction(
            dex_files=validated_apk.dex_files,
            methods=(raw,),
            issues=(),
            complete_coverage=True,
        )

    monkeypatch.setattr(decompile, "extract_raw_dex", recover_raw)
    result = extract_apk(apk, tmp_path / "artifacts" / "decompile")

    assert result.status is ExtractionStatus.PARTIAL
    assert result.backend_used is ExtractionBackend.RAW_DEX
    assert result.methods == (raw,)
    assert result.raw_dex_fallback_used


def test_extract_apk_mixed_fallback_prefers_smali_and_fills_missing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    apk = _write_apk(
        tmp_path / "multidex.apk",
        dex_entries=("classes.dex", "classes2.dex"),
    )
    _mock_apktool_with_smali(
        monkeypatch,
        {"smali/x/Test.smali": SIMPLE_SMALI},
    )
    duplicate_raw = _method(
        class_name="Lx/Test;",
        backend=ExtractionBackend.RAW_DEX,
    )
    raw_missing = replace(
        _method(
            class_name="Lz/Raw;",
            method_name="fromRaw",
            backend=ExtractionBackend.RAW_DEX,
        ),
        dex_name="classes2.dex",
        source_path=f"apk://{APK_HASH}!/classes2.dex",
    )

    def recover_raw(
        validated_apk: object,
        raw_dex_path: str | Path,
    ) -> RawDexExtraction:
        return RawDexExtraction(
            dex_files=validated_apk.dex_files,
            methods=(raw_missing, duplicate_raw),
            issues=(),
            complete_coverage=True,
        )

    monkeypatch.setattr(decompile, "extract_raw_dex", recover_raw)
    result = extract_apk(apk, tmp_path / "artifacts" / "decompile")

    assert result.status is ExtractionStatus.PARTIAL
    assert result.backend_used is ExtractionBackend.MIXED
    assert [method.backend for method in result.usable_methods] == [
        ExtractionBackend.SMALI,
        ExtractionBackend.RAW_DEX,
    ]
    assert [method.method_name for method in result.methods] == ["run", "fromRaw"]


def test_complete_smali_never_invokes_raw_fallback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    apk = _write_apk(tmp_path / "sample.apk")
    _mock_apktool_with_smali(
        monkeypatch,
        {"smali/x/Test.smali": SIMPLE_SMALI},
    )

    def unexpected_fallback(*args: object, **kwargs: object) -> RawDexExtraction:
        raise AssertionError("raw fallback must not run for complete Smali")

    monkeypatch.setattr(decompile, "extract_raw_dex", unexpected_fallback)
    result = extract_apk(apk, tmp_path / "artifacts" / "decompile")

    assert result.status is ExtractionStatus.SUCCESS
    assert not result.raw_dex_fallback_used


def test_missing_apktool_invokes_raw_fallback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    apk = _write_apk(tmp_path / "sample.apk")
    calls = 0

    def missing_tool(
        apk_path: str | Path,
        output_path: str | Path,
        *,
        timeout: float,
    ) -> ToolExecution:
        return ToolExecution(
            tool="apktool",
            command=("apktool",),
            installed=False,
            return_code=None,
            timed_out=False,
            stdout="",
            stderr="missing",
            output_path=str(output_path),
            duration_seconds=0,
        )

    def recover_raw(
        validated_apk: object,
        raw_dex_path: str | Path,
    ) -> RawDexExtraction:
        nonlocal calls
        calls += 1
        raw = _method(backend=ExtractionBackend.RAW_DEX)
        return RawDexExtraction(
            validated_apk.dex_files,
            (raw,),
            (),
            True,
        )

    monkeypatch.setattr(decompile, "run_apktool", missing_tool)
    monkeypatch.setattr(decompile, "extract_raw_dex", recover_raw)
    result = extract_apk(apk, tmp_path / "artifacts" / "decompile")

    assert calls == 1
    assert result.raw_dex_fallback_used
    assert result.status is ExtractionStatus.PARTIAL
    assert result.backend_used is ExtractionBackend.RAW_DEX


def test_jadx_failure_does_not_downgrade_complete_smali(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    apk = _write_apk(tmp_path / "sample.apk")
    _mock_apktool_with_smali(
        monkeypatch,
        {"smali/x/Test.smali": SIMPLE_SMALI},
    )

    def failed_jadx(
        apk_path: str | Path,
        output_path: str | Path,
        *,
        timeout: float,
    ) -> ToolExecution:
        return ToolExecution(
            tool="jadx",
            command=("jadx",),
            installed=True,
            return_code=2,
            timed_out=False,
            stdout="partial",
            stderr="failed",
            output_path=str(output_path),
            duration_seconds=0.02,
        )

    monkeypatch.setattr(decompile, "run_jadx", failed_jadx)
    result = extract_apk(apk, tmp_path / "artifacts" / "decompile")

    assert result.status is ExtractionStatus.SUCCESS
    assert result.backend_used is ExtractionBackend.SMALI
    assert not result.jadx_success
    assert [issue.code for issue in result.warnings] == ["JADX_NONZERO_EXIT"]
    assert result.errors == ()


def test_no_dex_with_native_library_is_partial_and_skips_jadx(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    apk = _write_apk(
        tmp_path / "native-only.apk",
        dex_entries=(),
        native_entries=("lib/arm64-v8a/libx.so",),
    )

    def unexpected_jadx(*args: object, **kwargs: object) -> ToolExecution:
        raise AssertionError("JADX must be skipped for no-DEX APKs")

    monkeypatch.setattr(decompile, "run_jadx", unexpected_jadx)
    result = extract_apk(apk, tmp_path / "artifacts" / "decompile")

    assert result.status is ExtractionStatus.PARTIAL
    assert result.backend_used is None
    assert result.jadx_execution is None
    assert len(result.native_libraries) == 1
    assert [issue.code for issue in result.errors] == ["NO_DEX_FILES"]


def test_no_dex_without_native_library_is_failed_and_skips_jadx(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    apk = _write_apk(tmp_path / "empty.apk", dex_entries=())

    def unexpected_jadx(*args: object, **kwargs: object) -> ToolExecution:
        raise AssertionError("JADX must be skipped for no-DEX APKs")

    monkeypatch.setattr(decompile, "run_jadx", unexpected_jadx)
    result = extract_apk(apk, tmp_path / "artifacts" / "decompile")

    assert result.status is ExtractionStatus.FAILED
    assert result.backend_used is None
    assert result.jadx_execution is None
    assert result.native_libraries == ()


def test_native_failure_downgrades_complete_smali_to_partial(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    apk = _write_apk(
        tmp_path / "sample.apk",
        native_entries=("lib/x86/libx.so",),
    )
    _mock_apktool_with_smali(
        monkeypatch,
        {"smali/x/Test.smali": SIMPLE_SMALI},
    )
    native_issue = ExtractionIssue(
        stage=ExtractionStage.NATIVE_INVENTORY,
        code="NATIVE_LIBRARY_EXTRACTION_FAILED",
        message="Synthetic native failure.",
        severity=IssueSeverity.ERROR,
        source_path="lib/x86/libx.so",
    )
    monkeypatch.setattr(
        decompile,
        "extract_native_libraries",
        lambda validated, output: ((), (native_issue,)),
    )

    result = extract_apk(apk, tmp_path / "artifacts" / "decompile")

    assert result.status is ExtractionStatus.PARTIAL
    assert result.backend_used is ExtractionBackend.SMALI
    assert result.errors == (native_issue,)


def test_repeated_extraction_clears_stale_jadx_and_native_artifacts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    apk = _write_apk(
        tmp_path / "sample.apk",
        native_entries=("lib/x86/libx.so",),
    )
    _mock_apktool_with_smali(
        monkeypatch,
        {"smali/x/Test.smali": SIMPLE_SMALI},
    )
    artifact_root = tmp_path / "artifacts" / "decompile"
    first = extract_apk(apk, artifact_root)
    stale_jadx = Path(first.jadx_output_path) / "stale.txt"
    stale_native = Path(first.native_output_path) / "stale.txt"
    stale_jadx.write_text("stale")
    stale_native.write_text("stale")

    second = extract_apk(apk, artifact_root)

    assert not stale_jadx.exists()
    assert not stale_native.exists()
    assert any(Path(second.jadx_output_path).rglob("*.java"))
    assert len(second.native_libraries) == 1
    assert Path(second.native_libraries[0].extracted_path).is_file()


def test_project_root_and_default_artifact_path_match_layout() -> None:
    expected_project_root = Path(__file__).resolve().parents[3]
    assert PROJECT_ROOT == expected_project_root
    assert DEFAULT_ARTIFACT_ROOT == expected_project_root / "artifacts" / "decompile"
