from __future__ import annotations

import hashlib
import subprocess
from dataclasses import FrozenInstanceError, replace
from pathlib import Path

import pytest

from kavach_ai.backend.pipeline.stage2_static import jni_bridge
from kavach_ai.backend.pipeline.stage2_static.decompile import (
    ExtractedMethod,
    ExtractionBackend,
    ExtractionResult,
    ExtractionStatus,
    Instruction,
    NativeLibrary,
)
from kavach_ai.backend.pipeline.stage2_static.jni_bridge import (
    ExportedSymbol,
    JniMappingKind,
    NativeAnalysisStatus,
    NativeIssue,
    NativeIssueSeverity,
    NativeLibraryAnalysis,
    NativeMethodIdentity,
    NativeSignal,
    NativeSignalCategory,
    NativeToolBackend,
    analyze_jni_bridges,
    encode_jni_long_name,
    encode_jni_short_name,
    extract_exported_symbols,
    find_library_load_evidence,
    scan_native_signals,
)


APK_HASH = "a" * 64


def ins(index: int, opcode: str, *operands: str) -> Instruction:
    return Instruction(
        index,
        None,
        opcode,
        tuple(operands),
        f"{opcode} {', '.join(operands)}".rstrip(),
    )


def method(
    signature: str = "Lcom/example/NativeBridge;->check(Ljava/lang/String;I)Z",
    *,
    dex_name: str = "classes.dex",
    flags: tuple[str, ...] = ("public", "static", "native"),
    instructions: tuple[Instruction, ...] = (),
    backend: ExtractionBackend = ExtractionBackend.SMALI,
) -> ExtractedMethod:
    class_name, tail = signature.split("->", 1)
    method_name, descriptor_tail = tail.split("(", 1)
    descriptor = f"({descriptor_tail}"
    return ExtractedMethod(
        dex_name=dex_name,
        class_name=class_name,
        method_name=method_name,
        descriptor=descriptor,
        full_signature=signature,
        access_flags=flags,
        parameters=(),
        register_count=4,
        local_count=2,
        instructions=instructions,
        labels=(),
        exception_handlers=(),
        declared_source_file="NativeBridge.java",
        source_path=f"apk://hash!/{dex_name}",
        backend=backend,
    )


def library(
    tmp_path: Path,
    *,
    name: str = "libnative.so",
    abi: str = "arm64-v8a",
    data: bytes = b"\x7fELF fixture",
) -> NativeLibrary:
    path = tmp_path / abi / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return NativeLibrary(
        filename=name,
        abi=abi,
        archive_path=f"lib/{abi}/{name}",
        extracted_path=str(path),
        sha256=hashlib.sha256(data).hexdigest(),
        size_bytes=len(data),
    )


def result(
    *,
    methods: tuple[ExtractedMethod, ...] = (),
    libraries: tuple[NativeLibrary, ...] = (),
) -> ExtractionResult:
    return ExtractionResult(
        apk_path="/tmp/sample.apk",
        apk_hash=APK_HASH,
        artifact_path="/tmp/artifacts",
        dex_files=(),
        methods=methods,
        native_libraries=libraries,
        apktool_output_path="/tmp/artifacts/apktool",
        jadx_output_path="/tmp/artifacts/jadx",
        raw_dex_output_path="/tmp/artifacts/raw_dex",
        native_output_path="/tmp/artifacts/native",
        backend_used=ExtractionBackend.SMALI if methods else None,
        apktool_execution=None,
        jadx_execution=None,
        raw_dex_fallback_used=False,
        status=ExtractionStatus.SUCCESS,
        issues=(),
    )


def install_tool_mocks(
    monkeypatch: pytest.MonkeyPatch,
    *,
    available: tuple[str, ...] = ("nm",),
    stdout: str = "Java_com_example_NativeBridge_check T 10 4\n",
    return_code: int = 0,
) -> list[tuple[str, ...]]:
    commands: list[tuple[str, ...]] = []

    def which(name: str) -> str | None:
        return f"/tools/{name}" if name in available else None

    def run(
        command: tuple[str, ...],
        **kwargs: object,
    ) -> subprocess.CompletedProcess[str]:
        commands.append(tuple(command))
        return subprocess.CompletedProcess(
            command,
            return_code,
            stdout,
            "failure" if return_code else "",
        )

    monkeypatch.setattr(jni_bridge.shutil, "which", which)
    monkeypatch.setattr(jni_bridge.subprocess, "run", run)
    monkeypatch.setattr(
        jni_bridge,
        "_extract_python_symbols",
        lambda *_: ((), False, "not installed"),
    )
    return commands


def test_public_models_are_immutable_and_ordered() -> None:
    identity = NativeMethodIdentity("classes.dex", "LA;->nativeCall()V")
    symbol = ExportedSymbol(
        "lib/arm64-v8a/liba.so",
        "arm64-v8a",
        "Java_A_nativeCall",
        "T",
        "10",
        NativeToolBackend.NM,
    )
    signal = NativeSignal(
        "lib/arm64-v8a/liba.so",
        "arm64-v8a",
        NativeSignalCategory.NETWORK,
        "connect",
        "exported_symbol",
        1,
    )
    issue = NativeIssue(
        "CODE",
        "message",
        NativeIssueSeverity.WARNING,
        method=identity,
    )
    analysis = NativeLibraryAnalysis(
        NativeLibrary("liba.so", "arm64-v8a", "lib/a.so", "/tmp/a", APK_HASH, 1),
        NativeToolBackend.NM,
        (symbol,),
        (signal,),
        (issue,),
    )
    assert identity < NativeMethodIdentity("classes2.dex", identity.full_signature)
    for value in (identity, symbol, signal, issue, analysis):
        with pytest.raises(FrozenInstanceError):
            value.__setattr__("changed", True)


@pytest.mark.parametrize(
    ("signature", "short_name", "long_name"),
    [
        (
            "Lcom/example/NativeBridge;->check(Ljava/lang/String;I)Z",
            "Java_com_example_NativeBridge_check",
            "Java_com_example_NativeBridge_check__Ljava_lang_String_2I",
        ),
        (
            "Lcom/example/Under_score;->native_call([I[[Ljava/lang/String;)V",
            "Java_com_example_Under_1score_native_1call",
            "Java_com_example_Under_1score_native_1call___3I_3_3Ljava_lang_String_2",
        ),
        (
            "Lx/C$Inner;->méthod()V",
            "Java_x_C_00024Inner_m_000E9thod",
            "Java_x_C_00024Inner_m_000E9thod__",
        ),
    ],
)
def test_jni_encoding(
    signature: str, short_name: str, long_name: str
) -> None:
    native = method(signature)
    assert encode_jni_short_name(native) == short_name
    assert encode_jni_long_name(native) == long_name


@pytest.mark.parametrize(
    "signature",
    [
        "Lx/C;-><init>()V",
        "Lx/C;->call(Lbad)V",
        "Lx/C;->call()",
    ],
)
def test_invalid_jni_encoding_is_safe(signature: str) -> None:
    with pytest.raises(ValueError):
        encode_jni_long_name(method(signature))


def test_native_discovery_deduplicates_backend_copy_but_not_multidex(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    install_tool_mocks(monkeypatch, available=())
    first = method()
    raw_copy = replace(first, backend=ExtractionBackend.RAW_DEX)
    second_dex = replace(first, dex_name="classes2.dex")
    non_native = replace(first, access_flags=("public",), instructions=(ins(0, "return-void"),))
    analyzed = analyze_jni_bridges(
        result(methods=(second_dex, non_native, raw_copy, first))
    )
    assert analyzed.native_methods == (
        NativeMethodIdentity("classes.dex", first.full_signature),
        NativeMethodIdentity("classes2.dex", first.full_signature),
    )
    assert analyzed.status is NativeAnalysisStatus.SUCCESS


def test_nm_exact_command_and_parsing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    native_library = library(tmp_path)
    commands = install_tool_mocks(
        monkeypatch,
        stdout=(
            "Java_com_example_NativeBridge_check T 10 4\n"
            "undefined U 0 0\n"
        ),
    )
    symbols, backend, issues = extract_exported_symbols(native_library)
    assert backend is NativeToolBackend.NM
    assert [symbol.name for symbol in symbols] == [
        "Java_com_example_NativeBridge_check"
    ]
    assert commands == [
        (
            "/tools/nm",
            "--dynamic",
            "--defined-only",
            "--extern-only",
            "--format=posix",
            native_library.extracted_path,
        )
    ]
    assert {issue.code for issue in issues} == {"NATIVE_SYMBOL_TOOL_MISSING"}


@pytest.mark.parametrize(
    ("tool", "backend"),
    [
        ("llvm-nm", NativeToolBackend.LLVM_NM),
        ("nm", NativeToolBackend.NM),
    ],
)
def test_nm_backends_are_selected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    tool: str,
    backend: NativeToolBackend,
) -> None:
    native_library = library(tmp_path)
    install_tool_mocks(monkeypatch, available=(tool,))
    assert extract_exported_symbols(native_library)[1] is backend


def test_readelf_backend_parses_defined_globals(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    native_library = library(tmp_path)
    install_tool_mocks(
        monkeypatch,
        available=("readelf",),
        stdout=(
            "Symbol table '.dynsym' contains 3 entries:\n"
            "  1: 00000010 4 FUNC GLOBAL DEFAULT 12 Java_x_C_call\n"
            "  2: 00000000 0 FUNC GLOBAL DEFAULT UND missing\n"
        ),
    )
    symbols, backend, _ = extract_exported_symbols(native_library)
    assert backend is NativeToolBackend.READELF
    assert [symbol.name for symbol in symbols] == ["Java_x_C_call"]


def test_successful_empty_symbol_output_is_complete(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    native_library = library(tmp_path)
    install_tool_mocks(monkeypatch, stdout="")
    symbols, backend, _ = extract_exported_symbols(native_library)
    assert symbols == ()
    assert backend is NativeToolBackend.NM
    analyzed = analyze_jni_bridges(result(libraries=(native_library,)))
    assert analyzed.status is NativeAnalysisStatus.SUCCESS


def test_earlier_backend_failure_later_success_does_not_downgrade(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    native_library = library(tmp_path)
    monkeypatch.setattr(
        jni_bridge.shutil,
        "which",
        lambda name: f"/tools/{name}" if name in {"llvm-nm", "nm"} else None,
    )

    def run(command: tuple[str, ...], **_: object) -> subprocess.CompletedProcess[str]:
        if command[0].endswith("llvm-nm"):
            return subprocess.CompletedProcess(command, 2, "", "bad ELF")
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(jni_bridge.subprocess, "run", run)
    analyzed = analyze_jni_bridges(result(libraries=(native_library,)))
    assert analyzed.status is NativeAnalysisStatus.SUCCESS
    assert analyzed.library_analyses[0].backend is NativeToolBackend.NM
    assert "NATIVE_SYMBOL_TOOL_NONZERO_EXIT" in {
        issue.code for issue in analyzed.issues
    }


@pytest.mark.parametrize("failure", ["timeout", "process", "nonzero", "malformed"])
def test_failed_backends_continue_and_are_structured(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure: str,
) -> None:
    native_library = library(tmp_path)
    monkeypatch.setattr(
        jni_bridge.shutil,
        "which",
        lambda name: "/tools/nm" if name == "nm" else None,
    )

    def run(command: tuple[str, ...], **_: object) -> subprocess.CompletedProcess[str]:
        if failure == "timeout":
            raise subprocess.TimeoutExpired(command, 1)
        if failure == "process":
            raise OSError("cannot run")
        if failure == "nonzero":
            return subprocess.CompletedProcess(command, 1, "", "failed")
        return subprocess.CompletedProcess(command, 0, "not valid output", "")

    monkeypatch.setattr(jni_bridge.subprocess, "run", run)
    monkeypatch.setattr(
        jni_bridge,
        "_extract_python_symbols",
        lambda *_: ((), False, "missing"),
    )
    _, backend, issues = extract_exported_symbols(native_library, timeout=1)
    assert backend is NativeToolBackend.NONE
    assert any(issue.code.startswith("NATIVE_SYMBOL_") for issue in issues)


def test_optional_python_backend(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    native_library = library(tmp_path)
    monkeypatch.setattr(jni_bridge.shutil, "which", lambda _: None)
    expected = ExportedSymbol(
        native_library.archive_path,
        native_library.abi,
        "Java_x_C_call",
        "STT_FUNC",
        "10",
        NativeToolBackend.PYTHON_ELF,
    )
    monkeypatch.setattr(
        jni_bridge,
        "_extract_python_symbols",
        lambda *_: ((expected,), True, None),
    )
    symbols, backend, _ = extract_exported_symbols(native_library)
    assert symbols == (expected,)
    assert backend is NativeToolBackend.PYTHON_ELF


@pytest.mark.parametrize("tamper", ["size", "hash"])
def test_invalid_library_is_not_scanned_or_parsed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    tamper: str,
) -> None:
    native_library = library(tmp_path, data=b"system connect")
    invalid = (
        replace(native_library, size_bytes=native_library.size_bytes + 1)
        if tamper == "size"
        else replace(native_library, sha256="0" * 64)
    )
    called = False

    def run(*_: object, **__: object) -> object:
        nonlocal called
        called = True
        raise AssertionError("invalid library must not reach symbol parsing")

    monkeypatch.setattr(jni_bridge.subprocess, "run", run)
    symbols, backend, issues = extract_exported_symbols(invalid)
    signals, scan_issues = scan_native_signals(invalid)
    assert not called
    assert symbols == signals == ()
    assert backend is NativeToolBackend.NONE
    assert issues[0].code == scan_issues[0].code == "NATIVE_LIBRARY_VALIDATION_FAILED"


def test_symlink_and_non_file_are_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = library(tmp_path)
    symlink = tmp_path / "link.so"
    try:
        symlink.symlink_to(target.extracted_path)
    except OSError:
        pytest.skip("symlinks unavailable")
    linked = replace(target, extracted_path=str(symlink))
    assert extract_exported_symbols(linked)[2][0].code == (
        "NATIVE_LIBRARY_VALIDATION_FAILED"
    )

    directory = tmp_path / "directory.so"
    directory.mkdir()
    as_directory = replace(target, extracted_path=str(directory))
    assert scan_native_signals(as_directory)[1][0].severity is (
        NativeIssueSeverity.ERROR
    )


def test_exact_long_and_short_mappings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    native_library = library(tmp_path)
    long_method = method("Lx/C;->over(I)V")
    short_method = method("Lx/C;->single()V")
    output = (
        f"{encode_jni_long_name(long_method)} T 10 4\n"
        f"{encode_jni_short_name(short_method)} T 20 4\n"
    )
    install_tool_mocks(monkeypatch, stdout=output)
    analyzed = analyze_jni_bridges(
        result(methods=(short_method, long_method), libraries=(native_library,))
    )
    by_method = {mapping.method.full_signature: mapping for mapping in analyzed.mappings}
    assert by_method[long_method.full_signature].mapping_kind is (
        JniMappingKind.EXACT_LONG_NAME
    )
    assert by_method[short_method.full_signature].mapping_kind is (
        JniMappingKind.EXACT_SHORT_NAME
    )


def test_overloaded_and_multidex_short_names_are_ambiguous(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    native_library = library(tmp_path)
    integer = method("Lx/C;->over(I)V")
    string = method(
        "Lx/C;->over(Ljava/lang/String;)V",
        dex_name="classes2.dex",
    )
    install_tool_mocks(
        monkeypatch,
        stdout=f"{encode_jni_short_name(integer)} T 10 4\n",
    )
    analyzed = analyze_jni_bridges(
        result(methods=(integer, string), libraries=(native_library,))
    )
    assert {
        mapping.mapping_kind for mapping in analyzed.mappings
    } == {JniMappingKind.AMBIGUOUS_OVERLOAD}
    assert analyzed.metrics.ambiguous_mappings == 2


def test_same_symbol_across_abis_is_preserved(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    first = library(tmp_path, abi="arm64-v8a")
    second = library(tmp_path, abi="x86_64")
    native = method("Lx/C;->call()V")
    install_tool_mocks(
        monkeypatch,
        stdout=f"{encode_jni_short_name(native)} T 10 4\n",
    )
    mapping = analyze_jni_bridges(
        result(methods=(native,), libraries=(second, first))
    ).mappings[0]
    assert len(mapping.matched_symbols) == len(mapping.matched_libraries) == 2


def test_unresolved_and_dynamic_registration_warning(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    native_library = library(tmp_path, data=b"\x00RegisterNatives\x00JNI_OnLoad\x00")
    native = method("Lx/C;->hidden()V")
    install_tool_mocks(monkeypatch, stdout="")
    analyzed = analyze_jni_bridges(
        result(methods=(native,), libraries=(native_library,))
    )
    assert analyzed.mappings[0].mapping_kind is JniMappingKind.UNRESOLVED
    assert "DYNAMIC_JNI_REGISTRATION_POSSIBLE" in {
        issue.code for issue in analyzed.issues
    }


def load_method(
    *,
    signature: str = "Lx/Loader;->run()V",
    instructions: tuple[Instruction, ...],
) -> ExtractedMethod:
    return method(
        signature,
        flags=("public", "static"),
        instructions=instructions,
    )


def test_load_library_constant_move_and_multiple_abis(tmp_path: Path) -> None:
    libraries = (
        library(tmp_path, name="libfoo.so", abi="x86"),
        library(tmp_path, name="libfoo.so", abi="arm64-v8a"),
    )
    loader = load_method(
        instructions=(
            ins(0, "const-string", "v0", '"foo"'),
            ins(1, "move-object", "v1", "v0"),
            ins(
                2,
                "invoke-static",
                "{v1}",
                "Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V",
            ),
            ins(3, "return-void"),
        )
    )
    evidence = find_library_load_evidence((loader,), libraries)
    assert evidence[0].requested_name == "foo"
    assert evidence[0].resolved_library_archive_paths == tuple(
        sorted(library.archive_path for library in libraries)
    )
    assert not evidence[0].dynamic_name


def test_system_load_preserves_path_and_matches_basename(tmp_path: Path) -> None:
    native_library = library(tmp_path, name="libfoo.so")
    requested = "/data/app/pkg/lib/arm64/libfoo.so"
    loader = load_method(
        instructions=(
            ins(0, "const-string", "v0", f'"{requested}"'),
            ins(
                1,
                "invoke-static",
                "{v0}",
                "Ljava/lang/System;->load(Ljava/lang/String;)V",
            ),
            ins(2, "return-void"),
        )
    )
    evidence = find_library_load_evidence((loader,), (native_library,))[0]
    assert evidence.requested_name == requested
    assert evidence.resolved_library_archive_paths == (
        native_library.archive_path,
    )


def test_dynamic_and_missing_load_names_warn(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    install_tool_mocks(monkeypatch, stdout="")
    native_library = library(tmp_path)
    loader = load_method(
        instructions=(
            ins(
                0,
                "invoke-static",
                "{v0}",
                "Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V",
            ),
            ins(1, "const-string", "v1", '"absent"'),
            ins(
                2,
                "invoke-static",
                "{v1}",
                "Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V",
            ),
            ins(3, "return-void"),
        )
    )
    analyzed = analyze_jni_bridges(
        result(methods=(loader,), libraries=(native_library,))
    )
    assert {item.dynamic_name for item in analyzed.load_evidence} == {False, True}
    assert {
        issue.code for issue in analyzed.issues
    } >= {"DYNAMIC_LIBRARY_LOAD_NAME", "LOADED_LIBRARY_NOT_IN_APK"}


@pytest.mark.parametrize(
    ("category", "signature"),
    [
        (NativeSignalCategory.PROCESS_EXECUTION, "execve"),
        (NativeSignalCategory.NETWORK, "connect"),
        (NativeSignalCategory.FILESYSTEM, "unlink"),
        (NativeSignalCategory.DYNAMIC_LOADING, "dlopen"),
        (NativeSignalCategory.ANTI_ANALYSIS, "TracerPid"),
        (NativeSignalCategory.CRYPTOGRAPHY, "EVP_Encrypt"),
        (NativeSignalCategory.PRIVILEGE_SYSTEM, "setuid"),
    ],
)
def test_every_signal_category(
    tmp_path: Path,
    category: NativeSignalCategory,
    signature: str,
) -> None:
    native_library = library(
        tmp_path,
        data=f"\x00{signature}\x00{signature}\x00".encode(),
    )
    signals, issues = scan_native_signals(native_library)
    matched = next(signal for signal in signals if signal.signature == signature)
    assert matched.category is category
    assert matched.occurrence_count == 2
    assert matched.evidence_kind == "binary_string"
    assert issues == ()


def test_generic_signal_boundaries_avoid_identifier_false_positives(
    tmp_path: Path,
) -> None:
    native_library = library(
        tmp_path,
        data=b"bread sendValue preopen open read send",
    )
    signals, _ = scan_native_signals(native_library)
    counts = {signal.signature: signal.occurrence_count for signal in signals}
    assert counts["open"] == counts["read"] == counts["send"] == 1


def test_exported_signal_precedes_raw_duplicate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    native_library = library(tmp_path, data=b"\x00connect\x00connect\x00")
    install_tool_mocks(monkeypatch, stdout="connect T 10 4\n")
    analysis = analyze_jni_bridges(
        result(libraries=(native_library,))
    ).library_analyses[0]
    connect = next(
        signal for signal in analysis.sensitive_signals
        if signal.signature == "connect"
    )
    assert connect.evidence_kind == "exported_symbol"
    assert connect.occurrence_count == 1


def test_not_applicable_status() -> None:
    analyzed = analyze_jni_bridges(result())
    assert analyzed.status is NativeAnalysisStatus.NOT_APPLICABLE
    assert analyzed.metrics.native_declarations == 0


def test_tooling_unavailable_with_byte_scan_is_partial(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    native_library = library(tmp_path, data=b"\x00socket\x00")
    install_tool_mocks(monkeypatch, available=())
    analyzed = analyze_jni_bridges(result(libraries=(native_library,)))
    assert analyzed.status is NativeAnalysisStatus.PARTIAL
    assert analyzed.metrics.sensitive_signals == 1


def test_total_invalid_library_failure_is_failed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    native_library = replace(
        library(tmp_path),
        sha256="0" * 64,
    )
    install_tool_mocks(monkeypatch)
    analyzed = analyze_jni_bridges(result(libraries=(native_library,)))
    assert analyzed.status is NativeAnalysisStatus.FAILED
    assert analyzed.metrics.libraries_scanned == 0


def test_partial_library_failure_does_not_stop_later_library(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    invalid = replace(library(tmp_path, abi="arm64-v8a"), size_bytes=999)
    valid = library(tmp_path, abi="x86", data=b"\x00socket\x00")
    install_tool_mocks(monkeypatch, stdout="")
    analyzed = analyze_jni_bridges(result(libraries=(valid, invalid)))
    assert analyzed.status is NativeAnalysisStatus.PARTIAL
    assert analyzed.metrics.libraries_scanned == 1
    assert len(analyzed.library_analyses) == 2


def test_unresolved_declaration_alone_is_success(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    install_tool_mocks(monkeypatch, available=())
    analyzed = analyze_jni_bridges(result(methods=(method(),)))
    assert analyzed.status is NativeAnalysisStatus.SUCCESS
    assert analyzed.mappings[0].mapping_kind is JniMappingKind.UNRESOLVED


def test_deterministic_output_and_input_immutability(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    first_library = library(tmp_path, abi="arm64-v8a")
    second_library = library(tmp_path, abi="x86")
    native = method()
    install_tool_mocks(
        monkeypatch,
        stdout=f"{encode_jni_short_name(native)} T 10 4\n",
    )
    extraction = result(
        methods=(native,),
        libraries=(second_library, first_library),
    )
    original_methods = extraction.methods
    original_libraries = extraction.native_libraries
    first = analyze_jni_bridges(extraction)
    second = analyze_jni_bridges(extraction)
    assert first == second
    assert extraction.methods == original_methods
    assert extraction.native_libraries == original_libraries
