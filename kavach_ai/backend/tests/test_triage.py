from __future__ import annotations

from dataclasses import fields
from pathlib import Path
from xml.etree import ElementTree
from zipfile import ZipFile

import pytest

from kavach_ai.backend.pipeline.stage1_triage import triage


class _FakeInstruction:
    def __init__(self, output: str, opcode: str = "invoke-static") -> None:
        self._output = output
        self._opcode = opcode

    def get_name(self) -> str:
        return self._opcode

    def get_output(self, _offset: int) -> str:
        return self._output


class _FakeMethod:
    def __init__(
        self,
        name: str,
        descriptor: str,
        instructions: tuple[_FakeInstruction, ...],
    ) -> None:
        self._name = name
        self._descriptor = descriptor
        self._instructions = instructions

    def get_name(self) -> str:
        return self._name

    def get_descriptor(self) -> str:
        return self._descriptor

    def get_code(self) -> object:
        return object()

    def get_instructions_idx(self):
        return tuple(
            (index * 2, instruction)
            for index, instruction in enumerate(self._instructions)
        )


class _FakeClass:
    def __init__(self, name: str, methods: tuple[_FakeMethod, ...]) -> None:
        self._name = name
        self._methods = methods

    def get_name(self) -> str:
        return self._name

    def get_methods(self) -> tuple[_FakeMethod, ...]:
        return self._methods


class _FakeDex:
    def __init__(self, classes: tuple[_FakeClass, ...]) -> None:
        self._classes = classes

    def get_classes(self) -> tuple[_FakeClass, ...]:
        return self._classes


def _write_apk(
    path: Path,
    *,
    dex_entries: tuple[tuple[str, bytes], ...] = (),
) -> Path:
    with ZipFile(path, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"manifest")
        for name, content in dex_entries:
            archive.writestr(name, content)
    return path


def _invoke(target: str, opcode: str = "invoke-static") -> _FakeInstruction:
    return _FakeInstruction(f"v0, {target}", opcode)


def test_dex_call_scan_detects_exact_targets_overloads_and_deduplicates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    instructions = (
        _invoke(
            "Ljava/lang/Class;->forName(Ljava/lang/String;)Ljava/lang/Class;"
        ),
        _invoke(
            "Ljava/lang/Class;->forName(Ljava/lang/String;)Ljava/lang/Class;"
        ),
        _invoke(
            "Ljava/lang/Class;->forName(Ljava/lang/String; Z "
            "Ljava/lang/ClassLoader;)Ljava/lang/Class;"
        ),
        _invoke(
            "Ljava/lang/Class;->getMethod(Ljava/lang/String; "
            "[Ljava/lang/Class;)Ljava/lang/reflect/Method;",
            "invoke-virtual",
        ),
        _invoke(
            "Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object; "
            "[Ljava/lang/Object;)Ljava/lang/Object;",
            "invoke-virtual",
        ),
        _invoke("Ljava/lang/System;->load(Ljava/lang/String;)V"),
        _invoke("Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V"),
        _invoke(
            "Ldalvik/system/DexClassLoader;-><init>(Ljava/lang/String; "
            "Ljava/lang/String; Ljava/lang/String; "
            "Ljava/lang/ClassLoader;)V",
            "invoke-direct",
        ),
        _invoke(
            "Ldalvik/system/DexClassLoader;->loadClass("
            "Ljava/lang/String;)Ljava/lang/Class;",
            "invoke-virtual",
        ),
        _invoke(
            "Ljava/lang/ClassLoader;->loadClass("
            "Ljava/lang/String;)Ljava/lang/Class;",
            "invoke-virtual",
        ),
        _FakeInstruction(
            "v0, Ljava/lang/Class;->forName(Ljava/lang/String;)"
            "Ljava/lang/Class;",
            "const-string",
        ),
    )
    fake_dex = _FakeDex(
        (
            _FakeClass(
                "Lexample/Caller;",
                (_FakeMethod("calls", "()V", instructions),),
            ),
        )
    )
    monkeypatch.setattr("androguard.core.dex.DEX", lambda _raw: fake_dex)

    references = triage._scan_dex_method_calls(b"dex")

    assert references == {
        "DYNAMIC_LOADING:Ldalvik/system/DexClassLoader;": {
            (
                "Ldalvik/system/DexClassLoader;",
                "<init>",
                "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;"
                "Ljava/lang/ClassLoader;)V",
            ),
            (
                "Ldalvik/system/DexClassLoader;",
                "loadClass",
                "(Ljava/lang/String;)Ljava/lang/Class;",
            ),
        },
        "DYNAMIC_LOADING:Ljava/lang/ClassLoader;->loadClass": {
            (
                "Ljava/lang/ClassLoader;",
                "loadClass",
                "(Ljava/lang/String;)Ljava/lang/Class;",
            )
        },
        "DYNAMIC_LOADING:Ljava/lang/System;->load": {
            ("Ljava/lang/System;", "load", "(Ljava/lang/String;)V")
        },
        "DYNAMIC_LOADING:Ljava/lang/System;->loadLibrary": {
            ("Ljava/lang/System;", "loadLibrary", "(Ljava/lang/String;)V")
        },
        "REFLECTION:Ljava/lang/Class;->forName": {
            (
                "Ljava/lang/Class;",
                "forName",
                "(Ljava/lang/String;)Ljava/lang/Class;",
            ),
            (
                "Ljava/lang/Class;",
                "forName",
                "(Ljava/lang/String;ZLjava/lang/ClassLoader;)"
                "Ljava/lang/Class;",
            ),
        },
        "REFLECTION:Ljava/lang/Class;->getMethod": {
            (
                "Ljava/lang/Class;",
                "getMethod",
                "(Ljava/lang/String;[Ljava/lang/Class;)"
                "Ljava/lang/reflect/Method;",
            )
        },
        "REFLECTION:Ljava/lang/reflect/Method;->invoke": {
            (
                "Ljava/lang/reflect/Method;",
                "invoke",
                "(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;",
            )
        },
    }


def test_multidex_aggregation_is_deduplicated_and_deterministic(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    apk_path = _write_apk(
        tmp_path / "multi.apk",
        dex_entries=(("classes2.dex", b"two"), ("classes.dex", b"one")),
    )
    shared = (
        "Ljava/lang/System;",
        "loadLibrary",
        "(Ljava/lang/String;)V",
    )

    def fake_scan(raw_dex: bytes):
        if raw_dex == b"one":
            return {
                "REFLECTION:Ljava/lang/Class;->forName": {
                    (
                        "Ljava/lang/Class;",
                        "forName",
                        "(Ljava/lang/String;)Ljava/lang/Class;",
                    )
                },
                "DYNAMIC_LOADING:Ljava/lang/System;->loadLibrary": {shared},
            }
        return {
            "DYNAMIC_LOADING:Ljava/lang/System;->loadLibrary": {shared},
            "DYNAMIC_LOADING:Ljava/lang/System;->load": {
                ("Ljava/lang/System;", "load", "(Ljava/lang/String;)V")
            },
        }

    monkeypatch.setattr(triage, "_scan_dex_method_calls", fake_scan)

    first = triage._scan_dex_signals(apk_path)
    second = triage._scan_dex_signals(apk_path)

    assert first == second
    assert first == (
        (
            "DYNAMIC_LOADING:Ljava/lang/System;->load:1",
            "DYNAMIC_LOADING:Ljava/lang/System;->loadLibrary:1",
            "REFLECTION:Ljava/lang/Class;->forName:1",
        ),
        (),
    )


def test_malformed_dex_does_not_discard_successful_multidex_signals(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    apk_path = _write_apk(
        tmp_path / "partial.apk",
        dex_entries=(("classes.dex", b"good"), ("classes2.dex", b"bad")),
    )

    def fake_scan(raw_dex: bytes):
        if raw_dex == b"bad":
            raise ValueError("corrupt DEX")
        return {
            "REFLECTION:Ljava/lang/reflect/Method;->invoke": {
                (
                    "Ljava/lang/reflect/Method;",
                    "invoke",
                    "(Ljava/lang/Object;[Ljava/lang/Object;)"
                    "Ljava/lang/Object;",
                )
            }
        }

    monkeypatch.setattr(triage, "_scan_dex_method_calls", fake_scan)

    signals, warnings = triage._scan_dex_signals(apk_path)

    assert signals == (
        "REFLECTION:Ljava/lang/reflect/Method;->invoke:1",
    )
    assert warnings == ("DEX_PARSE_FAILED:classes2.dex:ValueError",)


class _FakeApk:
    def __init__(self, _path: str) -> None:
        self._manifest = ElementTree.fromstring(
            """
            <manifest xmlns:android="http://schemas.android.com/apk/res/android">
              <application>
                <receiver
                  android:name=".SmsReceiver"
                  android:exported="true" />
              </application>
            </manifest>
            """
        )

    def get_android_manifest_xml(self):
        return self._manifest

    def get_package(self) -> str:
        return "example.app"

    def get_permissions(self) -> list[str]:
        return [
            "android.permission.INTERNET",
            "android.permission.READ_SMS",
            "android.permission.RECEIVE_SMS",
        ]

    def get_target_sdk_version(self) -> str:
        return "33"

    def get_min_sdk_version(self) -> str:
        return "24"

    def get_main_activity(self):
        return None


def test_no_dex_apk_returns_manifest_result_score_and_warning(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    apk_path = _write_apk(tmp_path / "manifest-only.apk")
    monkeypatch.setattr("androguard.core.apk.APK", _FakeApk)

    result = triage.analyze_apk(apk_path)

    assert result.package_name == "example.app"
    assert result.permissions == (
        "android.permission.INTERNET",
        "android.permission.READ_SMS",
        "android.permission.RECEIVE_SMS",
    )
    assert result.exported_components == ("example.app.SmsReceiver",)
    assert result.dangerous_permission_combinations == (
        "SMS_INTERCEPTION",
        "SMS_EXFILTRATION",
    )
    assert result.triage_score == 41.5
    assert result.warnings == (
        "NO_DEX_FILES",
        "NO_DISCOVERABLE_ENTRY_POINT",
    )


def test_score_weights_and_public_serialization_contract_are_unchanged(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert (
        triage._calculate_triage_score(
            permission_combinations=("one", "two"),
            exported_component_count=2,
            reflection_count=3,
            dynamic_loading_count=3,
            obfuscation_count=3,
        )
        == 81.0
    )

    apk_path = _write_apk(tmp_path / "contract.apk")
    monkeypatch.setattr("androguard.core.apk.APK", _FakeApk)
    result = triage.analyze_apk(apk_path)
    serialized = result.to_dict()

    expected_fields = tuple(field.name for field in fields(triage.TriageResult))
    assert tuple(serialized) == expected_fields
    assert isinstance(serialized["reflection_indicators"], tuple)
    assert isinstance(serialized["dynamic_loading_indicators"], tuple)
    assert isinstance(serialized["warnings"], tuple)
