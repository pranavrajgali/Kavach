"""Fast, non-verdict APK manifest triage.

This module extracts manifest metadata and lightweight static signals that help
prioritize APKs for deeper analysis.  A high score is a queueing signal, not a
malware classification.
"""

from __future__ import annotations

import hashlib
import math
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable
from zipfile import BadZipFile, ZipFile


ANDROID_NAMESPACE = "http://schemas.android.com/apk/res/android"
ANDROID_ATTRIBUTE = f"{{{ANDROID_NAMESPACE}}}"
COMPONENT_TYPES = ("activity", "service", "receiver", "provider")

REFLECTION_MARKERS = (
    b"Ljava/lang/Class;->forName",
    b"Ljava/lang/Class;->getMethod",
    b"Ljava/lang/reflect/Method;->invoke",
    b"Ljava/lang/reflect/Constructor;->newInstance",
)
DYNAMIC_LOADING_MARKERS = (
    b"Ldalvik/system/DexClassLoader;",
    b"Ldalvik/system/PathClassLoader;",
    b"Ldalvik/system/InMemoryDexClassLoader;",
    b"Ljava/lang/System;->loadLibrary",
    b"Ljava/lang/System;->load",
)

_REFLECTION_CALL_INDICATORS = {
    ("Ljava/lang/Class;", "forName"): "Ljava/lang/Class;->forName",
    ("Ljava/lang/Class;", "getMethod"): "Ljava/lang/Class;->getMethod",
    (
        "Ljava/lang/reflect/Method;",
        "invoke",
    ): "Ljava/lang/reflect/Method;->invoke",
    (
        "Ljava/lang/reflect/Constructor;",
        "newInstance",
    ): "Ljava/lang/reflect/Constructor;->newInstance",
}
_DYNAMIC_LOADING_CALL_INDICATORS = {
    ("Ljava/lang/System;", "loadLibrary"): "Ljava/lang/System;->loadLibrary",
    ("Ljava/lang/System;", "load"): "Ljava/lang/System;->load",
    (
        "Ldalvik/system/DexClassLoader;",
        "<init>",
    ): "Ldalvik/system/DexClassLoader;",
    (
        "Ldalvik/system/DexClassLoader;",
        "loadClass",
    ): "Ldalvik/system/DexClassLoader;",
    (
        "Ldalvik/system/PathClassLoader;",
        "<init>",
    ): "Ldalvik/system/PathClassLoader;",
    (
        "Ldalvik/system/PathClassLoader;",
        "loadClass",
    ): "Ldalvik/system/PathClassLoader;",
    (
        "Ldalvik/system/InMemoryDexClassLoader;",
        "<init>",
    ): "Ldalvik/system/InMemoryDexClassLoader;",
    (
        "Ldalvik/system/InMemoryDexClassLoader;",
        "loadClass",
    ): "Ldalvik/system/InMemoryDexClassLoader;",
    (
        "Ljava/lang/ClassLoader;",
        "loadClass",
    ): "Ljava/lang/ClassLoader;->loadClass",
}
_INVOKED_METHOD_RE = re.compile(
    r"(?P<class_name>L[^,\s]+;)->(?P<method_name>[^\s(]+)"
    r"(?P<descriptor>\([^)]*\).+)$"
)

# Combinations are deliberately more meaningful than individual permissions.
DANGEROUS_PERMISSION_COMBINATIONS: dict[str, frozenset[str]] = {
    "ACCESSIBILITY_SMS_OVERLAY": frozenset(
        {
            "android.permission.BIND_ACCESSIBILITY_SERVICE",
            "android.permission.RECEIVE_SMS",
            "android.permission.SYSTEM_ALERT_WINDOW",
        }
    ),
    "SMS_INTERCEPTION": frozenset(
        {
            "android.permission.RECEIVE_SMS",
            "android.permission.READ_SMS",
        }
    ),
    "SMS_EXFILTRATION": frozenset(
        {
            "android.permission.READ_SMS",
            "android.permission.INTERNET",
        }
    ),
    "BOOT_PERSISTENT_INSTALLER": frozenset(
        {
            "android.permission.RECEIVE_BOOT_COMPLETED",
            "android.permission.REQUEST_INSTALL_PACKAGES",
        }
    ),
    "CONTACT_EXFILTRATION": frozenset(
        {
            "android.permission.READ_CONTACTS",
            "android.permission.INTERNET",
        }
    ),
}


class TriageError(RuntimeError):
    """Raised when an APK cannot produce a trustworthy manifest result."""


@dataclass(frozen=True)
class IntentFilter:
    actions: tuple[str, ...] = ()
    categories: tuple[str, ...] = ()
    data: tuple[dict[str, str], ...] = ()


@dataclass(frozen=True)
class ManifestComponent:
    component_type: str
    name: str
    exported: bool
    exported_explicit: bool
    enabled: bool
    permission: str | None
    intent_filters: tuple[IntentFilter, ...] = ()


@dataclass(frozen=True)
class TriageResult:
    apk_path: str
    apk_hash: str
    package_name: str
    permissions: tuple[str, ...]
    activities: tuple[ManifestComponent, ...]
    services: tuple[ManifestComponent, ...]
    receivers: tuple[ManifestComponent, ...]
    providers: tuple[ManifestComponent, ...]
    main_activity: str | None
    entry_points: tuple[str, ...]
    exported_components: tuple[str, ...]
    min_sdk: int | None
    target_sdk: int | None
    dangerous_permission_combinations: tuple[str, ...]
    reflection_indicators: tuple[str, ...]
    dynamic_loading_indicators: tuple[str, ...]
    obfuscation_indicators: tuple[str, ...]
    triage_score: float
    requires_dynamic_analysis: bool
    warnings: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation."""

        return asdict(self)


def analyze_apk(apk_path: str | Path) -> TriageResult:
    """Extract manifest and lightweight bytecode triage signals from an APK.

    Raises:
        FileNotFoundError: if ``apk_path`` does not exist.
        TriageError: if the file is not a readable APK or its manifest cannot
            be parsed.  Parse failures are never converted into benign results.
    """

    path = Path(apk_path).expanduser().resolve()
    _validate_apk(path)

    try:
        from androguard.core.apk import APK
    except ImportError as exc:
        raise TriageError(
            "Androguard is required for manifest triage; install project dependencies."
        ) from exc

    try:
        apk = APK(str(path))
        manifest = apk.get_android_manifest_xml()
    except Exception as exc:
        raise TriageError(f"Unable to parse AndroidManifest.xml: {exc}") from exc

    if manifest is None:
        raise TriageError("APK does not contain a parseable AndroidManifest.xml.")

    package_name = _clean_text(apk.get_package())
    if not package_name:
        raise TriageError("AndroidManifest.xml does not declare a package name.")

    permissions = tuple(sorted(set(apk.get_permissions() or ())))
    target_sdk = _parse_sdk(apk.get_target_sdk_version())
    min_sdk = _parse_sdk(apk.get_min_sdk_version())
    components = _extract_components(manifest, package_name, target_sdk)

    main_activity = _clean_text(apk.get_main_activity()) or None
    entry_points = _find_entry_points(components, main_activity)
    exported_components = tuple(
        component.name
        for component in _iter_components(components)
        if component.exported and component.enabled
    )

    permission_combinations = tuple(
        name
        for name, required in DANGEROUS_PERMISSION_COMBINATIONS.items()
        if required.issubset(permissions)
    )
    code_signals, code_warnings = _scan_dex_signals(path)
    obfuscation_indicators = _manifest_obfuscation_signals(
        package_name, components, code_signals
    )
    reflection_indicators = tuple(
        marker
        for marker in code_signals
        if marker.startswith("REFLECTION:")
    )
    dynamic_loading_indicators = tuple(
        marker
        for marker in code_signals
        if marker.startswith("DYNAMIC_LOADING:")
    )

    warnings = list(code_warnings)
    if target_sdk is None:
        warnings.append("TARGET_SDK_UNAVAILABLE")
    if not entry_points:
        warnings.append("NO_DISCOVERABLE_ENTRY_POINT")

    score = _calculate_triage_score(
        permission_combinations=permission_combinations,
        exported_component_count=len(exported_components),
        reflection_count=len(reflection_indicators),
        dynamic_loading_count=len(dynamic_loading_indicators),
        obfuscation_count=len(obfuscation_indicators),
    )
    requires_dynamic = bool(
        score >= 60.0
        or permission_combinations
        or dynamic_loading_indicators
        or obfuscation_indicators
        or code_warnings
    )

    return TriageResult(
        apk_path=str(path),
        apk_hash=_sha256(path),
        package_name=package_name,
        permissions=permissions,
        activities=components["activity"],
        services=components["service"],
        receivers=components["receiver"],
        providers=components["provider"],
        main_activity=main_activity,
        entry_points=entry_points,
        exported_components=exported_components,
        min_sdk=min_sdk,
        target_sdk=target_sdk,
        dangerous_permission_combinations=permission_combinations,
        reflection_indicators=reflection_indicators,
        dynamic_loading_indicators=dynamic_loading_indicators,
        obfuscation_indicators=obfuscation_indicators,
        triage_score=score,
        requires_dynamic_analysis=requires_dynamic,
        warnings=tuple(sorted(set(warnings))),
    )


def _validate_apk(path: Path) -> None:
    if not path.exists():
        raise FileNotFoundError(path)
    if not path.is_file():
        raise TriageError(f"APK path is not a regular file: {path}")
    if path.suffix.lower() != ".apk":
        raise TriageError(f"Expected an .apk file, received: {path.name}")

    try:
        with ZipFile(path) as archive:
            names = set(archive.namelist())
            if "AndroidManifest.xml" not in names:
                raise TriageError("ZIP does not contain AndroidManifest.xml.")
    except BadZipFile as exc:
        raise TriageError("File is not a valid ZIP/APK archive.") from exc


def _extract_components(
    manifest: Any,
    package_name: str,
    target_sdk: int | None,
) -> dict[str, tuple[ManifestComponent, ...]]:
    result: dict[str, tuple[ManifestComponent, ...]] = {}
    for component_type in COMPONENT_TYPES:
        parsed: list[ManifestComponent] = []
        for element in manifest.findall(f".//{component_type}"):
            raw_name = element.get(f"{ANDROID_ATTRIBUTE}name")
            if not raw_name:
                continue

            filters = tuple(_parse_intent_filter(node) for node in element.findall("intent-filter"))
            exported_raw = element.get(f"{ANDROID_ATTRIBUTE}exported")
            exported_explicit = exported_raw is not None
            exported = _resolve_exported(
                component_type,
                exported_raw,
                has_intent_filter=bool(filters),
                target_sdk=target_sdk,
            )
            parsed.append(
                ManifestComponent(
                    component_type=component_type,
                    name=_qualify_component_name(package_name, raw_name),
                    exported=exported,
                    exported_explicit=exported_explicit,
                    enabled=_parse_bool(
                        element.get(f"{ANDROID_ATTRIBUTE}enabled"), default=True
                    ),
                    permission=_clean_text(
                        element.get(f"{ANDROID_ATTRIBUTE}permission")
                    )
                    or None,
                    intent_filters=filters,
                )
            )
        result[component_type] = tuple(sorted(parsed, key=lambda item: item.name))
    return result


def _parse_intent_filter(element: Any) -> IntentFilter:
    actions = tuple(
        sorted(
            value
            for node in element.findall("action")
            if (value := _clean_text(node.get(f"{ANDROID_ATTRIBUTE}name")))
        )
    )
    categories = tuple(
        sorted(
            value
            for node in element.findall("category")
            if (value := _clean_text(node.get(f"{ANDROID_ATTRIBUTE}name")))
        )
    )
    data_entries: list[dict[str, str]] = []
    for node in element.findall("data"):
        entry = {
            key.removeprefix(ANDROID_ATTRIBUTE): value
            for key, raw_value in sorted(node.attrib.items())
            if (value := _clean_text(raw_value))
        }
        if entry:
            data_entries.append(entry)
    return IntentFilter(
        actions=actions,
        categories=categories,
        data=tuple(data_entries),
    )


def _resolve_exported(
    component_type: str,
    raw_value: str | None,
    *,
    has_intent_filter: bool,
    target_sdk: int | None,
) -> bool:
    if raw_value is not None:
        return _parse_bool(raw_value, default=False)
    if component_type == "provider":
        # Provider default changed in Android 4.2 (API 17).
        return target_sdk is not None and target_sdk <= 16
    # Before Android 12, an intent filter implied exported=true. Android 12+
    # requires the attribute, so an absent value is not considered exported.
    return has_intent_filter and (target_sdk is None or target_sdk < 31)


def _find_entry_points(
    components: dict[str, tuple[ManifestComponent, ...]],
    main_activity: str | None,
) -> tuple[str, ...]:
    names: set[str] = {main_activity} if main_activity else set()
    entry_actions = {
        "android.intent.action.MAIN",
        "android.intent.action.BOOT_COMPLETED",
        "android.provider.Telephony.SMS_RECEIVED",
        "android.accessibilityservice.AccessibilityService",
    }
    for component in _iter_components(components):
        if any(
            entry_actions.intersection(intent_filter.actions)
            for intent_filter in component.intent_filters
        ):
            names.add(component.name)
    return tuple(sorted(names))


def _scan_dex_signals(path: Path) -> tuple[tuple[str, ...], tuple[str, ...]]:
    references: dict[str, set[tuple[str, str, str]]] = {}
    warnings: set[str] = set()
    try:
        with ZipFile(path) as archive:
            dex_names = sorted(
                name
                for name in archive.namelist()
                if re.fullmatch(r"classes(?:\d+)?\.dex", name)
            )
            if not dex_names:
                warnings.add("NO_DEX_FILES")
            for dex_name in dex_names:
                try:
                    raw_dex = archive.read(dex_name)
                except Exception:
                    warnings.add(f"DEX_READ_FAILED:{dex_name}")
                    continue
                try:
                    dex_references = _scan_dex_method_calls(raw_dex)
                except Exception as exc:
                    warnings.add(
                        f"DEX_PARSE_FAILED:{dex_name}:{type(exc).__name__}"
                    )
                    continue
                for indicator, method_references in dex_references.items():
                    references.setdefault(indicator, set()).update(method_references)
    except (BadZipFile, OSError) as exc:
        warnings.add(f"DEX_SCAN_FAILED:{type(exc).__name__}")
    signals = tuple(
        sorted(
            f"{indicator}:{len(method_references)}"
            for indicator, method_references in references.items()
        )
    )
    return signals, tuple(sorted(warnings))


def _scan_dex_method_calls(
    raw_dex: bytes,
) -> dict[str, set[tuple[str, str, str]]]:
    from androguard.core.dex import DEX

    dex = DEX(raw_dex)
    references: dict[str, set[tuple[str, str, str]]] = {}
    classes = sorted(dex.get_classes(), key=lambda item: item.get_name())
    for class_object in classes:
        methods = sorted(
            class_object.get_methods(),
            key=lambda item: (
                item.get_name(),
                "".join(str(item.get_descriptor()).split()),
            ),
        )
        for method in methods:
            if method.get_code() is None:
                continue
            for offset, instruction in method.get_instructions_idx():
                opcode = instruction.get_name()
                if not opcode.startswith("invoke-"):
                    continue
                invoked = _parse_invoked_method(instruction.get_output(offset))
                if invoked is None:
                    continue
                class_name, method_name, descriptor = invoked
                reflection_name = _REFLECTION_CALL_INDICATORS.get(
                    (class_name, method_name)
                )
                if reflection_name is not None:
                    references.setdefault(
                        f"REFLECTION:{reflection_name}", set()
                    ).add(invoked)
                loading_name = _DYNAMIC_LOADING_CALL_INDICATORS.get(
                    (class_name, method_name)
                )
                if loading_name is not None:
                    references.setdefault(
                        f"DYNAMIC_LOADING:{loading_name}", set()
                    ).add(invoked)
    return references


def _parse_invoked_method(output: object) -> tuple[str, str, str] | None:
    match = _INVOKED_METHOD_RE.search(str(output).strip())
    if match is None:
        return None
    return (
        match.group("class_name"),
        match.group("method_name"),
        "".join(match.group("descriptor").split()),
    )


def _manifest_obfuscation_signals(
    package_name: str,
    components: dict[str, tuple[ManifestComponent, ...]],
    code_signals: tuple[str, ...],
) -> tuple[str, ...]:
    indicators: set[str] = set()
    component_names = [
        component.name
        for component in _iter_components(components)
        if component.name.startswith(package_name)
    ]
    short_segments = 0
    total_segments = 0
    for name in component_names:
        relative_name = name.removeprefix(f"{package_name}.")
        for segment in relative_name.split("."):
            total_segments += 1
            if len(segment) <= 2 and segment.isidentifier():
                short_segments += 1
    if total_segments >= 4 and short_segments / total_segments >= 0.6:
        indicators.add("HIGH_SHORT_IDENTIFIER_DENSITY")
    if any(item.startswith("REFLECTION:") for item in code_signals):
        indicators.add("REFLECTION_PRESENT")
    if any(item.startswith("DYNAMIC_LOADING:") for item in code_signals):
        indicators.add("DYNAMIC_CODE_LOADING_PRESENT")
    return tuple(sorted(indicators))


def _calculate_triage_score(
    *,
    permission_combinations: tuple[str, ...],
    exported_component_count: int,
    reflection_count: int,
    dynamic_loading_count: int,
    obfuscation_count: int,
) -> float:
    score = 0.0
    score += min(len(permission_combinations) * 20.0, 50.0)
    score += min(exported_component_count * 1.5, 12.0)
    score += min(reflection_count * 6.0, 12.0)
    score += min(dynamic_loading_count * 8.0, 16.0)
    score += min(obfuscation_count * 5.0, 10.0)
    return round(min(score, 100.0), 2)


def _iter_components(
    components: dict[str, tuple[ManifestComponent, ...]],
) -> Iterable[ManifestComponent]:
    for component_type in COMPONENT_TYPES:
        yield from components[component_type]


def _qualify_component_name(package_name: str, name: str) -> str:
    cleaned = _clean_text(name)
    if cleaned.startswith("."):
        return f"{package_name}{cleaned}"
    if "." not in cleaned:
        return f"{package_name}.{cleaned}"
    return cleaned


def _parse_bool(value: Any, *, default: bool) -> bool:
    if value is None:
        return default
    return _clean_text(value).lower() == "true"


def _parse_sdk(value: Any) -> int | None:
    cleaned = _clean_text(value)
    if not cleaned:
        return None
    try:
        parsed = int(cleaned)
    except (TypeError, ValueError):
        return None
    return parsed if parsed >= 0 and math.isfinite(parsed) else None


def _clean_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode(errors="replace").strip()
    return str(value).strip()


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as apk_file:
        for chunk in iter(lambda: apk_file.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


__all__ = [
    "DANGEROUS_PERMISSION_COMBINATIONS",
    "IntentFilter",
    "ManifestComponent",
    "TriageError",
    "TriageResult",
    "analyze_apk",
]
