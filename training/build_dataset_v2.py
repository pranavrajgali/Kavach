"""Stage-1 representative-subset driver for Plan 2 static analysis.

This command refuses hashes outside the reviewed subset and does not build
ModelViews or modify the immutable V1 split manifests.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from kavach_ai.backend.pipeline.stage1_triage.manifest_context import extract_manifest_artifact
from kavach_ai.backend.pipeline.stage2_static.decompile import extract_native_libraries, validate_apk
from kavach_ai.backend.pipeline.stage2_static.flowdroid import run_flowdroid
from kavach_ai.backend.pipeline.stage2_static.v2_canonical import canonical_sha256, write_json_atomic


SUBSET_PATH = REPO_ROOT / "configs/static_v2/representative_subset.json"
FLOW_CONFIG_PATH = REPO_ROOT / "configs/static_v2/flowdroid_stage1.json"
DEFINITIONS_PATH = REPO_ROOT / "configs/static_v2/sources_sinks_stage1.txt"
CATEGORIES_PATH = REPO_ROOT / "configs/static_v2/categories_stage1.json"
ACTIONS_PATH = REPO_ROOT / "configs/static_v2/actions_stage1.json"


def _load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def selected_apks() -> tuple[tuple[Path, dict], ...]:
    output = []
    for item in _load_json(SUBSET_PATH)["selection"]:
        apk = REPO_ROOT / "data" / item["label"] / f"{item['apk_sha256']}.apk"
        if not apk.is_file():
            raise FileNotFoundError(f"reviewed subset APK is missing: {apk}")
        output.append((apk, item))
    return tuple(output)


def analyze_one(
    apk: Path, *, output_root: Path, java: Path, sidecar_jar: Path,
    android_platforms: Path, timeout_seconds: float,
) -> dict:
    validated = validate_apk(apk)
    if validated.apk_hash != apk.stem:
        raise ValueError(f"immutable APK identity mismatch for {apk}")
    root = output_root / validated.apk_hash
    root.mkdir(parents=True, exist_ok=True)
    manifest = extract_manifest_artifact(apk)
    write_json_atomic(root / "manifest.json", manifest)

    native_libraries, native_issues = extract_native_libraries(validated, root / "native")
    managed_output = root / "managed.json"
    flow_config = _load_json(FLOW_CONFIG_PATH)
    command = (
        str(java), "-Xmx8g", "-jar", str(sidecar_jar),
        "--platforms", str(android_platforms),
        "--sources-sinks", str(DEFINITIONS_PATH),
        "--categories", str(CATEGORIES_PATH),
        "--actions", str(ACTIONS_PATH),
        "--data-timeout", str(flow_config["data_timeout_seconds"]),
        "--callback-timeout", str(flow_config["callback_timeout_seconds"]),
        "--path-timeout", str(flow_config["path_timeout_seconds"]),
    )
    managed = run_flowdroid(
        command=command, apk_path=apk, output_path=managed_output,
        config=flow_config, timeout_seconds=timeout_seconds,
    )
    if not managed_output.exists():
        write_json_atomic(managed_output, managed)
    summary = {
        "apk_sha256": validated.apk_hash,
        "managed_status": managed.status,
        "flow_count": len(managed.flows),
        "action_count": len(managed.actions),
        "native_library_count": len(native_libraries),
        "native_libraries": [
            {"archive_path": item.archive_path, "abi": item.abi, "sha256": item.sha256, "path": item.extracted_path}
            for item in native_libraries
        ],
        "native_inventory_issues": [getattr(item, "code", "UNKNOWN") for item in native_issues],
        "manifest_component_count": len(manifest.components),
        "config_sha256": canonical_sha256(flow_config),
    }
    write_json_atomic(root / "summary.json", summary)
    return summary


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--java", type=Path, required=True)
    parser.add_argument("--sidecar-jar", type=Path, required=True)
    parser.add_argument("--android-platforms", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, default=REPO_ROOT / "training/data/.work/v2_subset")
    parser.add_argument("--apk-hash", action="append", default=[])
    parser.add_argument("--timeout-seconds", type=float, default=600)
    args = parser.parse_args()
    allowed = {item[1]["apk_sha256"] for item in selected_apks()}
    requested = set(args.apk_hash) if args.apk_hash else allowed
    unknown = requested - allowed
    if unknown:
        raise SystemExit(f"refusing hashes outside reviewed subset: {sorted(unknown)}")
    results = []
    for apk, item in selected_apks():
        if item["apk_sha256"] in requested:
            results.append(analyze_one(
                apk, output_root=args.output_root, java=args.java,
                sidecar_jar=args.sidecar_jar, android_platforms=args.android_platforms,
                timeout_seconds=args.timeout_seconds,
            ))
    print(json.dumps(results, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
