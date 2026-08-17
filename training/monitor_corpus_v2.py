"""Read-only progress display for a running frozen V2 corpus extraction."""

from __future__ import annotations

import argparse
import json
import statistics
import time
from collections import Counter
from pathlib import Path


def snapshot(root: Path, selection_path: Path, fingerprint: str) -> dict:
    selected = json.loads(selection_path.read_text(encoding="utf-8"))["apk_sha256"]
    completed, runtimes = [], []
    states: Counter[str] = Counter()
    lanes: Counter[str] = Counter()
    labels: Counter[str] = Counter()
    artifacts = zero_artifacts = 0
    current = None
    for digest in selected:
        status_path = root / "status" / f"{digest}.json"
        status = json.loads(status_path.read_text(encoding="utf-8")) if status_path.exists() else {}
        managed = status.get("phases", {}).get("managed", {})
        if managed.get("config_sha256") != fingerprint:
            if current is None:
                current = digest
            continue
        completed.append(digest)
        states[managed.get("status", "UNKNOWN")] += 1
        runtime = sum(
            value.get("runtime_seconds", 0.0)
            for name, value in status.get("phases", {}).items()
            if name == "managed_actions" or name.startswith("managed_taint_")
        )
        runtimes.append(runtime)
        behavior_path = root / "behavior_artifacts" / f"{digest}.json"
        if not behavior_path.exists():
            continue
        values = json.loads(behavior_path.read_text(encoding="utf-8")).get("artifacts", ())
        artifacts += len(values)
        zero_artifacts += not values
        for artifact in values:
            action, flow = artifact.get("action"), artifact.get("flow")
            native = artifact.get("native_context", {}).get("crossed", False)
            lane = "NATIVE_ACTION" if native and action else "FLOWDROID_TAINT" if flow else "ACTION_DEPENDENCY"
            lanes[lane] += 1
    mean = statistics.mean(runtimes) if runtimes else 0.0
    return {
        "completed": len(completed), "remaining": len(selected) - len(completed),
        "current_or_next_apk": current, "managed_status": dict(states),
        "zero_artifact_apks": zero_artifacts, "behavior_artifacts": artifacts,
        "lanes": dict(lanes), "managed_runtime_mean_seconds": round(mean, 1),
        "managed_runtime_median_seconds": round(statistics.median(runtimes), 1) if runtimes else 0.0,
        "eta_hours": round((len(selected) - len(completed)) * mean / 3600, 1),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path("training/data/v2"))
    parser.add_argument("--selection", type=Path,
                        default=Path("training/data/v2/corpus/balanced_500_v1.json"))
    parser.add_argument("--managed-fingerprint", required=True)
    parser.add_argument("--interval", type=float, default=0.0,
                        help="refresh interval; zero prints once")
    args = parser.parse_args()
    while True:
        print(json.dumps(snapshot(args.root, args.selection, args.managed_fingerprint), indent=2))
        if args.interval <= 0:
            return
        print("Press Ctrl-C to stop monitoring; extraction is unaffected.", flush=True)
        time.sleep(args.interval)


if __name__ == "__main__":
    main()
