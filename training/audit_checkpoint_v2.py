"""Audit an already-generated deterministic V2 prefix without mutating it."""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from transformers import AutoTokenizer

from kavach_ai.backend.pipeline.stage2_static.v2_canonical import read_json, write_json_atomic
from kavach_ai.backend.pipeline.stage3_ml.checkpoint_audit import (
    APKCheckpointRecord, PhaseMeasure, build_checkpoint_metrics,
)
from training.run_corpus_v2 import METADATA, SPLITS, V2_ROOT, inventory

MODEL = "cisco-ai/SecureBERT2.0-base"


def size(path: Path) -> int:
    return path.stat().st_size if path.exists() else 0


def percentile(values: list[int], p: float) -> int | None:
    if not values: return None
    ordered = sorted(values)
    return ordered[max(0, min(len(ordered) - 1, int((len(ordered) * p + 0.999999)) - 1))]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--limit", type=int, required=True)
    parser.add_argument("--total-planned", type=int, default=500)
    args = parser.parse_args()
    selected = inventory()[:args.limit]
    tokenizer = AutoTokenizer.from_pretrained(MODEL, local_files_only=True)
    records = []
    source_counts, endpoint_counts, source_endpoint_counts = Counter(), Counter(), Counter()
    api_counts, api_apks = Counter(), {}
    all_tokens: list[int] = []
    for item in selected:
        digest = item["apk_hash"]
        status = read_json(V2_ROOT / "status" / f"{digest}.json")
        behavior_path = V2_ROOT / "behavior_artifacts" / f"{digest}.json"
        behavior = read_json(behavior_path)
        artifacts = behavior.get("artifacts", ())
        token_counts, lanes, categories = [], Counter(), Counter()
        apk_source_endpoints, apk_definitions = Counter(), Counter()
        definitions_in_apk = set()
        semantic_hashes = []
        for artifact in artifacts:
            semantic_hashes.append(artifact["semantic_sha256"])
            categories[artifact["behavior_category"]] += 1
            source_counts[artifact["source_category"]] += 1
            endpoint_counts[artifact["sink_category"]] += 1
            source_endpoint_counts[
                f"{artifact['source_category']}->{artifact['sink_category']}"
            ] += 1
            apk_source_endpoints[
                f"{artifact['source_category']}->{artifact['sink_category']}"
            ] += 1
            flow, action = artifact.get("flow"), artifact.get("action")
            native = artifact.get("native_context", {}).get("crossed", False)
            lane = "NATIVE_ACTION" if native and action else "MULTI_LANE" if native else "FLOWDROID_TAINT" if flow else "ACTION_DEPENDENCY"
            lanes[lane] += 1
            definition = (flow or {}).get("sink", {}).get("definition") if flow else (action or {}).get("endpoint", {}).get("definition")
            if definition:
                api_counts[definition] += 1
                definitions_in_apk.add(definition)
                apk_definitions[definition] += 1
            view_path = V2_ROOT / "modelviews/v2/candidate1" / digest / f"{artifact['artifact_id']}.json"
            view = read_json(view_path)
            count = len(tokenizer(view["text"], add_special_tokens=True, truncation=False)["input_ids"])
            token_counts.append(count); all_tokens.append(count)
        for definition in definitions_in_apk:
            api_apks[definition] = api_apks.get(definition, 0) + 1
        measures = []
        for phase, value in status["phases"].items():
            output = Path(value["output"]) if value.get("output") else None
            measures.append(PhaseMeasure(phase, value["status"], value.get("runtime_seconds", 0.0),
                                         value.get("max_rss_kb"), size(output) if output else 0))
        records.append(APKCheckpointRecord(
            apk_sha256=digest, label=item["label"], split=item["split"],
            raw_occurrences=behavior.get("raw_occurrences", len(artifacts)),
            artifact_hashes=tuple(semantic_hashes), artifact_token_counts=tuple(token_counts),
            lane_counts=tuple(sorted(lanes.items())), behavior_counts=tuple(sorted(categories.items())),
            phase_measures=tuple(measures),
            source_endpoint_counts=tuple(sorted(apk_source_endpoints.items())),
            endpoint_definition_counts=tuple(sorted(apk_definitions.items())),
        ))
    metrics = build_checkpoint_metrics(records, total_planned_apks=args.total_planned,
                                       token_thresholds=(1024, 2048, 4096, 8192))
    metrics["source_counts"] = dict(source_counts.most_common())
    metrics["endpoint_counts"] = dict(endpoint_counts.most_common())
    metrics["source_endpoint_counts"] = dict(source_endpoint_counts.most_common())
    metrics["top_endpoint_definitions"] = dict(api_counts.most_common(20))
    metrics["top_endpoint_definition_apk_coverage"] = {
        definition: api_apks[definition]
        for definition, _ in api_counts.most_common(20)
    }
    metrics["token_distribution"].update({"p99": percentile(all_tokens, .99)})
    metrics["v2_storage_bytes_on_disk"] = sum(path.stat().st_size for path in V2_ROOT.rglob("*") if path.is_file())
    destination = V2_ROOT / "audit" / f"checkpoint_{args.limit}.json"
    write_json_atomic(destination, metrics)
    print(json.dumps(metrics, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
