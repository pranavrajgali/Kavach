"""Permanent YAML-driven SecureBERT training entry point."""

from __future__ import annotations

import hashlib
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Sequence

import torch

_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from training.pipeline.config import ResolvedConfig, load_config, parse_args  # noqa: E402
from training.pipeline.data import (  # noqa: E402
    Corpus, PreflightResult, ScanSummary, TinyDataset, TokenShardIterableDataset,
    apply_context_policy, create_collator, load_corpus, load_local_tokenizer,
    load_validated_shard, preflight_split, prepare_record, scan_split,
    select_smoke_records, select_tiny_records, validate_tokenizer,
)
from training.pipeline.model import (  # noqa: E402
    attach_lora, load_local_model_and_tokenizer, resolve_lora_targets,
    sanitize_adapter_artifacts, set_safe_adapter_metadata, validate_adapter_metadata,
    validate_peft_model, verify_saved_adapter,
)
from training.pipeline.provenance import (  # noqa: E402
    RUN_MANIFEST_SCHEMA, commit_provenance, config_hash, git_commit,
    package_versions, plan_output, update_lifecycle, utc_now,
    write_training_artifacts,
    write_json_atomic,
)
from training.pipeline.trainer import (  # noqa: E402
    build_trainer, effective_batch_size, resolve_hardware, run_training,
)
from training.utils.dataset import split_mapping_digest  # noqa: E402


def _selection_summary(records: list[Any], preflight: PreflightResult) -> ScanSummary:
    return ScanSummary(
        len(records), dict(Counter(item.label_name for item in records)),
        dict(Counter(item.sink_category for item in records)),
        len({item.apk_hash for item in records}),
        sum(item.internal_truncated for item in records),
        sum(item.context_truncated for item in records), preflight.summary.stored_records,
        preflight.summary.rejected_records, preflight.summary.rejection_counts,
    )


def _selected_hash(records: list[dict[str, Any]]) -> str:
    encoded = "".join(json.dumps(item, sort_keys=True) + "\n" for item in records).encode()
    return hashlib.sha256(encoded).hexdigest()


def _batch(dataset: Any, collator: Any, size: int) -> dict[str, torch.Tensor]:
    iterator = iter(dataset)
    return collator([next(iterator) for _ in range(min(size, len(dataset)))])


def _base_manifest(config: ResolvedConfig, corpus: Any, summary: ScanSummary) -> dict[str, Any]:
    return {
        "schema_version": RUN_MANIFEST_SCHEMA, "run_name": config["run"]["name"],
        "mode": config["run"]["mode"], "status": "prepared", "start_time": utc_now(),
        "git_commit": git_commit(), "dataset_version": corpus.manifest["dataset_version"],
        "split_digest": split_mapping_digest(corpus.splits),
        "tokenizer_fingerprint": corpus.tokenizer_fingerprint,
        "normalization_version": corpus.manifest.get("normalization_version"),
        "slicer_version": corpus.manifest.get("slicer_version"),
        "sampler": config["data"]["sampler"], "summary": summary.__dict__,
    }


def _log_summary(summary: ScanSummary) -> None:
    print(f"[DATA] eligible records: {summary.count}; APKs: {summary.apk_count}")
    print(f"[DATA] classes: {summary.class_counts}")
    print(f"[DATA] categories: {summary.category_counts}")
    print(f"[DATA] rejected: {summary.rejected_records} {summary.rejection_counts or {}}")
    print(f"[DATA] internal/context truncated: {summary.internal_truncated}/{summary.context_truncated}")


def run_pipeline(config_path: Path, config: ResolvedConfig) -> None:
    output = plan_output(config)
    corpus = load_corpus(config)
    train_preflight = preflight_split(corpus, config, config["data"]["train_split"])
    mode = config["run"]["mode"]
    if mode == "smoke":
        records = select_smoke_records(corpus, config, train_preflight)
        train_dataset: Any = TinyDataset(records)
        eval_dataset = None
        summary = _selection_summary(records, train_preflight)
        selected = [record.manifest_fields() for record in records]
    elif mode == "tiny_overfit":
        records = select_tiny_records(corpus, config, train_preflight)
        train_dataset = TinyDataset(records)
        eval_dataset = train_dataset
        summary = _selection_summary(records, train_preflight)
        selected = [record.manifest_fields() for record in records]
    else:
        train_dataset = TokenShardIterableDataset(
            corpus, config, config["data"]["train_split"], train_preflight,
        )
        summary = train_preflight.summary
        selected = list(train_preflight.records)
        eval_dataset = None
        if mode == "train":
            evaluation = preflight_split(corpus, config, config["data"]["eval_split"])
            eval_dataset = TokenShardIterableDataset(
                corpus, config, config["data"]["eval_split"], evaluation,
            )

    manifest = _base_manifest(config, corpus, summary)
    if mode == "dry_run":
        tokenizer = load_local_tokenizer(corpus, config)
        batch = _batch(train_dataset, create_collator(tokenizer, config),
                       config["trainer"]["per_device_train_batch_size"])
        manifest.update({
            "status": "completed",
            "end_time": utc_now(),
            "batch": {"input_ids_shape": list(batch["input_ids"].shape),
                      "attention_mask_shape": list(batch["attention_mask"].shape),
                      "labels_shape": list(batch["labels"].shape),
                      "pad_token_id": tokenizer.pad_token_id},
        })
        commit_provenance(output, config_path, config, selected, manifest)
        _log_summary(summary)
        print(f"[BATCH] input_ids={tuple(batch['input_ids'].shape)} attention_mask={tuple(batch['attention_mask'].shape)} labels={tuple(batch['labels'].shape)}")
        print(f"[SAVE] {output.directory}")
        return

    tokenizer, base_model = load_local_model_and_tokenizer(config)
    validate_tokenizer(corpus, tokenizer)
    targets = resolve_lora_targets(base_model)
    model = attach_lora(base_model, targets)
    base_identifier = set_safe_adapter_metadata(model, config["model"]["checkpoint"])
    parameters = validate_peft_model(model)
    hardware = resolve_hardware(config)
    collator = create_collator(tokenizer, config)
    inspection_batch = _batch(train_dataset, collator, config["trainer"]["per_device_train_batch_size"])
    model.eval()
    with torch.no_grad():
        logits = model(input_ids=inspection_batch["input_ids"],
                       attention_mask=inspection_batch["attention_mask"]).logits
    if tuple(logits.shape) != (len(inspection_batch["labels"]), 2):
        raise ValueError(f"Expected [batch, 2] logits, got {tuple(logits.shape)}")

    versions = package_versions()
    aggregate = {
        "config_sha256": config_hash(config), "summary": summary.__dict__,
        "dataset_version": corpus.manifest["dataset_version"],
        "split_digest": split_mapping_digest(corpus.splits),
        "tokenizer_fingerprint": corpus.tokenizer_fingerprint,
        "sampler": config["data"]["sampler"], "lora": config["lora"],
        "lora_match_count": len(targets), "parameters": parameters.serializable(),
        "hardware": hardware.__dict__, "package_versions": versions,
    }
    trainer = build_trainer(
        config, model, train_dataset, eval_dataset, collator, tokenizer,
        output_dir=output.directory, selected_records_hash=_selected_hash(selected),
        aggregate_counts=aggregate,
    )
    manifest.update({
        "hardware": hardware.__dict__, "package_versions": versions,
        "effective_batch_size": effective_batch_size(config),
        "lora_match_count": len(targets), "trainable_parameters": parameters.serializable(),
        "model": {"identifier": base_identifier, "model_type": base_model.config.model_type,
                  "num_hidden_layers": base_model.config.num_hidden_layers,
                  "max_position_embeddings": base_model.config.max_position_embeddings},
    })
    commit_provenance(output, config_path, config, selected, manifest)
    write_training_artifacts(
        output.directory, environment={"hardware": hardware.__dict__, "package_versions": versions,
                                       "git_commit": git_commit()},
        lora_targets={"matched_modules": list(targets), "settings": config["lora"]},
        trainable_parameters={**parameters.serializable(),
                              "names": [name for name, value in model.named_parameters() if value.requires_grad]},
    )

    def transition(status: str, details: dict[str, Any]) -> None:
        update_lifecycle(output.directory, status, **details)

    def finalize(result: Any) -> None:
        sanitize_adapter_artifacts(result.adapter_path, base_identifier)
        adapter = validate_adapter_metadata(result.adapter_path, base_identifier)
        reload_check = None
        if mode == "smoke":
            batch_ids = [item["example_id"] for item in selected[:len(inspection_batch["labels"])]]
            reload_check = verify_saved_adapter(
                model, config["model"]["checkpoint"], result.adapter_path,
                {"input_ids": inspection_batch["input_ids"],
                 "attention_mask": inspection_batch["attention_mask"]},
                batch_ids,
            )
            write_json_atomic(output.directory / "reload-check.json", reload_check)
        write_training_artifacts(
            output.directory, environment={"hardware": hardware.__dict__, "package_versions": versions,
                                           "git_commit": git_commit()},
            lora_targets={"matched_modules": list(targets), "settings": config["lora"]},
            trainable_parameters=parameters.serializable(), adapter_metadata=adapter,
            metrics=result.metrics,
        )

    _log_summary(summary)
    run_training(trainer, config, output.directory, transition=transition, finalize=finalize)


def main(argv: Sequence[str] | None = None) -> None:
    args = parse_args(argv)
    run_pipeline(args.config, load_config(args.config, args))


if __name__ == "__main__":
    main()
