"""Strict YAML configuration for the permanent training pipeline."""

from __future__ import annotations

import argparse
import copy
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator, Mapping, Sequence

import yaml


REPO_ROOT = Path(__file__).resolve().parents[2]
CONFIG_SCHEMA = "training-config-v2"
LABEL_IDS = {"Benign": 0, "Malicious": 1}
ID2LABEL = {0: "Benign", 1: "Malicious"}
KNOWN_METRICS = frozenset({"f1", "accuracy", "precision", "recall", "tn", "fp", "fn", "tp", "loss"})

CONFIG_KEYS = {
    "schema_version": None,
    "run": {"mode", "name", "seed", "output_dir", "overwrite_output_dir", "resume_from_checkpoint"},
    "data": {
        "root", "train_split", "eval_split", "tokenizer_fingerprint", "sampler",
        "exclude_internally_truncated", "min_token_length", "max_token_length",
        "include_sink_categories", "exclude_sink_categories", "excluded_example_ids",
        "max_context_length", "context_policy", "tiny_examples", "tiny_candidate_pool",
        "tiny_disallowed_boundaries", "smoke_examples",
    },
    "model": {"checkpoint", "tokenizer"},
    "lora": {"enabled", "task_type", "target_modules", "modules_to_save", "rank", "alpha", "dropout", "bias"},
    "hardware": {"device", "precision", "gradient_checkpointing", "torch_compile"},
    "trainer": {
        "per_device_train_batch_size", "per_device_eval_batch_size", "gradient_accumulation_steps",
        "learning_rate", "weight_decay", "warmup_ratio", "num_train_epochs", "max_steps",
        "logging_steps", "eval_strategy", "eval_steps", "save_strategy", "save_steps",
        "save_total_limit", "max_grad_norm", "load_best_model_at_end", "metric_for_best_model",
        "greater_is_better", "dataloader_num_workers", "dataloader_persistent_workers",
        "disable_tqdm", "seed", "data_seed", "pad_to_multiple_of",
    },
    "wandb": {"mode", "project", "entity", "group", "job_type", "tags", "notes", "log_model", "watch_model"},
}


@dataclass(frozen=True)
class ResolvedFilters:
    included_categories: frozenset[str]
    excluded_categories: frozenset[str]
    excluded_example_ids: frozenset[str]
    tiny_disallowed_boundaries: frozenset[str]


@dataclass(frozen=True)
class ResolvedConfig(Mapping[str, Any]):
    raw: dict[str, Any]
    filters: ResolvedFilters

    def __getitem__(self, key: str) -> Any:
        return self.raw[key]

    def __iter__(self) -> Iterator[str]:
        return iter(self.raw)

    def __len__(self) -> int:
        return len(self.raw)

    def serializable(self) -> dict[str, Any]:
        return copy.deepcopy(self.raw)


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Kavach SecureBERT training pipeline")
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--resume-from-checkpoint", type=Path)
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--run-name")
    parser.add_argument("--wandb-mode", choices=("online", "offline", "disabled"))
    return parser.parse_args(argv)


def _require(value: Any, expected: type, name: str, *, nullable: bool = False) -> None:
    if value is None and nullable:
        return
    valid = type(value) is expected if expected in {bool, int} else isinstance(value, expected)
    if not valid:
        raise ValueError(f"{name} must be {expected.__name__}" + (" or null" if nullable else ""))


def _number(value: Any, name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{name} must be a number")
    return float(value)


def _string_list(value: Any, name: str, *, nullable: bool = False) -> None:
    if value is None and nullable:
        return
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise ValueError(f"{name} must be a list of strings" + (" or null" if nullable else ""))


def _validate_section(name: str, value: Any, allowed: set[str]) -> None:
    if not isinstance(value, dict):
        raise ValueError(f"Config section {name!r} must be a mapping")
    extra, absent = set(value) - allowed, allowed - set(value)
    if extra or absent:
        raise ValueError(f"Invalid {name} keys: missing={sorted(absent)}, unknown={sorted(extra)}")


def validate_keys(config: Mapping[str, Any]) -> None:
    unknown, missing = set(config) - set(CONFIG_KEYS), set(CONFIG_KEYS) - set(config)
    if unknown or missing:
        raise ValueError(f"Invalid top-level config keys: missing={sorted(missing)}, unknown={sorted(unknown)}")
    for section, allowed in CONFIG_KEYS.items():
        if allowed is not None:
            _validate_section(section, config[section], allowed)
    _validate_section("data.sampler", config["data"]["sampler"], {"type", "active_apk_shards"})


def validate_config(config: Mapping[str, Any]) -> None:
    validate_keys(config)
    _require(config["schema_version"], str, "schema_version")
    if config["schema_version"] != CONFIG_SCHEMA:
        raise ValueError(f"Unsupported config schema: {config['schema_version']!r}")
    run, data, model = config["run"], config["data"], config["model"]
    lora, hardware, trainer, wandb = config["lora"], config["hardware"], config["trainer"], config["wandb"]

    for key in ("mode", "name"):
        _require(run[key], str, f"run.{key}")
    _require(run["seed"], int, "run.seed")
    _require(run["output_dir"], str, "run.output_dir", nullable=True)
    _require(run["overwrite_output_dir"], bool, "run.overwrite_output_dir")
    _require(run["resume_from_checkpoint"], str, "run.resume_from_checkpoint", nullable=True)
    if run["mode"] not in {"dry_run", "smoke", "tiny_overfit", "train"}:
        raise ValueError("run.mode must be dry_run, smoke, tiny_overfit, or train")
    if not run["name"].strip() or run["seed"] < 0:
        raise ValueError("run.name must be non-empty and seed non-negative")
    if run["resume_from_checkpoint"] is not None:
        raise NotImplementedError("Checkpoint resume is not implemented")

    for key in ("root", "train_split", "eval_split", "context_policy"):
        _require(data[key], str, f"data.{key}")
    _require(data["tokenizer_fingerprint"], str, "data.tokenizer_fingerprint", nullable=True)
    _require(data["exclude_internally_truncated"], bool, "data.exclude_internally_truncated")
    for key in ("min_token_length", "max_context_length", "tiny_examples", "tiny_candidate_pool", "smoke_examples"):
        _require(data[key], int, f"data.{key}")
    _require(data["max_token_length"], int, "data.max_token_length", nullable=True)
    _string_list(data["include_sink_categories"], "data.include_sink_categories", nullable=True)
    for key in ("exclude_sink_categories", "excluded_example_ids", "tiny_disallowed_boundaries"):
        _string_list(data[key], f"data.{key}")
    sampler = data["sampler"]
    _require(sampler["type"], str, "data.sampler.type")
    _require(sampler["active_apk_shards"], int, "data.sampler.active_apk_shards")
    if sampler["type"] not in {"standard", "apk_interleaved"} or sampler["active_apk_shards"] <= 0:
        raise ValueError("Invalid sampler type or active_apk_shards")
    if data["train_split"] != "train" or data["eval_split"] != "validation":
        raise ValueError("Immutable train/validation splits are required")
    if data["context_policy"] != "head":
        raise NotImplementedError("sink_centered requires unavailable sink-token spans")
    if data["min_token_length"] <= 0 or not 0 < data["max_context_length"] <= 8192:
        raise ValueError("Token length must be positive and context length in 1..8192")
    if data["max_token_length"] is not None and data["max_token_length"] < data["min_token_length"]:
        raise ValueError("max_token_length must be null or >= min_token_length")
    if data["tiny_examples"] not in range(16, 33) or data["tiny_examples"] % 2:
        raise ValueError("tiny_examples must be even and between 16 and 32")
    if data["tiny_candidate_pool"] < data["tiny_examples"] or data["smoke_examples"] <= 0:
        raise ValueError("Invalid tiny candidate pool or smoke example count")
    included, excluded = set(data["include_sink_categories"] or ()), set(data["exclude_sink_categories"])
    if included & excluded:
        raise ValueError(f"Sink categories overlap: {sorted(included & excluded)}")

    for key in ("checkpoint", "tokenizer"):
        _require(model[key], str, f"model.{key}", nullable=(key == "tokenizer"))
    _require(lora["enabled"], bool, "lora.enabled")
    for key in ("task_type", "bias"):
        _require(lora[key], str, f"lora.{key}")
    for key in ("target_modules", "modules_to_save"):
        _string_list(lora[key], f"lora.{key}")
    for key in ("rank", "alpha"):
        _require(lora[key], int, f"lora.{key}")
    dropout = _number(lora["dropout"], "lora.dropout")
    if not lora["enabled"] or lora["task_type"] != "SEQ_CLS" or lora["target_modules"] != ["Wqkv"]:
        raise ValueError("This pipeline requires enabled SEQ_CLS LoRA targeting only Wqkv")
    if lora["modules_to_save"] != ["head", "classifier"] or lora["rank"] <= 0 or lora["alpha"] <= 0:
        raise ValueError("Invalid LoRA save modules, rank, or alpha")
    if not 0 <= dropout < 1 or lora["bias"] != "none":
        raise ValueError("LoRA dropout must be in [0,1) and bias must be none")

    for key in ("device", "precision"):
        _require(hardware[key], str, f"hardware.{key}")
    for key in ("gradient_checkpointing", "torch_compile"):
        _require(hardware[key], bool, f"hardware.{key}")
    if hardware["device"] not in {"auto", "cpu", "mps", "cuda"}:
        raise ValueError("Invalid hardware.device")
    if hardware["precision"] not in {"fp32", "fp16", "bf16"}:
        raise ValueError("Invalid hardware.precision")

    integer_fields = (
        "per_device_train_batch_size", "per_device_eval_batch_size", "gradient_accumulation_steps",
        "max_steps", "logging_steps", "save_total_limit", "dataloader_num_workers", "seed", "data_seed",
    )
    for key in integer_fields:
        _require(trainer[key], int, f"trainer.{key}")
    for key in ("eval_steps", "save_steps", "pad_to_multiple_of"):
        _require(trainer[key], int, f"trainer.{key}", nullable=True)
    for key in ("eval_strategy", "save_strategy", "metric_for_best_model"):
        _require(trainer[key], str, f"trainer.{key}")
    for key in ("load_best_model_at_end", "greater_is_better", "dataloader_persistent_workers", "disable_tqdm"):
        _require(trainer[key], bool, f"trainer.{key}")
    learning_rate = _number(trainer["learning_rate"], "trainer.learning_rate")
    weight_decay = _number(trainer["weight_decay"], "trainer.weight_decay")
    warmup = _number(trainer["warmup_ratio"], "trainer.warmup_ratio")
    epochs = _number(trainer["num_train_epochs"], "trainer.num_train_epochs")
    max_grad = _number(trainer["max_grad_norm"], "trainer.max_grad_norm")
    if min(trainer["per_device_train_batch_size"], trainer["per_device_eval_batch_size"], trainer["gradient_accumulation_steps"]) <= 0:
        raise ValueError("Batch sizes and gradient accumulation must be positive")
    if learning_rate <= 0 or weight_decay < 0 or not 0 <= warmup < 1 or epochs <= 0 or max_grad <= 0:
        raise ValueError("Invalid optimizer numeric configuration")
    if trainer["max_steps"] != -1 and trainer["max_steps"] <= 0:
        raise ValueError("max_steps must be -1 or positive")
    if trainer["logging_steps"] <= 0 or trainer["save_total_limit"] <= 0:
        raise ValueError("logging_steps and save_total_limit must be positive")
    if trainer["eval_strategy"] not in {"no", "steps", "epoch"} or trainer["save_strategy"] not in {"no", "steps", "epoch"}:
        raise ValueError("Invalid eval/save strategy")
    if trainer["eval_strategy"] == "steps" and (trainer["eval_steps"] is None or trainer["eval_steps"] <= 0):
        raise ValueError("Positive eval_steps is required for steps evaluation")
    if trainer["save_strategy"] == "steps" and (trainer["save_steps"] is None or trainer["save_steps"] <= 0):
        raise ValueError("Positive save_steps is required for steps saving")
    if trainer["load_best_model_at_end"]:
        if trainer["eval_strategy"] == "no" or trainer["eval_strategy"] != trainer["save_strategy"]:
            raise ValueError("Best-model loading requires matching non-no eval/save strategies")
        if trainer["eval_strategy"] == "steps" and trainer["save_steps"] % trainer["eval_steps"]:
            raise ValueError("save_steps must be a multiple of eval_steps")
    if trainer["metric_for_best_model"] not in KNOWN_METRICS:
        raise ValueError("Unknown best-model metric")
    if trainer["dataloader_num_workers"] != 0 or trainer["dataloader_persistent_workers"]:
        raise ValueError("This pipeline requires workers=0 and persistent_workers=false")
    if trainer["pad_to_multiple_of"] is not None and trainer["pad_to_multiple_of"] <= 0:
        raise ValueError("pad_to_multiple_of must be positive or null")
    if run["seed"] != trainer["seed"] or run["seed"] != trainer["data_seed"]:
        raise ValueError("run.seed, trainer.seed, and trainer.data_seed must match")

    for key in ("mode", "project", "job_type"):
        _require(wandb[key], str, f"wandb.{key}")
    for key in ("entity", "group", "notes"):
        _require(wandb[key], str, f"wandb.{key}", nullable=True)
    _string_list(wandb["tags"], "wandb.tags")
    for key in ("log_model", "watch_model"):
        _require(wandb[key], bool, f"wandb.{key}")
    if wandb["mode"] not in {"online", "offline", "disabled"}:
        raise ValueError("Invalid wandb.mode")


def load_config(path: Path, overrides: argparse.Namespace | None = None) -> ResolvedConfig:
    value = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("Training config must be a YAML mapping")
    value = copy.deepcopy(value)
    if overrides is not None:
        for attribute, section, key in (
            ("resume_from_checkpoint", "run", "resume_from_checkpoint"),
            ("output_dir", "run", "output_dir"),
            ("run_name", "run", "name"),
            ("wandb_mode", "wandb", "mode"),
        ):
            override = getattr(overrides, attribute, None)
            if override is not None:
                value[section][key] = str(override)
    validate_config(value)
    data = value["data"]
    return ResolvedConfig(value, ResolvedFilters(
        frozenset(data["include_sink_categories"] or ()),
        frozenset(data["exclude_sink_categories"]),
        frozenset(data["excluded_example_ids"]),
        frozenset(data["tiny_disallowed_boundaries"]),
    ))


def resolve_path(value: str | Path, *, base: Path = REPO_ROOT) -> Path:
    path = Path(value)
    return path if path.is_absolute() else base / path


def canonical_config(config: ResolvedConfig | Mapping[str, Any]) -> dict[str, Any]:
    return config.serializable() if isinstance(config, ResolvedConfig) else json.loads(json.dumps(config))
