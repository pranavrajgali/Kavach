"""Hardware, Transformers Trainer, and privacy-preserving W&B integration."""

from __future__ import annotations

import os
import platform
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

import torch
from transformers import Trainer, TrainerCallback, TrainingArguments

from training.pipeline.metrics import binary_classification_metrics


FINAL_ADAPTER_DIRECTORY = "final-adapter"


@dataclass(frozen=True)
class HardwareResolution:
    device: str
    precision: str
    fp16: bool
    bf16: bool
    cuda_available: bool
    mps_built: bool
    mps_available: bool
    device_name: str
    dataloader_pin_memory: bool


@dataclass(frozen=True)
class TrainingRunResult:
    adapter_path: Path
    metrics: dict[str, Any]
    runtime_seconds: float


def _section(config: Mapping[str, Any], name: str) -> Mapping[str, Any]:
    value = config[name]
    if not isinstance(value, Mapping):
        raise ValueError(f"{name} must be a mapping")
    return value


def resolve_hardware(config: Mapping[str, Any]) -> HardwareResolution:
    hardware = _section(config, "hardware")
    cuda_available = torch.cuda.is_available()
    mps_built = torch.backends.mps.is_built()
    mps_available = torch.backends.mps.is_available()
    requested = hardware["device"]
    if requested == "auto":
        device = "cuda" if cuda_available else "mps" if mps_available else "cpu"
    elif requested == "cuda":
        if not cuda_available:
            raise RuntimeError("CUDA was requested but is unavailable")
        device = "cuda"
    elif requested == "mps":
        if not mps_available:
            raise RuntimeError("MPS was requested but is unavailable")
        device = "mps"
    elif requested == "cpu":
        device = "cpu"
    else:
        raise ValueError("hardware.device must be auto, cuda, mps, or cpu")

    precision = str(hardware["precision"]).lower()
    if precision not in {"fp32", "fp16", "bf16"}:
        raise ValueError("hardware.precision must be fp32, fp16, or bf16")
    if precision != "fp32" and device != "cuda":
        raise RuntimeError(f"{precision.upper()} is unsupported on {device.upper()}; use FP32")
    if precision == "bf16" and not torch.cuda.is_bf16_supported():
        raise RuntimeError("BF16 was requested but this CUDA device does not support it")
    device_name = (torch.cuda.get_device_name(0) if device == "cuda" else
                   "Apple MPS" if device == "mps" else platform.processor() or "CPU")
    return HardwareResolution(
        device, precision, precision == "fp16", precision == "bf16",
        cuda_available, mps_built, mps_available, device_name, device == "cuda",
    )


def effective_batch_size(config: Mapping[str, Any], *, world_size: int | None = None) -> int:
    trainer = _section(config, "trainer")
    resolved_world_size = int(os.environ.get("WORLD_SIZE", "1")) if world_size is None else world_size
    if resolved_world_size != 1:
        raise RuntimeError("Only single-process training (WORLD_SIZE=1) is supported in this phase")
    return (int(trainer["per_device_train_batch_size"])
            * int(trainer["gradient_accumulation_steps"]) * resolved_world_size)


def adapter_output_path(output_dir: str | Path) -> Path:
    return Path(output_dir) / FINAL_ADAPTER_DIRECTORY


def _sanitized_exception_message(error: BaseException) -> str:
    message = str(error).replace("\n", " ")[:1000]
    # Exception summaries are provenance, so redact Unix-style absolute paths.
    return re.sub(r"(?<![\w.])/(?:[^\s/:]+/)*[^\s:]*", "<absolute-path>", message)


def wandb_report_to(config: Mapping[str, Any]) -> list[str]:
    mode = _section(config, "wandb")["mode"]
    if mode == "disabled":
        return []
    if mode in {"offline", "online"}:
        return ["wandb"]
    raise ValueError("wandb.mode must be disabled, offline, or online")


def configure_wandb_environment(config: Mapping[str, Any]) -> None:
    """Configure W&B without ever inspecting or modifying an API key."""
    wandb = _section(config, "wandb")
    mode = wandb["mode"]
    if mode == "disabled":
        os.environ["WANDB_DISABLED"] = "true"
        os.environ.pop("WANDB_MODE", None)
    else:
        os.environ.pop("WANDB_DISABLED", None)
        os.environ["WANDB_MODE"] = mode
    os.environ["WANDB_WATCH"] = "all" if wandb["watch_model"] else "false"
    os.environ["WANDB_LOG_MODEL"] = "end" if wandb["log_model"] else "false"


def safe_wandb_config(config: Mapping[str, Any], *, selected_records_hash: str | None = None,
                      aggregate_counts: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Return the intentionally small allow-list sent to W&B."""
    run, data, trainer = (_section(config, key) for key in ("run", "data", "trainer"))
    result: dict[str, Any] = {
        "run_name": run["name"], "seed": run["seed"], "mode": run["mode"],
        "max_context_length": data["max_context_length"],
        "effective_batch_size": effective_batch_size(config),
        "learning_rate": trainer["learning_rate"],
    }
    if selected_records_hash is not None:
        result["selected_records_sha256"] = selected_records_hash
    if aggregate_counts is not None:
        result["aggregate_counts"] = dict(aggregate_counts)
    from training.pipeline.provenance import sanitize_metadata
    safe = sanitize_metadata(result)
    forbidden = {"api_key", "wandb_api_key", "secret", "token", "password"}
    def check(value: Any) -> None:
        if isinstance(value, Mapping):
            for key, item in value.items():
                if str(key).lower() in forbidden:
                    raise ValueError(f"Forbidden secret field in W&B metadata: {key}")
                check(item)
        elif isinstance(value, list):
            for item in value:
                check(item)
    check(safe)
    return safe


class SanitizedWandbCallback(TrainerCallback):
    """Logs scalar Trainer events without serializing arguments, models, or paths."""

    def __init__(self, config: Mapping[str, Any], safe_config: Mapping[str, Any]) -> None:
        self.config, self.safe_config, self._run = config, dict(safe_config), None

    def setup(self, args: Any, state: Any, model: Any, **kwargs: Any) -> None:
        if self._run is not None or not state.is_world_process_zero:
            return
        import wandb
        settings = _section(self.config, "wandb")
        self._run = wandb.init(project=settings["project"], entity=settings.get("entity"),
                               name=_section(self.config, "run")["name"],
                               group=settings.get("group"), job_type=settings["job_type"],
                               tags=settings.get("tags"), notes=settings.get("notes"),
                               config=self.safe_config, mode=settings["mode"])
        if settings["watch_model"]:
            wandb.watch(model)

    def on_train_begin(self, args: Any, state: Any, control: Any, model: Any = None, **kwargs: Any) -> None:
        self.setup(args, state, model)

    def on_log(self, args: Any, state: Any, control: Any, logs: Mapping[str, Any] | None = None, **kwargs: Any) -> None:
        if self._run is not None and logs:
            safe = {key: value for key, value in logs.items() if isinstance(value, (int, float))}
            self._run.log(safe, step=state.global_step)

    def on_train_end(self, args: Any, state: Any, control: Any, **kwargs: Any) -> None:
        if self._run is not None:
            self._run.finish()
            self._run = None


def build_training_arguments(config: Mapping[str, Any], output_dir: str | Path | None = None) -> TrainingArguments:
    run, trainer, hardware = (_section(config, key) for key in ("run", "trainer", "hardware"))
    resolved = resolve_hardware(config)
    kwargs = dict(
        output_dir=str(output_dir if output_dir is not None else run["output_dir"]),
        overwrite_output_dir=run["overwrite_output_dir"], seed=trainer["seed"], data_seed=trainer["data_seed"],
        per_device_train_batch_size=trainer["per_device_train_batch_size"],
        per_device_eval_batch_size=trainer["per_device_eval_batch_size"],
        gradient_accumulation_steps=trainer["gradient_accumulation_steps"],
        num_train_epochs=trainer["num_train_epochs"], max_steps=trainer["max_steps"],
        learning_rate=trainer["learning_rate"], weight_decay=trainer["weight_decay"],
        warmup_ratio=trainer["warmup_ratio"], max_grad_norm=trainer["max_grad_norm"],
        eval_strategy=trainer["eval_strategy"], eval_steps=trainer["eval_steps"],
        save_strategy=trainer["save_strategy"], save_steps=trainer["save_steps"],
        logging_strategy="steps", logging_steps=trainer["logging_steps"],
        save_total_limit=trainer["save_total_limit"], load_best_model_at_end=trainer["load_best_model_at_end"],
        metric_for_best_model=trainer["metric_for_best_model"], greater_is_better=trainer["greater_is_better"],
        dataloader_num_workers=trainer["dataloader_num_workers"],
        dataloader_persistent_workers=trainer["dataloader_persistent_workers"],
        dataloader_pin_memory=resolved.dataloader_pin_memory,
        report_to=wandb_report_to(config), run_name=run["name"], fp16=resolved.fp16, bf16=resolved.bf16,
        gradient_checkpointing=hardware["gradient_checkpointing"], torch_compile=hardware["torch_compile"],
        use_cpu=resolved.device == "cpu",
        disable_tqdm=trainer["disable_tqdm"], remove_unused_columns=False,
        label_names=["labels"],
    )
    arguments = TrainingArguments(**kwargs)
    actual = arguments.device.type
    if actual != resolved.device:
        raise RuntimeError(f"Trainer resolved device {actual!r}, expected {resolved.device!r}")
    return arguments


def build_trainer(config: Mapping[str, Any], model: Any, train_dataset: Any, eval_dataset: Any,
                  data_collator: Any, processing_class: Any = None, *, output_dir: str | Path | None = None,
                  selected_records_hash: str | None = None,
                  aggregate_counts: Mapping[str, Any] | None = None) -> Trainer:
    configure_wandb_environment(config)
    arguments = build_training_arguments(config, output_dir)
    instance = Trainer(model=model, args=arguments, train_dataset=train_dataset,
                       eval_dataset=eval_dataset, data_collator=data_collator,
                       processing_class=processing_class,
                       compute_metrics=binary_classification_metrics)
    if wandb_report_to(config):
        from transformers.integrations import WandbCallback
        instance.remove_callback(WandbCallback)
        instance.add_callback(SanitizedWandbCallback(
            config, safe_wandb_config(config, selected_records_hash=selected_records_hash,
                                      aggregate_counts=aggregate_counts)))
    return instance


def run_training(instance: Trainer, config: Mapping[str, Any], output_dir: str | Path,
                 *, transition: Any = None, finalize: Any = None) -> TrainingRunResult:
    """Run the standard Trainer lifecycle when explicitly invoked by the entry point.

    ``transition(status, details)`` owns atomic lifecycle persistence and ``finalize``
    commits metrics/provenance before the completed transition. Keeping these as
    callbacks avoids a dependency from runtime code back into provenance code.
    """
    mode = _section(config, "run")["mode"]
    adapter_path = adapter_output_path(output_dir)
    started = time.monotonic()

    def emit(status: str, details: Mapping[str, Any]) -> None:
        if transition is not None:
            transition(status, dict(details))

    emit("prepared", {"adapter_path": FINAL_ADAPTER_DIRECTORY})
    try:
        # This transition is deliberately adjacent to Trainer.train().
        emit("running", {})
        train_output = instance.train()
        metrics = dict(getattr(train_output, "metrics", {}) or {})
        if instance.eval_dataset is not None:
            prefix = "memorization" if mode == "tiny_overfit" else "eval"
            metrics.update(instance.evaluate(metric_key_prefix=prefix))
        instance.save_model(str(adapter_path))
        # The pickle contains local output/logging paths and is unnecessary for
        # loading a PEFT adapter; the sanitized config and Trainer state remain.
        (adapter_path / "training_args.bin").unlink(missing_ok=True)
        instance.save_state()
        elapsed = time.monotonic() - started
        result = TrainingRunResult(adapter_path, metrics, elapsed)
        if finalize is not None:
            finalize(result)
        emit("completed", {"runtime_seconds": elapsed})
        return result
    except BaseException as error:
        elapsed = time.monotonic() - started
        emit("failed", {"exception_type": type(error).__name__,
                        "exception_message": _sanitized_exception_message(error),
                        "runtime_seconds": elapsed})
        raise


# Stable public aliases used by the entry point and downstream callers.
calculate_effective_batch_size = effective_batch_size
create_training_arguments = build_training_arguments
create_trainer = build_trainer
