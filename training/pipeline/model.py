"""Local ModernBERT loading and tightly-scoped PEFT/LoRA helpers.

The functions in this module deliberately do not train or save a model.  Saving and
reload verification are lifecycle operations owned by the entry point.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import hashlib
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Mapping, Sequence

import torch
from peft import LoraConfig, PeftModel, TaskType, get_peft_model
from transformers import AutoModelForSequenceClassification, AutoTokenizer

from training.pipeline.config import LABEL_IDS, REPO_ROOT, resolve_path


NUM_LAYERS = 22
LORA_TARGETS = tuple(f"model.layers.{index}.attn.Wqkv" for index in range(NUM_LAYERS))
EXPECTED_LORA_PARAMETERS = 540_672
EXPECTED_HEAD_PARAMETERS = 590_592
EXPECTED_CLASSIFIER_PARAMETERS = 1_538
EXPECTED_TRAINABLE_PARAMETERS = 1_132_802
EXPECTED_TOTAL_PARAMETERS = 150_739_204
LOGIT_COMPARISON_ATOL = 1e-5
LOGIT_COMPARISON_RTOL = 1e-5


@dataclass(frozen=True)
class ParameterSummary:
    lora: int
    head: int
    classifier: int
    trainable: int
    total: int

    @property
    def trainable_percent(self) -> float:
        return 100.0 * self.trainable / self.total

    def serializable(self) -> dict[str, int | float]:
        return {**asdict(self), "trainable_percent": self.trainable_percent}


def _model_value(config: Mapping[str, Any], key: str) -> Any:
    section = config.get("model", config)
    if not isinstance(section, Mapping):
        raise ValueError("model configuration must be a mapping")
    return section[key]


def load_local_model_and_tokenizer(config: Mapping[str, Any]) -> tuple[Any, Any]:
    """Load both artifacts without permitting a Hub or other network fallback."""
    checkpoint = resolve_path(_model_value(config, "checkpoint"))
    tokenizer_value = _model_value(config, "tokenizer")
    tokenizer_path = resolve_path(tokenizer_value) if tokenizer_value else checkpoint
    tokenizer = AutoTokenizer.from_pretrained(tokenizer_path, local_files_only=True)
    model = AutoModelForSequenceClassification.from_pretrained(
        checkpoint,
        local_files_only=True,
        num_labels=2,
        id2label={value: key for key, value in LABEL_IDS.items()},
        label2id=dict(LABEL_IDS),
    )
    return tokenizer, model


def resolve_lora_targets(model: Any) -> tuple[str, ...]:
    """Return and validate the 22 exact fused-query/key/value projection names."""
    modules = dict(model.named_modules())
    module_names = set(modules)
    matches = tuple(name for name in LORA_TARGETS if name in module_names)
    if matches != LORA_TARGETS:
        missing = sorted(set(LORA_TARGETS) - set(matches))
        raise ValueError(f"Expected exactly 22 ModernBERT Wqkv targets; missing={missing}")
    unexpected = sorted(
        name for name in module_names
        if name.endswith(".attn.Wqkv") and name not in LORA_TARGETS
    )
    if unexpected:
        raise ValueError(f"Unexpected fused Wqkv targets: {unexpected}")
    invalid = [
        name for name in matches
        if not isinstance(modules[name], torch.nn.Linear)
        or modules[name].in_features != 768 or modules[name].out_features != 2304
        or modules[name].bias is not None
    ]
    if invalid:
        raise ValueError(f"Unexpected Wqkv module type or dimensions: {invalid}")
    return matches


def attach_lora(model: Any, targets: Sequence[str] | None = None) -> Any:
    resolved = tuple(targets) if targets is not None else resolve_lora_targets(model)
    if resolved != LORA_TARGETS:
        raise ValueError("LoRA targets must be exactly model.layers.0..21.attn.Wqkv")
    peft_config = LoraConfig(
        task_type=TaskType.SEQ_CLS,
        r=8,
        lora_alpha=16,
        lora_dropout=0.05,
        bias="none",
        target_modules=list(resolved),
        modules_to_save=["head", "classifier"],
    )
    return get_peft_model(model, peft_config)


def parameter_summary(model: Any) -> ParameterSummary:
    buckets = {"lora": 0, "head": 0, "classifier": 0}
    total = trainable = 0
    for name, parameter in model.named_parameters():
        count = parameter.numel()
        total += count
        if parameter.requires_grad:
            trainable += count
            if "lora_" in name:
                buckets["lora"] += count
            elif ".classifier." in f".{name}." or name.startswith("classifier."):
                buckets["classifier"] += count
            elif ".head." in f".{name}." or name.startswith("head."):
                buckets["head"] += count
    return ParameterSummary(buckets["lora"], buckets["head"], buckets["classifier"], trainable, total)


def validate_peft_model(model: Any, *, exact_counts: bool = True) -> ParameterSummary:
    """Validate adapter scope, frozen base weights, output shape, and known counts."""
    summary = parameter_summary(model)
    bad_trainables: list[str] = []
    for name, parameter in model.named_parameters():
        if not parameter.requires_grad:
            continue
        if not ("lora_" in name or ".modules_to_save." in name):
            bad_trainables.append(name)
        if any(token in name for token in ("embeddings", ".mlp.", ".attn.Wo.")):
            bad_trainables.append(name)
        if ".attn.Wqkv." in name and "lora_" not in name:
            bad_trainables.append(name)
    if bad_trainables:
        raise ValueError(f"Unexpected trainable base parameters: {sorted(set(bad_trainables))}")
    lora_targets = {
        name.split(".lora_", 1)[0].removeprefix("base_model.model.")
        for name, parameter in model.named_parameters()
        if parameter.requires_grad and ".lora_" in name and ".attn.Wqkv." in name
    }
    if lora_targets != set(LORA_TARGETS):
        raise ValueError(f"LoRA was not attached to exactly 22 Wqkv modules: {sorted(lora_targets)}")
    if exact_counts:
        expected = ParameterSummary(EXPECTED_LORA_PARAMETERS, EXPECTED_HEAD_PARAMETERS,
                                    EXPECTED_CLASSIFIER_PARAMETERS, EXPECTED_TRAINABLE_PARAMETERS,
                                    EXPECTED_TOTAL_PARAMETERS)
        if summary != expected:
            raise ValueError(f"Unexpected parameter counts: got={summary}, expected={expected}")
    return summary


def final_adapter_path(output_dir: str | Path) -> Path:
    return Path(output_dir) / "final-adapter"


def safe_base_model_identifier(checkpoint: str | Path, *, repo_root: Path = REPO_ROOT) -> str:
    """Return a portable repository-relative identifier, rejecting outside paths."""
    raw = Path(checkpoint)
    resolved = raw.resolve() if raw.is_absolute() else (repo_root / raw).resolve()
    try:
        relative = resolved.relative_to(repo_root.resolve())
    except ValueError as error:
        raise ValueError("Base model must be inside the repository; absolute external paths are unsafe") from error
    value = PurePosixPath(relative).as_posix()
    if value in {"", "."} or value.startswith("../"):
        raise ValueError("Unsafe base-model identifier")
    return value


def set_safe_adapter_metadata(model: Any, checkpoint: str | Path, *, repo_root: Path = REPO_ROOT) -> str:
    identifier = safe_base_model_identifier(checkpoint, repo_root=repo_root)
    configs = getattr(model, "peft_config", None)
    if not isinstance(configs, Mapping) or not configs:
        raise ValueError("PEFT model has no adapter configuration")
    for config in configs.values():
        config.base_model_name_or_path = identifier
    return identifier


def validate_adapter_metadata(adapter_dir: str | Path, expected_base_model: str) -> dict[str, Any]:
    import json

    path = Path(adapter_dir) / "adapter_config.json"
    metadata = json.loads(path.read_text(encoding="utf-8"))
    actual = metadata.get("base_model_name_or_path")
    if Path(str(actual)).is_absolute() or actual != expected_base_model:
        raise ValueError(f"Unsafe or incompatible adapter base model: {actual!r}")
    modules = set(metadata.get("modules_to_save") or ())
    if not {"head", "classifier"} <= modules:
        raise ValueError(f"Adapter metadata is missing head/classifier: {sorted(modules)}")
    from safetensors import safe_open
    weights = Path(adapter_dir) / "adapter_model.safetensors"
    if not weights.is_file():
        raise FileNotFoundError(f"Adapter weights are missing: {weights}")
    with safe_open(weights, framework="pt", device="cpu") as file:
        keys = set(file.keys())
    if not any(".head." in key for key in keys) or not any(".classifier." in key for key in keys):
        raise ValueError("Saved adapter weights are missing head or classifier parameters")
    return metadata


def sanitize_adapter_artifacts(adapter_dir: str | Path, safe_base_model: str) -> None:
    """Remove local paths emitted by PEFT/Trainer from shareable adapter files."""
    readme = Path(adapter_dir) / "README.md"
    if readme.is_file():
        lines = readme.read_text(encoding="utf-8").splitlines()
        lines = [f"base_model: {safe_base_model}" if line.startswith("base_model:") else line for line in lines]
        readme.write_text("\n".join(lines) + "\n", encoding="utf-8")
    training_arguments = Path(adapter_dir) / "training_args.bin"
    training_arguments.unlink(missing_ok=True)


def reload_adapter_and_compare_logits(
    base_model_dir: str | Path,
    adapter_dir: str | Path,
    inputs: Mapping[str, torch.Tensor],
    expected_logits: torch.Tensor,
    *,
    atol: float = LOGIT_COMPARISON_ATOL,
    rtol: float = LOGIT_COMPARISON_RTOL,
) -> torch.Tensor:
    """Deferred post-smoke verification helper (not called by the pipeline yet)."""
    expected_id = safe_base_model_identifier(base_model_dir)
    validate_adapter_metadata(adapter_dir, expected_id)
    base = AutoModelForSequenceClassification.from_pretrained(
        Path(base_model_dir), local_files_only=True, num_labels=2,
        id2label={value: key for key, value in LABEL_IDS.items()}, label2id=dict(LABEL_IDS),
    )
    reloaded = PeftModel.from_pretrained(base, Path(adapter_dir), local_files_only=True)
    if reloaded.config.label2id != dict(LABEL_IDS) or reloaded.config.id2label != {value: key for key, value in LABEL_IDS.items()}:
        raise ValueError("Reloaded adapter label mapping is incompatible")
    reloaded.eval()
    with torch.no_grad():
        logits = reloaded(**inputs).logits.detach().cpu()
    reference = expected_logits.detach().cpu()
    if logits.shape != reference.shape or logits.ndim != 2 or logits.shape[-1] != 2:
        raise ValueError(f"Expected matching [batch, 2] logits, got {tuple(logits.shape)} and {tuple(reference.shape)}")
    if not torch.allclose(logits, reference, atol=atol, rtol=rtol):
        maximum = (logits - reference).abs().max().item()
        raise ValueError(f"Reloaded logits differ (max_abs_error={maximum}, atol={atol}, rtol={rtol})")
    return logits


def verify_saved_adapter(
    source_model: Any,
    base_model_dir: str | Path,
    adapter_dir: str | Path,
    inputs: Mapping[str, torch.Tensor],
    batch_ids: Sequence[str],
    *,
    atol: float = LOGIT_COMPARISON_ATOL,
    rtol: float = LOGIT_COMPARISON_RTOL,
) -> dict[str, Any]:
    """Compare an in-memory trained model with its freshly reloaded adapter."""
    source_model.eval()
    device = next(source_model.parameters()).device
    source_inputs = {key: value.to(device) for key, value in inputs.items()}
    with torch.no_grad():
        reference = source_model(**source_inputs).logits.detach().cpu()
    reloaded = reload_adapter_and_compare_logits(
        base_model_dir, adapter_dir, inputs, reference, atol=atol, rtol=rtol,
    )
    maximum = float((reloaded - reference).abs().max().item())
    batch_hash = hashlib.sha256("\n".join(batch_ids).encode()).hexdigest()
    return {
        "batch_ids_sha256": batch_hash,
        "batch_size": len(batch_ids),
        "atol": atol,
        "rtol": rtol,
        "max_absolute_logit_difference": maximum,
        "comparison_result": "passed",
        "checked_at": datetime.now(timezone.utc).isoformat(),
    }
