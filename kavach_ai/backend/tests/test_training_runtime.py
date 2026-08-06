from __future__ import annotations

from types import SimpleNamespace

import numpy as np
import pytest
import torch

from training.pipeline.metrics import binary_classification_metrics
from training.pipeline import trainer as runtime


def _config() -> dict:
    return {
        "run": {"mode": "smoke", "name": "safe-name", "seed": 42,
                "output_dir": "relative/output", "overwrite_output_dir": False},
        "data": {"max_context_length": 256},
        "hardware": {"device": "cpu", "precision": "fp32",
                     "gradient_checkpointing": False, "torch_compile": False},
        "trainer": {
            "seed": 42, "data_seed": 42, "per_device_train_batch_size": 2,
            "per_device_eval_batch_size": 2,
            "gradient_accumulation_steps": 3, "num_train_epochs": 1.0, "max_steps": 3,
            "learning_rate": 0.0002, "weight_decay": 0.01, "warmup_ratio": 0.1,
            "max_grad_norm": 1.0, "eval_strategy": "no", "eval_steps": None,
            "save_strategy": "no", "save_steps": None,
            "logging_strategy": "steps", "logging_steps": 1, "save_total_limit": None,
            "load_best_model_at_end": False, "metric_for_best_model": None,
            "greater_is_better": True, "dataloader_num_workers": 0,
            "dataloader_persistent_workers": False, "disable_tqdm": False,
        },
        "wandb": {"mode": "disabled", "project": "unit", "entity": None,
                  "group": None, "job_type": "test", "tags": ["test"], "notes": None,
                  "watch_model": False, "log_model": False},
    }


def test_binary_metrics_known_confusion_matrix_and_zero_denominators() -> None:
    result = binary_classification_metrics((np.array([[2, 1], [0, 3], [4, 0], [5, 1]]),
                                            np.array([0, 0, 1, 1])))
    assert result == {"accuracy": 0.25, "precision": 0.0, "recall": 0.0, "f1": 0.0,
                      "tn": 1, "fp": 1, "fn": 2, "tp": 0}
    perfect = binary_classification_metrics(SimpleNamespace(
        predictions=np.array([[1, 0], [0, 1]]), label_ids=np.array([0, 1])))
    assert perfect["f1"] == 1.0


@pytest.mark.parametrize("predictions,labels", [
    (np.array([1, 2]), np.array([0, 1])),
    (np.ones((2, 3)), np.array([0, 1])),
    (np.ones((2, 2)), np.array([[0], [1]])),
    (np.ones((2, 2)), np.array([0, 2])),
    (np.ones((0, 2)), np.array([], dtype=int)),
])
def test_binary_metrics_reject_invalid_inputs(predictions, labels) -> None:
    with pytest.raises(ValueError):
        binary_classification_metrics((predictions, labels))


def test_hardware_resolution_matrix(monkeypatch) -> None:
    config = _config()
    assert runtime.resolve_hardware(config).device == "cpu"
    config["hardware"].update(device="cpu", precision="fp16")
    with pytest.raises(RuntimeError, match="unsupported"):
        runtime.resolve_hardware(config)
    config["hardware"].update(device="cuda", precision="fp32")
    monkeypatch.setattr(runtime.torch.cuda, "is_available", lambda: False)
    with pytest.raises(RuntimeError, match="unavailable"):
        runtime.resolve_hardware(config)
    config["hardware"].update(device="auto", precision="fp32")
    monkeypatch.setattr(runtime.torch.backends.mps, "is_available", lambda: False)
    assert runtime.resolve_hardware(config).device == "cpu"


def test_pin_memory_is_derived_from_resolved_device(monkeypatch) -> None:
    config = _config()
    assert runtime.resolve_hardware(config).dataloader_pin_memory is False
    config["hardware"]["device"] = "mps"
    monkeypatch.setattr(runtime.torch.backends.mps, "is_available", lambda: True)
    assert runtime.resolve_hardware(config).dataloader_pin_memory is False
    config["hardware"]["device"] = "cuda"
    monkeypatch.setattr(runtime.torch.cuda, "is_available", lambda: True)
    monkeypatch.setattr(runtime.torch.cuda, "get_device_name", lambda index: "Test CUDA")
    assert runtime.resolve_hardware(config).dataloader_pin_memory is True


def test_effective_batch_and_single_world_guard(monkeypatch) -> None:
    assert runtime.effective_batch_size(_config(), world_size=1) == 6
    with pytest.raises(RuntimeError, match="single-process"):
        runtime.effective_batch_size(_config(), world_size=2)


def test_training_arguments_exact_core_mapping(tmp_path) -> None:
    config = _config()
    arguments = runtime.build_training_arguments(config, tmp_path)
    assert arguments.eval_strategy.value == "no"
    assert arguments.save_strategy.value == "no"
    assert arguments.per_device_train_batch_size == 2
    assert arguments.per_device_eval_batch_size == 2
    assert arguments.gradient_accumulation_steps == 3
    assert arguments.eval_steps is None
    assert arguments.save_steps is None
    assert arguments.max_steps == 3
    assert arguments.learning_rate == pytest.approx(2e-4)
    assert arguments.report_to == []
    assert arguments.fp16 is arguments.bf16 is False
    assert arguments.label_names == ["labels"]
    assert arguments.dataloader_pin_memory is False


def test_wandb_modes_environment_and_safe_allowlist(monkeypatch) -> None:
    config = _config()
    runtime.configure_wandb_environment(config)
    assert runtime.wandb_report_to(config) == []
    assert runtime.os.environ["WANDB_DISABLED"] == "true"
    config["wandb"]["mode"] = "offline"
    runtime.configure_wandb_environment(config)
    assert runtime.wandb_report_to(config) == ["wandb"]
    assert runtime.os.environ["WANDB_MODE"] == "offline"
    safe = runtime.safe_wandb_config(config, selected_records_hash="abc",
                                     aggregate_counts={"records": 48})
    serialized = repr(safe)
    assert "relative/output" not in serialized
    assert "checkpoint" not in serialized
    assert safe["selected_records_sha256"] == "abc"


def test_adapter_output_is_distinct_from_checkpoints(tmp_path) -> None:
    assert runtime.adapter_output_path(tmp_path) == tmp_path / "final-adapter"


def test_build_trainer_constructs_without_training(monkeypatch, tmp_path) -> None:
    captured = {}

    class FakeTrainer:
        def __init__(self, **kwargs):
            captured.update(kwargs)

    monkeypatch.setattr(runtime, "Trainer", FakeTrainer)
    processing_class = object()
    instance = runtime.build_trainer(_config(), object(), [1], None, object(), processing_class,
                                     output_dir=tmp_path)
    assert isinstance(instance, FakeTrainer)
    assert captured["compute_metrics"] is binary_classification_metrics
    assert captured["processing_class"] is processing_class
    assert "train" not in captured


def test_peft_named_trainer_evaluation_receives_predictions_and_labels(monkeypatch, tmp_path) -> None:
    received = {}
    original = runtime.binary_classification_metrics
    def metrics(prediction):
        received["predictions"] = prediction.predictions
        received["labels"] = prediction.label_ids
        return original(prediction)
    monkeypatch.setattr(runtime, "binary_classification_metrics", metrics)

    class PeftModelForSequenceClassification(torch.nn.Module):
        def __init__(self):
            super().__init__()
            self.projection = torch.nn.Linear(1, 2)
        def forward(self, input_ids=None, attention_mask=None, labels=None):
            logits = self.projection(input_ids.float().mean(dim=1, keepdim=True))
            loss = torch.nn.functional.cross_entropy(logits, labels) if labels is not None else None
            return {"loss": loss, "logits": logits}

    dataset = [
        {"input_ids": [1, 2], "attention_mask": [1, 1], "labels": 0},
        {"input_ids": [3, 4], "attention_mask": [1, 1], "labels": 1},
    ]
    def collate(rows):
        return {key: torch.tensor([row[key] for row in rows]) for key in rows[0]}
    trainer = runtime.build_trainer(
        _config(), PeftModelForSequenceClassification(), dataset, dataset, collate,
        output_dir=tmp_path,
    )
    assert trainer.label_names == ["labels"]
    result = trainer.evaluate()
    assert received["predictions"].shape == (2, 2)
    assert received["labels"].tolist() == [0, 1]
    assert "eval_loss" in result and "eval_f1" in result


def test_run_training_fake_lifecycle_tiny_evaluation_and_adapter(tmp_path) -> None:
    events, finalized = [], []

    class FakeTrainer:
        eval_dataset = [1]

        def train(self):
            events.append(("train", {}))
            return SimpleNamespace(metrics={"train_loss": 0.2})

        def evaluate(self, **kwargs):
            events.append(("evaluate", kwargs))
            return {"memorization_f1": 1.0}

        def save_model(self, path):
            events.append(("save_model", path))

        def save_state(self):
            events.append(("save_state", {}))

    config = _config()
    config["run"]["mode"] = "tiny_overfit"
    result = runtime.run_training(
        FakeTrainer(), config, tmp_path,
        transition=lambda status, details: events.append((status, details)),
        finalize=finalized.append,
    )
    assert [event[0] for event in events] == [
        "prepared", "running", "train", "evaluate", "save_model", "save_state", "completed"
    ]
    assert events[3][1] == {"metric_key_prefix": "memorization"}
    assert result.adapter_path == tmp_path / "final-adapter"
    assert result.metrics == {"train_loss": 0.2, "memorization_f1": 1.0}
    assert finalized == [result]


def test_run_training_fake_failure_records_sanitized_shape(tmp_path) -> None:
    events = []

    class FailingTrainer:
        eval_dataset = None

        def train(self):
            raise LookupError("mock failure")

    with pytest.raises(LookupError, match="mock failure"):
        runtime.run_training(
            FailingTrainer(), _config(), tmp_path,
            transition=lambda status, details: events.append((status, details)),
        )
    assert [item[0] for item in events] == ["prepared", "running", "failed"]
    assert events[-1][1]["exception_type"] == "LookupError"
    assert events[-1][1]["exception_message"] == "mock failure"
