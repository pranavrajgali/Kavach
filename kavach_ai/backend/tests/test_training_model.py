from __future__ import annotations

import json
from types import SimpleNamespace

import pytest
import torch
from safetensors.torch import save_file

from training.pipeline import model as subject


class FakeModernBert:
    def __init__(self, extra=()):
        self.names = [*subject.LORA_TARGETS, *extra]
        self.linear = torch.nn.Linear(768, 2304, bias=False)

    def named_modules(self):
        return [(name, self.linear) for name in self.names]


def test_exact_modernbert_targets() -> None:
    assert subject.resolve_lora_targets(FakeModernBert()) == subject.LORA_TARGETS
    assert len(subject.LORA_TARGETS) == 22
    with pytest.raises(ValueError, match="missing"):
        subject.resolve_lora_targets(FakeModernBert()).__class__  # coverage sanity
        subject.resolve_lora_targets(SimpleNamespace(named_modules=lambda: iter([])))
    with pytest.raises(ValueError, match="Unexpected"):
        subject.resolve_lora_targets(FakeModernBert(("model.layers.22.attn.Wqkv",)))


def test_target_resolution_rejects_wrong_module_type() -> None:
    fake = FakeModernBert()
    fake.linear = torch.nn.Identity()
    with pytest.raises(ValueError, match="type or dimensions"):
        subject.resolve_lora_targets(fake)


def test_attach_lora_has_locked_configuration(monkeypatch) -> None:
    captured = {}
    monkeypatch.setattr(subject, "get_peft_model", lambda model, config: captured.update(config=config) or model)
    base = FakeModernBert()
    assert subject.attach_lora(base) is base
    config = captured["config"]
    assert config.r == 8
    assert config.lora_alpha == 16
    assert config.lora_dropout == 0.05
    assert config.bias == "none"
    assert config.task_type.value == "SEQ_CLS"
    assert config.target_modules == set(subject.LORA_TARGETS)
    assert set(config.modules_to_save) == {"head", "classifier"}


def test_local_only_two_label_loading(monkeypatch) -> None:
    calls = {}
    monkeypatch.setattr(subject.AutoTokenizer, "from_pretrained", lambda path, **kwargs: calls.update(tok=(path, kwargs)) or "tok")
    monkeypatch.setattr(subject.AutoModelForSequenceClassification, "from_pretrained", lambda path, **kwargs: calls.update(model=(path, kwargs)) or "model")
    tokenizer, model = subject.load_local_model_and_tokenizer({"model": {"checkpoint": "weights/base", "tokenizer": None}})
    assert (tokenizer, model) == ("tok", "model")
    assert calls["tok"][1] == {"local_files_only": True}
    assert calls["model"][1]["local_files_only"] is True
    assert calls["model"][1]["num_labels"] == 2
    assert calls["model"][1]["label2id"] == {"Benign": 0, "Malicious": 1}
    assert calls["model"][1]["id2label"] == {0: "Benign", 1: "Malicious"}


def test_parameter_summary_buckets_and_percent() -> None:
    def parameter(size, trainable=True):
        return SimpleNamespace(numel=lambda: size, requires_grad=trainable)

    fake = SimpleNamespace(named_parameters=lambda: iter((
        ("x.lora_A.default.weight", parameter(4)),
        ("x.modules_to_save.default.head.dense.weight", parameter(5)),
        ("x.modules_to_save.default.classifier.weight", parameter(2)),
        ("x.embeddings.weight", parameter(89, False)),
    )))
    result = subject.parameter_summary(fake)
    assert result == subject.ParameterSummary(4, 5, 2, 11, 100)
    assert result.serializable()["trainable_percent"] == 11.0


def test_expected_counts_are_locked() -> None:
    assert subject.EXPECTED_LORA_PARAMETERS == 540_672
    assert subject.EXPECTED_HEAD_PARAMETERS == 590_592
    assert subject.EXPECTED_CLASSIFIER_PARAMETERS == 1_538
    assert subject.EXPECTED_TRAINABLE_PARAMETERS == 1_132_802
    assert subject.EXPECTED_TOTAL_PARAMETERS == 150_739_204
    assert subject.EXPECTED_TRAINABLE_PARAMETERS / subject.EXPECTED_TOTAL_PARAMETERS == pytest.approx(.007515, rel=.001)


def test_adapter_paths_and_safe_metadata(tmp_path) -> None:
    assert subject.final_adapter_path(tmp_path) == tmp_path / "final-adapter"
    root = tmp_path / "repo"
    checkpoint = root / "models" / "securebert"
    checkpoint.mkdir(parents=True)
    assert subject.safe_base_model_identifier(checkpoint, repo_root=root) == "models/securebert"
    with pytest.raises(ValueError, match="inside the repository"):
        subject.safe_base_model_identifier(tmp_path / "outside", repo_root=root)
    config = SimpleNamespace(base_model_name_or_path=str(checkpoint))
    peft = SimpleNamespace(peft_config={"default": config})
    assert subject.set_safe_adapter_metadata(peft, checkpoint, repo_root=root) == "models/securebert"
    assert config.base_model_name_or_path == "models/securebert"


def test_adapter_metadata_validation(tmp_path) -> None:
    path = tmp_path / "adapter_config.json"
    path.write_text(json.dumps({"base_model_name_or_path": "models/securebert",
                                "modules_to_save": ["head", "classifier"]}), encoding="utf-8")
    save_file({"base_model.model.head.dense.weight": torch.ones(1),
               "base_model.model.classifier.weight": torch.ones(1)},
              tmp_path / "adapter_model.safetensors")
    assert subject.validate_adapter_metadata(tmp_path, "models/securebert")["base_model_name_or_path"] == "models/securebert"
    path.write_text(json.dumps({"base_model_name_or_path": "/secret/model"}), encoding="utf-8")
    with pytest.raises(ValueError, match="Unsafe"):
        subject.validate_adapter_metadata(tmp_path, "models/securebert")


def test_reload_helper_is_mockable_and_compares_two_logits(monkeypatch, tmp_path) -> None:
    adapter = tmp_path / "adapter"
    adapter.mkdir()
    (adapter / "adapter_config.json").write_text(
        json.dumps({"base_model_name_or_path": "training/mock-base",
                    "modules_to_save": ["head", "classifier"]}), encoding="utf-8")
    save_file({"base_model.model.head.dense.weight": torch.ones(1),
               "base_model.model.classifier.weight": torch.ones(1)},
              adapter / "adapter_model.safetensors")
    monkeypatch.setattr(subject.AutoModelForSequenceClassification, "from_pretrained", lambda *a, **k: object())

    class Reloaded:
        config = SimpleNamespace(label2id={"Benign": 0, "Malicious": 1},
                                 id2label={0: "Benign", 1: "Malicious"})
        def eval(self): pass
        def __call__(self, **kwargs):
            return SimpleNamespace(logits=torch.tensor([[0.25, 0.75]]))

    monkeypatch.setattr(subject.PeftModel, "from_pretrained", lambda *a, **k: Reloaded())
    logits = subject.reload_adapter_and_compare_logits(
        "training/mock-base", adapter, {"input_ids": torch.ones((1, 2), dtype=torch.long)},
        torch.tensor([[0.25, 0.75]]),
    )
    assert logits.shape == (1, 2)
