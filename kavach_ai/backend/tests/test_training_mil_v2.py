from __future__ import annotations

import json

import pytest
import torch

from training.pipeline.mil import (
    APKBag, APKBagDataset, APKMILClassifier, AttentionMILClassifier, build_attention_mil,
    SecureBERTEmbedder, build_mil, embed_apk_bags, collate_apk_bags,
    load_apk_bag_dataset,
)
from training.pipeline.mil_training import (
    EmbeddedAPKBag, collate_embedded, evaluate, load_embedding_cache,
    save_embedding_cache, train_pooler,
)
from training.utils.model_view import (
    APKModelViewIndex, ModelView, PhaseCompletion, write_apk_index,
)
from kavach_ai.backend.pipeline.stage2_static.v2_canonical import write_json_atomic


def _bag(digit: str, label: int, count: int) -> APKBag:
    return APKBag(
        apk_sha256=digit * 64,
        label=label,
        views=tuple(ModelView(f"artifact-{digit}-{index}", f"view {index}") for index in range(count)),
    )


def test_apk_dataset_is_grouped_and_deterministic() -> None:
    dataset = APKBagDataset((_bag("b", 1, 1), _bag("a", 0, 2)))
    assert len(dataset) == 2
    assert dataset[0].apk_sha256 == "a" * 64
    assert len(dataset[0].views) == 2
    with pytest.raises(ValueError, match="only one bag"):
        APKBagDataset((_bag("a", 0, 1), _bag("a", 0, 2)))


def test_collation_pads_instances_and_returns_mask() -> None:
    batch = collate_apk_bags(
        (_bag("a", 0, 2), _bag("b", 1, 1)),
        lambda text: torch.tensor([float(len(text)), 1.0]),
    )
    assert batch["embeddings"].shape == (2, 2, 2)
    assert batch["attention_mask"].tolist() == [[True, True], [True, False]]
    assert batch["labels"].tolist() == [0, 1]
    assert batch["artifact_ids"] == (("artifact-a-0", "artifact-a-1"), ("artifact-b-0",))


def test_disk_loader_preserves_split_empty_bags_and_partial_status(tmp_path) -> None:
    metadata_path = tmp_path / "apk_metadata.jsonl"
    splits_path = tmp_path / "apk_splits.json"
    modelview_root = tmp_path / "modelviews"
    first, second = "a" * 64, "b" * 64
    metadata_path.write_text(
        '\n'.join((
            '{"apk_hash":"' + first + '","label":"Benign"}',
            '{"apk_hash":"' + second + '","label":"Malicious"}',
        )) + '\n', encoding="utf-8",
    )
    write_json_atomic(splits_path, {first: "train", second: "train"})
    config = "c" * 64
    write_apk_index(modelview_root, APKModelViewIndex(
        first, (), (
            PhaseCompletion("managed_actions", "SUCCESS", True),
            PhaseCompletion("managed_taint_sensitive_external", "SUCCESS", True),
            PhaseCompletion("native", "NOT_APPLICABLE", True),
        ), config,
    ))
    view = ModelView("artifact-b", "[BEHAVIOR]", second, config_sha256=config)
    write_json_atomic(modelview_root / "v2/candidate1" / second / "artifact-b.json", view)
    write_apk_index(modelview_root, APKModelViewIndex(
        second, ("artifact-b",), (
            PhaseCompletion("managed_actions", "SUCCESS", True),
            PhaseCompletion("managed_taint_sensitive_external", "TIMEOUT", True),
            PhaseCompletion("native", "SUCCESS", True),
        ), config,
    ))

    dataset = load_apk_bag_dataset(
        modelview_root=modelview_root, metadata_path=metadata_path,
        splits_path=splits_path, split="train", apk_hashes=(second, first),
    )
    assert [bag.apk_sha256 for bag in dataset] == [first, second]
    assert dataset[0].views == ()
    assert dataset[0].analysis_complete is True
    assert dataset[1].label == 1
    assert dataset[1].analysis_complete is False
    assert dataset[1].completion_fraction == pytest.approx(2 / 3)


def test_disk_loader_rejects_split_mismatch(tmp_path) -> None:
    digest = "a" * 64
    metadata = tmp_path / "metadata.jsonl"
    splits = tmp_path / "splits.json"
    metadata.write_text('{"apk_hash":"' + digest + '","label":"Benign"}\n', encoding="utf-8")
    write_json_atomic(splits, {digest: "test"})
    with pytest.raises(ValueError, match="immutable split mismatch"):
        load_apk_bag_dataset(
            modelview_root=tmp_path / "views", metadata_path=metadata,
            splits_path=splits, split="train", apk_hashes=(digest,),
        )


def test_collation_supports_leading_and_all_empty_bags() -> None:
    empty = APKBag("c" * 64, 0, (), analysis_complete=False, completion_fraction=0.25)
    batch = collate_apk_bags(
        (empty, _bag("a", 1, 1)), lambda text: torch.tensor([float(len(text)), 1.0]),
    )
    assert batch["attention_mask"].tolist() == [[False], [True]]
    assert batch["analysis_status"].tolist() == [[0.0, 0.25], [1.0, 1.0]]
    all_empty = collate_apk_bags((empty,), lambda text: pytest.fail(text), embedding_dim=2)
    assert all_empty["embeddings"].shape == (1, 1, 2)
    assert all_empty["attention_mask"].tolist() == [[False]]


def test_attention_pool_ignores_padding_and_normalizes_real_instances() -> None:
    torch.manual_seed(4)
    model = AttentionMILClassifier(embedding_dim=3, attention_dim=2)
    embeddings = torch.tensor([[[1.0, 2.0, 3.0], [9.0, 9.0, 9.0]]])
    output = model(embeddings, torch.tensor([[True, False]]))
    assert output["logits"].shape == (1, 2)
    assert output["attention_weights"].tolist() == [[1.0, 0.0]]


def test_candidate_baseline_is_disabled_by_default() -> None:
    with pytest.raises(RuntimeError, match="disabled"):
        build_attention_mil({"enabled": False, "embedding_dim": 4, "attention_dim": 2})
    model = build_attention_mil({"enabled": True, "embedding_dim": 4, "attention_dim": 2})
    assert isinstance(model, AttentionMILClassifier)


class _FixtureEmbedder:
    embedding_dim = 3

    def encode(self, views):
        return torch.tensor([[float(len(view.text)), 1.0, 2.0] for view in views])


class _FixtureTokenizer:
    def __call__(self, texts, **kwargs):
        del kwargs
        width = max(len(text.split()) for text in texts)
        ids = torch.zeros((len(texts), width), dtype=torch.long)
        mask = torch.zeros_like(ids)
        for row, text in enumerate(texts):
            count = len(text.split())
            ids[row, :count] = torch.arange(1, count + 1)
            mask[row, :count] = 1
        return {"input_ids": ids, "attention_mask": mask}


class _FixtureEncoder(torch.nn.Module):
    config = type("Config", (), {"hidden_size": 2})()

    def __init__(self):
        super().__init__()
        self.anchor = torch.nn.Parameter(torch.zeros(()))

    def forward(self, input_ids, attention_mask):
        del attention_mask
        hidden = torch.stack((input_ids.float(), input_ids.float() * 2), dim=-1)
        return type("Output", (), {"last_hidden_state": hidden})()


def test_securebert_embedding_adapter_uses_masked_mean_and_batches() -> None:
    embedder = SecureBERTEmbedder(_FixtureTokenizer(), _FixtureEncoder(), batch_size=1)
    encoded = embedder.encode((ModelView("one", "a b"), ModelView("two", "a b c")))
    assert encoded.tolist() == [[1.5, 3.0], [2.0, 4.0]]
    assert not embedder.model.training


def test_embedding_boundary_preserves_empty_bag_and_status() -> None:
    empty = APKBag("c" * 64, 0, (), analysis_complete=False, completion_fraction=0.5)
    batch = embed_apk_bags((empty, _bag("a", 1, 2)), _FixtureEmbedder())
    assert batch["embeddings"].shape == (2, 2, 3)
    assert batch["attention_mask"].tolist() == [[False, False], [True, True]]
    assert batch["analysis_status"].tolist() == [[0.0, 0.5], [1.0, 1.0]]


@pytest.mark.parametrize("aggregation", ["mean", "max", "top_k", "attention"])
def test_configurable_poolers_predict_at_apk_level_with_empty_bag(aggregation: str) -> None:
    model = build_mil({
        "enabled": True,
        "embedding_dim": 3,
        "attention_dim": 2,
        "aggregation": aggregation,
        "top_k": 2,
    })
    assert isinstance(model, APKMILClassifier)
    output = model(
        torch.tensor([[[0.0, 0.0, 0.0]], [[1.0, 2.0, 3.0]]]),
        torch.tensor([[False], [True]]),
        torch.tensor([[1.0, 1.0], [0.0, 0.5]]),
    )
    assert output["logits"].shape == (2, 2)
    assert torch.isfinite(output["logits"]).all()


def test_general_mil_builder_remains_disabled() -> None:
    with pytest.raises(RuntimeError, match="disabled"):
        build_mil({"enabled": False, "embedding_dim": 3})


def _embedded(digit: str, label: int, values: list[list[float]]) -> EmbeddedAPKBag:
    return EmbeddedAPKBag(
        digit * 64, label, tuple(f"artifact-{digit}-{i}" for i in range(len(values))),
        torch.tensor(values, dtype=torch.float32).reshape(len(values), 2), True, 1.0,
    )


def test_embedding_cache_and_empty_bag_round_trip(tmp_path) -> None:
    bags = (_embedded("a", 0, []), _embedded("b", 1, [[1.0, 2.0]]))
    path = tmp_path / "cache.pt"
    save_embedding_cache(path, bags, checkpoint="fixture", max_length=12)
    loaded = load_embedding_cache(path, checkpoint="fixture", max_length=12)
    assert loaded[0].embeddings.shape == (0, 2)
    assert loaded[1].artifact_ids == ("artifact-b-0",)
    with pytest.raises(ValueError, match="configuration mismatch"):
        load_embedding_cache(path, checkpoint="different", max_length=12)


def test_mil_training_exports_attention_by_artifact_id(tmp_path) -> None:
    train = (
        _embedded("a", 0, []), _embedded("b", 0, [[0.0, 0.0]]),
        _embedded("c", 1, [[2.0, 2.0]]), _embedded("d", 1, [[3.0, 3.0], [2.0, 2.0]]),
    )
    batch = collate_embedded(train, device=torch.device("cpu"))
    assert batch["attention_mask"][0].tolist() == [False, False]
    result = train_pooler(
        aggregation="attention", train_bags=train, validation_bags=train,
        embedding_dim=2, attention_dim=2, top_k=2, epochs=2, batch_size=2,
        learning_rate=0.02, weight_decay=0.0, seed=3, device=torch.device("cpu"),
        output_dir=tmp_path,
    )
    assert (tmp_path / "attention/best.pt").is_file()
    rows = [json.loads(line) for line in (tmp_path / "attention/attention.jsonl").read_text().splitlines()]
    assert rows[-1]["artifacts"][0]["artifact_id"] == "artifact-d-0"
    assert result["metrics"]["tp"] + result["metrics"]["fn"] == 2
