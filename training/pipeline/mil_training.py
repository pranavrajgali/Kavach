"""Dependency-light training utilities for APK-level V2 MIL experiments."""

from __future__ import annotations

import json
import random
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Sequence

import numpy as np
import torch
from torch import nn

from training.pipeline.metrics import binary_classification_metrics
from training.pipeline.mil import APKBag, APKMILClassifier, ModelViewEmbedder, build_mil


@dataclass(frozen=True)
class EmbeddedAPKBag:
    apk_sha256: str
    label: int
    artifact_ids: tuple[str, ...]
    embeddings: torch.Tensor
    analysis_complete: bool
    completion_fraction: float


def seed_everything(seed: int) -> None:
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)


def encode_bags(bags: Sequence[APKBag], embedder: ModelViewEmbedder) -> tuple[EmbeddedAPKBag, ...]:
    """Encode each artifact once while retaining empty bags and exact identities."""
    result = []
    for bag in bags:
        embeddings = embedder.encode(bag.views).detach().cpu()
        expected = (len(bag.views), embedder.embedding_dim)
        if embeddings.shape != expected or not embeddings.is_floating_point():
            raise ValueError(f"invalid embeddings for {bag.apk_sha256}: {tuple(embeddings.shape)} != {expected}")
        result.append(EmbeddedAPKBag(
            bag.apk_sha256, bag.label, tuple(view.artifact_id for view in bag.views), embeddings,
            bag.analysis_complete, bag.completion_fraction,
        ))
    return tuple(result)


def save_embedding_cache(path: str | Path, bags: Sequence[EmbeddedAPKBag], *,
                         checkpoint: str, max_length: int) -> None:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema_version": "mil-embedding-cache-v1",
        "checkpoint": checkpoint,
        "max_length": max_length,
        "bags": [{
            "apk_sha256": bag.apk_sha256, "label": bag.label,
            "artifact_ids": bag.artifact_ids, "embeddings": bag.embeddings,
            "analysis_complete": bag.analysis_complete,
            "completion_fraction": bag.completion_fraction,
        } for bag in bags],
    }
    temporary = destination.with_name(f".{destination.name}.tmp")
    torch.save(payload, temporary)
    temporary.replace(destination)


def load_embedding_cache(path: str | Path, *, checkpoint: str,
                         max_length: int) -> tuple[EmbeddedAPKBag, ...]:
    payload = torch.load(Path(path), map_location="cpu", weights_only=True)
    if payload.get("schema_version") != "mil-embedding-cache-v1":
        raise ValueError("unsupported MIL embedding cache schema")
    if payload.get("checkpoint") != checkpoint or payload.get("max_length") != max_length:
        raise ValueError("MIL embedding cache encoder configuration mismatch")
    return tuple(EmbeddedAPKBag(
        str(item["apk_sha256"]), int(item["label"]), tuple(item["artifact_ids"]),
        item["embeddings"], bool(item["analysis_complete"]),
        float(item["completion_fraction"]),
    ) for item in payload["bags"])


def collate_embedded(bags: Sequence[EmbeddedAPKBag], *, device: torch.device) -> dict[str, Any]:
    if not bags:
        raise ValueError("cannot collate an empty batch")
    dimensions = {bag.embeddings.shape[1] for bag in bags}
    if len(dimensions) != 1:
        raise ValueError("embedding dimensions differ between APK bags")
    dimension, maximum = dimensions.pop(), max(1, *(len(bag.artifact_ids) for bag in bags))
    embeddings = torch.zeros(len(bags), maximum, dimension, device=device)
    mask = torch.zeros(len(bags), maximum, dtype=torch.bool, device=device)
    for index, bag in enumerate(bags):
        count = len(bag.artifact_ids)
        embeddings[index, :count] = bag.embeddings.to(device)
        mask[index, :count] = True
    return {
        "apk_sha256": tuple(bag.apk_sha256 for bag in bags),
        "artifact_ids": tuple(bag.artifact_ids for bag in bags),
        "embeddings": embeddings,
        "attention_mask": mask,
        "analysis_status": torch.tensor([
            [float(bag.analysis_complete), bag.completion_fraction] for bag in bags
        ], dtype=torch.float32, device=device),
        "labels": torch.tensor([bag.label for bag in bags], dtype=torch.long, device=device),
    }


def iter_minibatches(bags: Sequence[EmbeddedAPKBag], batch_size: int, *,
                     shuffle: bool, seed: int) -> Iterable[tuple[EmbeddedAPKBag, ...]]:
    if batch_size <= 0:
        raise ValueError("batch_size must be positive")
    indices = list(range(len(bags)))
    if shuffle:
        random.Random(seed).shuffle(indices)
    for start in range(0, len(indices), batch_size):
        yield tuple(bags[index] for index in indices[start:start + batch_size])


def evaluate(model: APKMILClassifier, bags: Sequence[EmbeddedAPKBag], *, batch_size: int,
             device: torch.device, export_attention: bool = False) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    model.eval()
    logits, labels, explanations = [], [], []
    with torch.no_grad():
        for items in iter_minibatches(bags, batch_size, shuffle=False, seed=0):
            batch = collate_embedded(items, device=device)
            output = model(batch["embeddings"], batch["attention_mask"], batch["analysis_status"])
            probabilities = torch.softmax(output["logits"], dim=1)
            logits.append(output["logits"].cpu())
            labels.append(batch["labels"].cpu())
            if export_attention:
                weights = output["instance_weights"].cpu()
                for row, item in enumerate(items):
                    explanations.append({
                        "apk_sha256": item.apk_sha256, "label": item.label,
                        "prediction": int(probabilities[row].argmax().item()),
                        "malware_probability": float(probabilities[row, 1].item()),
                        "analysis_complete": item.analysis_complete,
                        "completion_fraction": item.completion_fraction,
                        "artifacts": [{"artifact_id": artifact_id, "weight": float(weights[row, col])}
                                      for col, artifact_id in enumerate(item.artifact_ids)],
                    })
    if not logits:
        raise ValueError("evaluation split is empty")
    metrics = binary_classification_metrics((torch.cat(logits).numpy(), torch.cat(labels).numpy()))
    return metrics, explanations


def train_pooler(*, aggregation: str, train_bags: Sequence[EmbeddedAPKBag],
                 validation_bags: Sequence[EmbeddedAPKBag], embedding_dim: int,
                 attention_dim: int, top_k: int, epochs: int, batch_size: int,
                 learning_rate: float, weight_decay: float, seed: int,
                 device: torch.device, output_dir: str | Path) -> dict[str, Any]:
    if not train_bags or not validation_bags:
        raise ValueError("training and validation splits must both be non-empty")
    seed_everything(seed)
    model = build_mil({"enabled": True, "aggregation": aggregation,
                       "embedding_dim": embedding_dim, "attention_dim": attention_dim,
                       "top_k": top_k, "num_labels": 2}).to(device)
    optimizer = torch.optim.AdamW(model.parameters(), lr=learning_rate, weight_decay=weight_decay)
    loss_fn = nn.CrossEntropyLoss()
    destination = Path(output_dir) / aggregation
    destination.mkdir(parents=True, exist_ok=True)
    best_f1, history = -1.0, []
    for epoch in range(1, epochs + 1):
        model.train()
        losses = []
        for items in iter_minibatches(train_bags, batch_size, shuffle=True, seed=seed + epoch):
            batch = collate_embedded(items, device=device)
            optimizer.zero_grad(set_to_none=True)
            output = model(batch["embeddings"], batch["attention_mask"], batch["analysis_status"])
            loss = loss_fn(output["logits"], batch["labels"])
            loss.backward()
            optimizer.step()
            losses.append(float(loss.detach().cpu()))
        metrics, _ = evaluate(model, validation_bags, batch_size=batch_size, device=device)
        record = {"epoch": epoch, "train_loss": sum(losses) / len(losses), **metrics}
        history.append(record)
        if float(metrics["f1"]) > best_f1:
            best_f1 = float(metrics["f1"])
            torch.save({"schema_version": "apk-mil-checkpoint-v1", "aggregation": aggregation,
                        "embedding_dim": embedding_dim, "model_state_dict": model.state_dict(),
                        "epoch": epoch, "validation_metrics": metrics}, destination / "best.pt")
    checkpoint = torch.load(destination / "best.pt", map_location=device, weights_only=True)
    model.load_state_dict(checkpoint["model_state_dict"])
    metrics, explanations = evaluate(
        model, validation_bags, batch_size=batch_size, device=device,
        export_attention=aggregation == "attention",
    )
    (destination / "history.json").write_text(json.dumps(history, indent=2) + "\n", encoding="utf-8")
    (destination / "metrics.json").write_text(json.dumps(metrics, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if explanations:
        (destination / "attention.jsonl").write_text(
            "".join(json.dumps(item, sort_keys=True) + "\n" for item in explanations), encoding="utf-8",
        )
    return {"aggregation": aggregation, "metrics": metrics,
            "best_epoch": checkpoint["epoch"], "output_dir": str(destination)}
