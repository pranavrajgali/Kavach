"""APK-grouped MIL scaffolding for candidate V2 ModelViews.

This module is intentionally independent of corpus storage and tokenization.  It
accepts already-serialized ModelViews and stays opt-in until the V2 audit fixes
the representation and bag-size policies.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping, Protocol, Sequence

import torch
from torch import nn
from torch.utils.data import Dataset

from training.utils.dataset import load_apk_metadata, load_apk_splits
from training.utils.model_view import ModelView, index_path, read_apk_index, read_candidate


_CLEAN_ANALYSIS_STATES = frozenset({"SUCCESS", "NOT_APPLICABLE"})


@dataclass(frozen=True)
class APKBag:
    apk_sha256: str
    label: int
    views: tuple[ModelView, ...]
    analysis_complete: bool = True
    completion_fraction: float = 1.0

    def __post_init__(self) -> None:
        if len(self.apk_sha256) != 64:
            raise ValueError("apk_sha256 must contain 64 characters")
        if self.label not in (0, 1):
            raise ValueError("label must be 0 or 1")
        if not 0.0 <= self.completion_fraction <= 1.0:
            raise ValueError("completion_fraction must be between 0 and 1")
        identifiers = [view.artifact_id for view in self.views]
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("artifact_id values must be unique within an APK bag")


class APKBagDataset(Dataset[APKBag]):
    """Deterministic, one-item-per-APK dataset."""

    def __init__(self, bags: Sequence[APKBag]) -> None:
        ordered = sorted(bags, key=lambda bag: bag.apk_sha256)
        hashes = [bag.apk_sha256 for bag in ordered]
        if len(hashes) != len(set(hashes)):
            raise ValueError("each APK may appear in only one bag")
        self._bags = tuple(ordered)

    def __len__(self) -> int:
        return len(self._bags)

    def __getitem__(self, index: int) -> APKBag:
        return self._bags[index]


def load_apk_bag_dataset(
    *, modelview_root: str | Path, metadata_path: str | Path,
    splits_path: str | Path, split: str, apk_hashes: Sequence[str] | None = None,
) -> APKBagDataset:
    """Load validated V2 ModelViews as one immutable bag per APK.

    A completed index with no artifact IDs becomes an empty bag. A missing
    index is rejected, since it is not evidence of a clean zero-artifact run.
    """

    metadata = load_apk_metadata(Path(metadata_path))
    splits = load_apk_splits(Path(splits_path), set(metadata))
    selected = sorted(apk_hashes if apk_hashes is not None else (
        apk_hash for apk_hash, assigned in splits.items() if assigned == split
    ))
    if len(selected) != len(set(selected)):
        raise ValueError("apk_hashes contains duplicates")
    bags: list[APKBag] = []
    for apk_hash in selected:
        if apk_hash not in metadata or apk_hash not in splits:
            raise ValueError(f"unknown APK identity: {apk_hash}")
        if splits[apk_hash] != split:
            raise ValueError(
                f"immutable split mismatch for {apk_hash}: {splits[apk_hash]!r} != {split!r}"
            )
        path = index_path(modelview_root, apk_sha256=apk_hash)
        if not path.is_file():
            raise FileNotFoundError(f"ModelView index is missing for {apk_hash}: {path}")
        index = read_apk_index(path)
        if index.apk_sha256 != apk_hash:
            raise ValueError(f"ModelView index identity mismatch for {apk_hash}")
        views = tuple(read_candidate(path.parent / f"{artifact_id}.json")
                      for artifact_id in index.artifact_ids)
        for artifact_id, view in zip(index.artifact_ids, views):
            if view.artifact_id != artifact_id or view.apk_sha256 != apk_hash:
                raise ValueError(f"ModelView provenance mismatch for {apk_hash}/{artifact_id}")
            if view.config_sha256 != index.model_view_config_sha256:
                raise ValueError(f"ModelView configuration mismatch for {apk_hash}/{artifact_id}")
        phases = tuple(
            phase for phase in index.phases
            if phase.phase == "managed_actions"
            or phase.phase.startswith("managed_taint_")
            or phase.phase == "native"
        )
        clean = sum(phase.status in _CLEAN_ANALYSIS_STATES for phase in phases)
        complete = bool(phases) and clean == len(phases)
        fraction = clean / len(phases) if phases else 0.0
        label_name = str(metadata[apk_hash].get("label", "")).lower()
        if label_name not in {"benign", "malicious"}:
            raise ValueError(f"unknown APK label for {apk_hash}: {label_name!r}")
        bags.append(APKBag(apk_hash, int(label_name == "malicious"), views, complete, fraction))
    return APKBagDataset(bags)


class ModelViewEmbedder(Protocol):
    """Pluggable boundary for SecureBERT or a fixture embedding backend."""

    @property
    def embedding_dim(self) -> int: ...

    def encode(self, views: Sequence[ModelView]) -> torch.Tensor: ...


class SecureBERTEmbedder:
    """Small inference-only adapter from ModelViews to SecureBERT embeddings.

    Tokenizer/model objects can be injected in tests. ``from_pretrained`` is
    deliberately lazy so importing the MIL dataset does not load Transformers
    or model weights.
    """

    def __init__(self, tokenizer: Any, model: nn.Module, *, max_length: int = 512,
                 batch_size: int = 16, device: torch.device | str | None = None) -> None:
        if max_length <= 0 or batch_size <= 0:
            raise ValueError("max_length and batch_size must be positive")
        self.tokenizer = tokenizer
        self.model = model
        self.max_length = max_length
        self.batch_size = batch_size
        self.device = torch.device(device or next(model.parameters()).device)
        hidden_size = getattr(getattr(model, "config", None), "hidden_size", None)
        if not isinstance(hidden_size, int) or hidden_size <= 0:
            raise ValueError("SecureBERT model config must define a positive hidden_size")
        self._embedding_dim = hidden_size
        self.model.to(self.device)
        self.model.eval()

    @classmethod
    def from_pretrained(cls, checkpoint: str, **kwargs: Any) -> "SecureBERTEmbedder":
        from transformers import AutoModel, AutoTokenizer

        tokenizer = AutoTokenizer.from_pretrained(checkpoint)
        model = AutoModel.from_pretrained(checkpoint)
        return cls(tokenizer, model, **kwargs)

    @property
    def embedding_dim(self) -> int:
        return self._embedding_dim

    def encode(self, views: Sequence[ModelView]) -> torch.Tensor:
        if not views:
            return torch.empty((0, self.embedding_dim), device=self.device)
        chunks: list[torch.Tensor] = []
        with torch.inference_mode():
            for start in range(0, len(views), self.batch_size):
                texts = [view.text for view in views[start:start + self.batch_size]]
                tokens = self.tokenizer(
                    texts, padding=True, truncation=True, max_length=self.max_length,
                    return_tensors="pt",
                )
                tokens = {key: value.to(self.device) for key, value in tokens.items()}
                output = self.model(**tokens)
                hidden = output.last_hidden_state
                mask = tokens["attention_mask"].unsqueeze(-1).to(hidden.dtype)
                pooled = (hidden * mask).sum(1) / mask.sum(1).clamp_min(1)
                chunks.append(pooled)
        return torch.cat(chunks, dim=0)


def embed_apk_bags(bags: Sequence[APKBag], embedder: ModelViewEmbedder) -> dict[str, object]:
    """Turn APK-level ModelView lists into a padded MIL batch.

    Empty bags remain empty. They are represented by an all-false mask plus
    analysis status features, never by a fabricated artifact.
    """

    if not bags:
        raise ValueError("cannot embed an empty batch")
    dimension = int(embedder.embedding_dim)
    if dimension <= 0:
        raise ValueError("embedding_dim must be positive")
    encoded_nonempty = [embedder.encode(bag.views) for bag in bags if bag.views]
    device = encoded_nonempty[0].device if encoded_nonempty else torch.device("cpu")
    dtype = encoded_nonempty[0].dtype if encoded_nonempty else torch.float32
    iterator = iter(encoded_nonempty)
    encoded = [next(iterator) if bag.views else torch.empty((0, dimension), device=device, dtype=dtype)
               for bag in bags]
    if any(value.ndim != 2 or value.shape != (len(bag.views), dimension)
           for bag, value in zip(bags, encoded)):
        raise ValueError("embedder must return [number_of_views, embedding_dim]")
    if any(not value.is_floating_point() for value in encoded):
        raise ValueError("embedder must return floating tensors")
    if any(value.device != device or value.dtype != dtype for value in encoded):
        raise ValueError("all embedder outputs must share dtype and device")
    maximum = max(1, *(len(bag.views) for bag in bags))
    embeddings = torch.zeros((len(bags), maximum, dimension), dtype=dtype, device=device)
    mask = torch.zeros((len(bags), maximum), dtype=torch.bool, device=device)
    for index, value in enumerate(encoded):
        embeddings[index, : value.shape[0]] = value
        mask[index, : value.shape[0]] = True
    status = torch.tensor(
        [[float(bag.analysis_complete), bag.completion_fraction] for bag in bags],
        dtype=dtype, device=device,
    )
    return {
        "apk_sha256": tuple(bag.apk_sha256 for bag in bags),
        "artifact_ids": tuple(tuple(view.artifact_id for view in bag.views) for bag in bags),
        "embeddings": embeddings,
        "attention_mask": mask,
        "analysis_status": status,
        "labels": torch.tensor([bag.label for bag in bags], dtype=torch.long, device=device),
    }


def collate_apk_bags(
    bags: Sequence[APKBag], encode: Callable[[str], torch.Tensor], *, embedding_dim: int | None = None,
) -> dict[str, object]:
    """Encode views and pad only the instance dimension of a mini-batch."""

    if not bags:
        raise ValueError("cannot collate an empty batch")
    encoded = [[encode(view.text) for view in bag.views] for bag in bags]
    sample = next((item for items in encoded for item in items), None)
    if sample is None:
        if embedding_dim is None or embedding_dim <= 0:
            raise ValueError("embedding_dim is required when every APK bag is empty")
        sample = torch.empty(embedding_dim, dtype=torch.float32)
    if sample.ndim != 1 or not sample.is_floating_point():
        raise ValueError("encode must return a one-dimensional floating tensor")
    dimension = sample.shape[0]
    if any(item.ndim != 1 or item.shape[0] != dimension for bag in encoded for item in bag):
        raise ValueError("all encoded ModelViews must have the same dimension")

    maximum = max(1, *(len(bag) for bag in encoded))
    embeddings = sample.new_zeros((len(bags), maximum, dimension))
    mask = torch.zeros((len(bags), maximum), dtype=torch.bool, device=sample.device)
    for bag_index, instances in enumerate(encoded):
        for instance_index, item in enumerate(instances):
            embeddings[bag_index, instance_index] = item
            mask[bag_index, instance_index] = True
    return {
        "apk_sha256": tuple(bag.apk_sha256 for bag in bags),
        "artifact_ids": tuple(tuple(view.artifact_id for view in bag.views) for bag in bags),
        "embeddings": embeddings,
        "attention_mask": mask,
        "analysis_status": torch.tensor(
            [[float(bag.analysis_complete), bag.completion_fraction] for bag in bags],
            dtype=sample.dtype, device=sample.device,
        ),
        "labels": torch.tensor([bag.label for bag in bags], dtype=torch.long, device=sample.device),
    }


class AttentionPool(nn.Module):
    """Small gated-free attention pool over BehaviorArtifact instances."""

    def __init__(self, embedding_dim: int, attention_dim: int) -> None:
        super().__init__()
        if embedding_dim <= 0 or attention_dim <= 0:
            raise ValueError("attention dimensions must be positive")
        self.score = nn.Sequential(
            nn.Linear(embedding_dim, attention_dim), nn.Tanh(), nn.Linear(attention_dim, 1),
        )

    def forward(self, embeddings: torch.Tensor, mask: torch.Tensor) -> tuple[torch.Tensor, torch.Tensor]:
        if embeddings.ndim != 3 or mask.shape != embeddings.shape[:2] or mask.dtype != torch.bool:
            raise ValueError("expected embeddings [batch, instances, dim] and a boolean mask")
        nonempty = mask.any(dim=1)
        scores = self.score(embeddings).squeeze(-1).masked_fill(~mask, torch.finfo(embeddings.dtype).min)
        weights = torch.softmax(scores, dim=1)
        weights = torch.where(nonempty.unsqueeze(1), weights, torch.zeros_like(weights))
        pooled = torch.sum(embeddings * weights.unsqueeze(-1), dim=1)
        return pooled, weights


class MeanPool(nn.Module):
    def forward(self, embeddings: torch.Tensor, mask: torch.Tensor) -> tuple[torch.Tensor, torch.Tensor]:
        weights = mask.to(embeddings.dtype)
        weights = weights / weights.sum(1, keepdim=True).clamp_min(1)
        return torch.sum(embeddings * weights.unsqueeze(-1), 1), weights


class MaxPool(nn.Module):
    def forward(self, embeddings: torch.Tensor, mask: torch.Tensor) -> tuple[torch.Tensor, torch.Tensor]:
        masked = embeddings.masked_fill(~mask.unsqueeze(-1), torch.finfo(embeddings.dtype).min)
        pooled = masked.max(1).values
        pooled = torch.where(mask.any(1, keepdim=True), pooled, torch.zeros_like(pooled))
        return pooled, torch.zeros_like(mask, dtype=embeddings.dtype)


class TopKPool(nn.Module):
    """Average the k instances with the largest embedding L2 norm."""

    def __init__(self, k: int = 3) -> None:
        super().__init__()
        if k <= 0:
            raise ValueError("k must be positive")
        self.k = k

    def forward(self, embeddings: torch.Tensor, mask: torch.Tensor) -> tuple[torch.Tensor, torch.Tensor]:
        scores = embeddings.norm(dim=-1).masked_fill(~mask, torch.finfo(embeddings.dtype).min)
        take = min(self.k, embeddings.shape[1])
        indices = scores.topk(take, dim=1).indices
        selected = torch.zeros_like(mask).scatter(1, indices, True) & mask
        weights = selected.to(embeddings.dtype)
        weights = weights / weights.sum(1, keepdim=True).clamp_min(1)
        return torch.sum(embeddings * weights.unsqueeze(-1), 1), weights


class AttentionMILClassifier(nn.Module):
    def __init__(self, embedding_dim: int, attention_dim: int, num_labels: int = 2) -> None:
        super().__init__()
        self.pool = AttentionPool(embedding_dim, attention_dim)
        self.classifier = nn.Linear(embedding_dim, num_labels)

    def forward(self, embeddings: torch.Tensor, attention_mask: torch.Tensor) -> dict[str, torch.Tensor]:
        pooled, weights = self.pool(embeddings, attention_mask)
        return {"logits": self.classifier(pooled), "attention_weights": weights}


class APKMILClassifier(nn.Module):
    """Configurable aggregation and APK prediction with explicit status input."""

    def __init__(self, embedding_dim: int, pool: nn.Module, num_labels: int = 2) -> None:
        super().__init__()
        self.pool = pool
        self.classifier = nn.Linear(embedding_dim + 2, num_labels)

    def forward(self, embeddings: torch.Tensor, attention_mask: torch.Tensor,
                analysis_status: torch.Tensor) -> dict[str, torch.Tensor]:
        pooled, weights = self.pool(embeddings, attention_mask)
        if analysis_status.shape != (embeddings.shape[0], 2):
            raise ValueError("analysis_status must be [batch, 2]")
        logits = self.classifier(torch.cat((pooled, analysis_status), dim=1))
        return {"logits": logits, "instance_weights": weights}


def build_mil(config: Mapping[str, object]) -> APKMILClassifier:
    if config.get("enabled") is not True:
        raise RuntimeError("V2 MIL is disabled; enable only after corpus audit approval")
    dimension = int(config["embedding_dim"])
    name = str(config.get("aggregation", "mean"))
    pools: dict[str, nn.Module] = {
        "mean": MeanPool(),
        "max": MaxPool(),
        "top_k": TopKPool(int(config.get("top_k", 3))),
        "attention": AttentionPool(dimension, int(config.get("attention_dim", 128))),
    }
    if name not in pools:
        raise ValueError(f"unsupported aggregation: {name}")
    return APKMILClassifier(dimension, pools[name], int(config.get("num_labels", 2)))


def build_attention_mil(config: Mapping[str, object]) -> AttentionMILClassifier:
    """Build the candidate baseline only after an explicit opt-in."""

    if config.get("enabled") is not True:
        raise RuntimeError("V2 MIL is disabled; set enabled=true only after corpus audit approval")
    return AttentionMILClassifier(
        embedding_dim=int(config["embedding_dim"]),
        attention_dim=int(config["attention_dim"]),
        num_labels=int(config.get("num_labels", 2)),
    )
