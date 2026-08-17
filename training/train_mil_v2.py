"""Train APK-level pooling heads over frozen SecureBERT ModelView embeddings."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import torch

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from training.pipeline.mil import SecureBERTEmbedder, load_apk_bag_dataset  # noqa: E402
from training.pipeline.mil_training import (  # noqa: E402
    encode_bags, load_embedding_cache, save_embedding_cache, train_pooler,
)


def _args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--modelview-root", type=Path, required=True)
    parser.add_argument("--metadata", type=Path, required=True)
    parser.add_argument("--splits", type=Path, required=True)
    parser.add_argument("--checkpoint", default="training/models/SecureBERT2.0-base")
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--cache-dir", type=Path, required=True)
    parser.add_argument("--available-only", action="store_true",
                        help="train on the completed ModelView indexes currently present")
    parser.add_argument("--aggregations", nargs="+", choices=("mean", "max", "top_k", "attention"),
                        default=("mean", "max", "top_k", "attention"))
    parser.add_argument("--max-length", type=int, default=1024)
    parser.add_argument("--encoder-batch-size", type=int, default=16)
    parser.add_argument("--batch-size", type=int, default=16)
    parser.add_argument("--epochs", type=int, default=20)
    parser.add_argument("--learning-rate", type=float, default=1e-3)
    parser.add_argument("--weight-decay", type=float, default=1e-4)
    parser.add_argument("--attention-dim", type=int, default=128)
    parser.add_argument("--top-k", type=int, default=3)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--device", choices=("auto", "cpu", "mps", "cuda"), default="auto")
    return parser.parse_args()


def _device(name: str) -> torch.device:
    if name != "auto":
        return torch.device(name)
    if torch.cuda.is_available():
        return torch.device("cuda")
    if torch.backends.mps.is_available():
        return torch.device("mps")
    return torch.device("cpu")


def main() -> None:
    args = _args()
    device = _device(args.device)
    checkpoint = str(Path(args.checkpoint).resolve())
    selected = {"train": None, "validation": None}
    if args.available_only:
        split_mapping = json.loads(args.splits.read_text(encoding="utf-8"))
        index_root = args.modelview_root / "v2" / "candidate1"
        available = sorted(path.parent.name for path in index_root.glob("*/index.json"))
        selected = {name: tuple(item for item in available if split_mapping.get(item) == name)
                    for name in selected}
    datasets = {split: load_apk_bag_dataset(
        modelview_root=args.modelview_root, metadata_path=args.metadata,
        splits_path=args.splits, split=split, apk_hashes=selected[split],
    ) for split in selected}
    caches = {split: args.cache_dir / f"{split}.pt" for split in datasets}
    encoded = {}
    missing = [split for split, path in caches.items() if not path.is_file()]
    embedder = None
    if missing:
        embedder = SecureBERTEmbedder.from_pretrained(
            checkpoint, max_length=args.max_length, batch_size=args.encoder_batch_size, device=device,
        )
    for split, dataset in datasets.items():
        if caches[split].is_file():
            cached = load_embedding_cache(
                caches[split], checkpoint=checkpoint, max_length=args.max_length,
            )
            expected = tuple((bag.apk_sha256, tuple(view.artifact_id for view in bag.views))
                             for bag in dataset)
            observed = tuple((bag.apk_sha256, bag.artifact_ids) for bag in cached)
            encoded[split] = cached if observed == expected else None
        else:
            encoded[split] = None
        if encoded[split] is None:
            if embedder is None:
                embedder = SecureBERTEmbedder.from_pretrained(
                    checkpoint, max_length=args.max_length,
                    batch_size=args.encoder_batch_size, device=device,
                )
            assert embedder is not None
            encoded[split] = encode_bags(tuple(dataset), embedder)
            save_embedding_cache(caches[split], encoded[split], checkpoint=checkpoint,
                                 max_length=args.max_length)
    dimension = next((bag.embeddings.shape[1] for bags in encoded.values() for bag in bags), None)
    if dimension is None:
        raise ValueError("no APKs available for training")
    results = [train_pooler(
        aggregation=name, train_bags=encoded["train"], validation_bags=encoded["validation"],
        embedding_dim=dimension, attention_dim=args.attention_dim, top_k=args.top_k,
        epochs=args.epochs, batch_size=args.batch_size, learning_rate=args.learning_rate,
        weight_decay=args.weight_decay, seed=args.seed, device=device, output_dir=args.output_dir,
    ) for name in args.aggregations]
    args.output_dir.mkdir(parents=True, exist_ok=True)
    summary = {"device": str(device), "frozen_encoder": True, "checkpoint": checkpoint,
               "dataset_scope": "available_completed_indexes" if args.available_only else "full_split",
               "train_apks": len(encoded["train"]), "validation_apks": len(encoded["validation"]),
               "results": results}
    (args.output_dir / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
