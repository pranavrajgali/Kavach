"""Synthetic tests for exact-once APK interleaving and smoke selection."""

from __future__ import annotations

from collections import Counter
import hashlib
import json
from pathlib import Path

import pytest
import torch

import training.pipeline.data as data_module
from training.pipeline.data import (
    Corpus,
    TokenShardIterableDataset,
    preflight_split,
    select_smoke_records,
    validate_tokenizer,
)


def _config(sampler_type: str = "standard", *, seed: int = 19, active: int = 4) -> dict:
    return {
        "run": {"seed": seed},
        "data": {
            "train_split": "train",
            "sampler": {"type": sampler_type, "active_apk_shards": active},
            "exclude_internally_truncated": True,
            "min_token_length": 1,
            "max_token_length": None,
            "include_sink_categories": None,
            "exclude_sink_categories": [],
            "excluded_example_ids": [],
            "max_context_length": 32,
            "context_policy": "head",
            "tiny_disallowed_boundaries": [],
            "smoke_examples": 8,
        },
    }


def _corpus(tmp_path: Path, *, apks: int = 12, examples_per_apk: int = 4) -> Corpus:
    token_dir = tmp_path / "tokens"
    token_dir.mkdir()
    metadata, splits, statistics, names = {}, {}, {}, []
    for apk_number in range(apks):
        apk_hash = f"{apk_number:064x}"
        label = "Benign" if apk_number % 2 == 0 else "Malicious"
        examples = []
        for example_number in range(examples_per_apk):
            identifier = apk_number * 100 + example_number + 1
            examples.append({
                "example_id": f"{apk_hash}:{example_number}",
                "apk_hash": apk_hash,
                "input_ids": [identifier],
                "token_count": 1,
                "is_truncated": False,
                "sink_category": "reflection",
            })
        name = f"{apk_hash}.pt"
        torch.save({
            "schema_version": "tokens-v1",
            "slice_schema_version": "slice-v1",
            "normalization_version": "structural-v1",
            "normalization_config_sha256": "normalization",
            "tokenizer_fingerprint": "fingerprint",
            "apk_hash": apk_hash,
            "examples": examples,
        }, token_dir / name)
        metadata[apk_hash] = {"label": label}
        splits[apk_hash] = "train"
        statistics[apk_hash] = {"status": "completed", "label": label, "split": "train"}
        names.append(name)
    manifest = {
        "token_schema_version": "tokens-v1",
        "normalization_version": "structural-v1",
        "normalization_config_sha256": "normalization",
        "tokenizer_fingerprint": "fingerprint",
    }
    return Corpus(
        tmp_path, manifest, metadata, splits, statistics, token_dir,
        tuple(names), {"configuration": {}}, "fingerprint",
    )


def _tokens(dataset: TokenShardIterableDataset) -> list[int]:
    return [item["input_ids"][0] for item in dataset]


def _apk(token: int) -> int:
    return (token - 1) // 100


def test_interleaved_has_identical_exact_membership_and_bounded_queues(tmp_path: Path) -> None:
    corpus = _corpus(tmp_path)
    standard_config = _config()
    interleaved_config = _config("apk_interleaved")
    checked = preflight_split(corpus, standard_config, "train")
    standard = TokenShardIterableDataset(corpus, standard_config, "train", checked)
    interleaved = TokenShardIterableDataset(corpus, interleaved_config, "train", checked)

    standard_tokens, interleaved_tokens = _tokens(standard), _tokens(interleaved)
    assert len(interleaved_tokens) == len(interleaved) == checked.summary.count
    assert len(set(interleaved_tokens)) == len(interleaved_tokens)
    assert set(interleaved_tokens) == set(standard_tokens)
    assert Counter(token % 2 for token in interleaved_tokens) == Counter(token % 2 for token in standard_tokens)
    assert interleaved.peak_resident_queues == 4


def test_interleaved_is_deterministic_varies_by_epoch_and_improves_windows(tmp_path: Path) -> None:
    corpus = _corpus(tmp_path)
    checked = preflight_split(corpus, _config(), "train")
    first = TokenShardIterableDataset(corpus, _config("apk_interleaved"), "train", checked)
    same = TokenShardIterableDataset(corpus, _config("apk_interleaved"), "train", checked)
    standard = TokenShardIterableDataset(corpus, _config(), "train", checked)
    first_tokens = _tokens(first)
    assert first_tokens == _tokens(same)
    first.set_epoch(1)
    epoch_two = _tokens(first)
    assert epoch_two != first_tokens
    assert set(epoch_two) == set(first_tokens)
    standard_tokens = _tokens(standard)
    standard_diversity = sum(len({_apk(token) for token in standard_tokens[i:i + 4]}) for i in range(0, 16, 4))
    interleaved_diversity = sum(len({_apk(token) for token in first_tokens[i:i + 4]}) for i in range(0, 16, 4))
    assert interleaved_diversity > standard_diversity


def test_interleaved_loads_every_shard_once_per_epoch(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    corpus = _corpus(tmp_path)
    config = _config("apk_interleaved", active=3)
    checked = preflight_split(corpus, config, "train")
    original = data_module.load_validated_shard
    calls: Counter[str] = Counter()

    def counted(corpus_arg: Corpus, shard_name: str) -> dict:
        calls[shard_name] += 1
        return original(corpus_arg, shard_name)

    monkeypatch.setattr(data_module, "load_validated_shard", counted)
    dataset = TokenShardIterableDataset(corpus, config, "train", checked)
    assert len(_tokens(dataset)) == checked.summary.count
    assert calls == Counter({name: 1 for name in corpus.shard_names})
    assert dataset.peak_resident_queues <= 3


def test_smoke_ranking_is_stable_apk_diverse_and_never_opens_slices(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    corpus = _corpus(tmp_path, apks=6, examples_per_apk=3)
    config = _config(seed=23)
    checked = preflight_split(corpus, config, "train")
    monkeypatch.setattr(data_module.gzip, "open", lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("slice opened")))
    first = select_smoke_records(corpus, config, checked)
    second = select_smoke_records(corpus, config, checked)
    assert [record.example_id for record in first] == [record.example_id for record in second]
    assert len(first) == 8
    assert len({record.example_id for record in first}) == 8
    assert len({record.apk_hash for record in first[:6]}) == 6
    # Selection is deliberately not class/category balanced.
    expected = sorted(
        (record for record in first),
        key=lambda record: data_module._candidate_score(config["run"]["seed"], record.example_id),
    )
    assert set(record.example_id for record in expected) == set(record.example_id for record in first)


def test_interleaved_rejects_invalid_active_queue_bound(tmp_path: Path) -> None:
    corpus = _corpus(tmp_path)
    config = _config("apk_interleaved", active=0)
    checked = preflight_split(corpus, config, "train")
    with pytest.raises(ValueError, match="positive integer"):
        list(TokenShardIterableDataset(corpus, config, "train", checked))


def test_loaded_tokenizer_can_be_validated_without_loading_again(tmp_path: Path) -> None:
    corpus = _corpus(tmp_path)
    backend = {"model": {"type": "WordPiece"}}
    special_tokens = {"pad_token": "[PAD]"}
    corpus.tokenizer_manifest["configuration"] = {
        "special_tokens_map": special_tokens,
        "backend_schema_sha256": hashlib.sha256(
            json.dumps(backend, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest(),
    }

    class Backend:
        def to_str(self) -> str:
            return json.dumps(backend)

    class Tokenizer:
        pad_token = "[PAD]"
        pad_token_id = 0
        special_tokens_map = special_tokens
        backend_tokenizer = Backend()

    tokenizer = Tokenizer()
    assert validate_tokenizer(corpus, tokenizer) is tokenizer
    tokenizer.pad_token = None
    with pytest.raises(ValueError, match="pad token"):
        validate_tokenizer(corpus, tokenizer)
