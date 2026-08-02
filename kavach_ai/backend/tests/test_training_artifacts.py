from __future__ import annotations

import json
import gzip
import time

import pytest
import torch

from kavach_ai.backend.pipeline.stage2_static.decompile import (
    ExtractedMethod,
    ExtractionBackend,
    NativeLibrary,
)
from kavach_ai.backend.pipeline.stage2_static.jni_bridge import (
    ExportedSymbol,
    NativeLibraryAnalysis,
    NativeToolBackend,
    recompute_cached_jni_bridges,
)
from training.utils.dataset import (
    DynamicPaddingCollator,
    create_apk_splits,
    create_or_validate_apk_splits,
    load_apk_splits,
    load_token_examples,
    split_mapping_digest,
)
from training.utils.preprocessing import (
    run_interruptible_process,
    select_sinks_by_category,
)
from training.utils.static_ir import read_static_ir, static_ir_record, write_static_ir
from training.utils.token_statistics import apk_token_statistics, token_length_distribution
from training.utils.tokenization import tokenizer_identity
from kavach_ai.backend.pipeline.stage3_ml.slicing import MethodIdentity, SinkMatch


def _native_method() -> ExtractedMethod:
    return ExtractedMethod(
        "classes.dex", "Lapp/Main;", "check", "()V", "Lapp/Main;->check()V",
        ("native", "public", "static"), (), None, None, (), (), (), None,
        "temporary/source/path", ExtractionBackend.SMALI,
    )


def test_static_ir_round_trip_recomputes_jni_without_binary_path(tmp_path) -> None:
    method = _native_method()
    library = NativeLibrary(
        "libcheck.so", "arm64-v8a", "lib/arm64-v8a/libcheck.so",
        "/temporary/native/libcheck.so", "b" * 64, 123,
    )
    symbol = ExportedSymbol(
        library.archive_path, library.abi, "Java_app_Main_check", "T", "1234",
        NativeToolBackend.NM,
    )
    analysis = NativeLibraryAnalysis(library, NativeToolBackend.NM, (symbol,), (), ())
    jni = recompute_cached_jni_bridges((method,), (), (analysis,))
    record = static_ir_record("a" * 64, (method,), jni, "SUCCESS", ())
    path = tmp_path / "static.json.gz"
    write_static_ir(path, record)

    with gzip.open(path, "rt", encoding="utf-8") as file:
        serialized = file.read()
    assert "/temporary/native" not in serialized
    assert "temporary/source/path" not in serialized
    restored = read_static_ir(path)
    assert restored.apk_hash == "a" * 64
    assert restored.methods[0].source_path == ""
    assert restored.jni_result.mappings[0].matched_libraries == (library.archive_path,)
    assert restored.jni_result.library_analyses[0].library.extracted_path == ""


def test_fixed_apk_split_mapping_is_required_and_complete(tmp_path) -> None:
    path = tmp_path / "apk_splits_v1.json"
    with pytest.raises(FileNotFoundError):
        load_apk_splits(path)
    path.write_text(json.dumps({"a" * 64: "train"}), encoding="utf-8")
    assert load_apk_splits(path, {"a" * 64}) == {"a" * 64: "train"}
    with pytest.raises(ValueError, match="mismatch"):
        load_apk_splits(path, {"a" * 64, "b" * 64})


def test_loader_skips_explicit_unavailable_outcomes_but_rejects_unknown_missing_shards(
    tmp_path,
) -> None:
    apk_hash = "a" * 64
    metadata = {apk_hash: {"label": "Malicious"}}
    splits = {apk_hash: "train"}
    assert load_token_examples(
        tmp_path,
        metadata,
        splits,
        "train",
        apk_statistics={apk_hash: {"status": "timed_out"}},
    ) == []
    with pytest.raises(ValueError, match="no preprocessing outcome"):
        load_token_examples(
            tmp_path, metadata, splits, "train", apk_statistics={}
        )


class _FakeTokenizer:
    pad_token_id = 0

    def pad(self, features, **kwargs):
        width = max(len(item["input_ids"]) for item in features)
        ids = [item["input_ids"] + [0] * (width - len(item["input_ids"])) for item in features]
        masks = [[1] * len(item["input_ids"]) + [0] * (width - len(item["input_ids"])) for item in features]
        return {"input_ids": torch.tensor(ids), "attention_mask": torch.tensor(masks)}


class _FakeBackend:
    def __init__(self, schema: dict) -> None:
        self.schema = schema

    def to_str(self) -> str:
        return json.dumps(self.schema)


class _FingerprintTokenizer:
    _commit_hash = "revision-one"
    init_kwargs = {}
    special_tokens_map = {"cls_token": "[CLS]"}
    model_max_length = 8192
    padding_side = "right"
    truncation_side = "right"
    backend_tokenizer = _FakeBackend({"normalizer": "v1"})


def test_collator_creates_padding_and_attention_masks_dynamically() -> None:
    collator = DynamicPaddingCollator(_FakeTokenizer())
    batch = collator(
        (
            {"example_id": "one", "apk_hash": "a", "input_ids": [1, 2, 3], "label": 0},
            {"example_id": "two", "apk_hash": "b", "input_ids": [4], "label": 1},
        )
    )
    assert batch["input_ids"].tolist() == [[1, 2, 3], [4, 0, 0]]
    assert batch["attention_mask"].tolist() == [[1, 1, 1], [1, 0, 0]]
    assert batch["labels"].tolist() == [0, 1]


def test_global_group_and_per_apk_statistics_use_strict_thresholds() -> None:
    distribution = token_length_distribution([512, 513, 1024, 1025])
    assert distribution["count"] == 4
    assert distribution["percent_gt_512"] == 75.0
    assert distribution["percent_gt_1024"] == 25.0
    assert token_length_distribution([])["mean"] is None

    shard = {
        "examples": [
            {"token_count": 512, "is_truncated": False},
            {"token_count": 1025, "is_truncated": True},
        ]
    }
    stats = apk_token_statistics("a" * 64, shard)
    assert stats["slice_count"] == 2
    assert stats["complete_slice_count"] == stats["truncated_slice_count"] == 1
    assert stats["total_token_count"] == 1537
    assert stats["max_slice_token_count"] == 1025


def test_tokenizer_fingerprint_covers_revision_settings_and_schema() -> None:
    tokenizer = _FingerprintTokenizer()
    first, configuration, schema = tokenizer_identity(
        tokenizer, "model", add_special_tokens=True, token_schema_version="tokens-v1"
    )
    assert configuration["resolved_revision"] == "revision-one"
    assert schema == {"normalizer": "v1"}
    without_specials = tokenizer_identity(
        tokenizer, "model", add_special_tokens=False, token_schema_version="tokens-v1"
    )[0]
    tokenizer.backend_tokenizer = _FakeBackend({"normalizer": "v2"})
    changed_schema = tokenizer_identity(
        tokenizer, "model", add_special_tokens=True, token_schema_version="tokens-v1"
    )[0]
    changed_storage = tokenizer_identity(
        tokenizer, "model", add_special_tokens=True, token_schema_version="tokens-v2"
    )[0]
    assert len({first, without_specials, changed_schema, changed_storage}) == 4


def test_full_inventory_splits_are_stratified_deterministic_and_immutable(tmp_path) -> None:
    metadata = {
        f"{number:064x}": {"label": "Benign" if number < 10 else "Malicious"}
        for number in range(20)
    }
    first = create_apk_splits(metadata)
    assert first == create_apk_splits(dict(reversed(tuple(metadata.items()))))
    assert set(first) == set(metadata)
    path = tmp_path / "apk_splits_v1.json"
    assert create_or_validate_apk_splits(path, metadata) == first
    assert split_mapping_digest(first) == split_mapping_digest(load_apk_splits(path))
    changed = dict(metadata)
    changed[f"{99:064x}"] = {"label": "Benign"}
    with pytest.raises(ValueError, match="mismatch"):
        create_or_validate_apk_splits(path, changed)


def test_sink_selection_round_robins_categories_deterministically() -> None:
    identity = MethodIdentity("classes.dex", "Lx;->run()V")
    sinks = tuple(
        SinkMatch(identity, index, f"rule-{index}", category, f"Lx;->s{index}()V")
        for index, category in enumerate(("zeta", "alpha", "alpha", "zeta"))
    )
    selected = select_sinks_by_category(reversed(sinks), 3)
    assert [item.category for item in selected] == ["alpha", "zeta", "alpha"]
    assert selected == select_sinks_by_category(sinks, 3)


def test_interruptible_worker_times_out_cleanly() -> None:
    result = run_interruptible_process(time.sleep, (0.2,), timeout_seconds=0.01)
    assert result.timed_out
