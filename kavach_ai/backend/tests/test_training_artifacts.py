from __future__ import annotations

import json
import gzip
import hashlib
import time
from collections import Counter
from pathlib import Path

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
from training.train import (
    Corpus,
    TokenShardIterableDataset,
    apply_context_policy,
    scan_split,
    select_tiny_records,
)
from training.pipeline.config import ResolvedConfig, ResolvedFilters, load_config
from training.pipeline.data import (
    PreflightResult, PreparedRecord, RejectionReason, TinyDataset, create_collator,
    load_corpus, load_validated_shard, preflight_split, prepare_record,
)
from training.pipeline.provenance import (
    OutputState, config_hash, plan_output, sanitize_metadata, write_json_atomic,
    update_lifecycle, write_jsonl_atomic, write_training_artifacts,
)


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


def _training_config() -> dict:
    return {
        "run": {"seed": 7},
        "data": {
            "train_split": "train", "sampler": {"type": "standard", "active_apk_shards": 8},
            "exclude_internally_truncated": True, "min_token_length": 1,
            "max_token_length": None, "include_sink_categories": None,
            "exclude_sink_categories": [], "excluded_example_ids": [],
            "max_context_length": 8, "context_policy": "head",
            "tiny_examples": 16, "tiny_candidate_pool": 32,
            "tiny_disallowed_boundaries": ["recursion"],
        },
    }


def _resolved_training_config() -> ResolvedConfig:
    value = _training_config()
    return ResolvedConfig(value, ResolvedFilters(frozenset(), frozenset(), frozenset(), frozenset({"recursion"})))


def _tiny_corpus(tmp_path) -> Corpus:
    token_dir = tmp_path / "tokens"
    slice_dir = tmp_path / "slices" / "v1"
    token_dir.mkdir()
    slice_dir.mkdir(parents=True)
    metadata, splits, statistics, shard_names = {}, {}, {}, []
    for number in range(16):
        apk_hash = f"{number:064x}"
        label = "Benign" if number < 8 else "Malicious"
        example_id = f"{apk_hash}:example"
        item = {
            "example_id": example_id, "apk_hash": apk_hash,
            "input_ids": [number + 1, number + 2], "token_count": 2,
            "is_truncated": False,
            "sink_category": "sms" if number % 2 else "reflection",
            "slice_origin": "sink",
        }
        shard_name = f"{apk_hash}.pt"
        torch.save({
            "schema_version": "tokens-v1", "slice_schema_version": "slice-v1",
            "normalization_version": "structural-v1", "normalization_config_sha256": "n",
            "tokenizer_fingerprint": "fingerprint", "apk_hash": apk_hash,
            "examples": [item],
        }, token_dir / shard_name)
        with gzip.open(slice_dir / f"{apk_hash}.jsonl.gz", "wt", encoding="utf-8") as file:
            file.write(json.dumps({
                "example_id": example_id, "issues": [], "is_truncated": False,
                "unresolved_boundaries": [],
            }) + "\n")
        metadata[apk_hash] = {"apk_hash": apk_hash, "label": label}
        splits[apk_hash] = "train"
        statistics[apk_hash] = {"apk_hash": apk_hash, "status": "completed"}
        shard_names.append(shard_name)
    manifest = {
        "dataset_version": "dataset-v1", "token_schema_version": "tokens-v1",
        "normalization_version": "structural-v1", "normalization_config_sha256": "n",
        "tokenizer_fingerprint": "fingerprint",
    }
    return Corpus(
        tmp_path, manifest, metadata, splits, statistics, token_dir,
        tuple(shard_names), {"configuration": {}},
    )


def test_training_join_and_sized_iterable_are_exact_and_deterministic(tmp_path) -> None:
    corpus = _tiny_corpus(tmp_path)
    config = _training_config()
    summary = scan_split(corpus, config, "train")
    assert summary.count == 16
    assert summary.class_counts == {"Benign": 8, "Malicious": 8}
    dataset = TokenShardIterableDataset(corpus, config, "train", summary.count)
    first = [item["input_ids"] for item in dataset]
    assert len(first) == len(dataset) == 16
    assert len({tuple(item) for item in first}) == 16
    dataset.set_epoch(1)
    second = [item["input_ids"] for item in dataset]
    assert first != second
    assert {tuple(item) for item in first} == {tuple(item) for item in second}


def test_tiny_selection_is_balanced_clean_and_deterministic(tmp_path) -> None:
    corpus = _tiny_corpus(tmp_path)
    config = _training_config()
    first = select_tiny_records(corpus, config)
    second = select_tiny_records(corpus, config)
    assert [item["example_id"] for item in first] == [item["example_id"] for item in second]
    assert Counter(item["label_name"] for item in first) == {"Benign": 8, "Malicious": 8}
    assert len({tuple(item["input_ids"]) for item in first}) == 16
    assert len({item["apk_hash"] for item in first}) == 16


def test_context_policy_fits_truncates_and_rejects_sink_centered() -> None:
    assert apply_context_policy([1, 2], 2, "head") == ([1, 2], False)
    assert apply_context_policy([1, 2, 3], 2, "head") == ([1, 2], True)
    with pytest.raises(NotImplementedError, match="sink_centered"):
        apply_context_policy([1, 2, 3], 2, "sink_centered")


def test_training_config_rejects_quoted_boolean_and_bad_list(tmp_path) -> None:
    source = Path(__file__).parents[3] / "training" / "configs" / "dry_run.yaml"
    text = source.read_text(encoding="utf-8")
    quoted = tmp_path / "quoted.yaml"
    quoted.write_text(text.replace("overwrite_output_dir: true", 'overwrite_output_dir: "false"'), encoding="utf-8")
    with pytest.raises(ValueError, match="must be bool"):
        load_config(quoted)
    bad_list = tmp_path / "list.yaml"
    bad_list.write_text(text.replace("exclude_sink_categories: []", "exclude_sink_categories: reflection"), encoding="utf-8")
    with pytest.raises(ValueError, match="list of strings"):
        load_config(bad_list)


def test_unavailable_indexed_apk_is_counted_and_excluded(tmp_path) -> None:
    corpus = _tiny_corpus(tmp_path)
    first = next(iter(corpus.statistics))
    corpus.statistics[first]["status"] = "extraction_partial"
    result = preflight_split(corpus, _resolved_training_config(), "train")
    assert result.summary.stored_records == 16
    assert result.summary.count == 15
    assert result.summary.rejected_records == 1
    assert result.summary.rejection_counts == {RejectionReason.UNAVAILABLE_STATUS.value: 1}


def test_unsupported_category_is_reconciled_as_policy_rejection(tmp_path) -> None:
    corpus = _tiny_corpus(tmp_path)
    shard = torch.load(corpus.token_dir / corpus.shard_names[0], weights_only=True)
    shard["examples"][0]["sink_category"] = "unknown"
    torch.save(shard, corpus.token_dir / corpus.shard_names[0])
    result = preflight_split(corpus, _resolved_training_config(), "train")
    assert result.summary.stored_records == result.summary.count + result.summary.rejected_records
    assert result.summary.rejection_counts == {RejectionReason.EXCLUDED_CATEGORY.value: 1}


def test_duplicate_example_id_is_a_fatal_preflight_error(tmp_path) -> None:
    corpus = _tiny_corpus(tmp_path)
    first, second = corpus.shard_names[:2]
    first_item = torch.load(corpus.token_dir / first, weights_only=True)["examples"][0]
    shard = torch.load(corpus.token_dir / second, weights_only=True)
    shard["examples"][0]["example_id"] = first_item["example_id"]
    torch.save(shard, corpus.token_dir / second)
    with pytest.raises(ValueError, match="duplicate_example_id"):
        preflight_split(corpus, _resolved_training_config(), "train")


def test_duplicate_shards_metadata_disagreement_and_tokenizer_mismatch_fail(tmp_path) -> None:
    corpus = _tiny_corpus(tmp_path)
    duplicate_inventory = Corpus(
        corpus.root, corpus.manifest, corpus.metadata, corpus.splits, corpus.statistics,
        corpus.token_dir, corpus.shard_names + (corpus.shard_names[0],),
        corpus.tokenizer_manifest, corpus.tokenizer_fingerprint,
    )
    with pytest.raises(ValueError, match="duplicate shard"):
        preflight_split(duplicate_inventory, _resolved_training_config(), "train")
    corpus.statistics[next(iter(corpus.statistics))]["label"] = "Malicious"
    with pytest.raises(ValueError, match="label_split_mismatch"):
        preflight_split(corpus, _resolved_training_config(), "train")
    corpus.statistics[next(iter(corpus.statistics))].pop("label")
    shard = torch.load(corpus.token_dir / corpus.shard_names[0], weights_only=True)
    shard["tokenizer_fingerprint"] = "wrong"
    torch.save(shard, corpus.token_dir / corpus.shard_names[0])
    with pytest.raises(ValueError, match="tokenizer_mismatch"):
        preflight_split(corpus, _resolved_training_config(), "train")


def test_zero_eligible_records_has_direct_rejection_summary(tmp_path) -> None:
    corpus = _tiny_corpus(tmp_path)
    config = _training_config()
    config["data"]["min_token_length"] = 100
    resolved = ResolvedConfig(config, ResolvedFilters(frozenset(), frozenset(), frozenset(), frozenset()))
    with pytest.raises(ValueError, match="No eligible records.*length_filter"):
        preflight_split(corpus, resolved, "train")


def test_iterable_detects_preflight_drift(tmp_path) -> None:
    corpus = _tiny_corpus(tmp_path)
    config = _resolved_training_config()
    checked = preflight_split(corpus, config, "train")
    altered = PreflightResult(checked.summary, checked.records, checked.eligible_ids | {"missing"}, checked.rejections)
    with pytest.raises(RuntimeError, match="drift"):
        list(TokenShardIterableDataset(corpus, config, "train", altered))


def test_collator_is_given_only_model_fields(tmp_path) -> None:
    corpus = _tiny_corpus(tmp_path)
    config = _resolved_training_config()
    shard = load_validated_shard(corpus, corpus.shard_names[0])
    record = prepare_record(shard["examples"][0], Path(corpus.shard_names[0]).stem,
                            corpus, config, expected_split="train")
    assert isinstance(record, PreparedRecord)
    assert set(TinyDataset([record])[0]) == {"input_ids", "labels"}


def test_normal_preflight_and_iteration_never_open_canonical_slices(tmp_path, monkeypatch) -> None:
    corpus = _tiny_corpus(tmp_path)
    config = _resolved_training_config()
    monkeypatch.setattr(gzip, "open", lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("slice opened")))
    checked = preflight_split(corpus, config, "train")
    assert len(list(TokenShardIterableDataset(corpus, config, "train", checked))) == 16


def test_provenance_output_states_atomic_write_and_sanitization(tmp_path) -> None:
    config = json.loads(json.dumps(_resolved_training_config().raw))
    config["run"].update({"output_dir": str(tmp_path / "new"), "overwrite_output_dir": False,
                           "resume_from_checkpoint": None, "name": "test"})
    resolved = ResolvedConfig(config, ResolvedFilters(frozenset(), frozenset(), frozenset(), frozenset()))
    assert plan_output(resolved).state is OutputState.NEW
    target = tmp_path / "atomic.json"
    write_json_atomic(target, {"ok": True})
    assert json.loads(target.read_text()) == {"ok": True}
    assert not list(tmp_path.glob(".atomic.json.*.tmp"))
    sanitized = sanitize_metadata({"inside": Path(__file__), "outside": Path("/private/secret/value")})
    assert not sanitized["inside"].startswith("/")
    assert sanitized["outside"] == "<redacted>/value"
    resolved_path = sanitize_metadata(resolved.serializable())
    expected_hash = hashlib.sha256(json.dumps(resolved_path, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    assert config_hash(resolved) == expected_hash
    (tmp_path / "new").mkdir()
    (tmp_path / "new" / "existing").write_text("keep", encoding="utf-8")
    with pytest.raises(FileExistsError):
        plan_output(resolved)
    resolved.raw["run"]["overwrite_output_dir"] = True
    assert plan_output(resolved).state is OutputState.OVERWRITE
    resolved.raw["run"]["resume_from_checkpoint"] = "checkpoint-1"
    with pytest.raises(ValueError, match="cannot be combined"):
        plan_output(resolved)


def test_atomic_jsonl_failure_preserves_previous_file(tmp_path) -> None:
    target = tmp_path / "records.jsonl"
    target.write_text("previous\n", encoding="utf-8")
    def broken_records():
        yield {"one": 1}
        raise RuntimeError("boom")
    with pytest.raises(RuntimeError, match="boom"):
        write_jsonl_atomic(target, broken_records())
    assert target.read_text(encoding="utf-8") == "previous\n"
    assert not list(tmp_path.glob(".records.jsonl.*.tmp"))


def test_training_artifacts_and_lifecycle_are_atomic_and_sanitized(tmp_path) -> None:
    write_json_atomic(tmp_path / "run-manifest.json", {"schema_version": "training-run-v2"})
    update_lifecycle(tmp_path, "prepared", model_path=Path("/private/model"))
    prepared = json.loads((tmp_path / "run-manifest.json").read_text())
    assert prepared["status"] == "prepared"
    assert prepared["model_path"] == "<redacted>/model"
    update_lifecycle(tmp_path, "running")
    update_lifecycle(tmp_path, "failed", exception_type="RuntimeError")
    failed = json.loads((tmp_path / "run-manifest.json").read_text())
    assert failed["status"] == "failed" and "end_time" in failed
    write_training_artifacts(
        tmp_path, environment={"device": "cpu"}, lora_targets={"matches": 22},
        trainable_parameters={"trainable": 1_132_802}, metrics={"f1": 0.5},
    )
    assert json.loads((tmp_path / "metrics.json").read_text()) == {"f1": 0.5}


def test_all_permanent_training_configs_are_strict_and_loadable() -> None:
    root = Path(__file__).parents[3]
    expected = {
        "dry_run.yaml": "dry_run", "smoke.yaml": "smoke",
        "tiny_overfit.yaml": "tiny_overfit", "train.yaml": "train",
    }
    for name, mode in expected.items():
        config = load_config(root / "training" / "configs" / name)
        assert config["run"]["mode"] == mode
        assert config["data"]["exclude_internally_truncated"] is True
        assert config["trainer"]["dataloader_num_workers"] == 0


def test_new_schema_rejects_old_truncation_key_bad_sampler_and_seed_drift(tmp_path) -> None:
    source = Path(__file__).parents[3] / "training" / "configs" / "dry_run.yaml"
    text = source.read_text(encoding="utf-8")
    old = tmp_path / "old.yaml"
    old.write_text(text.replace("exclude_internally_truncated: true", "include_internally_truncated: false"), encoding="utf-8")
    with pytest.raises(ValueError, match="Invalid data keys"):
        load_config(old)
    bad_sampler = tmp_path / "sampler.yaml"
    bad_sampler.write_text(text.replace("active_apk_shards: 8", "active_apk_shards: false"), encoding="utf-8")
    with pytest.raises(ValueError, match="must be int"):
        load_config(bad_sampler)
    bad_seed = tmp_path / "seed.yaml"
    bad_seed.write_text(text.replace("data_seed: 42", "data_seed: 7"), encoding="utf-8")
    with pytest.raises(ValueError, match="must match"):
        load_config(bad_seed)
