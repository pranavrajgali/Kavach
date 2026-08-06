"""Atomic, sanitized provenance and output-state handling."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Iterable, Mapping

from training.pipeline.config import REPO_ROOT, ResolvedConfig, canonical_config, resolve_path


RUN_MANIFEST_SCHEMA = "training-run-v2"


class OutputState(str, Enum):
    NEW = "new"
    OVERWRITE = "overwrite"
    RESUME = "resume"


@dataclass(frozen=True)
class OutputPlan:
    directory: Path
    state: OutputState


def config_hash(config: ResolvedConfig | Mapping[str, Any]) -> str:
    encoded = json.dumps(
        sanitize_metadata(canonical_config(config)), sort_keys=True, separators=(",", ":"), default=str
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


def sanitize_metadata(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): sanitize_metadata(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [sanitize_metadata(item) for item in value]
    if isinstance(value, Path):
        value = str(value)
    if isinstance(value, str) and Path(value).is_absolute():
        path = Path(value)
        try:
            return str(path.relative_to(REPO_ROOT))
        except ValueError:
            return f"<redacted>/{path.name}"
    return value


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def git_commit() -> str | None:
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=REPO_ROOT, text=True, capture_output=True, check=False,
    )
    return result.stdout.strip() or None


def package_versions() -> dict[str, str]:
    import accelerate
    import peft
    import torch
    import transformers
    import wandb
    return {
        "torch": torch.__version__, "transformers": transformers.__version__,
        "peft": peft.__version__, "accelerate": accelerate.__version__, "wandb": wandb.__version__,
    }


def plan_output(config: ResolvedConfig) -> OutputPlan:
    run = config["run"]
    output = resolve_path(run["output_dir"] or f"training/outputs/{run['name']}")
    resume = run["resume_from_checkpoint"]
    overwrite = run["overwrite_output_dir"]
    if resume is not None and overwrite:
        raise ValueError("overwrite_output_dir and resume_from_checkpoint cannot be combined")
    if resume is not None:
        raise NotImplementedError("Resume output state is unavailable until Trainer wiring")
    nonempty = output.exists() and any(output.iterdir())
    if nonempty and not overwrite:
        raise FileExistsError(f"Output directory is non-empty: {output}")
    return OutputPlan(output, OutputState.OVERWRITE if nonempty else OutputState.NEW)


def _atomic_replace(path: Path, writer: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    os.close(descriptor)
    temporary = Path(temporary_name)
    try:
        writer(temporary)
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def write_json_atomic(path: Path, value: Any) -> None:
    _atomic_replace(path, lambda temporary: temporary.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    ))


def write_text_atomic(path: Path, value: str) -> None:
    _atomic_replace(path, lambda temporary: temporary.write_text(value, encoding="utf-8"))


def write_jsonl_atomic(path: Path, records: Iterable[Mapping[str, Any]]) -> None:
    def write(temporary: Path) -> None:
        with temporary.open("w", encoding="utf-8") as file:
            for record in records:
                file.write(json.dumps(record, sort_keys=True) + "\n")
    _atomic_replace(path, write)


def commit_provenance(
    plan: OutputPlan,
    config_path: Path,
    config: ResolvedConfig,
    selected_records: Iterable[Mapping[str, Any]],
    run_manifest: Mapping[str, Any],
) -> tuple[str, str]:
    directory = plan.directory
    directory.mkdir(parents=True, exist_ok=True)
    selected_path = directory / "selected-records.jsonl"
    write_jsonl_atomic(selected_path, selected_records)
    selected_hash = hashlib.sha256(selected_path.read_bytes()).hexdigest()
    digest = config_hash(config)
    _atomic_replace(directory / "source-config.yaml", lambda temporary: shutil.copyfile(config_path, temporary))
    write_json_atomic(directory / "resolved-config.json", sanitize_metadata(config.serializable()))
    write_text_atomic(directory / "config.sha256", digest + "\n")
    manifest = dict(run_manifest)
    manifest["config_sha256"] = digest
    manifest["selected_record_manifest_sha256"] = selected_hash
    manifest["output_state"] = plan.state.value
    write_json_atomic(directory / "run-manifest.json", sanitize_metadata(manifest))
    return digest, selected_hash


def write_training_artifacts(
    output: str | Path,
    *,
    environment: Mapping[str, Any],
    lora_targets: Mapping[str, Any],
    trainable_parameters: Mapping[str, Any],
    adapter_metadata: Mapping[str, Any] | None = None,
    metrics: Mapping[str, Any] | None = None,
) -> None:
    directory = Path(output)
    write_json_atomic(directory / "environment.json", sanitize_metadata(environment))
    write_json_atomic(directory / "lora-targets.json", sanitize_metadata(lora_targets))
    write_json_atomic(directory / "trainable-parameters.json", sanitize_metadata(trainable_parameters))
    if adapter_metadata is not None:
        write_json_atomic(directory / "adapter-metadata.json", sanitize_metadata(adapter_metadata))
    if metrics is not None:
        write_json_atomic(directory / "metrics.json", sanitize_metadata(metrics))


def update_lifecycle(output: str | Path, status: str, **fields: Any) -> dict[str, Any]:
    if status not in {"prepared", "running", "completed", "failed"}:
        raise ValueError(f"Invalid lifecycle status: {status!r}")
    path = Path(output) / "run-manifest.json"
    manifest = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {"schema_version": RUN_MANIFEST_SCHEMA}
    manifest.update(sanitize_metadata(fields))
    manifest["status"] = status
    manifest["updated_at"] = utc_now()
    if status in {"completed", "failed"}:
        manifest.setdefault("end_time", utc_now())
    write_json_atomic(path, manifest)
    return manifest
