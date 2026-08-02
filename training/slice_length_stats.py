from __future__ import annotations

import csv
import sys
from pathlib import Path

import numpy as np
from transformers import AutoTokenizer


TRAINING_DIR = Path(__file__).resolve().parent
REPO_ROOT = TRAINING_DIR.parent
sys.path.insert(0, str(REPO_ROOT))

from kavach_ai.backend.pipeline.stage2_static.decompile import extract_apk
from kavach_ai.backend.pipeline.stage3_ml.slicing import slice_extraction_result


MODEL_NAME = "cisco-ai/SecureBERT2.0-base"
DATA_DIR = REPO_ROOT / "data"
SLICE_CSV = TRAINING_DIR / "slice_length_stats.csv"
APK_CSV = TRAINING_DIR / "slice_length_apk_status.csv"
THRESHOLDS = (512, 1024, 2048, 4096, 8192)


def slice_text(program_slice) -> str:
    return "\n".join(
        item.instruction.raw_text
        for item in program_slice.retained_instructions
    )


def print_statistics(lengths: list[int]) -> None:
    values = np.asarray(lengths, dtype=np.int64)
    print("\nToken-length statistics")
    print(f"count:  {values.size}")
    if values.size == 0:
        return

    print(f"mean:   {values.mean():.2f}")
    print(f"median: {np.median(values):.2f}")
    for percentile in (90, 95, 99):
        print(f"p{percentile}:     {np.percentile(values, percentile):.2f}")
    print(f"max:    {values.max()}")
    for threshold in THRESHOLDS:
        percentage = 100 * np.count_nonzero(values > threshold) / values.size
        print(f"% > {threshold}: {percentage:.2f}%")


def main() -> None:
    tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)
    apks = sorted(
        apk
        for label in ("Benign", "Malicious")
        for apk in (DATA_DIR / label).glob("*.apk")
    )

    lengths: list[int] = []
    truncated_count = 0
    failed_count = 0
    zero_slice_count = 0

    with SLICE_CSV.open("w", newline="", encoding="utf-8") as slice_file, APK_CSV.open(
        "w", newline="", encoding="utf-8"
    ) as apk_file:
        slice_writer = csv.DictWriter(
            slice_file,
            fieldnames=(
                "apk_path",
                "class_label",
                "slice_index",
                "sink_rule",
                "token_count",
                "is_truncated",
            ),
        )
        apk_writer = csv.DictWriter(
            apk_file,
            fieldnames=("apk_path", "class_label", "status", "slice_count", "error"),
        )
        slice_writer.writeheader()
        apk_writer.writeheader()

        for apk_number, apk_path in enumerate(apks, start=1):
            label = apk_path.parent.name
            print(f"[{apk_number}/{len(apks)}] {label}/{apk_path.name}", flush=True)
            try:
                extraction = extract_apk(apk_path)
                slicing = slice_extraction_result(extraction)
            except Exception as exc:
                failed_count += 1
                apk_writer.writerow(
                    {
                        "apk_path": str(apk_path.relative_to(REPO_ROOT)),
                        "class_label": label,
                        "status": "failed",
                        "slice_count": 0,
                        "error": f"{type(exc).__name__}: {exc}",
                    }
                )
                apk_file.flush()
                continue

            if not slicing.slices:
                zero_slice_count += 1

            for slice_index, program_slice in enumerate(slicing.slices):
                # add_special_tokens defaults to True; truncation is explicitly disabled.
                token_count = len(
                    tokenizer(
                        slice_text(program_slice),
                        padding=False,
                        truncation=False,
                    )["input_ids"]
                )
                lengths.append(token_count)
                truncated_count += int(program_slice.truncated)
                slice_writer.writerow(
                    {
                        "apk_path": str(apk_path.relative_to(REPO_ROOT)),
                        "class_label": label,
                        "slice_index": slice_index,
                        "sink_rule": program_slice.sink.rule_id,
                        "token_count": token_count,
                        "is_truncated": program_slice.truncated,
                    }
                )

            slice_file.flush()
            apk_writer.writerow(
                {
                    "apk_path": str(apk_path.relative_to(REPO_ROOT)),
                    "class_label": label,
                    "status": extraction.status.value,
                    "slice_count": len(slicing.slices),
                    "error": "",
                }
            )
            apk_file.flush()

    with SLICE_CSV.open(newline="", encoding="utf-8") as file:
        csv_slice_count = sum(1 for _ in csv.DictReader(file))
    if csv_slice_count != len(lengths):
        raise RuntimeError(
            f"CSV contains {csv_slice_count} slices, but {len(lengths)} were measured."
        )

    print_statistics(lengths)
    print(f"\ntruncated slices:     {truncated_count}")
    print(f"non-truncated slices: {len(lengths) - truncated_count}")
    print(f"failed APKs:          {failed_count}")
    print(f"zero-slice APKs:      {zero_slice_count}")
    print(f"slice CSV:            {SLICE_CSV}")
    print(f"APK status CSV:       {APK_CSV}")


if __name__ == "__main__":
    main()
