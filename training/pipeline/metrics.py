"""Strict, dependency-light metrics for binary sequence classification."""

from __future__ import annotations

from typing import Any

import numpy as np


def _validated_predictions(value: Any) -> tuple[np.ndarray, np.ndarray]:
    if hasattr(value, "predictions") and hasattr(value, "label_ids"):
        predictions, labels = value.predictions, value.label_ids
    elif isinstance(value, (tuple, list)) and len(value) == 2:
        predictions, labels = value
    else:
        raise ValueError("metrics input must provide predictions and label_ids")
    if isinstance(predictions, tuple):
        if not predictions:
            raise ValueError("predictions tuple must not be empty")
        predictions = predictions[0]
    logits, labels = np.asarray(predictions), np.asarray(labels)
    if logits.ndim != 2 or logits.shape[1] != 2:
        raise ValueError(f"predictions must have shape (N, 2), got {logits.shape}")
    if labels.ndim != 1 or labels.shape[0] != logits.shape[0]:
        raise ValueError(f"labels must have shape ({logits.shape[0]},), got {labels.shape}")
    if logits.shape[0] == 0:
        raise ValueError("metrics require at least one example")
    if not np.issubdtype(logits.dtype, np.number) or not np.all(np.isfinite(logits)):
        raise ValueError("predictions must contain finite numbers")
    if labels.dtype.kind not in "biu" or not np.all(np.isin(labels, (0, 1))):
        raise ValueError("labels must contain only integer 0 (Benign) or 1 (Malicious)")
    return logits, labels.astype(np.int64, copy=False)


def binary_classification_metrics(eval_prediction: Any) -> dict[str, float | int]:
    """Return binary metrics, treating Malicious (label 1) as positive."""
    logits, labels = _validated_predictions(eval_prediction)
    predicted = np.argmax(logits, axis=1)
    tn = int(np.sum((labels == 0) & (predicted == 0)))
    fp = int(np.sum((labels == 0) & (predicted == 1)))
    fn = int(np.sum((labels == 1) & (predicted == 0)))
    tp = int(np.sum((labels == 1) & (predicted == 1)))

    def ratio(numerator: int, denominator: int) -> float:
        return float(numerator / denominator) if denominator else 0.0

    precision = ratio(tp, tp + fp)
    recall = ratio(tp, tp + fn)
    return {
        "accuracy": ratio(tp + tn, len(labels)),
        "precision": precision,
        "recall": recall,
        "f1": ratio(2.0 * precision * recall, precision + recall),
        "tn": tn,
        "fp": fp,
        "fn": fn,
        "tp": tp,
    }


compute_metrics = binary_classification_metrics
