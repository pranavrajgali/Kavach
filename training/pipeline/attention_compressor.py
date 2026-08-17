"""Optional learned compression for APK-level artifact embeddings.

This is experimental Stage-1B scaffolding.  It is deliberately independent of
the V2 extractor and is disabled unless a caller explicitly constructs it with
``enabled=True``.  Corpus measurements must determine whether it is useful.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

import torch
from torch import nn


@dataclass(frozen=True)
class AttentionCompressorConfig:
    enabled: bool = False
    embedding_dim: int = 768
    compressed_tokens: int = 8
    num_heads: int = 8
    dropout: float = 0.0

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any] | None = None) -> "AttentionCompressorConfig":
        config = cls(**dict(value or {}))
        config.validate()
        return config

    def validate(self) -> None:
        if self.embedding_dim <= 0 or self.compressed_tokens <= 0 or self.num_heads <= 0:
            raise ValueError("embedding_dim, compressed_tokens, and num_heads must be positive")
        if self.embedding_dim % self.num_heads:
            raise ValueError("embedding_dim must be divisible by num_heads")
        if not 0.0 <= self.dropout < 1.0:
            raise ValueError("dropout must be in [0, 1)")


@dataclass(frozen=True)
class CompressedArtifacts:
    embeddings: torch.Tensor
    mask: torch.Tensor
    attention_weights: torch.Tensor


class LearnedAttentionCompressor(nn.Module):
    """Compress a variable artifact bag with learned cross-attention queries."""

    def __init__(self, config: AttentionCompressorConfig) -> None:
        super().__init__()
        config.validate()
        if not config.enabled:
            raise ValueError("LearnedAttentionCompressor requires enabled=True")
        self.config = config
        self.queries = nn.Parameter(torch.empty(config.compressed_tokens, config.embedding_dim))
        self.attention = nn.MultiheadAttention(
            config.embedding_dim,
            config.num_heads,
            dropout=config.dropout,
            batch_first=True,
        )
        self.norm = nn.LayerNorm(config.embedding_dim)
        nn.init.normal_(self.queries, std=0.02)

    def forward(self, embeddings: torch.Tensor, mask: torch.Tensor) -> CompressedArtifacts:
        """Return fixed-size embeddings; ``mask=True`` denotes a real artifact."""
        if embeddings.ndim != 3:
            raise ValueError("embeddings must have shape [batch, artifacts, embedding_dim]")
        if mask.shape != embeddings.shape[:2] or mask.dtype != torch.bool:
            raise ValueError("mask must be boolean with shape [batch, artifacts]")
        if embeddings.shape[-1] != self.config.embedding_dim:
            raise ValueError("embedding dimension does not match compressor configuration")
        if (~mask).all(dim=1).any():
            raise ValueError("each APK bag must contain at least one artifact")

        queries = self.queries.unsqueeze(0).expand(embeddings.shape[0], -1, -1)
        compressed, weights = self.attention(
            queries,
            embeddings,
            embeddings,
            key_padding_mask=~mask,
            need_weights=True,
            average_attn_weights=False,
        )
        compressed = self.norm(compressed + queries)
        compressed_mask = torch.ones(
            compressed.shape[:2], dtype=torch.bool, device=compressed.device
        )
        return CompressedArtifacts(compressed, compressed_mask, weights)


def build_attention_compressor(
    config: AttentionCompressorConfig,
) -> LearnedAttentionCompressor | None:
    """Keep the experimental path inert unless explicitly enabled."""
    config.validate()
    return LearnedAttentionCompressor(config) if config.enabled else None
