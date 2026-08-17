from __future__ import annotations

import pytest
import torch

from training.pipeline.attention_compressor import (
    AttentionCompressorConfig,
    LearnedAttentionCompressor,
    build_attention_compressor,
)


def test_attention_compressor_is_disabled_by_default() -> None:
    config = AttentionCompressorConfig.from_mapping()

    assert config.enabled is False
    assert build_attention_compressor(config) is None


def test_attention_compressor_shapes_and_padding() -> None:
    torch.manual_seed(7)
    config = AttentionCompressorConfig(
        enabled=True, embedding_dim=12, compressed_tokens=3, num_heads=3
    )
    compressor = build_attention_compressor(config)
    assert isinstance(compressor, LearnedAttentionCompressor)
    embeddings = torch.randn(2, 5, 12)
    mask = torch.tensor([[True, True, True, False, False], [True, True, True, True, True]])

    output = compressor(embeddings, mask)

    assert output.embeddings.shape == (2, 3, 12)
    assert output.mask.shape == (2, 3)
    assert output.mask.all()
    assert output.attention_weights.shape == (2, 3, 3, 5)
    assert torch.allclose(
        output.attention_weights[0, :, :, 3:],
        torch.zeros(3, 3, 2),
        atol=1e-7,
    )


def test_attention_compressor_backpropagates() -> None:
    config = AttentionCompressorConfig(
        enabled=True, embedding_dim=8, compressed_tokens=2, num_heads=2
    )
    compressor = LearnedAttentionCompressor(config)
    embeddings = torch.randn(1, 4, 8, requires_grad=True)

    compressor(embeddings, torch.ones(1, 4, dtype=torch.bool)).embeddings.sum().backward()

    assert embeddings.grad is not None
    assert compressor.queries.grad is not None


def test_attention_compressor_rejects_empty_apk_bag() -> None:
    config = AttentionCompressorConfig(
        enabled=True, embedding_dim=8, compressed_tokens=2, num_heads=2
    )
    compressor = LearnedAttentionCompressor(config)

    with pytest.raises(ValueError, match="at least one artifact"):
        compressor(torch.randn(1, 3, 8), torch.zeros(1, 3, dtype=torch.bool))


@pytest.mark.parametrize(
    "values",
    [
        {"embedding_dim": 7, "num_heads": 2},
        {"compressed_tokens": 0},
        {"dropout": 1.0},
    ],
)
def test_attention_compressor_validates_configuration(values: dict[str, object]) -> None:
    with pytest.raises(ValueError):
        AttentionCompressorConfig.from_mapping(values)
