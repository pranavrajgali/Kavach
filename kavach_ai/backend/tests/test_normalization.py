from __future__ import annotations

from dataclasses import replace

from kavach_ai.backend.pipeline.stage2_static.decompile import (
    ExtractedMethod,
    ExtractionBackend,
    Instruction,
    Label,
)
from kavach_ai.backend.pipeline.stage3_ml.normalization import (
    NORMALIZATION_VERSION,
    build_method_normalization_maps,
    register_example_identity,
    serialize_program_slice,
    stable_example_id,
)
from kavach_ai.backend.pipeline.stage3_ml.slicing import (
    BoundaryKind,
    MethodIdentity,
    ProgramSlice,
    RetainedInstruction,
    RetentionReason,
    SinkMatch,
    UnresolvedBoundary,
)


def _method() -> ExtractedMethod:
    instructions = (
        Instruction(0, None, "const/4", ("v9", "0x1"), "const/4 v9, 0x1"),
        Instruction(1, None, "const-string", ("v2", '"v9   :cond_7"'), 'const-string   v2,   "v9   :cond_7"'),
        Instruction(2, None, "if-eqz", ("v2", ":cond_7"), "if-eqz v2, :cond_7"),
        Instruction(3, None, "invoke-static", ("{v2}", "Lx/Y;->sink(Ljava/lang/String;)V"), "invoke-static {v2}, Lx/Y;->sink(Ljava/lang/String;)V"),
    )
    return ExtractedMethod(
        "classes.dex", "Lapp/Main;", "run", "()V", "Lapp/Main;->run()V",
        ("public", "static"), (), 10, 10, instructions,
        (Label(":cond_7", 3),), (), None, "fixture", ExtractionBackend.SMALI,
    )


def _slice(method: ExtractedMethod, *, sink_index: int = 3) -> ProgramSlice:
    identity = MethodIdentity(method.dex_name, method.full_signature)
    sink = SinkMatch(identity, sink_index, "fixture.sink", "test", "Lx/Y;->sink(Ljava/lang/String;)V")
    retained = tuple(
        RetainedInstruction(identity, item.index, item, (RetentionReason.DATA_DEPENDENCY,))
        for item in method.instructions[1:]
    )
    boundary = UnresolvedBoundary(BoundaryKind.EXTERNAL_CALL, identity, 3, "Lx/Y;->sink(Ljava/lang/String;)V")
    return ProgramSlice(sink, retained, (identity,), (boundary,), (), False)


def test_structural_normalization_uses_full_method_order_and_preserves_quotes() -> None:
    method = _method()
    text = serialize_program_slice(_slice(method), (method,))
    assert text.normalization_version == NORMALIZATION_VERSION
    assert text.raw_slice_text.startswith('const-string   v2,   "v9   :cond_7"')
    assert text.normalized_slice_text.splitlines() == [
        "[METHOD] Lapp/Main;->run()V",
        'const-string v1, "v9   :cond_7"',
        "if-eqz v1, :label_0",
        "invoke-static {v1}, Lx/Y;->sink(Ljava/lang/String;)V",
        "[BOUNDARY] kind=external_call target=Lx/Y;->sink(Ljava/lang/String;)V",
    ]


def test_normalization_and_example_identity_are_deterministic() -> None:
    method = _method()
    program_slice = _slice(method)
    assert serialize_program_slice(program_slice, (method,)) == serialize_program_slice(program_slice, (method,))
    first = stable_example_id("a" * 64, program_slice)
    assert first == stable_example_id("a" * 64, program_slice)
    assert first != stable_example_id("a" * 64, replace(program_slice, sink=replace(program_slice.sink, instruction_index=2)))
    assert serialize_program_slice(
        program_slice,
        (method,),
        method_maps=build_method_normalization_maps((method,)),
    ) == serialize_program_slice(program_slice, (method,))


def test_duplicate_identity_error_contains_both_canonical_records() -> None:
    first = {"rule_id": "one", "instruction_index": 1}
    second = {"rule_id": "two", "instruction_index": 2}
    identities: dict[str, dict[str, object]] = {}
    register_example_identity(identities, "duplicate", first)
    try:
        register_example_identity(identities, "duplicate", second)
    except ValueError as exc:
        message = str(exc)
    else:
        raise AssertionError("duplicate example ID was accepted")
    assert repr(first) in message
    assert repr(second) in message
