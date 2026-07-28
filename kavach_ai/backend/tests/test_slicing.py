from __future__ import annotations

from dataclasses import FrozenInstanceError, replace

import pytest

from kavach_ai.backend.pipeline.stage2_static.decompile import (
    DataPayload,
    ExceptionHandler,
    ExtractedMethod,
    ExtractionBackend,
    ExtractionResult,
    ExtractionStatus,
    Instruction,
    Label,
    MethodParameter,
    PayloadEntry,
    PayloadKind,
)
from kavach_ai.backend.pipeline.stage3_ml.slicing import (
    BoundaryKind,
    CfgEdgeKind,
    DEFAULT_SINK_RULES,
    MethodIdentity,
    RetentionReason,
    SinkRule,
    SliceIssueSeverity,
    SliceLimits,
    build_cfg,
    find_sinks,
    instruction_use_def,
    map_callee_parameter_dependencies,
    slice_extraction_result,
    slice_methods,
)


def ins(index: int, opcode: str, *operands: str, offset: int | None = None) -> Instruction:
    raw = f"{opcode} {', '.join(operands)}".rstrip()
    return Instruction(index, offset, opcode, tuple(operands), raw)


def method(
    signature: str = "Lapp/Main;->run()V",
    *,
    dex_name: str = "classes.dex",
    instructions: tuple[Instruction, ...] = (Instruction(0, None, "return-void", (), "return-void"),),
    labels: tuple[Label, ...] = (),
    handlers: tuple[ExceptionHandler, ...] = (),
    payloads: tuple[DataPayload, ...] = (),
    flags: tuple[str, ...] = ("public", "static"),
    parameters: tuple[MethodParameter, ...] = (),
    backend: ExtractionBackend = ExtractionBackend.SMALI,
) -> ExtractedMethod:
    class_name, tail = signature.split("->", 1)
    method_name, descriptor_tail = tail.split("(", 1)
    descriptor = f"({descriptor_tail}"
    return ExtractedMethod(
        dex_name=dex_name,
        class_name=class_name,
        method_name=method_name,
        descriptor=descriptor,
        full_signature=signature,
        access_flags=flags,
        parameters=parameters,
        register_count=8,
        local_count=4,
        instructions=instructions,
        labels=labels,
        exception_handlers=handlers,
        declared_source_file="Main.java",
        source_path=f"apk://hash!/{dex_name}",
        backend=backend,
        payloads=payloads,
    )


def result(methods: tuple[ExtractedMethod, ...]) -> ExtractionResult:
    return ExtractionResult(
        apk_path="/tmp/input.apk",
        apk_hash="a" * 64,
        artifact_path="/tmp/artifacts",
        dex_files=(),
        methods=methods,
        native_libraries=(),
        apktool_output_path="/tmp/artifacts/apktool",
        jadx_output_path="/tmp/artifacts/jadx",
        raw_dex_output_path="/tmp/artifacts/raw_dex",
        native_output_path="/tmp/artifacts/native",
        backend_used=ExtractionBackend.SMALI,
        apktool_execution=None,
        jadx_execution=None,
        raw_dex_fallback_used=False,
        status=ExtractionStatus.SUCCESS,
        issues=(),
    )


SINK = "Ljava/lang/Runtime;->exec(Ljava/lang/String;)Ljava/lang/Process;"


def sink_method(
    *,
    signature: str = "Lapp/Main;->run()V",
    prefix: tuple[Instruction, ...] = (),
    invoke_opcode: str = "invoke-virtual",
) -> ExtractedMethod:
    index = len(prefix)
    return method(
        signature,
        instructions=prefix
        + (
            ins(index, invoke_opcode, "{v0, v1}", SINK),
            ins(index + 1, "return-void"),
        ),
    )


def test_contracts_are_immutable_ordered_and_limits_validate() -> None:
    first = MethodIdentity("classes.dex", "LA;->a()V")
    second = MethodIdentity("classes2.dex", "LA;->a()V")
    assert first < second
    with pytest.raises(FrozenInstanceError):
        first.dex_name = "changed.dex"  # type: ignore[misc]
    with pytest.raises(ValueError):
        MethodIdentity("", "LA;->a()V")
    with pytest.raises(ValueError):
        SliceLimits(max_traversal_states=0)
    assert SliceLimits().max_traversal_states == 4096


def test_default_sink_catalogue_has_all_required_categories() -> None:
    categories = {rule.category for rule in DEFAULT_SINK_RULES}
    assert categories == {
        "accessibility",
        "class_loader",
        "execution",
        "native_loading",
        "reflection",
        "sms",
    }
    assert tuple(sorted(DEFAULT_SINK_RULES)) == DEFAULT_SINK_RULES


def test_sink_matching_optional_descriptor_false_positive_and_order() -> None:
    exact = SinkRule("exact", "test", "Lx/C;", "call", "(I)V")
    overload = SinkRule("overload", "test", "Lx/C;", "other")
    body = method(
        instructions=(
            ins(0, "invoke-static", "{v0}", "Lx/C;->other(Ljava/lang/String;)V"),
            ins(1, "invoke-static", "{v0}", "Lx/C;->call(Ljava/lang/String;)V"),
            ins(2, "invoke-static", "{v0}", "Lx/C;->call(I)V"),
            ins(3, "return-void"),
        )
    )
    matches = find_sinks((body,), (exact, overload))
    assert [(item.instruction_index, item.rule_id) for item in matches] == [
        (0, "overload"),
        (2, "exact"),
    ]


def test_find_sinks_scans_only_usable_bodies_and_is_multidex_deterministic() -> None:
    native = replace(sink_method(), access_flags=("native",), instructions=())
    second = replace(sink_method(), dex_name="classes2.dex")
    first = sink_method()
    matches = find_sinks((second, native, first))
    assert [item.method.dex_name for item in matches] == ["classes.dex", "classes2.dex"]


def test_cfg_fallthrough_conditional_goto_and_termination() -> None:
    body = method(
        instructions=(
            ins(0, "const/4", "v0", "0x0"),
            ins(1, "if-eqz", "v0", ":yes"),
            ins(2, "goto", ":end"),
            ins(3, "return-void"),
        ),
        labels=(Label(":yes", 3), Label(":end", 3)),
    )
    cfg = build_cfg(body)
    edges = {(edge.source_index, edge.target_index, edge.kind) for edge in cfg.edges}
    assert (0, 1, CfgEdgeKind.FALLTHROUGH) in edges
    assert (1, 2, CfgEdgeKind.FALLTHROUGH) in edges
    assert (1, 3, CfgEdgeKind.BRANCH) in edges
    assert (2, 3, CfgEdgeKind.GOTO) in edges
    assert not any(edge.source_index == 3 for edge in cfg.edges)


@pytest.mark.parametrize(
    ("kind", "opcode"),
    [
        (PayloadKind.PACKED_SWITCH, "packed-switch"),
        (PayloadKind.SPARSE_SWITCH, "sparse-switch"),
    ],
)
def test_cfg_switch_payload_and_default_edges(kind: PayloadKind, opcode: str) -> None:
    payload = DataPayload(
        ":payload",
        kind,
        (
            PayloadEntry(0, ":case0", None, ":case0"),
            PayloadEntry(1, ":case1", None, ":case1"),
        ),
        "payload",
        "fixture",
    )
    body = method(
        instructions=(
            ins(0, opcode, "v0", ":payload"),
            ins(1, "return-void"),
            ins(2, "return-void"),
            ins(3, "return-void"),
        ),
        labels=(Label(":payload", None), Label(":case0", 2), Label(":case1", 3)),
        payloads=(payload,),
    )
    cfg = build_cfg(body)
    assert {(edge.target_index, edge.kind) for edge in cfg.edges if edge.source_index == 0} == {
        (1, CfgEdgeKind.FALLTHROUGH),
        (2, CfgEdgeKind.SWITCH),
        (3, CfgEdgeKind.SWITCH),
    }


def test_cfg_exception_edges_and_catchall() -> None:
    body = method(
        instructions=(
            ins(0, "const/4", "v0", "0"),
            ins(1, "throw", "v0"),
            ins(2, "return-void"),
        ),
        labels=(Label(":start", 0), Label(":end", 2), Label(":handler", 2)),
        handlers=(
            ExceptionHandler(None, ":start", ":end", ":handler", ".catchall {...}"),
        ),
    )
    cfg = build_cfg(body)
    exception_sources = {
        edge.source_index for edge in cfg.edges if edge.kind is CfgEdgeKind.EXCEPTION
    }
    assert exception_sources == {0, 1}


def test_cfg_unresolved_target_is_warning_and_graph_remains_usable() -> None:
    cfg = build_cfg(method(instructions=(ins(0, "goto", ":missing"),)))
    assert cfg.nodes == (0,)
    assert cfg.issues[0].code == "CFG_UNRESOLVED_TARGET"
    assert cfg.issues[0].severity is SliceIssueSeverity.WARNING


def test_cfg_unusable_body_is_error() -> None:
    declaration = method(flags=("abstract",), instructions=())
    cfg = build_cfg(declaration)
    assert cfg.issues[0].code == "CFG_NO_USABLE_GRAPH"
    assert cfg.issues[0].severity is SliceIssueSeverity.ERROR


@pytest.mark.parametrize(
    ("instruction", "uses", "definitions"),
    [
        (ins(0, "move", "v0", "v1"), {"v1"}, {"v0"}),
        (ins(0, "const-string", "v0", '"x"'), set(), {"v0"}),
        (ins(0, "add-int", "v0", "v1", "v2"), {"v1", "v2"}, {"v0"}),
        (ins(0, "iget", "v0", "v1", "LA;->f:I"), {"v1", "field:LA;->f:I"}, {"v0"}),
        (ins(0, "iput", "v0", "v1", "LA;->f:I"), {"v0", "v1"}, {"field:LA;->f:I"}),
        (
            ins(0, "aget", "v0", "v1", "v2"),
            {"v1", "v2", "array:v1"},
            {"v0"},
        ),
        (ins(0, "aput", "v0", "v1", "v2"), {"v0", "v1", "v2"}, {"array:v1"}),
        (ins(0, "if-eq", "v0", "v1", ":x"), {"v0", "v1"}, set()),
        (ins(0, "return", "v0"), {"v0"}, set()),
        (ins(0, "monitor-enter", "v0"), {"v0"}, set()),
    ],
)
def test_use_def_instruction_families(
    instruction: Instruction, uses: set[str], definitions: set[str]
) -> None:
    value = instruction_use_def(instruction)
    assert value.uses == frozenset(uses)
    assert value.definitions == frozenset(definitions)
    assert not value.unknown_opcode


def test_use_def_invoke_range_and_move_result_pairing() -> None:
    invoke = ins(0, "invoke-static/range", "{v2 .. v5}", "LX;->f()I")
    invoke_ud = instruction_use_def(invoke)
    assert invoke_ud.uses == frozenset({"v2", "v3", "v4", "v5"})
    assert "result:LX;->f()I" in invoke_ud.definitions
    moved = instruction_use_def(ins(1, "move-result", "v0"), invoke)
    assert moved.definitions == frozenset({"v0"})
    assert moved.uses == frozenset({"result:LX;->f()I"})


def test_use_def_two_address_cast_and_filled_array_pairing() -> None:
    two_address = instruction_use_def(ins(0, "add-int/2addr", "v0", "v1"))
    assert two_address.uses == frozenset({"v0", "v1"})
    assert two_address.definitions == frozenset({"v0"})
    cast = instruction_use_def(ins(0, "check-cast", "v2", "Ljava/lang/String;"))
    assert cast.uses == cast.definitions == frozenset({"v2"})
    filled = ins(0, "filled-new-array", "{v1, v2}", "[I")
    moved = instruction_use_def(ins(1, "move-result-object", "v0"), filled)
    assert instruction_use_def(filled).uses == frozenset({"v1", "v2"})
    assert moved.uses == frozenset({"result:filled-new-array"})
    assert not instruction_use_def(ins(0, "fill-array-data", "v0", ":data")).unknown_opcode


@pytest.mark.parametrize(
    "opcode",
    [
        "int-to-long",
        "long-to-int",
        "float-to-double",
        "double-to-float",
        "int-to-byte",
        "int-to-char",
        "int-to-short",
        "add-int/lit8",
        "add-int/lit16",
        "rsub-int",
        "rsub-int/lit8",
        "mul-int/lit8",
        "div-int/lit16",
        "and-int/lit8",
        "or-int/lit16",
        "xor-int/lit8",
        "shl-int/lit8",
        "shr-int/lit8",
        "ushr-int/lit8",
        "cmpl-float",
        "cmpg-double",
        "cmp-long",
        "neg-int",
        "not-long",
    ],
)
def test_common_conversion_literal_comparison_and_unary_opcodes(
    opcode: str,
) -> None:
    parsed = instruction_use_def(ins(0, opcode, "v0", "v1", "0x2"))
    assert parsed.definitions == frozenset({"v0"})
    assert parsed.uses == frozenset({"v1"})
    assert not parsed.unknown_opcode


def test_array_symbolic_flow_retains_write_read_and_value_definition() -> None:
    body = method(
        instructions=(
            ins(0, "const-string", "v1", '"secret"'),
            ins(1, "const/4", "v2", "0x0"),
            ins(2, "aput-object", "v1", "v0", "v2"),
            ins(3, "const-string", "v9", '"unrelated"'),
            ins(4, "const/4", "v8", "0x0"),
            ins(5, "aput-object", "v9", "v7", "v8"),
            ins(6, "aget-object", "v3", "v0", "v2"),
            ins(7, "invoke-virtual", "{v4, v3}", SINK),
            ins(8, "return-void"),
        )
    )
    retained = {
        item.instruction_index
        for item in slice_methods((body,)).slices[0].retained_instructions
    }
    assert {0, 1, 2, 6, 7} <= retained
    assert {3, 4, 5}.isdisjoint(retained)


def test_field_symbolic_flow_for_instance_and_static_fields() -> None:
    instance_field = "Lapp/State;->value:Ljava/lang/String;"
    static_field = "Lapp/State;->global:Ljava/lang/String;"
    body = method(
        instructions=(
            ins(0, "const-string", "v1", '"instance"'),
            ins(1, "iput-object", "v1", "v0", instance_field),
            ins(2, "iget-object", "v2", "v0", instance_field),
            ins(3, "const-string", "v3", '"static"'),
            ins(4, "sput-object", "v3", static_field),
            ins(5, "sget-object", "v4", static_field),
            ins(6, "invoke-virtual", "{v5, v2}", SINK),
            ins(7, "invoke-virtual", "{v5, v4}", SINK),
            ins(8, "return-void"),
        )
    )
    sliced = slice_methods((body,))
    first = {item.instruction_index for item in sliced.slices[0].retained_instructions}
    second = {item.instruction_index for item in sliced.slices[1].retained_instructions}
    assert {0, 1, 2, 6} <= first
    assert {3, 4, 5, 7} <= second


def test_descriptor_aware_parameter_mapping_instance_and_static() -> None:
    instance = method(
        "Lapp/H;->instance(Ljava/lang/String;)V",
        flags=("public",),
        parameters=(MethodParameter(0, "Ljava/lang/String;", "p1"),),
    )
    instance_call = ins(
        0,
        "invoke-direct",
        "{v9, v2}",
        instance.full_signature,
    )
    assert map_callee_parameter_dependencies(
        instance, instance_call, ("p0",)
    ) == frozenset({"v9"})
    assert map_callee_parameter_dependencies(
        instance, instance_call, ("p1",)
    ) == frozenset({"v2"})

    static = method(
        "Lapp/H;->staticCall(Ljava/lang/String;)V",
        flags=("public", "static"),
        parameters=(MethodParameter(0, "Ljava/lang/String;", "p0"),),
    )
    static_call = ins(0, "invoke-static", "{v6}", static.full_signature)
    assert map_callee_parameter_dependencies(
        static, static_call, ("p0",)
    ) == frozenset({"v6"})


def test_descriptor_aware_parameter_mapping_wide_and_range_registers() -> None:
    wide = method(
        "Lapp/H;->wide(JLjava/lang/String;)V",
        flags=("public", "static"),
        parameters=(
            MethodParameter(0, "J", "p0"),
            MethodParameter(1, "Ljava/lang/String;", "p2"),
        ),
    )
    range_call = ins(0, "invoke-static/range", "{v3 .. v5}", wide.full_signature)
    assert map_callee_parameter_dependencies(
        wide, range_call, ("p0",)
    ) == frozenset({"v3", "v4"})
    assert map_callee_parameter_dependencies(
        wide, range_call, ("p1",)
    ) == frozenset({"v3", "v4"})
    assert map_callee_parameter_dependencies(
        wide, range_call, ("p2",)
    ) == frozenset({"v5"})

    double_instance = method(
        "Lapp/H;->doubleValue(DLjava/lang/Object;)V",
        flags=("public",),
        parameters=(
            MethodParameter(0, "D", "p1"),
            MethodParameter(1, "Ljava/lang/Object;", "p3"),
        ),
    )
    call = ins(
        0,
        "invoke-direct",
        "{v0, v4, v5, v8}",
        double_instance.full_signature,
    )
    assert map_callee_parameter_dependencies(
        double_instance, call, ("p2",)
    ) == frozenset({"v4", "v5"})
    assert map_callee_parameter_dependencies(
        double_instance, call, ("p3",)
    ) == frozenset({"v8"})


def test_unknown_opcodes_aggregate_once_with_counts_per_run() -> None:
    body = sink_method(
        prefix=(
            ins(0, "mystery-op", "v1"),
            ins(1, "mystery-op", "v1"),
        )
    )
    sliced = slice_methods((body,))
    diagnostics = [issue for issue in sliced.issues if issue.code == "UNKNOWN_OPCODE"]
    assert len(diagnostics) == 1
    assert diagnostics[0].opcode == "mystery-op"
    assert diagnostics[0].occurrence_count == 2
    assert sliced.metrics.unknown_opcodes == (("mystery-op", 2),)


def test_straight_line_slice_keeps_definitions_and_drops_unrelated_code() -> None:
    body = sink_method(
        prefix=(
            ins(0, "const-string", "v1", '"command"'),
            ins(1, "const-string", "v7", '"unrelated"'),
        )
    )
    program_slice = slice_methods((body,)).slices[0]
    retained = {item.instruction_index for item in program_slice.retained_instructions}
    assert retained == {0, 2}
    assert next(
        item for item in program_slice.retained_instructions if item.instruction_index == 2
    ).reasons == (RetentionReason.DATA_DEPENDENCY, RetentionReason.SINK)


def test_control_dependency_fixed_point_retains_branch_and_its_definition() -> None:
    body = method(
        instructions=(
            ins(0, "const/4", "v2", "0x1"),
            ins(1, "if-eqz", "v2", ":sink"),
            ins(2, "return-void"),
            ins(3, "const-string", "v1", '"cmd"'),
            ins(4, "invoke-virtual", "{v0, v1}", SINK),
            ins(5, "return-void"),
        ),
        labels=(Label(":sink", 3),),
    )
    program_slice = slice_methods((body,)).slices[0]
    retained = {item.instruction_index for item in program_slice.retained_instructions}
    assert {0, 1, 3, 4} <= retained
    branch = next(
        item for item in program_slice.retained_instructions if item.instruction_index == 1
    )
    assert RetentionReason.CONTROL_DEPENDENCY in branch.reasons


def test_unrelated_branch_that_cannot_reach_slice_is_excluded() -> None:
    body = method(
        instructions=(
            ins(0, "const/4", "v5", "0x1"),
            ins(1, "if-eqz", "v5", ":dead"),
            ins(2, "return-void"),
            ins(3, "return-void"),
            ins(4, "const-string", "v1", '"cmd"'),
            ins(5, "invoke-virtual", "{v0, v1}", SINK),
            ins(6, "return-void"),
        ),
        labels=(Label(":dead", 3),),
    )
    retained = {
        item.instruction_index
        for item in slice_methods((body,)).slices[0].retained_instructions
    }
    assert {4, 5} <= retained
    assert {0, 1}.isdisjoint(retained)


def test_cfg_loop_terminates_with_deterministic_state_limit() -> None:
    body = method(
        instructions=(
            ins(0, "const/4", "v2", "0x2"),
            ins(1, "add-int/lit8", "v2", "v2", "-0x1"),
            ins(2, "if-nez", "v2", ":loop"),
            ins(3, "const-string", "v1", '"cmd"'),
            ins(4, "invoke-virtual", "{v0, v1}", SINK),
            ins(5, "return-void"),
        ),
        labels=(Label(":loop", 1),),
    )
    first = slice_methods(
        (body,), limits=SliceLimits(max_traversal_states=20)
    )
    second = slice_methods(
        (body,), limits=SliceLimits(max_traversal_states=20)
    )
    assert first == second
    assert first.metrics.traversal_states <= 20


def test_multiple_sinks_produce_independent_slices() -> None:
    body = method(
        instructions=(
            ins(0, "invoke-virtual", "{v0, v1}", SINK),
            ins(1, "invoke-virtual", "{v0, v2}", SINK),
            ins(2, "return-void"),
        )
    )
    sliced = slice_methods((body,))
    assert len(sliced.sinks) == len(sliced.slices) == 2


@pytest.mark.parametrize("opcode", ["invoke-static", "invoke-direct"])
def test_exact_static_and_direct_calls_trace_callee_returns(opcode: str) -> None:
    callee_signature = "Lapp/Helper;->command()Ljava/lang/String;"
    callee = method(
        callee_signature,
        instructions=(
            ins(0, "const-string", "v0", '"id"'),
            ins(1, "return-object", "v0"),
        ),
    )
    caller = sink_method(
        prefix=(
            ins(0, opcode, "{}", callee_signature),
            ins(1, "move-result-object", "v1"),
        )
    )
    program_slice = slice_methods((caller, callee)).slices[0]
    assert MethodIdentity("classes.dex", callee_signature) in program_slice.involved_methods
    assert any(
        item.method.full_signature == callee_signature
        and item.instruction_index == 0
        for item in program_slice.retained_instructions
    )


def test_local_call_multiple_returns_are_traced_conservatively() -> None:
    callee_signature = "Lapp/Helper;->command(Z)Ljava/lang/String;"
    callee = method(
        callee_signature,
        parameters=(MethodParameter(0, "Z", "p0"),),
        instructions=(
            ins(0, "if-eqz", "p0", ":second"),
            ins(1, "const-string", "v0", '"first"'),
            ins(2, "return-object", "v0"),
            ins(3, "const-string", "v1", '"second"'),
            ins(4, "return-object", "v1"),
        ),
        labels=(Label(":second", 3),),
    )
    caller = sink_method(
        prefix=(
            ins(0, "const/4", "v3", "0x1"),
            ins(1, "invoke-static", "{v3}", callee_signature),
            ins(2, "move-result-object", "v1"),
        )
    )
    retained = {
        item.instruction.raw_text
        for item in slice_methods((caller, callee)).slices[0].retained_instructions
    }
    assert any('"first"' in text for text in retained)
    assert any('"second"' in text for text in retained)


def test_malformed_separated_move_result_is_recoverable_and_not_truncated() -> None:
    body = method(
        instructions=(
            ins(
                0,
                "invoke-static",
                "{v1}",
                "Lexternal/X;->value(Ljava/lang/String;)Ljava/lang/String;",
            ),
            ins(1, "nop"),
            ins(2, "move-result-object", "v2"),
            ins(3, "invoke-virtual", "{v0, v2}", SINK),
            ins(4, "return-void"),
        )
    )
    sliced = slice_methods((body,))
    assert any(issue.code == "MALFORMED_MOVE_RESULT" for issue in sliced.issues)
    assert not sliced.slices[0].truncated


def test_void_invoke_has_no_result_dependency() -> None:
    void_call = ins(0, "invoke-static", "{v1}", "Lexternal/X;->run()V")
    assert instruction_use_def(void_call).definitions == frozenset()
    moved = instruction_use_def(ins(1, "move-result-object", "v2"), void_call)
    assert moved.uses == frozenset()


@pytest.mark.parametrize(
    ("declaration", "boundary_kind"),
    [
        (None, BoundaryKind.EXTERNAL_CALL),
        (
            method(
                "Lapp/N;->value(Ljava/lang/String;)Ljava/lang/String;",
                flags=("public", "static", "native"),
                parameters=(MethodParameter(0, "Ljava/lang/String;", "p0"),),
                instructions=(),
            ),
            BoundaryKind.NATIVE_METHOD,
        ),
    ],
)
def test_external_and_native_returning_calls_preserve_caller_arguments(
    declaration: ExtractedMethod | None,
    boundary_kind: BoundaryKind,
) -> None:
    target = (
        declaration.full_signature
        if declaration is not None
        else "Lexternal/X;->value(Ljava/lang/String;)Ljava/lang/String;"
    )
    caller = sink_method(
        prefix=(
            ins(0, "const-string", "v4", '"argument"'),
            ins(1, "invoke-static", "{v4}", target),
            ins(2, "move-result-object", "v1"),
        )
    )
    methods = (caller,) if declaration is None else (caller, declaration)
    program_slice = slice_methods(methods).slices[0]
    assert any(
        item.instruction_index == 0
        and item.method.full_signature == caller.full_signature
        for item in program_slice.retained_instructions
    )
    assert any(
        boundary.kind is boundary_kind
        for boundary in program_slice.unresolved_boundaries
    )
    assert not program_slice.truncated


def test_super_requires_exactly_one_match() -> None:
    signature = "Lbase/A;->value()Ljava/lang/String;"
    declarations = (
        method(signature, dex_name="classes.dex"),
        method(signature, dex_name="classes2.dex"),
    )
    caller = sink_method(
        prefix=(
            ins(0, "invoke-super", "{p0}", signature),
            ins(1, "move-result-object", "v1"),
        )
    )
    program_slice = slice_methods((caller, *declarations)).slices[0]
    assert any(
        boundary.kind is BoundaryKind.UNRESOLVED_LOCAL_CALL
        for boundary in program_slice.unresolved_boundaries
    )


@pytest.mark.parametrize("opcode", ["invoke-virtual", "invoke-interface"])
def test_virtual_and_interface_calls_are_boundaries(opcode: str) -> None:
    target = "Lapp/Local;->value()Ljava/lang/String;"
    callee = method(target)
    caller = sink_method(
        prefix=(
            ins(0, opcode, "{v0}", target),
            ins(1, "move-result-object", "v1"),
        )
    )
    program_slice = slice_methods((caller, callee)).slices[0]
    assert any(
        boundary.kind is BoundaryKind.VIRTUAL_DISPATCH
        and boundary.target_signature == target
        for boundary in program_slice.unresolved_boundaries
    )
    assert MethodIdentity("classes.dex", target) not in program_slice.involved_methods
    assert not program_slice.truncated


@pytest.mark.parametrize(
    ("target_method", "expected"),
    [
        (
            method(
                "Lapp/N;->call()Ljava/lang/String;",
                flags=("public", "native"),
                instructions=(),
            ),
            BoundaryKind.NATIVE_METHOD,
        ),
        (
            method(
                "Lapp/A;->call()Ljava/lang/String;",
                flags=("public", "abstract"),
                instructions=(),
            ),
            BoundaryKind.UNRESOLVED_LOCAL_CALL,
        ),
    ],
)
def test_declaration_based_native_and_local_boundaries(
    target_method: ExtractedMethod, expected: BoundaryKind
) -> None:
    caller = sink_method(
        prefix=(
            ins(0, "invoke-static", "{}", target_method.full_signature),
            ins(1, "move-result-object", "v1"),
        )
    )
    boundaries = slice_methods((caller, target_method)).slices[0].unresolved_boundaries
    assert any(boundary.kind is expected for boundary in boundaries)


def test_external_boundary_uses_absence_of_declaration() -> None:
    target = "Lunknown/X;->call()Ljava/lang/String;"
    caller = sink_method(
        prefix=(
            ins(0, "invoke-static", "{}", target),
            ins(1, "move-result-object", "v1"),
        )
    )
    program_slice = slice_methods((caller,)).slices[0]
    assert any(
        item.kind is BoundaryKind.EXTERNAL_CALL
        for item in program_slice.unresolved_boundaries
    )
    assert not program_slice.truncated


def test_unresolved_cfg_target_is_structured_without_truncating_slice() -> None:
    body = method(
        instructions=(
            ins(0, "goto", ":missing"),
            ins(1, "const-string", "v1", '"cmd"'),
            ins(2, "invoke-virtual", "{v0, v1}", SINK),
            ins(3, "return-void"),
        )
    )
    sliced = slice_methods((body,))
    assert any(issue.code == "CFG_UNRESOLVED_TARGET" for issue in sliced.issues)
    assert not sliced.slices[0].truncated


def test_reflection_is_both_sink_and_boundary() -> None:
    reflection = method(
        instructions=(
            ins(
                0,
                "invoke-virtual",
                "{v0, v1, v2}",
                "Ljava/lang/reflect/Method;->invoke"
                "(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;",
            ),
            ins(1, "return-void"),
        )
    )
    sliced = slice_methods((reflection,))
    assert sliced.sinks[0].category == "reflection"
    assert any(
        boundary.kind is BoundaryKind.REFLECTION
        for boundary in sliced.slices[0].unresolved_boundaries
    )


def test_candidate_limit_keeps_deterministic_first_callee_and_truncates() -> None:
    signature = "Lapp/H;->value()Ljava/lang/String;"
    callees = tuple(
        method(
            signature,
            dex_name=f"classes{number or ''}.dex",
            instructions=(
                ins(0, "const-string", "v0", f'"{number}"'),
                ins(1, "return-object", "v0"),
            ),
        )
        for number in (0, 2, 3)
    )
    caller = sink_method(
        prefix=(
            ins(0, "invoke-static", "{}", signature),
            ins(1, "move-result-object", "v1"),
        )
    )
    program_slice = slice_methods(
        (caller, *reversed(callees)),
        limits=SliceLimits(max_candidate_callees=1),
    ).slices[0]
    assert program_slice.truncated
    assert any(
        boundary.kind is BoundaryKind.CANDIDATE_LIMIT
        for boundary in program_slice.unresolved_boundaries
    )
    assert MethodIdentity("classes.dex", signature) in program_slice.involved_methods
    assert MethodIdentity("classes2.dex", signature) not in program_slice.involved_methods


def test_reverse_caller_parameter_tracing_uses_exact_static_sites() -> None:
    callee_signature = "Lapp/H;->send(Ljava/lang/String;)V"
    callee = method(
        callee_signature,
        flags=("public", "static"),
        parameters=(MethodParameter(0, "Ljava/lang/String;", "p0", "command"),),
        instructions=(
            ins(0, "invoke-virtual", "{v0, p0}", SINK),
            ins(1, "return-void"),
        ),
    )
    caller = method(
        "Lapp/Main;->entry()V",
        instructions=(
            ins(0, "const-string", "v3", '"caller-value"'),
            ins(1, "invoke-static", "{v3}", callee_signature),
            ins(2, "return-void"),
        ),
    )
    program_slice = slice_methods((callee, caller)).slices[0]
    assert MethodIdentity("classes.dex", caller.full_signature) in program_slice.involved_methods
    assert any(
        item.method.full_signature == caller.full_signature
        and item.instruction_index == 0
        for item in program_slice.retained_instructions
    )


def test_forward_call_context_does_not_mix_unrelated_reverse_callers() -> None:
    helper_signature = "Lapp/H;->identity(Ljava/lang/String;)Ljava/lang/String;"
    helper = method(
        helper_signature,
        parameters=(MethodParameter(0, "Ljava/lang/String;", "p0"),),
        instructions=(ins(0, "return-object", "p0"),),
    )
    caller_a = method(
        "Lapp/A;->run()V",
        instructions=(
            ins(0, "const-string", "v1", '"secret-A"'),
            ins(1, "invoke-static", "{v1}", helper_signature),
            ins(2, "move-result-object", "v2"),
            ins(3, "invoke-virtual", "{v0, v2}", SINK),
            ins(4, "return-void"),
        ),
    )
    caller_b = method(
        "Lapp/B;->run()V",
        instructions=(
            ins(0, "const-string", "v1", '"secret-B"'),
            ins(1, "invoke-static", "{v1}", helper_signature),
            ins(2, "move-result-object", "v2"),
            ins(3, "return-void"),
        ),
    )
    program_slice = slice_methods((caller_b, helper, caller_a)).slices[0]
    involved = {item.full_signature for item in program_slice.involved_methods}
    assert caller_a.full_signature in involved
    assert helper.full_signature in involved
    assert caller_b.full_signature not in involved
    retained_text = {
        item.instruction.raw_text for item in program_slice.retained_instructions
    }
    assert any("secret-A" in text for text in retained_text)
    assert not any("secret-B" in text for text in retained_text)


def test_root_callee_sink_may_search_bounded_reverse_callers() -> None:
    helper_signature = "Lapp/H;->send(Ljava/lang/String;)V"
    helper = method(
        helper_signature,
        parameters=(MethodParameter(0, "Ljava/lang/String;", "p0"),),
        instructions=(
            ins(0, "invoke-virtual", "{v0, p0}", SINK),
            ins(1, "return-void"),
        ),
    )
    callers = tuple(
        method(
            f"Lapp/C{suffix};->run()V",
            dex_name=dex,
            instructions=(
                ins(0, "const-string", "v1", f'"{suffix}"'),
                ins(1, "invoke-static", "{v1}", helper_signature),
                ins(2, "return-void"),
            ),
        )
        for suffix, dex in (("A", "classes.dex"), ("B", "classes2.dex"))
    )
    program_slice = slice_methods((helper, *callers)).slices[0]
    involved = {item.full_signature for item in program_slice.involved_methods}
    assert {helper.full_signature, *(item.full_signature for item in callers)} <= involved


def test_malformed_parameter_mapping_is_recoverable_issue() -> None:
    helper_signature = "Lapp/H;->send(J)V"
    helper = method(
        helper_signature,
        parameters=(MethodParameter(0, "J", "p0"),),
        instructions=(
            ins(0, "invoke-virtual", "{v0, p0}", SINK),
            ins(1, "return-void"),
        ),
    )
    malformed_caller = method(
        "Lapp/C;->run()V",
        instructions=(
            ins(0, "const-wide", "v1", "0x1"),
            ins(1, "invoke-static", "{v1}", helper_signature),
            ins(2, "return-void"),
        ),
    )
    sliced = slice_methods((helper, malformed_caller))
    assert any(issue.code == "MALFORMED_PARAMETER_MAPPING" for issue in sliced.issues)
    assert not sliced.slices[0].truncated


def test_reverse_virtual_caller_is_recorded_but_not_traversed() -> None:
    callee_signature = "Lapp/H;->send(Ljava/lang/String;)V"
    callee = method(
        callee_signature,
        flags=("public",),
        parameters=(MethodParameter(0, "Ljava/lang/String;", "p1", "command"),),
        instructions=(
            ins(0, "invoke-virtual", "{v0, p1}", SINK),
            ins(1, "return-void"),
        ),
    )
    caller = method(
        "Lapp/Main;->entry()V",
        instructions=(
            ins(0, "const-string", "v3", '"caller-value"'),
            ins(1, "invoke-virtual", "{v2, v3}", callee_signature),
            ins(2, "return-void"),
        ),
    )
    program_slice = slice_methods((callee, caller)).slices[0]
    assert any(
        boundary.kind is BoundaryKind.VIRTUAL_DISPATCH
        and boundary.method.full_signature == caller.full_signature
        for boundary in program_slice.unresolved_boundaries
    )
    assert MethodIdentity("classes.dex", caller.full_signature) not in program_slice.involved_methods


def test_reverse_caller_candidate_limit_selects_sites_deterministically() -> None:
    callee_signature = "Lapp/H;->send(Ljava/lang/String;)V"
    callee = method(
        callee_signature,
        parameters=(MethodParameter(0, "Ljava/lang/String;", "p0"),),
        instructions=(
            ins(0, "invoke-virtual", "{v0, p0}", SINK),
            ins(1, "return-void"),
        ),
    )
    callers = tuple(
        method(
            f"Lapp/C{number};->entry()V",
            dex_name=f"classes{number or ''}.dex",
            instructions=(
                ins(0, "const-string", "v1", f'"{number}"'),
                ins(1, "invoke-static", "{v1}", callee_signature),
                ins(2, "return-void"),
            ),
        )
        for number in (0, 2)
    )
    program_slice = slice_methods(
        (callee, *reversed(callers)),
        limits=SliceLimits(max_candidate_callees=1),
    ).slices[0]
    assert program_slice.truncated
    assert MethodIdentity("classes.dex", callers[0].full_signature) in program_slice.involved_methods
    assert MethodIdentity("classes2.dex", callers[1].full_signature) not in program_slice.involved_methods


def test_instruction_limit_reserves_sink_and_records_exact_boundary() -> None:
    body = sink_method(
        prefix=(
            ins(0, "const-string", "v2", '"a"'),
            ins(1, "move-object", "v1", "v2"),
        )
    )
    program_slice = slice_methods(
        (body,),
        limits=SliceLimits(max_slice_instructions=1),
    ).slices[0]
    assert [
        item.instruction_index for item in program_slice.retained_instructions
    ] == [2]
    assert program_slice.truncated
    boundary = next(
        item
        for item in program_slice.unresolved_boundaries
        if item.kind is BoundaryKind.INSTRUCTION_LIMIT
    )
    assert boundary.instruction_index == 1


def test_contributing_method_limit_does_not_count_inspected_only_declarations() -> None:
    native = method("Lapp/N;->n()V", flags=("native",), instructions=())
    body = sink_method(prefix=(ins(0, "const-string", "v1", '"x"'),))
    sliced = slice_methods(
        (body, native),
        limits=SliceLimits(max_methods_per_slice=1),
    )
    assert not any(
        item.kind is BoundaryKind.METHOD_LIMIT
        for item in sliced.slices[0].unresolved_boundaries
    )


def test_contributing_method_limit_blocks_second_retained_method() -> None:
    callee_signature = "Lapp/H;->value()Ljava/lang/String;"
    callee = method(
        callee_signature,
        instructions=(
            ins(0, "const-string", "v0", '"x"'),
            ins(1, "return-object", "v0"),
        ),
    )
    caller = sink_method(
        prefix=(
            ins(0, "invoke-static", "{}", callee_signature),
            ins(1, "move-result-object", "v1"),
        )
    )
    program_slice = slice_methods(
        (caller, callee),
        limits=SliceLimits(max_methods_per_slice=1),
    ).slices[0]
    assert program_slice.involved_methods == (
        MethodIdentity("classes.dex", caller.full_signature),
    )
    assert any(
        boundary.kind is BoundaryKind.METHOD_LIMIT
        for boundary in program_slice.unresolved_boundaries
    )


def test_recursive_call_preserves_partial_slice_and_boundary() -> None:
    recursive_signature = "Lapp/R;->value()Ljava/lang/String;"
    recursive = method(
        recursive_signature,
        instructions=(
            ins(0, "invoke-static", "{}", recursive_signature),
            ins(1, "move-result-object", "v0"),
            ins(2, "return-object", "v0"),
        ),
    )
    caller = sink_method(
        prefix=(
            ins(0, "invoke-static", "{}", recursive_signature),
            ins(1, "move-result-object", "v1"),
        )
    )
    program_slice = slice_methods((caller, recursive)).slices[0]
    assert program_slice.retained_instructions
    assert any(
        boundary.kind is BoundaryKind.RECURSION
        for boundary in program_slice.unresolved_boundaries
    )
    assert program_slice.truncated


def test_call_depth_zero_for_sink_method_and_one_for_first_boundary() -> None:
    callee_signature = "Lapp/H;->value()Ljava/lang/String;"
    callee = method(
        callee_signature,
        instructions=(ins(0, "return-object", "v0"),),
    )
    caller = sink_method(
        prefix=(
            ins(0, "invoke-static", "{}", callee_signature),
            ins(1, "move-result-object", "v1"),
        )
    )
    program_slice = slice_methods(
        (caller, callee),
        limits=SliceLimits(max_call_depth=1),
    ).slices[0]
    assert MethodIdentity("classes.dex", callee_signature) in program_slice.involved_methods
    assert not any(
        item.kind is BoundaryKind.CALL_DEPTH_LIMIT
        for item in program_slice.unresolved_boundaries
    )


def test_traversal_state_limit_is_deterministic_and_keeps_sink() -> None:
    body = sink_method(
        prefix=(
            ins(0, "const-string", "v2", '"a"'),
            ins(1, "move-object", "v1", "v2"),
        )
    )
    sliced = slice_methods(
        (body,),
        limits=SliceLimits(max_traversal_states=1),
    )
    program_slice = sliced.slices[0]
    assert any(
        item.kind is BoundaryKind.TRAVERSAL_STATE_LIMIT
        for item in program_slice.unresolved_boundaries
    )
    assert any(RetentionReason.SINK in item.reasons for item in program_slice.retained_instructions)


def test_raw_and_smali_methods_have_backend_neutral_slice_parity() -> None:
    smali = sink_method(prefix=(ins(0, "const-string", "v1", '"x"'),))
    raw = replace(
        smali,
        backend=ExtractionBackend.RAW_DEX,
        source_path="apk://hash!/classes.dex",
    )
    left = slice_methods((smali,))
    right = slice_methods((raw,))
    assert [
        (item.instruction_index, item.instruction.opcode)
        for item in left.slices[0].retained_instructions
    ] == [
        (item.instruction_index, item.instruction.opcode)
        for item in right.slices[0].retained_instructions
    ]


def test_determinism_input_immutability_and_extraction_adapter() -> None:
    first = sink_method(prefix=(ins(0, "const-string", "v1", '"x"'),))
    second = method("Lapp/Z;->unused()V")
    original = (second, first)
    direct = slice_methods(original)
    repeated = slice_methods(tuple(reversed(original)))
    adapted = slice_extraction_result(result(original))
    assert direct == repeated == adapted
    assert original == (second, first)


def test_zero_configured_sinks_is_valid() -> None:
    sliced = slice_methods((method(),))
    assert sliced.sinks == ()
    assert sliced.slices == ()
    assert sliced.metrics.sinks_found == sliced.metrics.slices_created == 0
