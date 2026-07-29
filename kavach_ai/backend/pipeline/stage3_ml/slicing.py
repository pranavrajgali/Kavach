"""Deterministic, backend-neutral backward slicing for extracted Dalvik methods.

This module intentionally stops at a structured, pre-ML representation.  It
does not normalize instructions, tokenize slices, run a model, resolve JNI, or
persist results.

The v1 abstractions are deliberately conservative: fields are one symbolic
location per full signature (not object-sensitive), arrays are one symbolic
location per array register (not index-sensitive), and reachability-based
control dependencies can over-include branches compared with post-dominator
analysis.
"""

from __future__ import annotations

import re
from collections import Counter, defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Iterable, Mapping, Sequence

from kavach_ai.backend.pipeline.stage2_static.decompile import (
    ExtractedMethod,
    ExtractionResult,
    Instruction,
    PayloadKind,
)


REGISTER_PATTERN = re.compile(r"\b[vp]\d+\b")
METHOD_REFERENCE_PATTERN = re.compile(
    r"(?P<class>L[^;\s]+;)->(?P<name>[^\s(]+)"
    r"(?P<descriptor>\([^)]*\)(?:V|[ZBSCIJFD]|L[^;]+;|"
    r"\[+(?:[ZBSCIJFD]|L[^;]+;)))"
)
FIELD_REFERENCE_PATTERN = re.compile(r"(L[^;\s]+;->[^\s:,]+:[^\s,}]+)")
LABEL_PATTERN = re.compile(r":[A-Za-z0-9_$.-]+")


class SliceIssueSeverity(str, Enum):
    WARNING = "warning"
    ERROR = "error"


class RetentionReason(str, Enum):
    SINK = "sink"
    DATA_DEPENDENCY = "data_dependency"
    CONTROL_DEPENDENCY = "control_dependency"
    CALLEE_RETURN = "callee_return"
    CALLER_ARGUMENT = "caller_argument"


class BoundaryKind(str, Enum):
    NATIVE_METHOD = "native_method"
    UNRESOLVED_LOCAL_CALL = "unresolved_local_call"
    EXTERNAL_CALL = "external_call"
    VIRTUAL_DISPATCH = "virtual_dispatch"
    REFLECTION = "reflection"
    CALL_DEPTH_LIMIT = "call_depth_limit"
    METHOD_LIMIT = "method_limit"
    CANDIDATE_LIMIT = "candidate_limit"
    INSTRUCTION_LIMIT = "instruction_limit"
    TRAVERSAL_STATE_LIMIT = "traversal_state_limit"
    RECURSION = "recursion"


class CfgEdgeKind(str, Enum):
    FALLTHROUGH = "fallthrough"
    BRANCH = "branch"
    GOTO = "goto"
    SWITCH = "switch"
    EXCEPTION = "exception"


@dataclass(frozen=True, order=True)
class MethodIdentity:
    dex_name: str
    full_signature: str

    def __post_init__(self) -> None:
        if not self.dex_name.strip() or not self.full_signature.strip():
            raise ValueError("MethodIdentity fields must be non-empty.")


@dataclass(frozen=True)
class SliceLimits:
    max_call_depth: int = 3
    max_methods_per_slice: int = 8
    max_slice_instructions: int = 256
    max_candidate_callees: int = 4
    max_traversal_states: int = 4096

    def __post_init__(self) -> None:
        for name, value in vars(self).items():
            if value <= 0:
                raise ValueError(f"{name} must be positive.")


@dataclass(frozen=True, order=True)
class SinkRule:
    rule_id: str
    category: str
    class_name: str
    method_name: str
    descriptor: str | None = None


@dataclass(frozen=True, order=True)
class SinkMatch:
    method: MethodIdentity
    instruction_index: int
    rule_id: str
    category: str
    invoked_signature: str


@dataclass(frozen=True, order=True)
class CfgEdge:
    source_index: int
    target_index: int
    kind: CfgEdgeKind


@dataclass(frozen=True)
class SliceIssue:
    code: str
    message: str
    severity: SliceIssueSeverity
    method: MethodIdentity | None = None
    instruction_index: int | None = None
    opcode: str | None = None
    occurrence_count: int | None = None


@dataclass(frozen=True)
class ControlFlowGraph:
    method: MethodIdentity
    instruction_count: int
    nodes: tuple[int, ...]
    edges: tuple[CfgEdge, ...]
    issues: tuple[SliceIssue, ...] = ()

    @property
    def predecessors(self) -> Mapping[int, tuple[int, ...]]:
        values: dict[int, list[int]] = defaultdict(list)
        for edge in self.edges:
            values[edge.target_index].append(edge.source_index)
        return {key: tuple(sorted(set(items))) for key, items in values.items()}

    @property
    def successors(self) -> Mapping[int, tuple[int, ...]]:
        values: dict[int, list[int]] = defaultdict(list)
        for edge in self.edges:
            values[edge.source_index].append(edge.target_index)
        return {key: tuple(sorted(set(items))) for key, items in values.items()}


@dataclass(frozen=True)
class UseDef:
    uses: frozenset[str] = frozenset()
    definitions: frozenset[str] = frozenset()
    unknown_opcode: bool = False


@dataclass(frozen=True)
class _IncomingCallContext:
    caller: MethodIdentity
    call_instruction_index: int
    callee: MethodIdentity


@dataclass(frozen=True, order=True)
class RetainedInstruction:
    method: MethodIdentity
    instruction_index: int
    instruction: Instruction = field(compare=False)
    reasons: tuple[RetentionReason, ...] = field(compare=False)


@dataclass(frozen=True, order=True)
class UnresolvedBoundary:
    kind: BoundaryKind
    method: MethodIdentity
    instruction_index: int
    target_signature: str | None = None
    detail: str | None = None


@dataclass(frozen=True)
class ProgramSlice:
    sink: SinkMatch
    retained_instructions: tuple[RetainedInstruction, ...]
    involved_methods: tuple[MethodIdentity, ...]
    unresolved_boundaries: tuple[UnresolvedBoundary, ...]
    issues: tuple[SliceIssue, ...]
    truncated: bool


@dataclass(frozen=True)
class SlicingMetrics:
    methods_indexed: int
    usable_methods_scanned: int
    sinks_found: int
    slices_created: int
    traversal_states: int
    unknown_opcodes: tuple[tuple[str, int], ...]


@dataclass(frozen=True)
class SlicingResult:
    sinks: tuple[SinkMatch, ...]
    slices: tuple[ProgramSlice, ...]
    issues: tuple[SliceIssue, ...]
    metrics: SlicingMetrics


DEFAULT_SINK_RULES: tuple[SinkRule, ...] = tuple(
    sorted(
        (
            SinkRule(
                "sms.send_text",
                "sms",
                "Landroid/telephony/SmsManager;",
                "sendTextMessage",
                "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;"
                "Landroid/app/PendingIntent;Landroid/app/PendingIntent;)V",
            ),
            SinkRule("runtime.exec", "execution", "Ljava/lang/Runtime;", "exec"),
            SinkRule(
                "process_builder.start",
                "execution",
                "Ljava/lang/ProcessBuilder;",
                "start",
                "()Ljava/lang/Process;",
            ),
            SinkRule(
                "dex_class_loader.init",
                "class_loader",
                "Ldalvik/system/DexClassLoader;",
                "<init>",
                "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;"
                "Ljava/lang/ClassLoader;)V",
            ),
            SinkRule(
                "dex_class_loader.load",
                "class_loader",
                "Ldalvik/system/DexClassLoader;",
                "loadClass",
            ),
            SinkRule(
                "class_loader.load",
                "class_loader",
                "Ljava/lang/ClassLoader;",
                "loadClass",
            ),
            SinkRule(
                "accessibility.global_action",
                "accessibility",
                "Landroid/accessibilityservice/AccessibilityService;",
                "performGlobalAction",
                "(I)Z",
            ),
            SinkRule(
                "accessibility.dispatch_gesture",
                "accessibility",
                "Landroid/accessibilityservice/AccessibilityService;",
                "dispatchGesture",
            ),
            SinkRule(
                "accessibility.node_action",
                "accessibility",
                "Landroid/view/accessibility/AccessibilityNodeInfo;",
                "performAction",
            ),
            SinkRule(
                "reflection.class_for_name",
                "reflection",
                "Ljava/lang/Class;",
                "forName",
            ),
            SinkRule(
                "reflection.get_method",
                "reflection",
                "Ljava/lang/Class;",
                "getMethod",
            ),
            SinkRule(
                "reflection.invoke",
                "reflection",
                "Ljava/lang/reflect/Method;",
                "invoke",
            ),
            SinkRule(
                "native.system_load",
                "native_loading",
                "Ljava/lang/System;",
                "load",
                "(Ljava/lang/String;)V",
            ),
            SinkRule(
                "native.system_load_library",
                "native_loading",
                "Ljava/lang/System;",
                "loadLibrary",
                "(Ljava/lang/String;)V",
            ),
        )
    )
)


def _identity(method: ExtractedMethod) -> MethodIdentity:
    return MethodIdentity(method.dex_name, method.full_signature)


def _method_reference(instruction: Instruction) -> tuple[str, str, str, str] | None:
    for text in (*instruction.operands, instruction.raw_text):
        match = METHOD_REFERENCE_PATTERN.search(text)
        if match:
            class_name = match.group("class")
            method_name = match.group("name")
            descriptor = match.group("descriptor")
            return (
                class_name,
                method_name,
                descriptor,
                f"{class_name}->{method_name}{descriptor}",
            )
    return None


def _registers(instruction: Instruction) -> tuple[str, ...]:
    text = " ".join(instruction.operands)
    range_match = re.search(r"\b([vp])(\d+)\s*\.\.\s*([vp])(\d+)\b", text)
    expanded: list[str] = []
    if range_match and range_match.group(1) == range_match.group(3):
        prefix = range_match.group(1)
        expanded.extend(
            f"{prefix}{number}"
            for number in range(
                int(range_match.group(2)), int(range_match.group(4)) + 1
            )
        )
        text = text[: range_match.start()] + text[range_match.end() :]
    expanded.extend(REGISTER_PATTERN.findall(text))
    # findall returns full matches because the pattern has no capture groups.
    return tuple(dict.fromkeys(expanded))


def _descriptor_parameter_types(descriptor: str) -> tuple[str, ...]:
    if not descriptor.startswith("(") or ")" not in descriptor:
        raise ValueError(f"Malformed method descriptor: {descriptor}")
    closing = descriptor.index(")")
    values: list[str] = []
    position = 1
    while position < closing:
        start = position
        while position < closing and descriptor[position] == "[":
            position += 1
        if position >= closing:
            raise ValueError(f"Malformed array parameter in descriptor: {descriptor}")
        if descriptor[position] == "L":
            terminator = descriptor.find(";", position, closing)
            if terminator < 0:
                raise ValueError(f"Unterminated object parameter: {descriptor}")
            position = terminator + 1
        elif descriptor[position] in "ZBSCIJFD":
            position += 1
        else:
            raise ValueError(f"Invalid parameter type in descriptor: {descriptor}")
        values.append(descriptor[start:position])
    return tuple(values)


def map_callee_parameter_dependencies(
    callee: ExtractedMethod,
    call_instruction: Instruction,
    dependencies: Iterable[str],
) -> frozenset[str]:
    """Map callee ``pN`` word dependencies to one exact caller invocation.

    Wide ``J``/``D`` parameters map either of their callee word slots to both
    corresponding caller registers.  ``ValueError`` reports malformed metadata
    or insufficient invocation registers; callers should convert it into a
    recoverable structured slicing issue.
    """

    call_registers = _registers(call_instruction)
    parameter_types = _descriptor_parameter_types(callee.descriptor)
    parameters = tuple(sorted(callee.parameters, key=lambda item: item.position))
    if len(parameters) != len(parameter_types):
        raise ValueError(
            "Extracted parameter metadata does not match the method descriptor."
        )

    is_static = "static" in callee.access_flags
    slot_groups: dict[str, tuple[str, ...]] = {}
    caller_cursor = 0
    computed_callee_slot = 0
    if not is_static:
        if not call_registers:
            raise ValueError("Instance invocation is missing its receiver register.")
        slot_groups["p0"] = (call_registers[0],)
        caller_cursor = 1
        computed_callee_slot = 1

    for position, (parameter, type_descriptor) in enumerate(
        zip(parameters, parameter_types, strict=True)
    ):
        if parameter.position != position or parameter.type_descriptor != type_descriptor:
            raise ValueError(
                "Extracted parameter positions/types do not match the descriptor."
            )
        width = 2 if type_descriptor in {"J", "D"} else 1
        declared_register = parameter.register
        if declared_register is not None:
            if not re.fullmatch(r"p\d+", declared_register):
                raise ValueError(
                    f"Malformed parameter register metadata: {declared_register}"
                )
            callee_slot = int(declared_register[1:])
            if callee_slot != computed_callee_slot:
                raise ValueError(
                    "Parameter register metadata is inconsistent with descriptor slots."
                )
        else:
            callee_slot = computed_callee_slot
        if caller_cursor + width > len(call_registers):
            raise ValueError(
                "Invocation register list is too short for the target descriptor."
            )
        caller_words = tuple(call_registers[caller_cursor : caller_cursor + width])
        for word_offset in range(width):
            slot_groups[f"p{callee_slot + word_offset}"] = caller_words
        caller_cursor += width
        computed_callee_slot += width

    expected_words = computed_callee_slot
    if len(call_registers) != expected_words:
        raise ValueError(
            f"Invocation supplies {len(call_registers)} register words; "
            f"target requires {expected_words}."
        )

    mapped: set[str] = set()
    for dependency in dependencies:
        if not dependency.startswith("p"):
            continue
        caller_words = slot_groups.get(dependency)
        if caller_words is None:
            raise ValueError(f"Unknown callee parameter dependency: {dependency}")
        mapped.update(caller_words)
    return frozenset(mapped)


def find_sinks(
    methods: Iterable[ExtractedMethod],
    sink_rules: Sequence[SinkRule] = DEFAULT_SINK_RULES,
) -> tuple[SinkMatch, ...]:
    """Find configured invoke-family sinks in usable method bodies."""

    rules = tuple(sorted(sink_rules))
    matches: list[SinkMatch] = []
    for method in sorted(
        (item for item in methods if item.is_usable), key=_identity
    ):
        identity = _identity(method)
        for instruction in method.instructions:
            if not instruction.opcode.startswith("invoke-"):
                continue
            reference = _method_reference(instruction)
            if reference is None:
                continue
            class_name, method_name, descriptor, signature = reference
            for rule in rules:
                if (
                    rule.class_name == class_name
                    and rule.method_name == method_name
                    and (rule.descriptor is None or rule.descriptor == descriptor)
                ):
                    matches.append(
                        SinkMatch(
                            identity,
                            instruction.index,
                            rule.rule_id,
                            rule.category,
                            signature,
                        )
                    )
    return tuple(sorted(set(matches)))


def build_cfg(method: ExtractedMethod) -> ControlFlowGraph:
    """Build a conservative instruction-level CFG for one usable method."""

    identity = _identity(method)
    instructions = method.instructions
    nodes = tuple(instruction.index for instruction in instructions)
    if not method.is_usable or not nodes:
        issue = SliceIssue(
            "CFG_NO_USABLE_GRAPH",
            "Method has no usable instruction graph.",
            SliceIssueSeverity.ERROR,
            identity,
        )
        return ControlFlowGraph(identity, len(instructions), nodes, (), (issue,))

    valid_nodes = set(nodes)
    label_targets = {
        label.name: label.instruction_index
        for label in method.labels
        if label.instruction_index in valid_nodes
    }
    payloads = {payload.label: payload for payload in method.payloads}
    edges: set[CfgEdge] = set()
    issues: list[SliceIssue] = []

    def add_target(
        source: int, label: str, kind: CfgEdgeKind, *, context: str
    ) -> None:
        target = label_targets.get(label)
        if target is None:
            issues.append(
                SliceIssue(
                    "CFG_UNRESOLVED_TARGET",
                    f"Could not resolve {context} target {label}.",
                    SliceIssueSeverity.WARNING,
                    identity,
                    source,
                )
            )
            return
        edges.add(CfgEdge(source, target, kind))

    for position, instruction in enumerate(instructions):
        opcode = instruction.opcode
        current = instruction.index
        next_index = instructions[position + 1].index if position + 1 < len(instructions) else None
        labels = LABEL_PATTERN.findall(" ".join(instruction.operands))

        if opcode.startswith("goto"):
            if labels:
                add_target(current, labels[-1], CfgEdgeKind.GOTO, context="goto")
            else:
                issues.append(
                    SliceIssue(
                        "CFG_MISSING_TARGET",
                        "Goto instruction has no label target.",
                        SliceIssueSeverity.WARNING,
                        identity,
                        current,
                    )
                )
            continue
        if opcode.startswith("if-"):
            if labels:
                add_target(current, labels[-1], CfgEdgeKind.BRANCH, context="branch")
            else:
                issues.append(
                    SliceIssue(
                        "CFG_MISSING_TARGET",
                        "Conditional branch has no label target.",
                        SliceIssueSeverity.WARNING,
                        identity,
                        current,
                    )
                )
            if next_index is not None:
                edges.add(CfgEdge(current, next_index, CfgEdgeKind.FALLTHROUGH))
            continue
        if "switch" in opcode:
            payload_label = labels[-1] if labels else None
            payload = payloads.get(payload_label or "")
            if payload is None:
                issues.append(
                    SliceIssue(
                        "CFG_UNRESOLVED_PAYLOAD",
                        f"Could not resolve switch payload {payload_label!r}.",
                        SliceIssueSeverity.WARNING,
                        identity,
                        current,
                    )
                )
            else:
                for entry in payload.entries:
                    if entry.target_label:
                        add_target(
                            current,
                            entry.target_label,
                            CfgEdgeKind.SWITCH,
                            context="switch",
                        )
            if next_index is not None:
                edges.add(CfgEdge(current, next_index, CfgEdgeKind.FALLTHROUGH))
            continue
        if opcode.startswith(("return", "throw")):
            continue
        if next_index is not None:
            edges.add(CfgEdge(current, next_index, CfgEdgeKind.FALLTHROUGH))

    for handler in method.exception_handlers:
        start = label_targets.get(handler.try_start_label)
        end = label_targets.get(handler.try_end_label)
        target = label_targets.get(handler.handler_label)
        if start is None or target is None:
            issues.append(
                SliceIssue(
                    "CFG_UNRESOLVED_EXCEPTION",
                    f"Could not resolve exception handler: {handler.raw_text}",
                    SliceIssueSeverity.WARNING,
                    identity,
                )
            )
            continue
        upper = end if end is not None else len(instructions)
        for instruction in instructions:
            if start <= instruction.index < upper:
                edges.add(
                    CfgEdge(
                        instruction.index,
                        target,
                        CfgEdgeKind.EXCEPTION,
                    )
                )

    if not nodes:
        issues.append(
            SliceIssue(
                "CFG_NO_USABLE_GRAPH",
                "No usable instruction nodes were produced.",
                SliceIssueSeverity.ERROR,
                identity,
            )
        )
    return ControlFlowGraph(
        identity,
        len(instructions),
        nodes,
        tuple(sorted(edges)),
        tuple(sorted(issues, key=_issue_key)),
    )


def instruction_use_def(
    instruction: Instruction,
    previous_instruction: Instruction | None = None,
) -> UseDef:
    """Return conservative symbolic uses and definitions for Dalvik bytecode."""

    opcode = instruction.opcode.lower()
    regs = _registers(instruction)
    fields = tuple(
        f"field:{item}"
        for item in FIELD_REFERENCE_PATTERN.findall(
            " ".join((*instruction.operands, instruction.raw_text))
        )
    )
    uses: set[str] = set()
    definitions: set[str] = set()

    def first_def_rest_use() -> None:
        if regs:
            definitions.add(regs[0])
            uses.update(regs[1:])

    if opcode.startswith(("move-result", "move-exception")):
        if regs:
            definitions.add(regs[0])
        if opcode.startswith("move-result") and previous_instruction is not None:
            reference = _method_reference(previous_instruction)
            if reference and not reference[2].endswith(")V"):
                uses.add(f"result:{reference[3]}")
            elif previous_instruction.opcode.startswith("filled-new-array"):
                uses.add("result:filled-new-array")
    elif opcode.startswith("move"):
        first_def_rest_use()
    elif opcode.startswith("const"):
        if regs:
            definitions.add(regs[0])
    elif opcode.startswith("filled-new-array"):
        uses.update(regs)
        definitions.add("result:filled-new-array")
    elif opcode.startswith("new-array"):
        first_def_rest_use()
    elif opcode.startswith("new-instance"):
        if regs:
            definitions.add(regs[0])
    elif opcode.startswith("array-length"):
        first_def_rest_use()
    elif opcode.startswith("invoke-"):
        uses.update(regs)
        reference = _method_reference(instruction)
        if reference and not reference[2].endswith(")V"):
            definitions.add(f"result:{reference[3]}")
    elif opcode.startswith(("iget", "sget")):
        first_def_rest_use()
        uses.update(fields)
    elif opcode.startswith(("iput", "sput")):
        uses.update(regs)
        definitions.update(fields)
    elif opcode.startswith("aget"):
        first_def_rest_use()
        if len(regs) >= 2:
            uses.add(f"array:{regs[1]}")
    elif opcode.startswith("aput"):
        uses.update(regs)
        if len(regs) >= 2:
            definitions.add(f"array:{regs[1]}")
    elif re.match(
        r"^(?:byte|char|short|int|long|float|double)-to-"
        r"(?:byte|char|short|int|long|float|double)$",
        opcode,
    ):
        first_def_rest_use()
    elif opcode.startswith(
        (
            "add-",
            "sub-",
            "mul-",
            "div-",
            "rem-",
            "and-",
            "or-",
            "xor-",
            "shl-",
            "shr-",
            "ushr-",
            "neg-",
            "not-",
            "cmp",
            "instance-of",
            "rsub-",
        )
    ):
        first_def_rest_use()
        if "/2addr" in opcode and regs:
            uses.add(regs[0])
    elif opcode.startswith("check-cast"):
        if regs:
            uses.add(regs[0])
            definitions.add(regs[0])
    elif opcode.startswith(
        (
            "if-",
            "return",
            "throw",
            "monitor-",
            "packed-switch",
            "sparse-switch",
            "fill-array-data",
        )
    ):
        uses.update(regs)
        if opcode.startswith("fill-array-data") and regs:
            definitions.add(f"array:{regs[0]}")
    elif opcode.startswith(("goto", "nop")):
        pass
    else:
        return UseDef(frozenset(regs), frozenset(), True)
    return UseDef(frozenset(uses), frozenset(definitions), False)


def _issue_key(issue: SliceIssue) -> tuple[object, ...]:
    return (
        issue.code,
        issue.method.dex_name if issue.method else "",
        issue.method.full_signature if issue.method else "",
        issue.instruction_index if issue.instruction_index is not None else -1,
        issue.opcode or "",
        issue.message,
    )


def _boundary_key(boundary: UnresolvedBoundary) -> tuple[object, ...]:
    return (
        boundary.kind.value,
        boundary.method,
        boundary.instruction_index,
        boundary.target_signature or "",
        boundary.detail or "",
    )


def _call_kind(opcode: str) -> str | None:
    if opcode.startswith("invoke-static"):
        return "static"
    if opcode.startswith("invoke-direct"):
        return "direct"
    if opcode.startswith("invoke-super"):
        return "super"
    if opcode.startswith("invoke-virtual"):
        return "virtual"
    if opcode.startswith("invoke-interface"):
        return "interface"
    return None


def _is_valid_move_result_predecessor(instruction: Instruction | None) -> bool:
    if instruction is None:
        return False
    if instruction.opcode.startswith("filled-new-array"):
        return True
    if not instruction.opcode.startswith("invoke-"):
        return False
    reference = _method_reference(instruction)
    return reference is not None and not reference[2].endswith(")V")


class _SliceBuilder:
    def __init__(
        self,
        methods: Sequence[ExtractedMethod],
        limits: SliceLimits,
        unknown_counts: Counter[str],
    ) -> None:
        self.limits = limits
        self.unknown_counts = unknown_counts
        self.all_methods = tuple(sorted(methods, key=_identity))
        self.usable = {_identity(method): method for method in self.all_methods if method.is_usable}
        self.by_signature: dict[str, list[ExtractedMethod]] = defaultdict(list)
        for method in self.all_methods:
            self.by_signature[method.full_signature].append(method)
        for candidates in self.by_signature.values():
            candidates.sort(key=_identity)
        self.cfgs = {identity: build_cfg(method) for identity, method in self.usable.items()}
        self.callers: dict[str, list[tuple[MethodIdentity, int]]] = defaultdict(list)
        self.unsafe_callers: dict[
            str, list[tuple[MethodIdentity, int, BoundaryKind]]
        ] = defaultdict(list)
        for identity, method in self.usable.items():
            for instruction in method.instructions:
                reference = _method_reference(instruction)
                kind = _call_kind(instruction.opcode)
                if reference and kind in {"virtual", "interface"}:
                    self.unsafe_callers[reference[3]].append(
                        (identity, instruction.index, BoundaryKind.VIRTUAL_DISPATCH)
                    )
                elif (
                    reference
                    and kind == "super"
                    and len(self.by_signature.get(reference[3], ())) != 1
                ):
                    self.unsafe_callers[reference[3]].append(
                        (
                            identity,
                            instruction.index,
                            BoundaryKind.UNRESOLVED_LOCAL_CALL,
                        )
                    )
                if (
                    reference
                    and kind in {"static", "direct", "super"}
                    and (
                        kind != "super"
                        or len(self.by_signature.get(reference[3], ())) == 1
                    )
                ):
                    self.callers[reference[3]].append((identity, instruction.index))
        for sites in self.callers.values():
            sites.sort()
        for sites in self.unsafe_callers.values():
            sites.sort()
        self.total_states = 0

    def build(self, sink: SinkMatch) -> ProgramSlice:
        retained: dict[tuple[MethodIdentity, int], set[RetentionReason]] = {}
        boundaries: set[UnresolvedBoundary] = set()
        issues: list[SliceIssue] = []
        truncated = False
        state_count = 0

        def mark_limit(
            kind: BoundaryKind,
            method: MethodIdentity,
            index: int,
            target: str | None,
            message: str,
        ) -> None:
            nonlocal truncated
            truncated = True
            boundaries.add(UnresolvedBoundary(kind, method, index, target, message))
            issues.append(
                SliceIssue(
                    kind.name,
                    message,
                    SliceIssueSeverity.WARNING,
                    method,
                    index,
                )
            )

        def retain(
            identity: MethodIdentity,
            index: int,
            reason: RetentionReason,
            *,
            reserve: bool = False,
        ) -> bool:
            key = (identity, index)
            if key in retained:
                retained[key].add(reason)
                return True
            contributing = {item[0] for item in retained}
            if (
                not reserve
                and identity not in contributing
                and len(contributing) >= self.limits.max_methods_per_slice
            ):
                mark_limit(
                    BoundaryKind.METHOD_LIMIT,
                    identity,
                    index,
                    None,
                    f"Method limit blocked {identity.full_signature} at instruction {index}.",
                )
                return False
            if not reserve and len(retained) >= self.limits.max_slice_instructions:
                mark_limit(
                    BoundaryKind.INSTRUCTION_LIMIT,
                    identity,
                    index,
                    None,
                    f"Instruction limit blocked {identity.full_signature} at instruction {index}.",
                )
                return False
            retained[key] = {reason}
            return True

        def candidate_subset(
            candidates: Sequence[ExtractedMethod],
            source: MethodIdentity,
            index: int,
            target: str,
        ) -> tuple[ExtractedMethod, ...]:
            ordered = tuple(sorted(candidates, key=_identity))
            if len(ordered) > self.limits.max_candidate_callees:
                mark_limit(
                    BoundaryKind.CANDIDATE_LIMIT,
                    source,
                    index,
                    target,
                    f"Candidate limit retained the first "
                    f"{self.limits.max_candidate_callees} of {len(ordered)} callees.",
                )
            return ordered[: self.limits.max_candidate_callees]

        def record_call_boundary(
            identity: MethodIdentity,
            index: int,
            instruction: Instruction,
            reference: tuple[str, str, str, str] | None,
        ) -> tuple[ExtractedMethod, ...]:
            target = reference[3] if reference else None
            kind = _call_kind(instruction.opcode)
            if reference and reference[0] in {
                "Ljava/lang/Class;",
                "Ljava/lang/reflect/Method;",
            } and reference[1] in {"forName", "getMethod", "invoke"}:
                boundaries.add(
                    UnresolvedBoundary(
                        BoundaryKind.REFLECTION, identity, index, target,
                        "Runtime reflection target is unresolved.",
                    )
                )
                return ()
            declarations = self.by_signature.get(target or "", [])
            if kind in {"virtual", "interface"}:
                boundaries.add(
                    UnresolvedBoundary(
                        BoundaryKind.VIRTUAL_DISPATCH,
                        identity,
                        index,
                        target,
                        "Virtual/interface dispatch is a v1 boundary.",
                    )
                )
                return ()
            if kind == "super" and len(declarations) != 1:
                boundaries.add(
                    UnresolvedBoundary(
                        BoundaryKind.UNRESOLVED_LOCAL_CALL
                        if declarations
                        else BoundaryKind.EXTERNAL_CALL,
                        identity,
                        index,
                        target,
                        "Super dispatch requires exactly one extracted match.",
                    )
                )
                return ()
            if not declarations:
                boundaries.add(
                    UnresolvedBoundary(
                        BoundaryKind.EXTERNAL_CALL,
                        identity,
                        index,
                        target,
                        "No matching extracted declaration.",
                    )
                )
                return ()
            usable = [item for item in declarations if item.is_usable]
            if usable:
                return candidate_subset(usable, identity, index, target or "")
            boundary_kind = (
                BoundaryKind.NATIVE_METHOD
                if any(item.is_native for item in declarations)
                else BoundaryKind.UNRESOLVED_LOCAL_CALL
            )
            boundaries.add(
                UnresolvedBoundary(
                    boundary_kind,
                    identity,
                    index,
                    target,
                    "Matching declaration has no usable body.",
                )
            )
            return ()

        def walk(
            identity: MethodIdentity,
            start_index: int,
            dependencies: frozenset[str],
            depth: int,
            reason: RetentionReason,
            context_stack: tuple[_IncomingCallContext, ...] = (),
            method_path: tuple[MethodIdentity, ...] = (),
        ) -> None:
            nonlocal state_count, truncated
            method = self.usable.get(identity)
            if method is None:
                return
            cfg = self.cfgs[identity]
            issues.extend(cfg.issues)
            instructions = {item.index: item for item in method.instructions}
            predecessors = cfg.predecessors
            queue: deque[tuple[int, frozenset[str]]] = deque([(start_index, dependencies)])
            seen: set[
                tuple[
                    MethodIdentity,
                    int,
                    frozenset[str],
                    int,
                    MethodIdentity | None,
                    int | None,
                ]
            ] = set()
            entry_dependencies: set[frozenset[str]] = set()
            incoming = context_stack[-1] if context_stack else None
            while queue:
                index, relevant = queue.popleft()
                state = (
                    identity,
                    index,
                    relevant,
                    depth,
                    incoming.caller if incoming else None,
                    incoming.call_instruction_index if incoming else None,
                )
                if state in seen:
                    continue
                if state_count >= self.limits.max_traversal_states:
                    mark_limit(
                        BoundaryKind.TRAVERSAL_STATE_LIMIT,
                        identity,
                        index,
                        None,
                        f"Traversal-state limit stopped expansion at "
                        f"{identity.full_signature} instruction {index}.",
                    )
                    return
                seen.add(state)
                state_count += 1
                self.total_states += 1
                instruction = instructions.get(index)
                if instruction is None:
                    continue
                previous = instructions.get(index - 1)
                if (
                    instruction.opcode.startswith("move-result")
                    and not _is_valid_move_result_predecessor(previous)
                ):
                    issues.append(
                        SliceIssue(
                            "MALFORMED_MOVE_RESULT",
                            (
                                "move-result is not immediately preceded by an "
                                "invoke or filled-new-array instruction."
                            ),
                            SliceIssueSeverity.WARNING,
                            identity,
                            index,
                        )
                    )
                use_def = instruction_use_def(instruction, previous)
                new_relevant = relevant
                should_retain = index == start_index or bool(
                    use_def.definitions & relevant
                )
                if should_retain and retain(identity, index, reason):
                    remaining = set(relevant) - set(use_def.definitions)
                    new_relevant = frozenset(remaining | set(use_def.uses))
                    if instruction.opcode.startswith("invoke-"):
                        reference = _method_reference(instruction)
                        callees = record_call_boundary(
                            identity, index, instruction, reference
                        )
                        result_is_relevant = bool(use_def.definitions & relevant)
                        if callees and result_is_relevant:
                            # Local return flow determines which formal
                            # parameters matter; do not taint every call
                            # argument pre-emptively.
                            new_relevant = frozenset(remaining)
                            if depth >= self.limits.max_call_depth:
                                mark_limit(
                                    BoundaryKind.CALL_DEPTH_LIMIT,
                                    identity,
                                    index,
                                    reference[3] if reference else None,
                                    "Call-depth limit prevented callee traversal.",
                                )
                            else:
                                for callee in callees:
                                    callee_identity = _identity(callee)
                                    if callee_identity in method_path:
                                        boundaries.add(
                                            UnresolvedBoundary(
                                                BoundaryKind.RECURSION,
                                                identity,
                                                index,
                                                callee.full_signature,
                                                "Recursive expansion stopped.",
                                            )
                                        )
                                        truncated = True
                                        continue
                                    returns = [
                                        item
                                        for item in callee.instructions
                                        if item.opcode.startswith("return")
                                        and not item.opcode.startswith("return-void")
                                    ]
                                    for return_instruction in returns:
                                        return_ud = instruction_use_def(
                                            return_instruction
                                        )
                                        walk(
                                            callee_identity,
                                            return_instruction.index,
                                            return_ud.uses,
                                            depth + 1,
                                            RetentionReason.CALLEE_RETURN,
                                            context_stack
                                            + (
                                                _IncomingCallContext(
                                                    identity,
                                                    index,
                                                    callee_identity,
                                                ),
                                            ),
                                            method_path + (callee_identity,),
                                        )
                prior = predecessors.get(index, ())
                if not prior and any(item.startswith("p") for item in new_relevant):
                    entry_dependencies.add(new_relevant)
                for predecessor in prior:
                    queue.append((predecessor, new_relevant))

            parameter_dependencies = sorted(
                {
                    dependency
                    for dependencies_at_entry in entry_dependencies
                    for dependency in dependencies_at_entry
                    if dependency.startswith("p")
                }
            )
            if parameter_dependencies:
                if incoming is not None and incoming.callee == identity:
                    caller = self.usable.get(incoming.caller)
                    if caller is not None:
                        call_instruction = next(
                            (
                                item
                                for item in caller.instructions
                                if item.index == incoming.call_instruction_index
                            ),
                            None,
                        )
                        try:
                            if call_instruction is None:
                                raise ValueError(
                                    "Incoming caller instruction is unavailable."
                                )
                            mapped = map_callee_parameter_dependencies(
                                method,
                                call_instruction,
                                parameter_dependencies,
                            )
                        except ValueError as exc:
                            issues.append(
                                SliceIssue(
                                    "MALFORMED_PARAMETER_MAPPING",
                                    str(exc),
                                    SliceIssueSeverity.WARNING,
                                    identity,
                                    start_index,
                                )
                            )
                        else:
                            for predecessor in self.cfgs[
                                incoming.caller
                            ].predecessors.get(
                                incoming.call_instruction_index, ()
                            ):
                                walk(
                                    incoming.caller,
                                    predecessor,
                                    mapped,
                                    max(0, depth - 1),
                                    RetentionReason.CALLER_ARGUMENT,
                                    context_stack[:-1],
                                    method_path[:-1],
                                )
                    # A known incoming context is exclusive: never search
                    # unrelated reverse callers for this callee expansion.
                else:
                    for caller_identity, call_index, boundary_kind in self.unsafe_callers.get(
                        identity.full_signature, ()
                    ):
                        boundaries.add(
                            UnresolvedBoundary(
                                boundary_kind,
                                caller_identity,
                                call_index,
                                identity.full_signature,
                                "Reverse traversal is unsafe under v1 dispatch rules.",
                            )
                        )
                    sites = tuple(self.callers.get(identity.full_signature, ()))
                    if len(sites) > self.limits.max_candidate_callees:
                        mark_limit(
                            BoundaryKind.CANDIDATE_LIMIT,
                            identity,
                            start_index,
                            identity.full_signature,
                            f"Candidate limit retained the first "
                            f"{self.limits.max_candidate_callees} of {len(sites)} "
                            "reverse caller sites.",
                        )
                    selected_sites = sites[: self.limits.max_candidate_callees]
                    if selected_sites and depth >= self.limits.max_call_depth:
                        mark_limit(
                            BoundaryKind.CALL_DEPTH_LIMIT,
                            identity,
                            start_index,
                            identity.full_signature,
                            "Call-depth limit prevented reverse caller traversal.",
                        )
                    elif selected_sites:
                        for caller_identity, call_index in selected_sites:
                            caller = self.usable[caller_identity]
                            call_instruction = next(
                                item
                                for item in caller.instructions
                                if item.index == call_index
                            )
                            try:
                                mapped = map_callee_parameter_dependencies(
                                    method,
                                    call_instruction,
                                    parameter_dependencies,
                                )
                            except ValueError as exc:
                                issues.append(
                                    SliceIssue(
                                        "MALFORMED_PARAMETER_MAPPING",
                                        str(exc),
                                        SliceIssueSeverity.WARNING,
                                        caller_identity,
                                        call_index,
                                    )
                                )
                                continue
                            if mapped:
                                retain(
                                    caller_identity,
                                    call_index,
                                    RetentionReason.CALLER_ARGUMENT,
                                )
                                for predecessor in self.cfgs[
                                    caller_identity
                                ].predecessors.get(call_index, ()):
                                    walk(
                                        caller_identity,
                                        predecessor,
                                        mapped,
                                        depth + 1,
                                        RetentionReason.CALLER_ARGUMENT,
                                        (),
                                        method_path + (caller_identity,),
                                    )

            # Conservative control-dependency fixed point.
            changed = True
            successors = cfg.successors
            while changed:
                changed = False
                retained_here = {
                    index for method_id, index in retained if method_id == identity
                }
                for instruction in method.instructions:
                    if not (
                        instruction.opcode.startswith("if-")
                        or "switch" in instruction.opcode
                    ):
                        continue
                    reachable = _reachable(successors, instruction.index)
                    if retained_here & reachable and instruction.index not in retained_here:
                        ud = instruction_use_def(instruction)
                        if retain(
                            identity,
                            instruction.index,
                            RetentionReason.CONTROL_DEPENDENCY,
                        ):
                            changed = True
                            walk(
                                identity,
                                instruction.index,
                                ud.uses,
                                depth,
                                RetentionReason.DATA_DEPENDENCY,
                                context_stack,
                                method_path,
                            )

        sink_method = self.usable[sink.method]
        sink_instruction = next(
            item for item in sink_method.instructions if item.index == sink.instruction_index
        )
        sink_ud = instruction_use_def(
            sink_instruction,
            next(
                (
                    item
                    for item in sink_method.instructions
                    if item.index == sink.instruction_index - 1
                ),
                None,
            ),
        )
        retain(sink.method, sink.instruction_index, RetentionReason.SINK, reserve=True)
        # Reflection evidence also records an unresolved boundary at the sink.
        record_call_boundary(
            sink.method,
            sink.instruction_index,
            sink_instruction,
            _method_reference(sink_instruction),
        )
        walk(
            sink.method,
            sink.instruction_index,
            sink_ud.uses,
            0,
            RetentionReason.DATA_DEPENDENCY,
            (),
            (sink.method,),
        )

        retained_models = []
        for (identity, index), reasons in sorted(retained.items()):
            instruction = next(
                item for item in self.usable[identity].instructions if item.index == index
            )
            retained_models.append(
                RetainedInstruction(
                    identity,
                    index,
                    instruction,
                    tuple(sorted(reasons, key=lambda item: item.value)),
                )
            )
        involved = tuple(sorted({item.method for item in retained_models}))
        return ProgramSlice(
            sink,
            tuple(retained_models),
            involved,
            tuple(sorted(boundaries, key=_boundary_key)),
            tuple(sorted(set(issues), key=_issue_key)),
            truncated,
        )


def _reachable(
    successors: Mapping[int, tuple[int, ...]], start: int
) -> set[int]:
    found: set[int] = set()
    queue = deque(successors.get(start, ()))
    while queue:
        current = queue.popleft()
        if current in found:
            continue
        found.add(current)
        queue.extend(successors.get(current, ()))
    return found


def slice_methods(
    methods: Iterable[ExtractedMethod],
    *,
    sink_rules: Sequence[SinkRule] = DEFAULT_SINK_RULES,
    limits: SliceLimits | None = None,
) -> SlicingResult:
    """Find sinks and build one deterministic structured slice per sink."""

    method_tuple = tuple(methods)
    configured_limits = limits or SliceLimits()
    sinks = find_sinks(method_tuple, sink_rules)
    unknown_counts: Counter[str] = Counter()
    for method in sorted(
        (item for item in method_tuple if item.is_usable), key=_identity
    ):
        for position, instruction in enumerate(method.instructions):
            previous = method.instructions[position - 1] if position else None
            if instruction_use_def(instruction, previous).unknown_opcode:
                unknown_counts[instruction.opcode] += 1
    builder = _SliceBuilder(method_tuple, configured_limits, unknown_counts)
    slices = tuple(builder.build(sink) for sink in sinks)
    issues: list[SliceIssue] = []
    for program_slice in slices:
        issues.extend(program_slice.issues)
    for opcode, count in sorted(unknown_counts.items()):
        issues.append(
            SliceIssue(
                "UNKNOWN_OPCODE",
                f"Unknown opcode {opcode!r} occurred {count} time(s).",
                SliceIssueSeverity.WARNING,
                opcode=opcode,
                occurrence_count=count,
            )
        )
    unique_issues = tuple(sorted(set(issues), key=_issue_key))
    return SlicingResult(
        sinks,
        slices,
        unique_issues,
        SlicingMetrics(
            methods_indexed=len(method_tuple),
            usable_methods_scanned=sum(method.is_usable for method in method_tuple),
            sinks_found=len(sinks),
            slices_created=len(slices),
            traversal_states=builder.total_states,
            unknown_opcodes=tuple(sorted(unknown_counts.items())),
        ),
    )


def slice_extraction_result(
    extraction_result: ExtractionResult,
    *,
    sink_rules: Sequence[SinkRule] = DEFAULT_SINK_RULES,
    limits: SliceLimits | None = None,
) -> SlicingResult:
    """Slice an extraction result without reading backend artifacts."""

    return slice_methods(
        extraction_result.methods,
        sink_rules=sink_rules,
        limits=limits,
    )


__all__ = [
    "BoundaryKind",
    "CfgEdge",
    "CfgEdgeKind",
    "ControlFlowGraph",
    "DEFAULT_SINK_RULES",
    "MethodIdentity",
    "ProgramSlice",
    "RetainedInstruction",
    "RetentionReason",
    "SinkMatch",
    "SinkRule",
    "SliceIssue",
    "SliceIssueSeverity",
    "SliceLimits",
    "SlicingMetrics",
    "SlicingResult",
    "UnresolvedBoundary",
    "UseDef",
    "build_cfg",
    "find_sinks",
    "instruction_use_def",
    "map_callee_parameter_dependencies",
    "slice_extraction_result",
    "slice_methods",
]
