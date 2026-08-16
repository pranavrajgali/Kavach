"""Evidence-bounded investigation planning for the Kavach sandbox.

The planner may use an LLM to improve analyst-facing wording, but evidence
states are assigned locally.  That separation prevents a generated hypothesis
from being presented as a runtime observation.
"""

from __future__ import annotations

import json
import os
from typing import Any, Literal

from pydantic import BaseModel, Field

try:
    from groq import Groq
except ImportError:  # pragma: no cover - optional runtime integration
    Groq = None


EvidenceState = Literal["observed", "dormant_capability", "hypothesis"]


class EvidenceRef(BaseModel):
    source: Literal["static", "runtime"]
    detail: str


class InvestigationHypothesis(BaseModel):
    id: str
    claim: str
    state: EvidenceState
    confidence: Literal["low", "medium", "high"]
    rationale: str
    static_evidence: list[EvidenceRef] = Field(default_factory=list)
    runtime_evidence: list[EvidenceRef] = Field(default_factory=list)
    sandbox_goal: str
    expected_runtime_evidence: list[str]
    next_step: str


class InvestigationPlan(BaseModel):
    generated_by: Literal["groq", "evidence_rules"]
    evidence_policy: str
    limitations: list[str]
    hypotheses: list[InvestigationHypothesis]


def _strings(value: Any) -> list[str]:
    """Flatten telemetry into short, searchable analyst evidence."""
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [f"{key}: {item}" for key, item in value.items() if item not in (None, [], {})]
    if isinstance(value, list):
        return [str(item) for item in value if item not in (None, "")]
    return [str(value)]


def _contains(values: list[str], *tokens: str) -> bool:
    corpus = " ".join(values).lower()
    return any(token.lower() in corpus for token in tokens)


def _static_inputs(static_results: dict[str, Any]) -> list[str]:
    triage = static_results.get("triage", {})
    metrics = static_results.get("ml_metrics", {})
    return (
        _strings(triage.get("permissions"))
        + _strings(triage.get("permission_combinations"))
        + _strings(triage.get("manifest_indicators"))
        + _strings(triage.get("code_signals"))
        + _strings(triage.get("dynamic_loading_indicators"))
        + _strings(triage.get("reflection_indicators"))
        + [slice_.get("code_snippet", "")[:240] for slice_ in metrics.get("slice_evaluations", [])]
    )


def _runtime_inputs(telemetry: dict[str, Any]) -> list[str]:
    ebpf = telemetry.get("ebpf_telemetry", telemetry.get("dynamic_data", {}))
    return (
        _strings(ebpf.get("syscalls"))
        + _strings(ebpf.get("network_connections"))
        + _strings(ebpf.get("files_accessed"))
        + _strings(telemetry.get("llm_frida_intercepts"))
        + _strings(telemetry.get("time_dilution_events"))
        + _strings(telemetry.get("fuzzed_intents"))
    )


def _state(static_match: bool, runtime_match: bool) -> EvidenceState:
    if runtime_match:
        return "observed"
    if static_match:
        return "dormant_capability"
    return "hypothesis"


def _hypothesis(
    *,
    id: str,
    claim: str,
    static_match: bool,
    runtime_match: bool,
    static_detail: str,
    runtime_detail: str,
    sandbox_goal: str,
    expected: list[str],
) -> InvestigationHypothesis:
    state = _state(static_match, runtime_match)
    return InvestigationHypothesis(
        id=id,
        claim=claim,
        state=state,
        confidence="high" if state == "observed" else "medium" if static_match else "low",
        rationale=(
            "Runtime evidence corroborates the static signal."
            if state == "observed"
            else "Static evidence indicates a capability, but this behavior has not been observed in the current sandbox run."
            if state == "dormant_capability"
            else "No direct evidence is available yet; this is a sandbox exploration lead, not a finding."
        ),
        static_evidence=[EvidenceRef(source="static", detail=static_detail)] if static_match else [],
        runtime_evidence=[EvidenceRef(source="runtime", detail=runtime_detail)] if runtime_match else [],
        sandbox_goal=sandbox_goal,
        expected_runtime_evidence=expected,
        next_step="Document as observed behavior." if state == "observed" else "Run the bounded sandbox experiment and reassess the evidence state.",
    )


def _rule_plan(static_results: dict[str, Any], telemetry: dict[str, Any]) -> InvestigationPlan:
    static = _static_inputs(static_results)
    runtime = _runtime_inputs(telemetry)
    hypotheses = [
        _hypothesis(
            id="credential-or-sms-flow",
            claim="The application may access or transmit sensitive messaging or credential data after an interaction-gated flow.",
            static_match=_contains(static, "SMS", "READ_CONTACTS", "GET_ACCOUNTS", "sendTextMessage"),
            runtime_match=_contains(runtime, "sms", "sendtext", "telephony"),
            static_detail="Messaging or account-access indicator found in the static scan.",
            runtime_detail="Messaging-related runtime event captured.",
            sandbox_goal="Navigate only through benign onboarding and login screens using synthetic credentials; observe messaging APIs without sending real messages.",
            expected=["Telephony or SMS API hook", "network connection after form submission", "new sensitive-data file access"],
        ),
        _hypothesis(
            id="dynamic-payload",
            claim="The application may reveal additional behavior through dynamic code loading or reflection.",
            static_match=_contains(static, "DexClassLoader", "reflection", "Class.forName", "loadClass"),
            runtime_match=_contains(runtime, "dexclassloader", "loadclass", "memfd_create"),
            static_detail="Dynamic-loading or reflection marker found in the static scan.",
            runtime_detail="Dynamic code-loading event captured during execution.",
            sandbox_goal="Exercise settings, onboarding, and permission transitions, then observe class loading and file creation events.",
            expected=["DexClassLoader or reflection hook", "new DEX/archive file access", "process or memory-backed payload event"],
        ),
        _hypothesis(
            id="encrypted-network-flow",
            claim="The application may establish an encrypted outbound flow after its cryptographic routine is exercised.",
            static_match=_contains(static, "Cipher", "crypto", "encrypt", "decrypt", "INTERNET"),
            runtime_match=_contains(runtime, "connect", "tls", "socket", "cipher"),
            static_detail="Cryptographic or network-capable code/permission found in the static scan.",
            runtime_detail="Network or cryptographic runtime event captured.",
            sandbox_goal="Trigger normal app initialization and one synthetic form submission while recording only connection metadata and cryptographic API use.",
            expected=["socket/connect event", "TLS destination metadata", "Cipher API hook correlated with the connection"],
        ),
    ]
    return InvestigationPlan(
        generated_by="evidence_rules",
        evidence_policy="Only runtime telemetry may mark a claim as observed. Static-only signals remain dormant capabilities; unsupported ideas remain hypotheses.",
        limitations=[
            "A non-observation does not prove the capability is absent.",
            "Sandbox experiments use synthetic inputs and must not send real credentials or messages.",
        ],
        hypotheses=hypotheses,
    )


def generate_investigation_plan(static_results: dict[str, Any], telemetry: dict[str, Any]) -> InvestigationPlan:
    """Create a bounded plan; optionally let Groq improve wording without changing states."""
    plan = _rule_plan(static_results, telemetry)
    api_key = os.getenv("GROQ_API_KEY")
    if not api_key or Groq is None:
        return plan

    try:  # Keep the deterministic plan usable if the model or network is unavailable.
        client = Groq(api_key=api_key)
        payload = {"static": _static_inputs(static_results)[:20], "runtime": _runtime_inputs(telemetry)[:20]}
        response = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            response_format={"type": "json_object"},
            messages=[{
                "role": "system",
                "content": "You improve wording for defensive Android sandbox experiments. Return JSON {items:[{id,claim,sandbox_goal,expected_runtime_evidence}]}. Never claim behavior was observed and never include exploit, credential, or evasion instructions.",
            }, {"role": "user", "content": json.dumps({"evidence": payload, "draft": plan.model_dump()})}],
        )
        refined = json.loads(response.choices[0].message.content or "{}")
        by_id = {item.get("id"): item for item in refined.get("items", []) if isinstance(item, dict)}
        for hypothesis in plan.hypotheses:
            item = by_id.get(hypothesis.id)
            if item:
                hypothesis.claim = str(item.get("claim") or hypothesis.claim)
                hypothesis.sandbox_goal = str(item.get("sandbox_goal") or hypothesis.sandbox_goal)
                expected = item.get("expected_runtime_evidence")
                if isinstance(expected, list) and all(isinstance(value, str) for value in expected):
                    hypothesis.expected_runtime_evidence = expected[:4]
        plan.generated_by = "groq"
    except Exception:
        pass
    return plan
