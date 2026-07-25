from kavach_ai.backend.app.schemas.contracts import (
    DynamicAnalysisResult,
    MergedTelemetry,
    StaticAnalysisResult,
)


def merge_telemetry(
    static_data: StaticAnalysisResult | dict,
    dynamic_data: DynamicAnalysisResult | dict,
    *,
    job_id: str | None = None,
    apk_hash: str | None = None,
) -> MergedTelemetry:
    static = _coerce_static(static_data)
    dynamic = _coerce_dynamic(dynamic_data)

    base_score = int(round(static.securebert_probability * 100))
    dynamic_score = _dynamic_score(dynamic)
    pre_override_score = min(base_score + dynamic_score, 100)
    label = _contradiction_label(base_score, dynamic)
    final_score = _apply_contradiction_override(pre_override_score, base_score, label)

    shap_evidence = [
        attribution
        for slice_result in static.slices
        for attribution in slice_result.attributions
    ]

    return MergedTelemetry(
        job_id=job_id,
        apk_hash=apk_hash,
        final_score=final_score,
        contradiction_label=label,
        apk_meta={
            "permissions": static.permissions,
            "obfuscation_tags": static.obfuscated,
            "triage_score": static.triage_score,
        },
        static_evidence={
            "securebert_probability": static.securebert_probability,
            "indicators": static.indicators,
            "slice_count": len(static.slices),
            "max_slice_probability": max(
                [slice_result.probability_score for slice_result in static.slices],
                default=static.securebert_probability,
            ),
        },
        behavioral_fingerprint={
            "syscalls": dynamic.syscalls,
            "ips": dynamic.ips,
            "sockets": dynamic.sockets,
            "file_writes": dynamic.file_writes,
            "evasion_signals": dynamic.evasion_signals,
            "observed_sms_exfiltration": dynamic.observed_sms_exfiltration,
            "observed_c2_connection": dynamic.observed_c2_connection,
            "observed_banking_data_access": dynamic.observed_banking_data_access,
            "observed_root_escalation": dynamic.observed_root_escalation,
            "observed_runtime_dex_loading": dynamic.observed_runtime_dex_loading,
        },
        shap_evidence=shap_evidence,
    )


def _coerce_static(static_data: StaticAnalysisResult | dict) -> StaticAnalysisResult:
    if isinstance(static_data, StaticAnalysisResult):
        return static_data
    return StaticAnalysisResult(**static_data)


def _coerce_dynamic(dynamic_data: DynamicAnalysisResult | dict) -> DynamicAnalysisResult:
    if isinstance(dynamic_data, DynamicAnalysisResult):
        return dynamic_data
    return DynamicAnalysisResult(**dynamic_data)


def _dynamic_score(dynamic: DynamicAnalysisResult) -> int:
    score = 0
    if dynamic.observed_c2_connection or dynamic.ips:
        score += 10
    if dynamic.observed_sms_exfiltration:
        score += 15
    if dynamic.observed_banking_data_access:
        score += 10
    if dynamic.observed_root_escalation:
        score += 12
    if dynamic.observed_runtime_dex_loading:
        score += 8
    if dynamic.file_writes:
        score += 5
    return score


def _contradiction_label(base_score: int, dynamic: DynamicAnalysisResult) -> str:
    dynamic_high = _dynamic_score(dynamic) >= 15 or bool(dynamic.ips)
    evasion_high = bool(dynamic.evasion_signals)
    static_high = base_score >= 60
    static_low = base_score < 40

    if evasion_high and not static_high:
        return "SANDBOX_EVASION_DETECTED"
    if static_high and dynamic_high:
        return "CONFIRMED_MALWARE"
    if static_low and dynamic_high:
        return "PACKED_DROPPER"
    if static_high and not dynamic_high:
        return "DORMANT_MALWARE"
    if evasion_high:
        return "SANDBOX_EVASION_DETECTED"
    return "LIKELY_BENIGN"


def _apply_contradiction_override(score: int, base_score: int, label: str) -> int:
    if label == "PACKED_DROPPER":
        return max(score, 85)
    if label == "DORMANT_MALWARE":
        return max(score, base_score)
    if label == "SANDBOX_EVASION_DETECTED":
        return max(score, 75)
    if label == "LIKELY_BENIGN" and base_score <= 50:
        return min(score, 30)
    return score
