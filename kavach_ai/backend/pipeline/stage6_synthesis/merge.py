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
) -> dict:
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
    ).dict()


def _coerce_static(static_data: StaticAnalysisResult | dict) -> StaticAnalysisResult:
    if isinstance(static_data, StaticAnalysisResult):
        return static_data
    return StaticAnalysisResult(**static_data)


def _coerce_dynamic(dynamic_data: DynamicAnalysisResult | dict) -> DynamicAnalysisResult:
    if isinstance(dynamic_data, DynamicAnalysisResult):
        return dynamic_data

    # The raw telemetry dict from ebpf_trace has a nested structure that doesn't
    # match DynamicAnalysisResult's flat fields. Transform it here.
    d = dict(dynamic_data)

    # Flatten ebpf_telemetry sub-dict into top-level fields
    ebpf = d.pop("ebpf_telemetry", {})
    if isinstance(ebpf, dict):
        if "syscalls" in ebpf and "syscalls" not in d:
            d["syscalls"] = ebpf["syscalls"]
        if "network_connections" in ebpf:
            d.setdefault("ips", [])
            for conn in ebpf["network_connections"]:
                if isinstance(conn, dict) and conn.get("ip"):
                    d["ips"].append(conn["ip"])
                    d.setdefault("sockets", []).append(
                        f"{conn['ip']}:{conn.get('port', '?')}/{conn.get('protocol', 'TCP')}"
                    )
        if "files_accessed" in ebpf:
            d.setdefault("file_writes", []).extend(ebpf["files_accessed"])

    # Derive behavioral flags from telemetry signals
    intercepts = d.pop("llm_frida_intercepts", [])
    fuzzed = d.pop("fuzzed_intents", [])
    time_events = d.pop("time_dilution_events", [])

    evasion = d.get("evasion_signals", [])
    if d.get("time_dilution_bypass"):
        evasion.append("TIME_DILUTION_BYPASS")
    if d.get("objection_root_bypass"):
        evasion.append("ROOT_DETECTION_BYPASS")
    if d.get("objection_ssl_pinning_bypass"):
        evasion.append("SSL_PINNING_BYPASS")
    for evt in time_events:
        evasion.append(evt)
    d["evasion_signals"] = evasion

    # Detect C2 connection from Frida intercepts
    if intercepts:
        d["observed_c2_connection"] = any(
            "command-node" in i or "gate.php" in i or "c2" in i.lower()
            for i in intercepts
        )

    # Detect root escalation from bypass flags
    if d.get("objection_root_bypass"):
        d["observed_root_escalation"] = True

    # Strip keys that DynamicAnalysisResult doesn't accept
    valid_keys = set(DynamicAnalysisResult.model_fields.keys())
    filtered = {k: v for k, v in d.items() if k in valid_keys}

    return DynamicAnalysisResult(**filtered)


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
