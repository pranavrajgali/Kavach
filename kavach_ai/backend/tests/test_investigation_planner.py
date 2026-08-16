from kavach_ai.backend.app.services.investigation_planner import generate_investigation_plan


def test_static_only_signal_is_not_reported_as_observed(monkeypatch) -> None:
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    plan = generate_investigation_plan(
        {"triage": {"permissions": ["android.permission.SEND_SMS"]}},
        {},
    )
    sms = next(item for item in plan.hypotheses if item.id == "credential-or-sms-flow")
    assert sms.state == "dormant_capability"
    assert sms.runtime_evidence == []


def test_runtime_signal_promotes_matching_claim_to_observed(monkeypatch) -> None:
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    plan = generate_investigation_plan(
        {"triage": {"permissions": ["android.permission.INTERNET"]}},
        {"ebpf_telemetry": {"syscalls": ["connect"], "network_connections": [{"ip": "198.51.100.2", "port": 443}]}},
    )
    network = next(item for item in plan.hypotheses if item.id == "encrypted-network-flow")
    assert network.state == "observed"
    assert network.runtime_evidence
