from kavach_ai.backend.pipeline.stage4_dynamic.scripts.ebpf_trace import EBPFTracker


def test_simulation_trace_is_repeatable_per_artifact_and_varies_by_fingerprint() -> None:
    tracker = EBPFTracker()
    first = tracker.generate_mock_telemetry("com.example.target", is_malicious=True, fingerprint="artifact-a")
    repeat = tracker.generate_mock_telemetry("com.example.target", is_malicious=True, fingerprint="artifact-a")
    other = tracker.generate_mock_telemetry("com.example.target", is_malicious=True, fingerprint="artifact-b")

    assert first == repeat
    assert first["simulation_fingerprint"] != other["simulation_fingerprint"]
    assert first["ebpf_telemetry"]["network_connections"] != other["ebpf_telemetry"]["network_connections"]


def test_simulation_console_logs_follow_telemetry_profile() -> None:
    tracker = EBPFTracker()
    telemetry = tracker.generate_mock_telemetry(
        "com.example.target",
        is_malicious=True,
        fingerprint="artifact-dynamic-loader",
    )
    logs = "\n".join(tracker.build_console_logs("com.example.target", "sample.apk", telemetry))

    assert telemetry["execution_mode"] == "SIMULATION_FALLBACK"
    if telemetry["time_dilution_bypass"]:
        assert "Time dilution" in logs or "Time-Dilution" in logs
    else:
        assert "Time-Dilution" not in logs
        assert "No root escalation attempted" in logs or telemetry["objection_root_bypass"]
    if telemetry["objection_root_bypass"]:
        assert "Root safeguards" in logs
    else:
        assert "No root escalation attempted" in logs
    if telemetry["llm_frida_intercepts"]:
        assert telemetry["llm_frida_intercepts"][0] in logs


def test_benign_simulation_does_not_claim_evasion() -> None:
    tracker = EBPFTracker()
    telemetry = tracker.generate_mock_telemetry("com.example.calculator", is_malicious=False, fingerprint="clean")
    logs = "\n".join(tracker.build_console_logs("com.example.calculator", "calc.apk", telemetry))

    assert telemetry["simulation_profile"] == "benign-baseline"
    assert telemetry["objection_root_bypass"] is False
    assert "Root safeguards" not in logs
    assert "No root escalation attempted" in logs
    assert telemetry["ebpf_telemetry"]["dns_resolutions"]
    assert telemetry["ebpf_telemetry"]["permissions_exercised"]
