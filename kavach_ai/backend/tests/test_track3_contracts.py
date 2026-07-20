import json
from pathlib import Path

from kavach_ai.backend.app.schemas.contracts import (
    DynamicAnalysisResult,
    MergedTelemetry,
    ShapTokenAttribution,
    StaticAnalysisResult,
    StaticSliceResult,
)


FIXTURES_DIR = Path(__file__).parent / "fixtures"


def test_static_dynamic_and_merged_contracts_validate_mock_payloads() -> None:
    static_result = StaticAnalysisResult(
        permissions=["RECEIVE_SMS", "SYSTEM_ALERT_WINDOW"],
        obfuscated=True,
        triage_score=82.5,
        securebert_probability=0.91,
        indicators=["accessibility_abuse"],
        slices=[
            StaticSliceResult(
                slice_text="invoke-virtual SmsManager.sendTextMessage",
                source_method="Lcom/example/Stealer;->sendOtp",
                probability_score=0.91,
                attributions=[
                    ShapTokenAttribution(token="sendTextMessage", weight=0.42),
                    ShapTokenAttribution(token="Base64", weight=0.2),
                ],
            )
        ],
    )
    dynamic_result = DynamicAnalysisResult(
        syscalls=["openat", "connect"],
        ips=["203.0.113.10"],
        file_writes=["/data/user/0/com.fake/cache/payload.dex"],
        observed_c2_connection=True,
        observed_runtime_dex_loading=True,
    )

    merged = MergedTelemetry(
        job_id="mock-job",
        apk_hash="a" * 64,
        final_score=100,
        contradiction_label="CONFIRMED_MALWARE",
        apk_meta={
            "permissions": static_result.permissions,
            "obfuscation_tags": static_result.obfuscated,
        },
        static_evidence={
            "securebert_probability": static_result.securebert_probability,
            "indicators": static_result.indicators,
        },
        behavioral_fingerprint={
            "syscalls": dynamic_result.syscalls,
            "ips": dynamic_result.ips,
            "file_writes": dynamic_result.file_writes,
        },
        shap_evidence=static_result.slices[0].attributions,
    )

    assert merged.final_score == 100
    assert merged.shap_evidence[0].token == "sendTextMessage"


def test_fixture_payloads_match_contracts() -> None:
    static_result = StaticAnalysisResult(**_load_fixture("static_result.json"))
    dynamic_result = DynamicAnalysisResult(**_load_fixture("dynamic_result.json"))
    merged = MergedTelemetry(**_load_fixture("merged_telemetry.json"))

    assert static_result.securebert_probability == 0.91
    assert dynamic_result.observed_sms_exfiltration is True
    assert merged.contradiction_label == "CONFIRMED_MALWARE"


def _load_fixture(filename: str) -> dict:
    return json.loads((FIXTURES_DIR / filename).read_text(encoding="utf-8"))
