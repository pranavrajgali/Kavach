import asyncio
import os
import tempfile
import uuid
from pathlib import Path

TEST_DB_PATH = Path(tempfile.gettempdir()) / f"kavach_test_{uuid.uuid4().hex}.db"
os.environ["KAVACH_DATABASE_URL"] = f"sqlite+aiosqlite:///{TEST_DB_PATH.as_posix()}"

from fastapi.testclient import TestClient

from kavach_ai.backend.app.api import endpoints
from kavach_ai.backend.app.main import app
from kavach_ai.backend.pipeline.stage6_synthesis.merge import merge_telemetry
from kavach_ai.backend.workers.arq_worker import run_report_synthesis_job


def test_health_check() -> None:
    with TestClient(app) as client:
        response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_upload_status_and_report_not_ready(monkeypatch) -> None:
    async def fake_enqueue(job_id: str) -> bool:
        return False

    monkeypatch.setattr(endpoints, "enqueue_analysis_job", fake_enqueue)

    with TestClient(app) as client:
        upload_response = client.post(
            "/upload",
            files={
                "file": (
                    "queued-sample.apk",
                    _apk_bytes("queued"),
                    "application/vnd.android.package-archive",
                )
            },
        )

        assert upload_response.status_code == 200
        upload_json = upload_response.json()
        assert upload_json["status"] == "QUEUED"
        assert upload_json["apk_hash"]
        assert upload_json["job_id"]

        status_response = client.get(f"/status/{upload_json['job_id']}")
        assert status_response.status_code == 200
        status_json = status_response.json()
        assert status_json["status"] == "QUEUED"
        assert status_json["apk_hash"] == upload_json["apk_hash"]
        assert status_json["filename"] == "queued-sample.apk"

        report_response = client.get(f"/report/{upload_json['job_id']}")
        assert report_response.status_code == 404
        assert report_response.json()["detail"] == "Report is not ready for this job."


def test_mock_worker_completion_is_idempotent(monkeypatch) -> None:
    async def fake_enqueue(job_id: str) -> bool:
        return False

    monkeypatch.setattr(endpoints, "enqueue_analysis_job", fake_enqueue)

    with TestClient(app) as client:
        upload_response = client.post(
            "/upload",
            files={
                "file": (
                    "completed-sample.apk",
                    _apk_bytes("completed"),
                    "application/vnd.android.package-archive",
                )
            },
        )
        job_id = upload_response.json()["job_id"]

        asyncio.run(run_report_synthesis_job({}, job_id))
        asyncio.run(run_report_synthesis_job({}, job_id))

        status_response = client.get(f"/status/{job_id}")
        assert status_response.status_code == 200
        assert status_response.json()["status"] == "COMPLETED"
        assert status_response.json()["final_score"] == 0

        report_response = client.get(f"/report/{job_id}")
        assert report_response.status_code == 200
        report_json = report_response.json()
        assert report_json["status"] == "COMPLETED"
        assert report_json["compliance_status"] == "MOCK_READY"
        assert report_json["report"]["contradiction_label"] == "LIKELY_BENIGN"


def test_stage6_merger_contradiction_labels() -> None:
    packed = merge_telemetry(
        {"securebert_probability": 0.2},
        {"ips": ["1.2.3.4"]},
    )
    assert packed.contradiction_label == "PACKED_DROPPER"
    assert packed.final_score == 85

    evasion = merge_telemetry(
        {"securebert_probability": 0.2},
        {"evasion_signals": ["anti_vm_exit"]},
    )
    assert evasion.contradiction_label == "SANDBOX_EVASION_DETECTED"
    assert evasion.final_score == 75

    confirmed = merge_telemetry(
        {"securebert_probability": 0.75},
        {"observed_sms_exfiltration": True},
    )
    assert confirmed.contradiction_label == "CONFIRMED_MALWARE"
    assert confirmed.final_score == 90

    dormant = merge_telemetry(
        {"securebert_probability": 0.7},
        {},
    )
    assert dormant.contradiction_label == "DORMANT_MALWARE"
    assert dormant.final_score == 70


def _apk_bytes(label: str) -> bytes:
    return f"PK\x03\x04mock-apk-{label}-{uuid.uuid4()}".encode()

