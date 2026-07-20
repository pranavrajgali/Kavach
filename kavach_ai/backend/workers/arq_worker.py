from sqlmodel import select

from kavach_ai.backend.app.db.models import APK, CertInReport
from kavach_ai.backend.app.db.session import get_session
from kavach_ai.backend.app.schemas.contracts import DynamicAnalysisResult, JobStatus, StaticAnalysisResult
from kavach_ai.backend.pipeline.stage6_synthesis.merge import merge_telemetry


async def run_triage_and_static_job(ctx: dict, job_id: str) -> None:
    try:
        await _set_job_status(job_id, JobStatus.PROCESSING)
        await run_dynamic_sandbox_job(ctx, job_id)
    except Exception:
        await _set_job_status(job_id, JobStatus.FAILED)
        raise


async def run_dynamic_sandbox_job(ctx: dict, job_id: str) -> None:
    try:
        await run_report_synthesis_job(ctx, job_id)
    except Exception:
        await _set_job_status(job_id, JobStatus.FAILED)
        raise


async def run_report_synthesis_job(ctx: dict, job_id: str) -> None:
    try:
        async for session in get_session():
            result = await session.exec(select(APK).where(APK.job_id == job_id))
            apk = result.one_or_none()
            if apk is None:
                return

            static_result = StaticAnalysisResult(
                permissions=[],
                obfuscated=False,
                securebert_probability=0.0,
                indicators=[],
            )
            dynamic_result = DynamicAnalysisResult()
            merged = merge_telemetry(static_result, dynamic_result, job_id=job_id, apk_hash=apk.apk_hash)

            apk.final_score = merged.final_score
            apk.status = JobStatus.COMPLETED.value
            report_result = await session.exec(
                select(CertInReport).where(CertInReport.apk_hash == apk.apk_hash)
            )
            report = report_result.one_or_none()
            if report is None:
                report = CertInReport(
                    apk_hash=apk.apk_hash,
                    mitre_attack_json=_model_to_dict(merged),
                    report_pdf_path="",
                    compliance_status="MOCK_READY",
                )
            else:
                report.mitre_attack_json = _model_to_dict(merged)
                report.compliance_status = "MOCK_READY"

            session.add(apk)
            session.add(report)
            await session.commit()
            return
    except Exception:
        await _set_job_status(job_id, JobStatus.FAILED)
        raise


async def _set_job_status(job_id: str, status: JobStatus) -> None:
    async for session in get_session():
        result = await session.exec(select(APK).where(APK.job_id == job_id))
        apk = result.one_or_none()
        if apk is None:
            return
        apk.status = status.value
        session.add(apk)
        await session.commit()
        return


def _model_to_dict(model: object) -> dict:
    model_dump = getattr(model, "model_dump", None)
    if model_dump is not None:
        return model_dump()
    return model.dict()


class WorkerSettings:
    functions = [
        run_triage_and_static_job,
        run_dynamic_sandbox_job,
        run_report_synthesis_job,
    ]
