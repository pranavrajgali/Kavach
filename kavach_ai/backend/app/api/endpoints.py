import hashlib
import uuid
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, UploadFile, status
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from kavach_ai.backend.app.db.models import APK, CertInReport
from kavach_ai.backend.app.db.session import get_session
from kavach_ai.backend.app.schemas.contracts import (
    JobStatus,
    JobStatusResponse,
    ReportResponse,
    UploadResponse,
)
from kavach_ai.backend.workers.queue import enqueue_analysis_job

router = APIRouter()

BACKEND_DIR = Path(__file__).resolve().parents[2]
UPLOAD_DIR = BACKEND_DIR / "uploads"


@router.post("/upload", response_model=UploadResponse)
async def upload_apk(
    file: UploadFile,
    session: AsyncSession = Depends(get_session),
) -> UploadResponse:
    contents = await file.read()
    if not contents:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Uploaded APK is empty.",
        )

    job_id = str(uuid.uuid4())
    apk_hash = hashlib.sha256(contents).hexdigest()
    filename = file.filename or f"{job_id}.apk"

    existing = await session.exec(select(APK).where(APK.apk_hash == apk_hash))
    existing_apk = existing.one_or_none()
    if existing_apk is not None:
        return UploadResponse(
            job_id=existing_apk.job_id,
            status=JobStatus(existing_apk.status),
            apk_hash=existing_apk.apk_hash,
        )

    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    upload_path = UPLOAD_DIR / f"{job_id}.apk"
    upload_path.write_bytes(contents)

    apk = APK(
        apk_hash=apk_hash,
        job_id=job_id,
        filename=filename,
        file_size=len(contents),
        status=JobStatus.QUEUED.value,
    )
    session.add(apk)
    await session.commit()

    await enqueue_analysis_job(job_id)

    return UploadResponse(
        job_id=job_id,
        status=JobStatus.QUEUED,
        apk_hash=apk_hash,
    )


@router.get("/status/{job_id}", response_model=JobStatusResponse)
async def get_job_status(
    job_id: str,
    session: AsyncSession = Depends(get_session),
) -> JobStatusResponse:
    apk = await _get_apk_by_job_id(job_id, session)
    return JobStatusResponse(
        job_id=apk.job_id,
        status=JobStatus(apk.status),
        apk_hash=apk.apk_hash,
        filename=apk.filename,
        triage_score=apk.triage_score,
        final_score=apk.final_score,
    )


@router.get("/report/{job_id}", response_model=ReportResponse)
async def get_report(
    job_id: str,
    session: AsyncSession = Depends(get_session),
) -> ReportResponse:
    apk = await _get_apk_by_job_id(job_id, session)
    result = await session.exec(
        select(CertInReport).where(CertInReport.apk_hash == apk.apk_hash)
    )
    report = result.one_or_none()
    if report is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Report is not ready for this job.",
        )

    return ReportResponse(
        job_id=apk.job_id,
        apk_hash=apk.apk_hash,
        status=JobStatus(apk.status),
        report=report.mitre_attack_json,
        report_pdf_path=report.report_pdf_path,
        compliance_status=report.compliance_status,
    )


async def _get_apk_by_job_id(job_id: str, session: AsyncSession) -> APK:
    result = await session.exec(select(APK).where(APK.job_id == job_id))
    apk = result.one_or_none()
    if apk is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Job ID not found.",
        )
    return apk
