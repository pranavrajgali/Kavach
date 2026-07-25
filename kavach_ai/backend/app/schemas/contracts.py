from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class JobStatus(str, Enum):
    QUEUED = "QUEUED"
    PROCESSING = "PROCESSING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class UploadResponse(BaseModel):
    job_id: str
    status: JobStatus
    apk_hash: str


class JobStatusResponse(BaseModel):
    job_id: str
    status: JobStatus
    apk_hash: str
    filename: str
    triage_score: Optional[float] = None
    final_score: Optional[int] = None


class ShapTokenAttribution(BaseModel):
    token: str
    weight: float = Field(ge=-1.0, le=1.0)


class StaticSliceResult(BaseModel):
    slice_text: str
    source_method: str
    probability_score: float = Field(ge=0.0, le=1.0)
    attributions: List[ShapTokenAttribution] = Field(default_factory=list)


class StaticAnalysisResult(BaseModel):
    permissions: List[str] = Field(default_factory=list)
    obfuscated: bool = False
    triage_score: Optional[float] = Field(default=None, ge=0.0, le=100.0)
    securebert_probability: float = Field(default=0.0, ge=0.0, le=1.0)
    slices: List[StaticSliceResult] = Field(default_factory=list)
    indicators: List[str] = Field(default_factory=list)


class DynamicAnalysisResult(BaseModel):
    syscalls: List[str] = Field(default_factory=list)
    ips: List[str] = Field(default_factory=list)
    sockets: List[str] = Field(default_factory=list)
    file_writes: List[str] = Field(default_factory=list)
    evasion_signals: List[str] = Field(default_factory=list)
    observed_sms_exfiltration: bool = False
    observed_c2_connection: bool = False
    observed_banking_data_access: bool = False
    observed_root_escalation: bool = False
    observed_runtime_dex_loading: bool = False


class MergedTelemetry(BaseModel):
    job_id: Optional[str] = None
    apk_hash: Optional[str] = None
    final_score: int = Field(ge=0, le=100)
    contradiction_label: str
    apk_meta: Dict[str, Any]
    static_evidence: Dict[str, Any]
    behavioral_fingerprint: Dict[str, Any]
    shap_evidence: List[ShapTokenAttribution] = Field(default_factory=list)


class ReportResponse(BaseModel):
    job_id: str
    apk_hash: str
    status: JobStatus
    report: Dict[str, Any]
    report_pdf_path: Optional[str] = None
    compliance_status: Optional[str] = None
