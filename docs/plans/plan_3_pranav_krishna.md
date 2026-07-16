# LLM Prompt Context: Plan 3 (Pranav Krishna)
## Track 3: FastAPI Backend, Database, & Task Queue Lead

> [!IMPORTANT]  
> Before generating code, refer to the [Integration Roadmap](file:///c:/Users/Admin/Documents/Projects/Kavach/docs/plans/integration_roadmap.md) and the [BUILD_GUIDE.md](file:///c:/Users/Admin/Documents/Projects/Kavach/docs/BUILD_GUIDE.md) to understand chronological dependencies. Establishing Pydantic data contracts (`contracts.py`) and database schemas is Phase 1 and must be done first to unblock all other tracks.
> **DO NOT modify or touch any other files in the workspace that are not explicitly listed in this plan.**

> **FOR THE LLM:** You are an AI coding assistant helping Pranav Krishna implement the **FastAPI Server**, **SQLModel database schemas**, **Redis/ARQ Task Workers**, and the **Stage 6 Telemetry Merger** for Kavach.ai. Below are the context, exact requirements, directory structures, and code snippets to complete this track. Follow these guidelines strictly.

---

## 🛠️ Architecture & Directory Mapping
1. **FastAPI Endpoints:** `kavach_ai/backend/app/api/endpoints.py` & `main.py`
2. **SQLModel DB Setup:** `kavach_ai/backend/app/db/session.py` & `schemas/models.py`
3. **Redis Task Workers:** `kavach_ai/backend/workers/arq_worker.py` & `queue.py`
4. **Stage 6 merger:** `kavach_ai/backend/pipeline/stage6_synthesis/merge.py`

---

## 📋 Step-by-Step Task List

### 🌐 FastAPI Server (`kavach_ai/backend/app/...`)
- [ ] **Main Entrypoint:** Configure the root `main.py` router with CORS settings allowing connection from Streamlit (Port 8501).
- [ ] **Restaurant Ticket Upload Endpoint (`/upload`):** Receive uploaded APK binary, save it temporarily, generate a unique `job_id`, write an entry to the DB with status `QUEUED`, enqueue a background worker job, and return the `job_id` instantly.
- [ ] **Job Status Endpoint (`/status/{job_id}`):** Return pipeline execution states (`QUEUED`, `PROCESSING`, `COMPLETED`, `FAILED`).
- [ ] **Report Endpoint (`/report/{job_id}`):** Fetch and return final CERT-In compliance JSON.

### 💾 SQLModel Database State Manager (`kavach_ai/backend/app/db/...`)
- [ ] **Database Schemas (BCNF):** Design PostgreSQL / SQLite DB models matching the BCNF schema in [BUILD_GUIDE.md](file:///c:/Users/Admin/Documents/Projects/Kavach/docs/BUILD_GUIDE.md):
  * `apks` (tracks uploaded binaries, status, job IDs, hashes).
  * `smali_slices` (decompiled code blocks analyzed by SecureBERT).
  * `shap_attributions` (token-attribution explainability weights).
  * `cert_in_reports` (final structures and PDF reports mapping to CERT-In).
- [ ] **Session Pooler:** Implement connection pool and async session generator.

### ⚙️ Redis Background workers (`kavach_ai/backend/workers/...`)
- [ ] **ARQ Task Pipeline:** Define ARQ task functions to orchestrate the pipeline:
  * `run_triage_and_static_job(job_id)` (Triggers Track 1 decompiler and ML).
  * `run_dynamic_sandbox_job(job_id)` (Triggers Track 2 emulator/Frida hooks).
  * `run_report_synthesis_job(job_id)` (Merges telemetry and runs Groq prompt).

### 🔄 Stage 6 Telemetry Merger (`kavach_ai/backend/pipeline/stage6_synthesis/...`)
- [ ] **Telemetry Fusion Logic:** Combine permissions lists and static features with active system calls and file write traces into a single telemetry payload.

---

## 💡 Code & Prompt Templates for LLM

### 🗃️ SQLModel DB Models (BCNF structure)
```python
from datetime import datetime
from typing import List, Optional, Dict, Any
from sqlmodel import Field as SQLField, Relationship, SQLModel, JSON, UniqueConstraint

class APK(SQLModel, table=True):
    __tablename__ = "apks"

    apk_hash: str = SQLField(primary_key=True, max_length=64)
    job_id: str = SQLField(max_length=36, unique=True, nullable=False)
    filename: str = SQLField(max_length=255, nullable=False)
    file_size: int = SQLField(sa_column_kwargs={"type_": "BIGINT"}, nullable=False)
    triage_score: Optional[float] = SQLField(default=None, nullable=True)
    final_score: Optional[int] = SQLField(default=None, nullable=True)
    status: str = SQLField(default="QUEUED", max_length=50, nullable=False)
    uploaded_at: datetime = SQLField(default_factory=datetime.utcnow, nullable=False)

    slices: List["SmaliSlice"] = Relationship(back_populates="apk", cascade_delete=True)
    report: Optional["CertInReport"] = Relationship(back_populates="apk", cascade_delete=True)

class SmaliSlice(SQLModel, table=True):
    __tablename__ = "smali_slices"

    slice_id: Optional[int] = SQLField(default=None, primary_key=True)
    apk_hash: str = SQLField(foreign_key="apks.apk_hash", max_length=64, nullable=False, ondelete="CASCADE")
    slice_text: str = SQLField(nullable=False)
    source_method: str = SQLField(max_length=255, nullable=False)
    probability_score: float = SQLField(nullable=False)

    apk: APK = Relationship(back_populates="slices")
    attributions: List["ShapAttribution"] = Relationship(back_populates="slice", cascade_delete=True)

class ShapAttribution(SQLModel, table=True):
    __tablename__ = "shap_attributions"
    __table_args__ = (
        UniqueConstraint("slice_id", "token", name="uq_slice_token"),
    )

    attribution_id: Optional[int] = SQLField(default=None, primary_key=True)
    slice_id: int = SQLField(foreign_key="smali_slices.slice_id", nullable=False, ondelete="CASCADE")
    token: str = SQLField(max_length=100, nullable=False)
    weight: float = SQLField(nullable=False)

    slice: SmaliSlice = Relationship(back_populates="attributions")

class CertInReport(SQLModel, table=True):
    __tablename__ = "cert_in_reports"

    report_id: Optional[int] = SQLField(default=None, primary_key=True)
    apk_hash: str = SQLField(foreign_key="apks.apk_hash", max_length=64, unique=True, nullable=False, ondelete="CASCADE")
    mitre_attack_json: Dict[str, Any] = SQLField(default_factory=dict, sa_type=JSON, nullable=False)
    report_pdf_path: str = SQLField(max_length=512, nullable=False)
    compliance_status: str = SQLField(max_length=50, nullable=False)
    created_at: datetime = SQLField(default_factory=datetime.utcnow, nullable=False)

    apk: APK = Relationship(back_populates="report")
```

### ⚡ FastAPI Async Upload & Background Job Dispatch
```python
from fastapi import FastAPI, UploadFile, BackgroundTasks
import uuid
import hashlib
from sqlmodel import Session
from app.db.models import APK

app = FastAPI()

async def run_pipeline_task(job_id: str, apk_hash: str):
    # This will be picked up by Redis / local threads
    pass

@app.post("/upload")
async def upload_apk(file: UploadFile, background_tasks: BackgroundTasks):
    job_id = str(uuid.uuid4())
    contents = await file.read()
    
    # Compute SHA-256 hash of the uploaded binary
    apk_hash = hashlib.sha256(contents).hexdigest()
    
    # Save file to disk
    file_path = f"uploads/{job_id}.apk"
    with open(file_path, "wb") as f:
        f.write(contents)
        
    # Write initial state to DB
    # apk_record = APK(
    #     apk_hash=apk_hash,
    #     job_id=job_id,
    #     filename=file.filename,
    #     file_size=len(contents),
    #     status="QUEUED"
    # )
    # db_session.add(apk_record)
    
    # Run async execution
    background_tasks.add_task(run_pipeline_task, job_id, apk_hash)
    
    return {"job_id": job_id, "status": "QUEUED"}
```

### 🔀 Stage 6 Telemetry Merger Schema
```python
def merge_telemetry(static_data: dict, dynamic_data: dict) -> dict:
    # Blend static indicators and sandbox actions for ML/Groq consumption
    merged = {
        "apk_meta": {
            "permissions": static_data.get("permissions", []),
            "obfuscation_tags": static_data.get("obfuscated", False)
        },
        "behavioral_fingerprint": {
            "syscalls": dynamic_data.get("syscalls", []),
            "ips": dynamic_data.get("ips", []),
            "file_writes": dynamic_data.get("files", [])
        }
    }
    return merged
```

---

## 🎯 Verification Checklist for LLM
1. FastAPI app runs on `uvicorn main:app --reload` on port 8000.
2. Database writes are completed properly without locking.
3. Uploading an APK file returns a JSON with `job_id` and registers `QUEUED` in the database.
4. Telemetry merger runs and joins mock static & dynamic inputs into a single object.
