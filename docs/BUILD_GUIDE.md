# Kavach.ai: Complete Independent Build Guide

## Table of Contents
1. Project Overview & Architecture
2. Tools & Resources
3. Database Schema
4. Feature Breakdown
5. Project Structure
6. Free Tier Limits & Constraints
7. Implementation Roadmap & Timeline
8. Phase-by-Phase Build Plan
9. Security Checklist

---

## 1. Project Overview & Architecture

### What Kavach.ai is
Kavach.ai is an Android malware detection and forensic reporting pipeline built for CyberShield 2026 (Phase 2, PS1). It ingests an uploaded APK and produces a full forensic verdict — static risk indicators, dynamic sandbox behavior, a SecureBERT-based ML classification score, SHAP-based explainability, and an auto-generated CERT-In-style compliance report — inside a single SOC (Security Operations Center) dashboard.

### Who it's for
Bank/SOC analysts and CyberShield judges evaluating banking-malware triage tools. The design assumption throughout is that outputs must be auditable and explainable, not just accurate — every risk score needs a traceable reason a human analyst or compliance auditor can inspect.

### Core Architecture
Kavach.ai is split into two clearly separated lifecycles:

- **Training Part (offline):** corpus compilation → backward program slicing (LAMD method) → SecureBERT-2.0 tokenization → LoRA fine-tuning → frozen weights + adapters saved to disk.
- **Actual Part (runtime/live):** uploaded APK → manifest triage → static analysis (Androguard) → dynamic sandbox (MobSF + Objection + eBPF) → local SecureBERT-2.0 inference → SHAP attribution → telemetry fusion → LLaMA-3 (Groq) forensic report generation.

The two are connected by one artifact: the trained weights/adapters directory (`backend/pipeline/stage3_ml/weights/`), loaded once at startup by the runtime pipeline.

### Data Flow
```
[ OFFLINE TRAINING PART ]
AMD / Drebin / CICMalDroid / PRAGuard / AndroZoo
       │
       ▼
LAMD Backward Program Slicing
       │
       ▼
SecureBERT-2.0 Tokenizer
       │
       ▼
LoRA Fine-Tuning (PyTorch + DDP + AMP)
       │
       ▼
Saved Weights & Adapters ──┐
                           │ (Loaded at Startup)
===========================│=================================
[ LIVE ACTUAL PART ]        ▼
APK ──► Manifest Triage ──► SecureBERT Inference ──► SHAP Attribution
              │                                              │
              ▼                                              ▼
     Local Dynamic Sandbox ─────────────────► Telemetry Fusion & Merge
      (MobSF + Objection + eBPF)                             │
                                                               ▼
                                                    LLaMA-3 Groq Compiler
                                                  (Forensic PDF / CERT-In Form)
```

---

## 2. Tools & Resources

### 2.1 Streamlit (Frontend Dashboard)
- Serves as the SOC-facing presentation layer: drag-and-drop APK upload, live job status, SHAP visualizations, report download.
- Kept intentionally "light" — no heavy computation happens in the Streamlit process itself, it only renders state pulled from the backend.

### 2.2 FastAPI (Backend Orchestrator)
- Owns job dispatching, async workers, and the `/upload` and `/jobs/{id}` endpoints.
- Chosen specifically to avoid the "Monolithic Bottleneck" — the UI must never freeze while SecureBERT inference or the MobSF sandbox is running.

### 2.3 PostgreSQL (Relational State + Storage)
- Local, Docker-containerized instance — no Supabase/cloud dependency, since banking malware samples cannot leave the local environment.
- Schema built with SQLModel (Pydantic + SQLAlchemy) up to BCNF.

### 2.4 SecureBERT-2.0 + LoRA/PEFT (ML Engine)
- Base model pre-trained on 13.6B cybersecurity tokens.
- LoRA adapters injected into attention layers (`W_q`, `W_v`) to keep trainable parameters under ~2.5%, making fine-tuning feasible on 8GB VRAM.

### 2.5 Androguard, MobSF, Objection, eBPF (Static + Dynamic Analysis)
- **Androguard:** manifest parsing, CFG/DFG extraction, the 10ms triage filter.
- **MobSF:** self-hosted dynamic sandbox / emulator orchestration (chosen over Any.run, whose free tier makes uploaded samples publicly visible — disqualifying for banking malware forensics).
- **Objection:** disables root checks and SSL pinning at runtime so the sandbox can observe true behavior.
- **eBPF:** kernel-level, anti-Frida-invisible syscall/network logging (flagged as a roadmap feature, not required for MVP).

### 2.6 Groq Cloud + LLaMA-3 (Report Generation Engine)
- Converts fused telemetry into a structured, Pydantic-validated forensic report.
- Wrapped in try/except with a regex-based recovery parser so malformed model output never crashes the UI — falls back to a safe markdown report instead.

### 2.7 Supporting Libraries
- SHAP (`PartitionSHAP`/`FastSHAP` for latency-bounded explainability)
- Plotly (SHAP bar charts, risk gauges)
- Docker Compose (Postgres, MobSF, Redis containers)
- Redis + Celery/ARQ (background task queue)

---

## 3. Database Schema & BCNF SQLModel Definitions

To guarantee data integrity and eliminate redundancies, the database is normalized up to **Boyce-Codd Normal Form (BCNF)**. 

### Normalization Logic (BCNF Verification)
A relation is in BCNF if, for every non-trivial functional dependency $X \rightarrow Y$, $X$ is a superkey.
1. **`apks`**: Key is `apk_hash`. All attributes functionally depend strictly on `apk_hash` (which is a candidate key).
2. **`smali_slices`**: Key is `slice_id`. All attributes depend on `slice_id` (candidate key).
3. **`shap_attributions`**: Surrogate key is `attribution_id`. To prevent multi-valued redundancies and ensure BCNF, a composite unique constraint is enforced on `(slice_id, token)`. Thus, any dependency `(slice_id, token) -> weight` has a candidate key on the left.
4. **`cert_in_reports`**: Both `report_id` and `apk_hash` are candidate keys (since `apk_hash` is marked UNIQUE). Every functional dependency has a candidate key on the left side.

### SQL DDL
```sql
CREATE TABLE apks (
    apk_hash VARCHAR(64) PRIMARY KEY,
    job_id VARCHAR(36) UNIQUE NOT NULL,
    filename VARCHAR(255) NOT NULL,
    file_size BIGINT NOT NULL,
    triage_score NUMERIC(5,2),
    final_score INT,
    status VARCHAR(50) NOT NULL DEFAULT 'QUEUED',
    uploaded_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE smali_slices (
    slice_id SERIAL PRIMARY KEY,
    apk_hash VARCHAR(64) NOT NULL REFERENCES apks(apk_hash) ON DELETE CASCADE,
    slice_text TEXT NOT NULL,
    source_method VARCHAR(255) NOT NULL,
    probability_score NUMERIC(4,3) NOT NULL
);

CREATE TABLE shap_attributions (
    attribution_id SERIAL PRIMARY KEY,
    slice_id INT NOT NULL REFERENCES smali_slices(slice_id) ON DELETE CASCADE,
    token VARCHAR(100) NOT NULL,
    weight NUMERIC(5,4) NOT NULL,
    CONSTRAINT uq_slice_token UNIQUE (slice_id, token)
);

CREATE TABLE cert_in_reports (
    report_id SERIAL PRIMARY KEY,
    apk_hash VARCHAR(64) UNIQUE NOT NULL REFERENCES apks(apk_hash) ON DELETE CASCADE,
    mitre_attack_json JSONB NOT NULL,
    report_pdf_path VARCHAR(512) NOT NULL,
    compliance_status VARCHAR(50) NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
```

### SQLModel Python Implementation
Below is the BCNF-compliant model representation mapping to our relational state manager:

```python
from datetime import datetime
from typing import List, Optional, Dict, Any
from pydantic import Field
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

    # Relationships
    slices: List["SmaliSlice"] = Relationship(back_populates="apk", cascade_delete=True)
    report: Optional["CertInReport"] = Relationship(back_populates="apk", cascade_delete=True)


class SmaliSlice(SQLModel, table=True):
    __tablename__ = "smali_slices"

    slice_id: Optional[int] = SQLField(default=None, primary_key=True)
    apk_hash: str = SQLField(foreign_key="apks.apk_hash", max_length=64, nullable=False, ondelete="CASCADE")
    slice_text: str = SQLField(nullable=False)
    source_method: str = SQLField(max_length=255, nullable=False)
    probability_score: float = SQLField(nullable=False)

    # Relationships
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

    # Relationships
    slice: SmaliSlice = Relationship(back_populates="attributions")


class CertInReport(SQLModel, table=True):
    __tablename__ = "cert_in_reports"

    report_id: Optional[int] = SQLField(default=None, primary_key=True)
    apk_hash: str = SQLField(foreign_key="apks.apk_hash", max_length=64, unique=True, nullable=False, ondelete="CASCADE")
    mitre_attack_json: Dict[str, Any] = SQLField(default_factory=dict, sa_type=JSON, nullable=False)
    report_pdf_path: str = SQLField(max_length=512, nullable=False)
    compliance_status: str = SQLField(max_length=50, nullable=False)
    created_at: datetime = SQLField(default_factory=datetime.utcnow, nullable=False)

    # Relationships
    apk: APK = Relationship(back_populates="report")
```

---

## 4. Feature Breakdown

### 5.1 Manifest Triage (Stage 1)
Androguard-based 10ms scan of `AndroidManifest.xml`. Flags dangerous permission combinations (e.g. `BIND_ACCESSIBILITY_SERVICE` + `RECEIVE_SMS` + `SYSTEM_ALERT_WINDOW`) and computes a reflection/obfuscation density score; crossing the threshold routes the APK straight to dynamic analysis with an elevated risk rating.

### 5.2 Static Analysis & Backward Slicing (Stage 2A)
CFG/DFG traversal backward from dangerous sinks (SMS handlers, dynamic class loaders, accessibility binds) to isolate only the code contributing to malicious behavior. Falls back to raw Smali extraction if decompilation crashes. Also maps JNI bridges and scans `.so` native libraries for sensitive hooks.

### 5.3 Local Dynamic Sandbox (Stage 2B)
MobSF orchestrates the emulator; Objection disables root/SSL-pinning checks; time dilution and intent broadcasts (`BOOT_COMPLETED`, `BATTERY_LOW`) force dormant malware to execute. eBPF kernel-level observation is a roadmap item.

### 5.4 SecureBERT-2.0 Inference (Stage 4)
Fully local PyTorch inference using the LoRA-adapted model, loaded from disk at startup — guarantees sub-second scoring and ensures zero-day samples never leave the local environment. Falls back to a rule-based similarity hasher if running on CPU without weights.

### 5.5 SHAP Explainability (Stage 5)
PartitionSHAP/FastSHAP hierarchical grouping keeps explainability sub-second; results are rendered as interactive HSL-highlighted Smali code (red = malicious signal, blue = benign) directly in the dashboard.

### 5.6 Telemetry Fusion & Serialization (Stage 6)
Merges static + dynamic tracks, resolves contradictions, scrapes post-detonation app state (`/data/user/0/<package_name>`), and serializes everything into the normalized PostgreSQL schema.

### 5.7 LLaMA-3 Forensic Report Generation (Stage 7)
Groq-hosted LLaMA-3 compiles fused telemetry into a Pydantic-validated forensic report and CERT-In compliance form, with a graceful-degradation fallback if structured parsing fails.

### 5.8 SOC Dashboard & Job Polling
Streamlit UI polls `GET /jobs/{id}` every 2 seconds, showing "Analyzing" → "Completed" states without blocking on long-running analysis.

### 5.9 Historical Reports View
Browse past analyses via `apk_hash` lookup — ties directly into the audit-trail design of the database schema.

---

## 5. Project Structure

```
kavach_ai/
├── .env
├── pyproject.toml
│
├── infrastructure/
│   ├── docker-compose.yml      # PostgreSQL, MobSF, Redis
│   ├── Dockerfile.api
│   └── Dockerfile.streamlit
│
├── frontend/
│   ├── app.py
│   ├── assets/
│   │   └── styles.css
│   ├── components/
│   └── pages/
│
└── backend/
    ├── app/
    │   ├── main.py
    │   ├── api/
    │   ├── common/
    │   ├── db/
    │   └── schemas/
    │
    ├── pipeline/
    │   ├── init.py
    │   ├── stage1_triage/
    │   ├── stage2_static/
    │   ├── stage3_ml/
    │   ├── stage4_dynamic/
    │   ├── stage5_explain/
    │   └── stage6_synthesis/
    │
    └── workers/
        ├── queue.py
        └── arq_worker.py
```

---

## 6. Free Tier Limits & Constraints

- **Any.run:** free tier makes uploaded samples publicly visible — disqualifying for banking malware; replaced with self-hosted MobSF.
- **Groq Cloud:** rate limits apply on the free tier — the graceful-degradation fallback (safe markdown report) exists partly to handle failed/rate-limited LLaMA-3 calls, not just malformed output.
- **8GB VRAM ceiling:** the reason LoRA (not full fine-tuning) is mandatory for SecureBERT-2.0.
- **Local-only PostgreSQL/MobSF:** no cloud DB — avoids both cost and the data-residency problem of sending bank malware samples off-device.

---

## 7. Implementation Roadmap & Timeline

- **Jul 7 – Jul 21:** Learning sprint — transformer fundamentals (3Blue1Brown, Karpathy micrograd/GPT-from-scratch), LoRA/PEFT mechanics, SHAP-transformer integration. Anchored directly to the stages above so theory maps to what gets built next.
- **Jul 22 – Aug 17:** Build phase — full 7-stage pipeline, dashboard, and report generation, culminating in the CyberShield 2026 Phase 2 submission deadline.

---

## 8. Phase-by-Phase Build Plan

### Phase 1: Project Setup
Repo scaffold, Docker Compose (Postgres + MobSF + Redis), FastAPI skeleton, Streamlit skeleton.

### Phase 2: Manifest Triage
Androguard integration, 10ms permission filter, obfuscation density scoring.

### Phase 3: Static Analysis
CFG/DFG extraction, LAMD backward slicing, JNI/.so scanning.

### Phase 4: Dynamic Sandbox
MobSF + Objection wiring, intent broadcast triggers, (stub) eBPF hook.

### Phase 5: SecureBERT-2.0 + LoRA Inference
Load fine-tuned weights/adapters, local PyTorch inference path, CPU fallback classifier.

### Phase 6: SHAP Explainability
PartitionSHAP integration, interactive Smali highlighting component.

### Phase 7: Telemetry Fusion & DB Serialization
Merge static/dynamic results, resolve contradictions, write to `apks` / `smali_slices` / `shap_attributions`.

### Phase 8: LLaMA-3 Report Generation
Groq API integration, Pydantic schema enforcement, regex fallback parser, CERT-In form template.

### Phases 9–N: Continued Build
Historical reports view, polish pass on Streamlit dashboard, load testing on async job queue.

---

## 9. Security Checklist

### Local Environment
- [ ] Malware samples never transmitted to third-party sandboxes (MobSF self-hosted only)
- [ ] SecureBERT inference runs 100% locally — no code slices sent to external APIs
- [ ] Docker network isolation between the sandbox emulator and host

### Backend / FastAPI
- [ ] File upload size limits enforced
- [ ] Job IDs are non-guessable (UUID, not sequential)
- [ ] Groq API key stored in `.env`, never logged in forensic reports

### Data
- [ ] APK binaries stored as BYTEA/local storage, not world-readable paths
- [ ] `cert_in_reports` PDF paths access-controlled, not publicly served
- [ ] Post-detonation scraped app state (decrypted configs, C2 data) treated as sensitive — not exposed in any public-facing log
