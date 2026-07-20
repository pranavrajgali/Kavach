# Kavach.ai Track 3 Roadmap

Owner: Pranav Krishna  
Track: FastAPI Backend, Database, Task Queue, and Stage 6 Telemetry Merger

This roadmap turns the Track 3 plan into a working checklist. The goal is to unblock the rest of the team early by defining stable contracts, database state, and API endpoints before the heavier analysis modules are integrated.

## Current Repo State

- The fork workflow is configured locally:
  - `origin`: `https://github.com/aaauuugggghhhh/Kavach`
  - `upstream`: `https://github.com/pranavrajgali/Kavach.git`
- Most implementation files are placeholders.
- `kavach_ai/backend/app/db/models.py` exists, but it still needs Track 3 alignment:
  - Add `job_id`.
  - Add `status`.
  - Make `triage_score` optional.
- Canonical API routes for team integration should be:
  - `POST /upload`
  - `GET /status/{job_id}`
  - `GET /report/{job_id}`

## Ground Rules

- Work on a feature branch, not directly on `main`.
- Keep Track 3 changes scoped to backend API, DB, workers, schemas, and Stage 6 synthesis files.
- Use mock outputs until Track 1 dynamic sandbox and Track 2 static/ML modules are ready.
- Keep contracts stable so Track 1 frontend and Track 4 tests can build against them.

## Phase 0: Git Setup

- [ ] Confirm local repo is clean with `git status`.
- [ ] Sync local main from upstream.
- [x] Create feature branch: `feature/track-3-fastapi-backend`.
- [ ] Push branch to fork when the first working slice is ready.

## Phase 1: Shared Contracts

Files:

- `kavach_ai/backend/app/schemas/contracts.py`

Checklist:

- [x] Create Pydantic response model for upload: `job_id`, `status`, `apk_hash`.
- [x] Create Pydantic response model for job status.
- [x] Create Pydantic response model for final report.
- [x] Create static-analysis contract for permissions, obfuscation flags, scores, and slices.
- [x] Create dynamic-analysis contract for syscalls, IPs, file writes, sockets, and evasion signals.
- [x] Create SHAP attribution contract for token weights.
- [x] Create merged telemetry contract for Stage 6.
- [x] Export types clearly so teammates can import them without guessing names.

Definition of done:

- Contracts import cleanly.
- Mock payloads can be validated with Pydantic.
- Track 1 and Track 4 know which response shapes to expect.

## Phase 2: SQLModel Database Layer

Files:

- `kavach_ai/backend/app/db/models.py`
- `kavach_ai/backend/app/db/session.py`

Checklist:

- [x] Update `APK` model to include `job_id`, `status`, optional `triage_score`, and optional `final_score`.
- [x] Keep `apk_hash` as the primary key.
- [x] Keep `job_id` unique and non-null.
- [x] Verify `SmaliSlice` maps to `APK`.
- [x] Verify `ShapAttribution` has unique `(slice_id, token)`.
- [x] Verify `CertInReport` maps one-to-one with `APK`.
- [x] Implement database URL configuration from environment.
- [x] Support SQLite for local development.
- [x] Support PostgreSQL for Docker/runtime.
- [x] Add session generator for FastAPI dependencies.
- [x] Add database initialization helper.

Definition of done:

- Tables can be created locally.
- A queued APK row can be inserted and queried by `job_id`.
- Relationship mappings are valid.

## Phase 3: FastAPI Backend

Files:

- `kavach_ai/backend/app/main.py`
- `kavach_ai/backend/app/api/endpoints.py`

Checklist:

- [x] Create FastAPI app in `main.py`.
- [x] Add CORS for Streamlit at `http://localhost:8501`.
- [x] Include API router from `endpoints.py`.
- [x] Implement `POST /upload`.
- [x] Read APK upload bytes safely.
- [x] Compute SHA-256 hash.
- [x] Generate UUID `job_id`.
- [x] Save uploaded APK to ignored local upload storage.
- [x] Insert DB row with `QUEUED` status.
- [x] Enqueue background work or use a temporary mock dispatcher.
- [x] Return immediately with `job_id`.
- [x] Implement `GET /status/{job_id}`.
- [x] Return `QUEUED`, `PROCESSING`, `COMPLETED`, or `FAILED`.
- [x] Implement `GET /report/{job_id}`.
- [x] Return final CERT-In JSON when available.
- [x] Return clear 404/409-style errors when report is not ready.

Definition of done:

- FastAPI app boots.
- Upload returns a real `job_id`.
- Status endpoint reads from DB.
- Report endpoint has a predictable response shape.

## Phase 4: Redis and ARQ Workers

Files:

- `kavach_ai/backend/workers/queue.py`
- `kavach_ai/backend/workers/arq_worker.py`

Checklist:

- [x] Configure Redis connection settings.
- [x] Implement enqueue helper for analysis jobs.
- [x] Add `run_triage_and_static_job(job_id)`.
- [x] Add `run_dynamic_sandbox_job(job_id)`.
- [x] Add `run_report_synthesis_job(job_id)`.
- [x] Set status to `PROCESSING` when a worker starts.
- [x] Set status to `COMPLETED` after mock pipeline success.
- [x] Set status to `FAILED` with controlled error handling.
- [x] Keep Track 1 and Track 2 calls mocked until their modules are ready.

Definition of done:

- Worker functions can be imported.
- Mock jobs update DB state.
- API stays non-blocking after upload.

## Phase 5: Stage 6 Telemetry Merger

Files:

- `kavach_ai/backend/pipeline/stage6_synthesis/merge.py`

Checklist:

- [x] Merge static permissions and obfuscation indicators.
- [x] Merge SecureBERT slice scores.
- [x] Merge SHAP token attribution evidence.
- [x] Merge dynamic syscalls, IPs, sockets, file writes, and evasion signals.
- [x] Implement final score calculation.
- [x] Implement contradiction labels:
  - [x] `CONFIRMED_MALWARE`
  - [x] `PACKED_DROPPER`
  - [x] `DORMANT_MALWARE`
  - [x] `SANDBOX_EVASION_DETECTED`
  - [x] `LIKELY_BENIGN`
- [x] Produce one normalized telemetry payload for Groq report generation.
- [x] Include mock examples for early testing.

Definition of done:

- Static mock + dynamic mock produce one merged dictionary.
- Contradiction logic is deterministic.
- Output can be serialized to JSON.

## Phase 6: Verification

Checklist:

- [x] Run import checks for all new backend modules.
- [x] Start FastAPI locally.
- [x] Upload mock APK bytes.
- [x] Confirm DB row is created.
- [x] Confirm `/status/{job_id}` returns expected state.
- [x] Confirm telemetry merger works with mock static and dynamic inputs.
- [x] Add initial pytest coverage for Siri to extend.

Suggested commands:

```bash
git status
python -m compileall kavach_ai/backend
uvicorn kavach_ai.backend.app.main:app --reload --port 8000
```

## Phase 7: Pull Request Handoff

Checklist:

- [ ] Rebase branch on latest upstream `main`.
- [ ] Run available checks.
- [ ] Commit with a clear message, for example:

```bash
git commit -m "feat(backend): add track 3 API and database foundation"
```

- [ ] Push to fork.
- [ ] Open PR from `aaauuugggghhhh:feature/track-3-fastapi-backend` into `pranavrajgali:main`.
- [ ] Mention that Track 1 can consume `/upload` and `/status/{job_id}`.
- [ ] Mention that Track 4 can begin endpoint and DB transaction tests.

## Shared Working Checklist

Use this section when we work together session by session.

- [x] Branch created.
- [x] Contracts implemented.
- [x] DB models corrected.
- [x] DB session implemented.
- [x] FastAPI app created.
- [x] Upload endpoint implemented.
- [x] Status endpoint implemented.
- [x] Report endpoint implemented.
- [x] Queue helper implemented.
- [x] ARQ worker skeleton implemented.
- [x] Telemetry merger implemented.
- [x] Mock pipeline path works.
- [x] Basic verification passes.
- [ ] PR is ready.
