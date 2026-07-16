# Kavach.ai Technical Architecture: Training vs. Actual (Inference) Pipelines

This document maps how the **Universal Project Blueprint** structures the AI/ML lifecycle of Kavach.ai. It separates the offline **Training Part** (data compilation, model engineering, fine-tuning, and weight freezing) from the live **Actual Part** (real-time binary analysis, sandbox execution, score fusion, and GenAI report generation).

---

## Technical Overview: Aligned Architecture

```
[ OFFLINE TRAINING PART ]
Multi-Source Corpora (AMD, Drebin, AndroZoo)
       │
       ▼
Slice Extraction (LAMD Slicing)
       │
       ▼
SecureBERT-2.0 Tokenizer
       │
       ▼
Model Fine-Tuning (PyTorch + DDP + LoRA)
       │
       ▼
Saved Weights & Adapters (backend/pipeline/stage3_ml/weights/) ──┐
                                                         │ (Loaded at Startup)
=========================================================│===================================================
[ LIVE ACTUAL PART (RUN-TIME) ]                          │
                                                         ▼
Uploaded APK ──► Stage 1: Manifest Triage ──► Stage 4: SecureBERT Inference ──► Stage 5: SHAP Attribution
                     (Lightweight AXML)            (Local model/adapter)             (Plotly Bar Chart)
                            │                                                                │
                            ▼                                                                ▼
                 Stage 2: Local Dynamic Sandbox ─────────────────────► Stage 6: Telemetry Fusion & Merge
                  (MobSF + Objection + eBPF)                               (Contradiction overrides)
                                                                                     │
                                                                                     ▼
                                                                        Stage 7: LLaMA-3 Groq Compiler
                                                                          (Forensic PDF & CERT-In Forms)
```

---

## 1. The Training Part (Offline Pipeline)

The training pipeline handles data ingestion, bytecode processing, tokenization, model fine-tuning, and weights storage. In accordance with the project layout, all training-related code is placed in isolated scripts under a `training/` folder at root, preventing training code from polluting the runtime `backend/pipeline/` directory.

### A. Data Engineering & Preprocessing
* **Corpora Compilation:**
  * **Malicious Sources:** AMD (24.6k samples), Drebin (5.5k samples), CICMalDroid (11.5k samples), and PRAGuard (10.4k obfuscated samples).
  * **Benign Baseline:** AndroZoo (~750k filtered samples compiled post-2019 to prevent temporal bias).
* **Data Leakage Mitigation:**
  * Splitting is done strictly at the **APK level** (70% train / 15% validation / 15% test) before extracting slices. Doing slice-level splits would leak methods from the same APK into both training and validation sets, artificially inflating validation accuracy.
* **LAMD-based Backward Program Slicing:**
  * Suspicious API calls (SMS handlers, dynamic class loaders, accessibility binds) are marked as **sinks**.
  * The control and data flow graphs are traversed backward to extract only the instruction slices directly contributing to these sinks.
  * Extracted slices are normalized to plain text Smali tokens, stripping offset markers and variable names to make the representation obfuscation-invariant.

### B. SecureBERT-2.0 Fine-Tuning
* **Tokenizer Setup:**
  * Uses SecureBERT-2.0's vocabulary (pre-trained on 13.6B cybersecurity tokens).
  * Out-of-vocabulary (OOV) Smali strings are handled by sub-word byte-pair encoding (BPE).
* **Model Training:**
  * Runs on Distributed Data Parallel (DDP) PyTorch with Automatic Mixed Precision (AMP) for GPU acceleration.
  * Loss function is weighted to handle positive/negative imbalance.
  * **LoRA (Low-Rank Adaptation):** Instead of retraining all 100M+ parameters of SecureBERT, LoRA adapters are injected into the attention layers (`W_q`, `W_v`), drastically reducing the trainable parameters to under 2.5%, allowing fast incremental weight updates.
* **Outputs (Artifacts):**
  * The frozen SecureBERT base weights combined with the trained LoRA adapter weights are exported and stored in the local model cache `backend/pipeline/stage3_ml/weights/`.

---

## 2. The Actual Part (Runtime Inference Pipeline)

The "Actual Part" is the live forensic engine wrapped by the Streamlit dashboard. It operates in under 30 seconds for the synchronous analysis path. It uses decoupled utilities located under `backend/pipeline/` and `backend/app/` to process inputs and produce outputs.

### B. The Decoupled Architecture (FastAPI & PostgreSQL)

To avoid the **Monolithic Bottleneck** where the user interface freezes while waiting for heavy ML model calculations and dynamic sandbox execution, Kavach.ai employs a completely decoupled architecture:
* **Streamlit Frontend:** Serves as a light presentation layer that takes user actions and displays forensic outputs.
* **FastAPI Orchestrator:** Manages job dispatching and asynchronous background workers.
* **PostgreSQL State Manager:** Relational database mapping process state and analysis results.

#### FastAPI Asynchronous Non-Blocking Flow ("Restaurant Ticket" Paradigm)
When an APK is uploaded, the FastAPI backend does not block:
1. **Ingest:** FastAPI accepts the uploaded file.
2. **Vault:** Immediately vaults the physical binary file to the local PostgreSQL database (stashed as a secure BYTEA payload or in local offline storage).
3. **Ticket Generation:** Records a transaction row in PostgreSQL, returning a unique `Job ID` (receipt ticket) instantly to the Streamlit client.
4. **Background Handoff:** Dispatches the file analysis tasks to background Celery or ARQ worker processes, freeing FastAPI to ingest concurrent requests.

#### Client-Side Polling
Rather than maintaining a persistent connection, the Streamlit client uses its `Job ID` to poll the FastAPI backend via a lightweight endpoint (`GET /jobs/{id}`) every 2 seconds:
- If the database indicates **"Analyzing"**, the UI renders a loading animation.
- If the database status transitions to **"Completed"**, the UI retrieves the normalized report metrics and halts polling.

### A. Stage-by-Stage Inference Flow
* **Stage 1: Manifest Triage & 10-Millisecond Triage Filter (`backend/pipeline/stage1_triage/`)**
  * **10-Millisecond Triage Filter:** Uses Androguard to instantly unzip the APK and read `AndroidManifest.xml` in under 10 milliseconds. It flags critical permission combinations (e.g. `BIND_ACCESSIBILITY_SERVICE` paired with `RECEIVE_SMS` or `SYSTEM_ALERT_WINDOW`) to immediately prioritize high-risk files.
  * **Reflection & Obfuscation Density Scan:** Computes a metric based on the concentration of dynamic reflection calls (`Class.forName`, `getMethod`, `method.invoke`) and high-entropy cryptographic strings. If an obfuscation threshold is crossed, the static track triggers an anomaly flag, bypassing standard slicing and routing the APK directly to the dynamic sandbox with an elevated risk rating.
* **Stage 2A: Decompilation, Slicing & Native Code Scan (`backend/pipeline/stage2_static/`)**
  * **Static Track Slicing:** Traverses control flow and data flow graphs backward from dangerous sinks to isolate code paths.
  * **Smali Fallback:** If decompiling triggers abstract syntax tree (AST) crashes due to malformed ZIP headers or obfuscation tactics, Kavach.ai falls back to extracting raw Smali instructions, preserving raw Dalvik opcodes.
  * **JNI Bridge Mapping:** The static scan traverses compiled `.so` binaries, resolving export symbols using the `Java_package_class_method` convention to map transitions between the Dalvik runtime and compiled native libraries.
  * **Binary Payload Byte-Scanning (.so files):** Scans the APK's `/lib` directory for compiled C/C++ Shared Object (`.so`) libraries loaded via `System.loadLibrary()`. Kavach.ai runs an ELF parser/sub-process to scan native binary bytes for sensitive system hooks or socket connection signatures, alerting the dynamic track to monitor these triggers.
* **Stage 2B: Local Dynamic Sandbox: MobSF + Objection + eBPF (`backend/pipeline/stage4_dynamic/`)**
  * **MobSF Environment Management:** MobSF acts as the environment manager, orchestrating the local Android emulator, installing the malicious APK, and starting the Frida server on the device.
  * **Objection User-Land Breacher:** Spawns an `objection` subprocess to disable root check and SSL pinning (`objection -g <package_name> explore -s "android root disable" -s "android sslpinning disable"`), removing the malware's surface defenses.
  * **eBPF Kernel-Land Stealth Observer (Roadmap Feature):** Designed to pre-load a precompiled eBPF/bpftrace probe into the emulator's Linux kernel using root-level ADB commands prior to application launch. Because eBPF runs in kernel-space, it is invisible to user-land anti-Frida/anti-analysis checks, silently logging every system call, file I/O, and network connection.
  * **Time Dilution & Intent Broadcasts:** Intercepts runtime delays (e.g. `Thread.sleep`) and triggers system intents (such as `BOOT_COMPLETED` or `android.intent.action.BATTERY_LOW`) via ADB to force dormant malware components to wake up and execute immediately.
  * **Frida Hook Synchronization:** Syncs script injection directly onto `System.loadLibrary` initialization to drop execution interceptors smoothly without pointer crashes, and uses clock dilution to fast-forward execution delay APIs.
* **Stage 4: Local SecureBERT-2.0 Inference (`backend/pipeline/stage3_ml/`)**
  * **Local PyTorch Execution:** SecureBERT-2.0 is hosted 100% locally using PyTorch, loading model weights and adapters directly from `backend/pipeline/stage3_ml/weights/` at startup. This guarantees sub-second inference speeds and ensures zero-day malware code slices are never leaked to external public clouds.
  * **Fallback Classifier:** If executing on standard CPU or offline without weight initialization, it activates a fallback rule-based similarity hashing system to match code slices against known threat heuristics, outputting a deterministic risk probability between `0.0` and `1.0`.
* **Stage 5: SHAP Feature Attribution & Interactive Highlighting (`backend/pipeline/stage5_explain/`)**
  * **SHAP Latency Mitigation:** To keep explainability sub-second, Kavach.ai replaces brute-force SHAP with `PartitionSHAP`/`FastSHAP` hierarchical grouping, and truncates inputs to only the top 3 execution blocks.
  * **Interactive Highlighting Engine:** A custom UI component physically highlights the Smali code in the dashboard, using HSL-based colored glows to map token weights (red for malicious, blue for benign), visualizing the model's exact decision boundaries.
* **Stage 6: Telemetry Merge, Local State Scraping & Database Serialization (`backend/pipeline/stage6_synthesis/`)**
  * **Telemetry Merge:** Fuses static and dynamic tracks and resolves contradictions.
  * **Post-Detonation Local State Scraping:** Scrapes the application's private filesystems (`/data/user/0/<package_name>`) to capture decrypted configuration databases (SQLite/XML) and cleartext C2 data.
  * **BCNF Database Serialization:** Serializes findings into the normalized PostgreSQL backend, validating data constraints and mapping the APK hash, slices, and attributes to relational tables.
* **Stage 7: LLaMA-3 Groq Compiler & Graceful Degradation (`backend/pipeline/stage6_synthesis/`)**
  * Submits telemetry to Groq LLaMA-3.
  * **Graceful Degradation via Text Recovery:** To prevent formatting crash errors due to garbage malware strings, the JSON/Pydantic validation layer is wrapped in try/except blocks. If validation fails, it triggers a regex-based recovery parser to salvage key threat metrics and falls back to rendering a safe, pre-formatted markdown report so the UI never displays traceback errors.

---

## 3. Relational Database Backend (Enterprise Data Integrity)

To move away from chaotic flat JSON files and cloud dependencies (like Cloud Supabase), Kavach.ai connects to a **local PostgreSQL database instance** containerized natively inside Docker. 

The schema is defined using the **SQLModel Database Layer** (which merges Pydantic schemas and validations with SQLAlchemy ORM models) structured up to BCNF (Boyce-Codd Normal Form) to manage analysis states. A dedicated `session.py` manager handles robust thread-safe SQL connection pooling to support concurrent background workers without blocking.

### Relational Domain Separation

To enforce data integrity and enable auditable tracking, the database schema is divided into three relational domains:
1. **The Artifact Domain (`apks`):** Stores immutable facts about the physical file (SHA-256 hash, filename, file size, upload timestamp).
2. **The Execution Domain (`smali_slices` & state tracking):** Represents the "State Machine." It tracks the analysis lifecycle and details intermediate static and SHAP feature attributions, mapping them back to the Artifact Domain via Foreign Keys.
3. **The Intelligence Domain (`cert_in_reports`):** Stores final structured findings (MITRE ATT&CK codes, compliance statuses, and PDF reports) linking them back to the specific execution runs.

This domain separation creates a cryptographically verifiable audit trail. Bank auditors can instantly locate threat analysis reports and matching forensic evidence by hashing a file, without parsing through flat JSON files.

### Entity-Relationship Schema Model

* **apks** (Tracks uploaded binaries):
  - `apk_hash` VARCHAR(64) PRIMARY KEY
  - `filename` VARCHAR(255) NOT NULL
  - `file_size` BIGINT NOT NULL
  - `triage_score` NUMERIC(5,2) NOT NULL
  - `final_score` INT
  - `uploaded_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP

* **smali_slices** (Decompiled code blocks analyzed by SecureBERT):
  - `slice_id` SERIAL PRIMARY KEY
  - `apk_hash` VARCHAR(64) REFERENCES apks(apk_hash) ON DELETE CASCADE
  - `slice_text` TEXT NOT NULL
  - `source_method` VARCHAR(255) NOT NULL
  - `probability_score` NUMERIC(4,3) NOT NULL

* **shap_attributions** (Token-level explainability vectors):
  - `attribution_id` SERIAL PRIMARY KEY
  - `slice_id` INT REFERENCES smali_slices(slice_id) ON DELETE CASCADE
  - `token` VARCHAR(100) NOT NULL
  - `weight` NUMERIC(5,4) NOT NULL

* **cert_in_reports** (Compliance audit deliverables):
  - `report_id` SERIAL PRIMARY KEY
  - `apk_hash` VARCHAR(64) UNIQUE REFERENCES apks(apk_hash) ON DELETE CASCADE
  - `mitre_attack_json` JSONB NOT NULL
  - `report_pdf_path` VARCHAR(512) NOT NULL
  - `compliance_status` VARCHAR(50) NOT NULL
  - `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP

---

## 4. Applying the Project Blueprint Rules

| Blueprint Rule | Application in Kavach.ai |
|:---|:---|
| **Spec before code** | Standardized [docs/PRODUCT_SPEC.md](file:///c:/Users/Admin/Documents/Projects/Kavach/docs/PRODUCT_SPEC.md) acts as our roadmap. |
| **Backend before frontend** | All analytical capabilities (manifest parser, local dynamic sandbox orchestrator, classifier logic) are written as decoupled Python modules under `backend/pipeline/` and fully tested before the Streamlit layout is constructed. |
| **One source of truth** | [docs/PROJECT_HANDOFF.md](file:///c:/Users/Admin/Documents/Projects/Kavach/docs/PROJECT_HANDOFF.md) is updated after every development session. |
| **Free does not mean fragile** | Heavy deep learning models and paid API calls (Groq) are structured with robust, high-fidelity fallback simulators, ensuring the dashboard remains usable. |
| **Polish is not optional** | Streamlit views utilize custom CSS elements (`frontend/assets/styles.css`) to display loading animations, styled tables, and interactive dashboards rather than raw JSON strings. |

---

## 5. Unified Project Directory Structure

```
kavach_ai/
├── .env                        # Environment variables (Database credentials, API keys)
├── pyproject.toml              # Modern Python dependency management (uv/poetry)
│
├── infrastructure/             # DevOps & Local Environment
│   ├── docker-compose.yml      # Spins up PostgreSQL, MobSF, & Redis containers natively
│   ├── Dockerfile.api
│   └── Dockerfile.streamlit
│
├── frontend/                   # Streamlit SOC Dashboard (React 19 on standby)
│   ├── app.py                  # Main entry point (drag-and-drop file upload)
│   ├── assets/
│   │   └── styles.css          # Custom styling
│   ├── components/             # Reusable UI widgets (e.g., render_shap_graphs.py)
│   └── pages/                  # Historical reports & system logs
│
└── backend/                    # The FastAPI Orchestrator & Workers
    ├── app/                    # Web Server Layer (Traffic Controller)
    │   ├── main.py             # FastAPI entrypoint
    │   ├── api/                # HTTP Endpoints (routes.py - handles /upload & /status)
    │   ├── common/             # Centralized utilities (logger.py, security.py, exceptions.py)
    │   ├── db/                 # SQLModel layer (session.py, models.py)
    │   └── schemas/            # Pydantic schemas (data validation layers)
    │
    ├── pipeline/               # The Proprietary Kavach.ai Brain (Isolated)
    │   ├── init.py
    │   ├── stage1_triage/      # Manifest parsing & 10ms permission filter
    │   ├── stage2_static/      # Androguard CFG & Smali fallback extraction
    │   ├── stage3_ml/          # SecureBERT-2.0 PyTorch local inference logic
    │   ├── stage4_dynamic/     # Frida hooks, clock dilution & ADB Intent triggers
    │   ├── stage5_explain/     # PartitionSHAP / FastSHAP attributions
    │   └── stage6_synthesis/   # Telemetry merge & LLaMA-3 JSON formatting
    │
    └── workers/                # Background Task Queue (Redis Broker)
        ├── queue.py            # Redis task queues
        └── arq_worker.py       # Celery/ARQ task runner (preserves execution on crash)
```
