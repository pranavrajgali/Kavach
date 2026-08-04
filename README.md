# Kavach.ai: Android Malware Detection and Forensic Reporting Pipeline

Kavach.ai is a banking-malware triage and forensic reporting pipeline designed to analyze Android applications. It runs lightweight triage filters, dynamic sandboxing, local ML classification, explainable attribution, and LLM-synthesized compliance reporting in an integrated Security Operations Center (SOC) dashboard.

This repository is organized to separate the offline training pipeline from the live, synchronous runtime analysis environment.

## Directory Structure

The workspace is organized as follows:

```text
Kavach/
├── data/                    # Raw APK files and datasets (ignored by Git)
├── docs/                    # Project documentation, technical specifications, and team plans
│   └── plans/               # Chronological roadmap and individual developer tracks
├── kavach_ai/               # Main application package
│   ├── backend/             # FastAPI orchestrator, database models, workers, and pipelines
│   ├── frontend/            # React (Vite) Dashboard UI
│   └── infrastructure/      # Deployment configurations
└── training/                # Offline ML model training pipeline and dataset building scripts
```
## Key Documentation

Please refer to these documents before starting development:

* Technical Architecture: Outlines training vs. runtime pipelines and FastAPI non-blocking design. Refer to [ARCHITECTURE.md](file:///c:/Users/Admin/Documents/Projects/Kavach/docs/ARCHITECTURE.md).
* Complete Build Guide: Specifies third-party tools, BCNF database schemas, features, and constraints. Refer to [BUILD_GUIDE.md](file:///c:/Users/Admin/Documents/Projects/Kavach/docs/BUILD_GUIDE.md).
* Dynamic Sandbox Detonation Walkthrough: Details the eBPF kernel tracing, Frida bypass hooks, SSE log streaming, and Recharts frontend integration. Refer to [DYNAMIC_ANALYSIS_WALKTHROUGH.md](file:///c:/Users/Admin/Documents/Projects/Kavach/docs/DYNAMIC_ANALYSIS_WALKTHROUGH.md).
* Team Integration Roadmap: Defines chronological task dependencies and mock integrations across tracks. Refer to [integration_roadmap.md](file:///c:/Users/Admin/Documents/Projects/Kavach/docs/plans/integration_roadmap.md).

## Developer Track Assignments

Each teammate is assigned a specific development track. Ensure you follow your individual step-by-step tasks and guidelines:

* Track 1 (Galipalli Pranav Raj): Dynamic Sandbox and Streamlit Frontend Lead. Integrates emulator sandboxing, Frida bypass scripts, eBPF logging, and front-end components. Refer to [plan_1_pranav_raj.md](file:///c:/Users/Admin/Documents/Projects/Kavach/docs/plans/plan_1_pranav_raj.md).
* Track 2 (Abhinav Mucharla): Static, ML, and LLM Core. Implements Androguard extraction, JNI mapping, backward program slicing, SecureBERT-2.0 inference, PartitionSHAP, and Groq LLaMA-3 reporting. Refer to [plan_2_abhinav.md](file:///c:/Users/Admin/Documents/Projects/Kavach/docs/plans/plan_2_abhinav.md).
* Track 3 (Pranav Krishna): FastAPI Backend, Database, and Task Queue Lead. Responsible for FastAPI endpoints, SQLModel BCNF models, Redis background workers, and telemetry merger. Refer to [plan_3_pranav_krishna.md](file:///c:/Users/Admin/Documents/Projects/Kavach/docs/plans/plan_3_pranav_krishna.md).
* Track 4 (Siri Chandana): Testing and UI Support Specialist. Handles FastAPI route testing, SQLModel transaction verification, pipeline mock testing, and Plotly visualization charts. Refer to [plan_4_siri.md](file:///c:/Users/Admin/Documents/Projects/Kavach/docs/plans/plan_4_siri.md).

## Phased Integration Timeline

Development is divided into five main phases:

1. Contracts and Database: Establish Pydantic contracts, SQLModel schemas, and initial FastAPI endpoints.
2. Parallel Analysis Track: Build the decompiler / slicing wrappers and dynamic sandbox Frida hooks in isolation.
3. ML Inference and Attribution: Set up the SecureBERT tokenizer, classification window, and PartitionSHAP calculations.
4. Telemetry Synthesis and Reports: Combine static and dynamic logs and trigger Groq report generation.
5. UI Integration and Testing: Connect Streamlit components to real endpoints and execute pytest verification.

## Model Training Setup

The model training pipeline is isolated in the root `training/` directory.

### Environment Installation

1. Create a dedicated virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate
   pip install -e ./kavach_ai[training]
   ```

### Preprocessing and Slicing

1. Place raw APK files under the root `data/` folder (e.g. `data/raw_apks/` which is ignored by Git).
2. Run preprocessing to parse control flow graphs and extract Smali backward program slices:
   ```bash
   python training/preprocess.py
   ```

### Model Fine-Tuning

We support two modes of model fine-tuning:
1. **Single-Device / Notebook-Friendly (train.py):** Run locally or inside an online Jupyter notebook (such as Colab or RunPod) on a single GPU/MPS/CPU.
   ```bash
   python training/train.py
   ```
2. **Distributed Multi-GPU (train_ddp.py):** Run on distributed multi-GPU servers using `torchrun`.
   ```bash
   torchrun --nproc_per_node=NUM_GPUS training/train_ddp.py
   ```

All fine-tuned weights and model configurations will be saved directly into the local backend cache: `kavach_ai/backend/pipeline/stage3_ml/weights/`.

## Running the Dynamic Analysis Pipeline Test

You can verify the dynamic analysis pipeline (sandbox detonation, hook injection, and telemetry serialization) by running the automated test script at the root:

```bash
python run_dynamic_test.py
```

This script executes the Stage 4 pipeline (either using a connected emulator/device via ADB, or falling back automatically to high-fidelity simulated telemetry) and prints the BCNF-ready telemetry payload to the terminal.

## Running the Dynamic Analysis with the UI

Kavach.ai uses a modern **React (Vite) Dashboard** for dynamic analysis and detonation monitoring.

### 1. Starting the FastAPI Backend Server
Before running either UI, start the FastAPI orchestrator backend using the project virtual environment:

**Option A: Run directly using the virtual environment interpreter**
```bash
# Navigate to the package directory
cd kavach_ai

# Start the uvicorn server via python module using relative path to venv
..\venv\Scripts\python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload
```

**Option B: Activate the virtual environment in PowerShell first**
```powershell
# Navigate to the package directory
cd kavach_ai

# Activate the venv
..\venv\Scripts\Activate.ps1

# Start the uvicorn server
uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload
```
The API documentation will be available at `http://127.0.0.1:8000/docs`.

### 2. Launching the React (Vite) UI Dashboard (Recommended)
The React dashboard communicates directly with the FastAPI server via Server-Sent Events (SSE) to display real-time terminal telemetry logs and interactive Recharts visualizations:
```bash
# Navigate to the frontend directory
cd kavach_ai/frontend

# Install dependencies (on first run)
npm install

# Start the development server
npm run dev
```
Open `http://localhost:5173` in your browser. Drag and drop your `.apk` file into the upload zone to initiate the live dynamic sandbox detonation stream.

