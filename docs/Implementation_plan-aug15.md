# Implementation & Submission Plan: August 15 – 17, 2026

## Objective
Implement, verify, and package all flagship Generative AI features and compile the prototype paper before the final submission deadline on **August 17, 2026**. **All features are 100% additive—zero modifications to the core static extraction, SecureBERT classification, or `frida_bypass.js` foundation.**

---

## Architectural Overview: Purely Additive GenAI Layer

```mermaid
graph TD
    subgraph "Core Existing Pipeline (100% Unchanged)"
        S1["Stage 1: Manifest Triage"] --> S2["Stage 2: Static Slicing & JNI Bridge"]
        S2 --> S3["Stage 3: SecureBERT-2.0 LoRA"]
        S3 --> S4["Stage 4: Dynamic Sandbox (frida_bypass.js + eBPF)"]
        S4 --> Data["Unified Structured Telemetry (static_ir + telemetry.json)"]
    end

    subgraph "Additive GenAI Innovation Layer (New Additions)"
        S2 -->|Suspicious Sinks| G1["1. LLMFrida Synthesizer & Active Evasion Suite [DONE]"]
        G1 -->|Injected on top of frida_bypass.js| S4
        Data --> G2["2. Vajra Hybrid GraphRAG & RAG Agent Workbench [DONE]"]
        Data --> G3["3. Multi-Agent CERT-In & Kavach Report Generator (LangGraph) [NEXT]"]
        S2 -->|Smali Slices| G4["4. Smali De-obfuscator (Code-LLM Pseudocode Generator) [Stretch Goal]"]
    end
```

---

## Active & Upcoming Milestones

### Milestone 1: Multi-Agent CERT-In & Kavach Regulatory Synthesis [NEXT UP]
* **Objective:** A LangGraph workflow that resolves track contradictions and generates Annexure A compliance forms.
* **Core Technology Stack:**
  - **Agent Framework:** **LangGraph** (managing cyclical states) or **custom lightweight asyncio state router**.
  - **LLM Agent Routing:** **OpenRouter / Groq API** (`llama-3.3-70b-versatile` for synthesis, `llama-3.1-8b-instruct` for formatting/writing).
* **Tasks:**
  - [ ] **Multi-Agent Orchestrator (`kavach_ai/backend/pipeline/stage6_synthesis/multi_agent.py`):**
    - Implement 4 independent agents:
      1. **Static Auditor Agent:** Reviews permissions, static slices, and Attention LRP relevance markers.
      2. **Dynamic Sandbox Agent:** Parses Frida logs, eBPF syscalls, and modified files.
      3. **Synthesis Agent:** Cross-references static claims against dynamic observations (differentiates active exploits vs. dormant capabilities).
      4. **Compliance Writer Agent:** Formats verified threat data into the official **CERT-In Annexure A** template.
  - [ ] **Report UI & Export (`kavach_ai/frontend/src/components/views/cert-in-view.tsx`):**
    - Render interactive side-by-side preview with 1-click Markdown / PDF download.

---

### Milestone 2: Smali De-obfuscator & Pseudocode Generator (Stretch Goal)
* **Objective:** Translate unreadable Dalvik/Smali control-flow slices into high-level Python/Java pseudocode.
* **Core Technology Stack:**
  - **Inference Engine:** **OpenRouter (Qwen 2.5 Coder 32B)** or **Groq Cloud API** (`llama-3.3-70b-versatile` with `temperature=0.1`).
  - **Context Splitting:** **AST-based chunker** written in Python (using method declarations `.method` to `.end method` as boundaries).
* **Tasks:**
  - [ ] **Backend Endpoint (`kavach_ai/backend/pipeline/stage6_synthesis/deobfuscator.py`):**
    - Accepts a raw Smali bytecode slice + dangerous sink signature.
    - Applies prompt formatting with PEFT/LoRA style task directives.
    - Exposes `POST /api/decompile-slice`.
  - [ ] **Frontend UI Integration (`kavach_ai/frontend/src/components/views/bert-classifier-view.tsx`):**
    - Add **"AI Decompile & Explain"** toggle button next to raw Smali slices.
    - Stream and display reconstructed pseudocode with syntax highlighting.

---

### Milestone 3: Prototype Paper Compilation & Submission Readiness (Deadline Day)
- [ ] **LaTeX Compilation (`docs/kavach_prototype_paper.tex`):**
  - Compile the `kavach_prototype_paper.tex` file using a local LaTeX compiler to generate the final IEEE submission PDF.
  - Double-check abstract, figures, diagrams, and formatting metrics.
- [ ] **Full Regression Testing:**
  - Execute a full end-to-end triage-to-report sweep with a sample APK to ensure no exceptions or async database race conditions occur.
- [ ] **Code Clean-up:**
  - Remove redundant debug/scratch files from the repository.
- [ ] **Zip Package Generation:**
  - Compress the final codebase, database models, static weights, and documentation folder according to BOI Hackathon submission constraints.

---

## Completed Milestones & Features

### [COMPLETED] Feature 1: Explainability Migration (SHAP to Attention LRP)
* **Objective:** Completely replace computationally heavy SHAP calculations with real-time model-specific Attention LRP relevance scores across the codebase.
* **Delivered Tasks:**
  - [x] **Backend Realignment (`kavach_ai/backend/pipeline/stage3_ml/lrp_validation.py`):**
    - Implemented Attention LRP relevance propagation ($\bar{A} = I + (\nabla A \odot A)^+$) for instant token attributions without perturbation loops.
  - [x] **Database Schema Refactoring (`kavach_ai/backend/app/db/models.py`):**
    - Refactored database models and attributions for direct Layerwise Relevance Propagation.
  - [x] **Frontend Visual Integration (`kavach_ai/frontend/src/components/views/bert-classifier-view.tsx`):**
    - Visualized Attention LRP token relevance heatmaps directly over decompiled Smali slices with confidence scores.

---

### [COMPLETED] Feature 2: Static-to-Dynamic LLMFrida Synthesizer
* **Objective:** Automatically write custom Frida JS scripts on the fly targeting obfuscated malware methods.
* **Core Technology Stack:**
  - **Synthesizer Engine:** **OpenRouter (Qwen 2.5 Coder 32B)** / **Groq Cloud API** (`llama-3.3-70b-versatile` / `temperature=0.1`).
  - **Grounding Mode:** Dynamic Dalvik memory inspection, object string converters, and hex dumping.
* **Delivered Tasks:**
  - [x] **Backend Hook Generator (`kavach_ai/backend/pipeline/stage4_dynamic/llm_frida_synthesizer.py`):**
    - Analyzes static sinks (e.g. custom decrypt methods, DexClassLoader, reflection callers) and generates targeted JavaScript hooks wrapped in safe `Java.perform()` and `try/catch` wrappers.
    - Includes deterministic fallback templates for reliable offline operation.
  - [x] **Detonation Runner Integration (`kavach_ai/backend/pipeline/stage4_dynamic/detonate.py`):**
    - Dynamically merges the generated AI scripts directly with `frida_bypass.js` into a temporary unified script before sandbox launch.
  - [x] **FastAPI Preview Endpoint (`kavach_ai/backend/app/main.py`):**
    - Added `POST /api/llm-frida/preview` endpoint for real-time frontend script generation and analysis.
  - [x] **Frontend UI Sandbox Card (`kavach_ai/frontend/src/components/upload-panel.tsx`):**
    - Previews the synthesized hook code in an expandable code drawer. Allows toggling LLMFrida, Chronos Time Dilution, and Apex Fuzzing before sandbox detonation.

---

### [COMPLETED] Feature 3: Active Evasion Bypassing (Combined Intent Fuzzing & Chronos Time Dilution)
* **Objective:** Combine passive sleep defusal (Frida clock acceleration) and active stimulus (ADB Intent/IPC Fuzzing) to guarantee evasive banking trojans detonate within the 20-second dynamic sandbox window.
* **Core Technology Stack:**
  - **Fuzzing Controller:** Python-based ADB orchestrator parsing exported activities, services, and receivers from Stage 1 manifest telemetry.
  - **Evasion Hook:** Frida-based Chronos time dilution engine (`frida_bypass.js` modifying `Thread.sleep` and `SystemClock.sleep`).
* **Delivered Tasks:**
  - [x] **Chronos Time Dilution Engine (`kavach_ai/backend/pipeline/stage4_dynamic/scripts/frida_bypass.js`):**
    - Intercepts `java.lang.Thread.sleep()` and `android.os.SystemClock.sleep()`, compressing delays $>50\text{ ms}$ down to $10\text{ ms} - 15\text{ ms}$.
  - [x] **Apex Intent Fuzzer (`kavach_ai/backend/pipeline/stage4_dynamic/fuzzer.py`):**
    - Reads manifest targets and dispatches fuzzed shell broadcasts (`am broadcast` with `FLAG_INCLUDE_STOPPED_PACKAGES: 0x00000020`, `am startservice`).
  - [x] **Execution Hook Synchronization (`kavach_ai/backend/pipeline/stage4_dynamic/detonate.py` & `__init__.py`):**
    - Synchronizes fuzzer triggering halfway through the observation window and captures `[LLM-Frida-Hook]` decrypted strings and `[Time-Dilution]` events into dynamic telemetry.
  - [x] **Frontend Terminal & Scorecard Updates (`terminal-console.tsx`, `report-view.tsx`, `kavach-scorecard.tsx`):**
    - Live terminal displays color-coded badges (`LLM-FRIDA`, `TIME-DILUTION`, `APEX-FUZZER`).
    - Added dedicated "Evasion Defusal & AI Hooks" evidence tab with 4-way evasion matrix (Time Dilution, Apex Fuzzing, Anti-Root Guard, SSL Pinning) and decrypted memory viewer. Zero emojis, pure Obsidian cyber aesthetic.
  - [x] **Automated Test Suite (`kavach_ai/backend/tests/test_llm_frida_and_evasion.py`):**
    - 5/5 automated unit and integration tests passing (`pytest` verified).

---

### [COMPLETED] Feature 4: Vajra Hybrid GraphRAG Engine & Connected RAG Agent Workbench
* **Objective:** In-process localized GraphRAG engine combining structural graph traversal, semantic vector search, and dynamic telemetry interrogation with real-time SSE streaming.
* **Core Technology Stack:**
  - **Knowledge Graph:** In-memory graph modeling `Package`, `Class`, `Method`, `APISink`, `FridaIntercept`, and `Syscall` nodes with `CALLS`, `TRIGGERS_SINK`, and `RESOLVES_AT_RUNTIME` relationships.
  - **Vector Index:** Sub-token and camelCase-aware BM25 search index with JSON caching under `data/rag_storage/{apk_hash}/`.
  - **LLM Engine:** Dual-cloud provider with OpenRouter (`qwen/qwen-2.5-coder-32b-instruct`) and Groq (`llama-3.3-70b-versatile` / `llama-3.1-8b-instant`), plus deterministic local fallback.
  - **Frontend UI:** Dual-format access via dedicated full-page **`RAG Agent`** workspace and persistent floating quick drawer (`VajraAssistantDrawer`).
* **Delivered Tasks:**
  - [x] **Backend Hybrid GraphRAG Engine (`kavach_ai/backend/pipeline/stage6_synthesis/rag_engine.py`):**
    - Progressive multi-stage indexing: static slices $\to$ dynamic intercepts $\to$ forensic reports.
    - "Seed-and-Expand" multi-hop retrieval and smart model routing.
    - SSE streaming endpoint `POST /api/chat-rag`, status endpoint `GET /api/rag/status/{apk_hash}`, and on-the-fly hook synthesis `POST /api/rag/synthesize-hook`.
  - [x] **Frontend RAG Agent & Floating Drawer (`rag-agent-view.tsx`, `vajra-assistant-drawer.tsx`):**
    - Added **RAG Agent** sidebar navigation item under *Threat Analysis*.
    - Built zero-dependency custom `MarkdownRenderer.tsx` with syntax code blocks and 1-click copy.
    - Synchronized unified conversational state in `DetonationContext.tsx` across both the floating drawer and full workspace.
    - Dynamic welcome message summarizing target app profile, intended capabilities, and SecureBERT risk scorecard with zero emojis.
  - [x] **API Credentials Management (`api-credentials-view.tsx`):**
    - Added OpenRouter API key management card alongside Groq and VirusTotal.
  - [x] **Automated Test Suite (`kavach_ai/backend/tests/test_rag_engine.py`):**
    - Unit tests covering indexing, dynamic enrichment, multi-hop retrieval, model routing, and streaming passed 100%.

---

## Safety & System Constraints

1. **100% Additive Design:** All new GenAI modules hook into data outputs; the underlying extraction, slicing, and classification remain untouched.
2. **Zero Laptop Hardware Bottlenecks:** All heavy LLM inference routes through OpenRouter / Groq Cloud APIs (`temperature=0.1 - 0.2`), keeping the laptop completely free and responsive for the Android emulator and frontend UI.
3. **Graceful Fallback:** If cloud API keys are missing or offline, the local deterministic synthesis and core pipeline still complete and display static and dynamic results normally.
