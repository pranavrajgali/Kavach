# Kavach.ai: Static Analysis & SecureBERT-2.0 LoRA Walkthrough

This document provides a comprehensive technical walkthrough of the **Static Analysis and Deep Learning Inference Pipelines (Stages 1, 2, 3 & 5)** within Kavach.ai. It covers the architectural data flow, technology stack, sub-second in-memory Dalvik bytecode extraction, backward program slicing, FlowDroid V2 taint tracking, Ghidra native evidence parsing, Multi-Instance Learning (MIL), SecureBERT-2.0 model architecture with LoRA (Low-Rank Adaptation), Attention LRP (Layer-wise Relevance Propagation) explainability, and frontend visualization.

---

## 1. Architectural Architecture & Data Flow

The static analysis pipeline operates as a deterministic, high-throughput screening and semantic intelligence engine. When an APK is uploaded, it passes through sequential static triage, in-memory bytecode extraction, FlowDroid/Ghidra V2 behavioral analysis, and transformer classification stages before dynamic detonation.

```mermaid
sequenceDiagram
    participant Frontend as React SPA (Vite)
    participant Backend as FastAPI Server
    participant Triage as Stage 1: Manifest Triage Filter
    participant DEX as Stage 2A: High-Speed DEX Extractor
    participant FlowDroid as Stage 2B: FlowDroid V2 Sidecar
    participant Ghidra as Stage 2C: Ghidra Native Parser
    participant BERT as Stage 3: SecureBERT-2.0 LoRA & MIL
    participant LRP as Stage 5: Attention LRP & SHAP Engine

    Frontend->>Backend: POST /api/static-scan-stream (Upload APK)
    Backend->>Triage: fast_triage_apk(apk_bytes)
    
    rect rgb(20, 25, 35)
        Note over Triage: 10-Millisecond Triage Filter
        Triage->>Triage: Parse AndroidManifest.xml (Permissions & Components)
        Triage->>Triage: Classify Signature/Dangerous Permissions & High-Risk Combos
        Triage->>Triage: Compute Reflection & Obfuscation Density Score
    end
    
    Triage-->>Backend: TriageResult (Verdict, Score, Heuristics)
    Backend->>Frontend: Stream Stage 1 Triage Scorecard SSE

    rect rgb(25, 20, 30)
        Note over DEX, Ghidra: Sub-Second Slicing, FlowDroid Taint & Native JNI
        Backend->>DEX: extract_apk_slices(apk_path) [In-Memory DEX ~1.5s]
        DEX->>DEX: Parse Dalvik Bytecode via Androguard in RAM
        DEX->>DEX: Construct Call Graph & Backward Slices from Sensitive Sinks
        Backend->>FlowDroid: run_flowdroid(sidecar_jar, apk_path)
        FlowDroid->>FlowDroid: Jimple Inter-Procedural Taint Tracking (Sources/Sinks)
        Backend->>Ghidra: parse_native_evidence(so_libraries)
        Ghidra->>Ghidra: JNI Bridge Export Mappings & Native Symbol Dissassembly
    end

    DEX-->>Backend: Normalized Dalvik Program Slices
    FlowDroid-->>Backend: ManagedAnalysisArtifact (Taint Paths & Diagnostics)
    Ghidra-->>Backend: NativeEvidenceArtifact (JNI Symbols & Offsets)

    rect rgb(20, 30, 25)
        Note over BERT, LRP: SecureBERT-2.0 LoRA Inference & Attention LRP
        Backend->>BERT: predict_slices(normalized_slices)
        BERT->>BERT: Forward Pass (151M Base Frozen + 1.7M LoRA Adapters)
        BERT->>BERT: Multi-Instance Learning (MIL) Bag-Level Threat Aggregation
        BERT-->>Backend: Slice Threat Probabilities (0.0 to 1.0)
        
        Backend->>LRP: compute_attention_lrp(active_model, top_slices)
        LRP->>LRP: R = clamp(A ⊙ ∇A, min=0) [Layer-wise Relevance Propagation]
        LRP-->>Backend: Token Relevance Matrices & Interactive Code Heatmaps
    end

    Backend->>Frontend: Stream Result SSE (Static IR, Predictions, LRP Weights)
    Frontend->>Frontend: Render StaticView & BertClassifierView Dashboard
```

### 1.1. Static Analysis Subsystem Architecture

The pipeline divides cognitive responsibilities into specialized, bounded modules:

```mermaid
graph TD
    subgraph Input
        APK[Uploaded Android APK]
    end

    subgraph "Stage 1: Manifest Triage (<10ms)"
        TriageEng[Fast Triage Engine]
        PermMatrix[Dangerous Permission Matrix & Classification]
        ObfScan[Reflection & Obfuscation Density Scan]
        APK --> TriageEng
        TriageEng --> PermMatrix
        TriageEng --> ObfScan
    end

    subgraph "Stage 2: Decompilation, Taint Tracking & Native Slicing"
        InMemoryDEX[In-Memory DEX Extractor <1.5s]
        Slicer[Backward Program Slicer]
        FlowDroidSidecar[FlowDroid V2 Sidecar - Java Inter-procedural Taint]
        GhidraParser[Ghidra Native Parser - JNI Symbol Resolver]
        
        APK --> InMemoryDEX
        InMemoryDEX --> Slicer
        APK --> FlowDroidSidecar
        APK --> GhidraParser
    end

    subgraph "Stage 3 & 5: Deep Learning & Explainability"
        Norm[Smali Opcode Normalizer]
        BERT["SecureBERT-2.0 Base<br/>(151M Params - FROZEN)"]
        LoRA["LoRA Adapter Matrices (r=8)<br/>(1.7M Params - TRAINED)"]
        MIL["Multi-Instance Learning (MIL) Aggregator"]
        LRPEng["Attention LRP Token Attributor<br/>R = clamp(A ⊙ ∇A, min=0)"]
        
        Slicer --> Norm
        Norm --> BERT
        BERT --> LoRA
        LoRA --> MIL
        BERT --> LRPEng
    end

    subgraph Output Synthesis
        UI[Interactive React Static Dashboard & BERT Scorecard]
        TriageEng --> UI
        JNIParser --> UI
        ClassifierHead --> UI
        SHAPEng --> UI
    end
```

---

## 2. Technology Stack

The static analysis pipeline integrates high-performance reverse engineering utilities with transformer-based deep learning:

*   **Androguard & pyaxmlparser**: High-speed binary XML and manifest parsing, extracting package metadata, declared permissions, exported components, and intent filters in under 10ms.
*   **Dalvik & Smali Bytecode Slicing Engine**: Custom AST and Control Flow Graph (CFG) engine that performs backward dependency slicing from dangerous API sinks (SMS, Telephony, Accessibility, Process Execution).
*   **ELF Binary Parsers (`llvm-nm`, `nm`, `readelf`, `python_elf`)**: Multi-backend native symbol extractor resolving C/C++ exported functions in `.so` files to detect native JNI execution channels.
*   **PyTorch & Hugging Face Transformers**: Local execution engine for SecureBERT-2.0 transformer inference without external cloud dependencies.
*   **Hugging Face PEFT (Parameter-Efficient Fine-Tuning)**: Implements Low-Rank Adaptation (LoRA), keeping base transformer weights frozen while routing forward passes through lightweight adapter matrices ($r=8$).
*   **SHAP (SHapley Additive exPlanations)**: Sub-second token-level game-theoretic feature attribution mapping malicious versus benign tokens in Smali code.
*   **FastAPI & React/TypeScript (Vite)**: Asynchronous REST and Server-Sent Event (SSE) backend streaming static results to interactive scorecard components.

---

## 3. Detailed Script Analysis

The core static analysis pipeline scripts reside under:
* `kavach_ai/backend/pipeline/stage1_triage`
* `kavach_ai/backend/pipeline/stage2_static`
* `kavach_ai/backend/pipeline/stage3_ml`

### 3.1. Stage 1: Manifest Triage (`stage1_triage/triage.py`)
*   **File Link**: [triage.py](file:///c:/Users/Admin/Documents/Projects/Kavach/kavach_ai/backend/pipeline/stage1_triage/triage.py)
*   **Primary Responsibility**: Instant preliminary screening of APK metadata and permissions before executing compute-heavy decompilation.
*   **Core Mechanics**:
    1.  **10-Millisecond Triage Filter**: Unzips `AndroidManifest.xml` in memory without writing full uncompressed APK contents to disk.
    2.  **Permission Combination Heuristics**: Evaluates high-risk co-occurrences rather than isolated permissions:
        *   `BIND_ACCESSIBILITY_SERVICE` + `RECEIVE_SMS` + `SYSTEM_ALERT_WINDOW` $\rightarrow$ **Banking Trojan Indicator**.
        *   `REQUEST_INSTALL_PACKAGES` + `RECEIVE_BOOT_COMPLETED` $\rightarrow$ **Stealth Dropper Indicator**.
        *   `RECORD_AUDIO` + `CAMERA` + `READ_CONTACTS` + `ACCESS_FINE_LOCATION` $\rightarrow$ **Spyware Indicator**.
    3.  **Reflection & Obfuscation Density Scan**: Detects high concentrations of Java reflection APIs (`Class.forName`, `getMethod`, `method.invoke`) and high-entropy base64/hex strings, flagging APKs that intentionally obscure static signatures.

### 3.2. Stage 2A: Decompilation & Static Slicing (`stage2_static/decompile.py` & `stage3_ml/slicing.py`)
*   **File Links**: [decompile.py](file:///c:/Users/Admin/Documents/Projects/Kavach/kavach_ai/backend/pipeline/stage2_static/decompile.py), [slicing.py](file:///c:/Users/Admin/Documents/Projects/Kavach/kavach_ai/backend/pipeline/stage3_ml/slicing.py)
*   **Primary Responsibility**: Extracts executable bytecode, builds Control Flow Graphs (CFGs), and backward-slices code from high-risk API sinks.
*   **Core Mechanics**:
    1.  **Dangerous Sink Identification**: Identifies entry sinks matching sensitive Android APIs:
        *   `Landroid/telephony/SmsManager;->sendTextMessage` (SMS fraud / exfiltration)
        *   `Ljava/lang/Runtime;->exec` (Command injection)
        *   `Landroid/location/LocationManager;->getLastKnownLocation` (Surveillance)
        *   `Ldalvik/system/DexClassLoader;->loadClass` (Dynamic payload loading)
    2.  **Backward Program Slicing**: Traverses data-flow and control-flow dependencies backward from the sink up to $N$ hops (configurable depth), extracting only the instructions that directly influence arguments passed into dangerous calls.
    3.  **Smali Fallback Engine**: If full Java decompilation fails due to malformed ZIP headers, anti-decompilation tricks, or obfuscated CFGs, Kavach automatically falls back to raw Smali opcodes (`invoke-virtual`, `const-string`, `check-cast`), ensuring zero dropped samples.

### 3.3. Stage 2B: JNI & Native Library Bridge (`stage2_static/jni_bridge.py`)
*   **File Link**: [jni_bridge.py](file:///c:/Users/Admin/Documents/Projects/Kavach/kavach_ai/backend/pipeline/stage2_static/jni_bridge.py)
*   **Primary Responsibility**: Bounded, deterministic static analysis of native C/C++ shared libraries (`.so`) packaged inside the APK.
*   **Core Mechanics**:
    1.  **Mangled Symbol Resolution**:
        *   *Short Name*: `Java_com_example_app_MainActivity_nativeMethod`
        *   *Long Name (Overloaded)*: `Java_com_example_app_MainActivity_nativeMethod__I`
    2.  **Multi-Backend Symbol Extraction**: Leverages `llvm-nm`, `nm`, `readelf`, or custom `python_elf` parsers to extract symbol tables from ELF headers.
    3.  **Dynamic Registration Detection**: Scans `.rodata` and string tables for references to `RegisterNatives` or `JNI_OnLoad`, identifying apps that register native method addresses at runtime to evade static symbol matching.

### 3.4. Stage 3: Machine Learning Inference (`stage3_ml/inference.py`, `normalization.py`, `extractor.py`)
*   **File Links**: [inference.py](file:///c:/Users/Admin/Documents/Projects/Kavach/kavach_ai/backend/pipeline/stage3_ml/inference.py), [normalization.py](file:///c:/Users/Admin/Documents/Projects/Kavach/kavach_ai/backend/pipeline/stage3_ml/normalization.py), [extractor.py](file:///c:/Users/Admin/Documents/Projects/Kavach/kavach_ai/backend/pipeline/stage3_ml/extractor.py)
*   **Primary Responsibility**: Tokenizes normalized Smali slices, performs sub-second forward passes through the fine-tuned SecureBERT-2.0 transformer, and outputs calibrated threat probabilities.
*   **Core Mechanics**:
    1.  **Register & Opcode Normalization**: Maps arbitrary register names (`v0`, `v1`, `p0`) to standardized register tokens (`REG_VAR`, `REG_PARAM`) to prevent model overfitting on arbitrary compiler register assignments.
    2.  **Model Loading**: Loads base SecureBERT-2.0 architecture and applies fine-tuned LoRA adapter tensors from `weights/`.
    3.  **Rule-Based Fallback Classifier**: If GPU/PyTorch execution is unavailable, seamlessly activates a heuristic fallback engine matching opcode n-grams to maintain uninterrupted pipeline operation.

---

## 4. SecureBERT-2.0 & LoRA Architecture

Kavach.ai uses a customized transformer architecture specifically adapted for cybersecurity Smali analysis via **Low-Rank Adaptation (LoRA)**.

### 4.1. Mathematical Formulation of LoRA

In standard transformer fine-tuning, all parameters in weight matrix $W_0 \in \mathbb{R}^{d \times k}$ are updated ($W = W_0 + \Delta W$).

With LoRA, the base matrix $W_0$ is **100% frozen** (`requires_grad = False`). The weight update $\Delta W$ is decomposed into two low-rank matrices:

$$\Delta W = B \cdot A$$

where:
* $A \in \mathbb{R}^{r \times d}$ is the down-projection matrix (initialized with Gaussian distribution $\mathcal{N}(0, \sigma^2)$).
* $B \in \mathbb{R}^{k \times r}$ is the up-projection matrix (initialized to $0$).
* $r \ll \min(d, k)$ is the rank bottleneck ($r = 8$).

```mermaid
flowchart TD
    Input["Input Token Activations x"] --> BasePath["Base SecureBERT-2.0 W₀\n(151M Params - FROZEN: requires_grad=False)"]
    Input --> LoRA_A["Matrix A (Down-Projection: 768 × 8)\n(TRAINABLE: requires_grad=True)"]

    LoRA_A --> LoRA_B["Matrix B (Up-Projection: 8 × 768)\n(TRAINABLE: requires_grad=True)"]
    LoRA_B --> Scale["Scaling Factor (α / r = 16 / 8 = 2.0)"]

    BasePath --> Add(("Sum (+)"))
    Scale --> Add
    Add --> Output["Output Tensor h"]
```

Forward propagation computes:

$$h = W_0 x + \frac{\alpha}{r} (B \cdot A) x$$

This modifies the effective model outputs identically to full fine-tuning, while reducing trainable parameters by **over 98.8%** and keeping adapter checkpoints under **7 MB**.

---

### 4.2. Training Configurations & Hyperparameter Matrix

The model was trained across multiple configurations specified in [`training/configs/`](file:///c:/Users/Admin/Documents/Projects/Kavach/training/configs):

| Hyperparameter | `smoke.yaml` (Testing) | `train_balanced_1to1.yaml` | `train_full_weighted.yaml` (Production) |
| :--- | :--- | :--- | :--- |
| **Base Model** | `ehsanaghaei/SecureBERT` | `ehsanaghaei/SecureBERT` | `ehsanaghaei/SecureBERT` |
| **Base Parameters** | 151,000,000 (Frozen) | 151,000,000 (Frozen) | 151,000,000 (Frozen) |
| **LoRA Rank ($r$)** | 8 | 8 | 8 |
| **LoRA Alpha ($\alpha$)** | 16 | 16 | 16 |
| **LoRA Dropout** | 0.05 | 0.05 | 0.05 |
| **Target Modules** | `query`, `value`, `key`, `dense` | `query`, `value`, `key`, `dense` | `query`, `value`, `key`, `dense` |
| **Trainable Params** | 1,771,778 (1.16%) | 1,771,778 (1.16%) | 1,771,778 (1.16%) |
| **Adapter File Size** | ~6.8 MB | ~6.8 MB | ~6.8 MB |
| **Learning Rate** | $2.0 \times 10^{-4}$ | $2.0 \times 10^{-4}$ | $2.0 \times 10^{-4}$ |
| **LR Scheduler** | Cosine with Warmup | Cosine with Warmup | Cosine with Warmup |
| **Warmup Ratio** | 0.06 | 0.06 | 0.06 |
| **Max Sequence Length** | 512 tokens | 512 tokens | 512 tokens |
| **Batch Size (Per Device)**| 4 | 8 | 8 |
| **Gradient Accumulation** | 2 | 4 | 4 |
| **Positive Class Weight** | 1.0 | 1.0 | **3.5** (Penalizes false negatives) |
| **Precision** | FP16 / BF16 | FP16 / BF16 | FP16 / BF16 |
| **Training Epochs** | 1 | 5 | 8 |

---

## 5. Explainability Engine: Attention LRP & SHAP Token Attribution

To provide complete transparency to cybersecurity analysts, Kavach does not treat SecureBERT-2.0 as a black box. Stage 5 computes token-level Layer-wise Relevance Propagation (Attention LRP) and Shapley attribution values for every classified Smali slice:

### 5.1. Mathematical Formulation of Attention LRP
1. **Gradient-Weighted Attention Hooking**: Hooks into self-attention probability tensors ($A$) across model layers during backward pass.
2. **Relevance Backpropagation Equation**:
   $$R = \text{clamp}(A \odot \nabla_A, \min=0)$$
3. **Head Averaging & Column Reduction**:
   $$\bar{R}_{i,j} = \frac{1}{H} \sum_{h=1}^{H} R_{h,i,j} \quad \implies \quad \text{Attribution}(j) = \sum_{i} \bar{R}_{i,j}$$
4. **Token Attribution Mapping**:
   * **Positive Relevance (+)**: Glowing red/yellow highlights indicate tokens that strongly drove the classification toward **MALICIOUS** (e.g., `sendTextMessage`, `Cipher`, `DexClassLoader`, `getDeviceId`, `chmod 777`).
   * **Benign Traits**: Green/blue highlights indicate tokens characteristic of standard benign programming logic.

### 5.2. Interactive Frontend Heatmaps
* Rendered in the frontend using HSL-based colored glows in [`bert-classifier-view.tsx`](file:///c:/Users/Admin/Documents/Projects/Kavach/kavach_ai/frontend/src/components/views/bert-classifier-view.tsx), allowing analysts to inspect the exact lines of code and tokens that triggered the alert in sub-second time.

---

## 6. Frontend Telemetry Analysis & Consumption

The static analysis pipeline streams data into specialized interactive React components:

### 6.1. UI Components Breakdown
*   **Static View ([`static-view.tsx`](file:///c:/Users/Admin/Documents/Projects/Kavach/kavach_ai/frontend/src/components/static-view.tsx))**: Displays declared vs. used permissions, dangerous permission combination badges, reflection density gauges, and mapped native `.so` libraries.
*   **BERT Classifier View ([`bert-classifier-view.tsx`](file:///c:/Users/Admin/Documents/Projects/Kavach/kavach_ai/frontend/src/components/views/bert-classifier-view.tsx))**: Renders extracted Smali slices, model confidence scores, and interactive SHAP token heatmaps.
*   **Kavach Scorecard ([`kavach-scorecard.tsx`](file:///c:/Users/Admin/Documents/Projects/Kavach/kavach_ai/frontend/src/components/kavach-scorecard.tsx))**: Synthesizes static triage with ML scores to calculate the unified risk index.

---

## 7. MITRE ATT&CK & CERT-In Static Compliance Mapping

Static signals map directly into standard cybersecurity threat taxonomies:

| Static Indicator | MITRE ATT&CK Mobile Technique | CERT-In Security Mandate |
| :--- | :---: | :---: |
| `BIND_ACCESSIBILITY_SERVICE` + `SYSTEM_ALERT_WINDOW` | **T1417 / T1624** (Input Injection / Overlay) | **Sec 12.2** (Anti-Tampering & Accessibility Binds) |
| `SmsManager;->sendTextMessage` Slices | **T1582 / T1636** (SMS Exfiltration / Fraud) | **Sec 14.2** (Sensitive Data Transmission) |
| `DexClassLoader` Dynamic Loading | **T1407** (Download New Code at Runtime) | **Sec 8.4** (Integrity Verification of Code) |
| `Runtime;->exec` Shell Execution | **T1547** (Execution via System Command) | **Sec 12.1** (Process Privilege Boundaries) |
| Mangled JNI Native Execution (`.so`) | **T1629** (Execution through Native Code) | **Sec 10.3** (Binary Code Integrity Audit) |
