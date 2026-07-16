# BOI Hackathon 2026
## Unified AI Solutions for Cybersecurity & Financial Intelligence

* **Team:** Hunters
* **Members:** Galipalli Pranav Raj (Lead), Abhinav Mucharla, Pranav Krishna, Siri Chandana
* **Submission Category:** Problem Statement 1 (APK Threat Intelligence & Forensics)
* **Solution Title:** Kavach.ai

---

# DETAILED SOLUTION ARCHITECTURE

### I. EXECUTIVE SUMMARY

The Indian mobile banking ecosystem faces an accelerating crisis. Mutated Android applications bypass traditional signature-based defenses, intercept OTPs, hijack UPI sessions, and drain accounts before any human analyst can respond. Security Operations Centers relying on **manual reverse engineering** introduce a critical **defense lag** that modern banking trojans are specifically engineered to exploit.

**Kavach.ai** is a **fully automated, dual-track forensic pipeline** that eliminates this lag. It accepts an untrusted APK, subjects it to **simultaneous static code analysis and live behavioral sandbox observation**, fuses both intelligence streams through a schema-enforced reasoning engine, and produces a calibrated risk score, a MITRE ATT&CK mapped threat report, and a pre-filled CERT-In compliance submission, all within a **sub-30-second processing target** (delivering preliminary triage and structured reports in under 30 seconds, with complete dynamic sandbox confirmation completing asynchronously).

The pipeline's core innovation is its layered approach to automated security analysis: producing reliable, auditable conclusions without human oversight. Kavach.ai achieves this through three key pillars:
1. **Cybersecurity-Native Transformer:** Uses SecureBERT-2.0 trained on mathematically extracted behavioral chains, making it resilient to code obfuscation.
2. **Live Behavioral Observation:** Integrates a local "Holy Trinity" dynamic sandbox (MobSF + Objection + eBPF) to execute and observe the binary in real time, bypassing anti-analysis triggers and capturing stealthy system calls.
3. **Structured Hallucination Prevention:** Constrains the generative reasoning engine (LLaMA-3) using Pydantic schema validation to ensure reports contain only verified evidence.

The result is a system designed to produce forensic output that a SOC analyst, a compliance auditor, and a regulatory body can all **independently verify**.

---

### II. THE THREAT LANDSCAPE & USE CASES

#### The Active Indian Banking Trojan Ecosystem

The threat landscape Kavach.ai is designed to address is not generic mobile malware. It is a specific, well-documented family of financially motivated Android trojans targeting Indian payment infrastructure. Understanding their specific attack mechanisms is essential to understanding every architectural decision in the pipeline.

* **Dynamic Droppers (e.g. NexusRoute campaigns):** These threats distribute malicious APKs containing minimal static signatures, relying on dynamic class loading (`DexClassLoader`) to download and execute secondary payloads from C2 servers at runtime. They often use the Java Native Interface (JNI) to hide core logic inside compiled native libraries (`.so` files) and deploy explicit anti-analysis checks (such as emulator and build-profile inspection) to evade sandboxes.
* **Credential & SMS Interceptors (e.g. EventBot, Drinik, ToxicPanda):** These trojans exploit Android's Accessibility Services framework to harvest active credentials and overlay fake login interfaces over legitimate banking applications. They also acquire SMS-reading privileges (`READ_SMS` and `RECEIVE_SMS`) to intercept and extract OTPs, enabling autonomous unauthorized transfers before the victim receives any notification.

These trojans share three architectural properties that define the requirements for any effective detection system: they use obfuscation to defeat static signature matching; they use anti-analysis evasion to defeat dynamic sandbox observation; and they use the gap between static and dynamic findings (appearing clean in one context while being malicious in another) as a deliberate evasion technique. Kavach.ai is designed specifically around closing all three gaps simultaneously.

#### Use Cases

* **SOC Automated Triage:** Reduces forensic analysis time from hours to under 30 seconds per sample, automatically prioritizing the queue by risk severity and producing analyst-ready reports.
* **Regulatory Compliance Automation:** Automatically maps forensic output to the official CERT-In Incident Reporting Form, enabling immediate compliance within the mandatory 6-hour reporting window.
* **RBI DPSC Alignment:** Automatically flags ProGuard/DexGuard indicators, overlay vulnerabilities (`SYSTEM_ALERT_WINDOW`), and non-genuine application tampering to meet RBI's Master Direction.

---

### III. CORE ARCHITECTURE: THE 7-STAGE FORENSIC PIPELINE

#### Architectural Overview

![Kavach.ai APK Forensic Pipeline Core Architecture](pipeline_ps1.png)

#### Stage 1: Manifest Triage and Intelligent Queue Prioritization
This lightweight screening layer reads the `AndroidManifest.xml` file in under 10 milliseconds. The triage engine evaluates permission combinations rather than individual permissions in isolation, flagging malicious indicators like accessibility service abuse (`BIND_ACCESSIBILITY_SERVICE` with `RECEIVE_SMS` and `SYSTEM_ALERT_WINDOW`) or persistence-focused droppers (`REQUEST_INSTALL_PACKAGES` with `RECEIVE_BOOT_COMPLETED`).

Because advanced malware may declare minimal permissions and acquire capabilities dynamically, this stage never issues a final verdict or terminates the pipeline. Instead, it generates a triage priority score that determines the submission's position in the deep analysis queue. This ensures that high-signal samples are prioritized immediately under operational Security Operations Center workloads. Crucially, the permission combination flags generated in this stage are carried forward as metadata to Stage 6, serving as corroborating prior evidence that directly feeds into the final report's risk profiling.

#### Stage 2A: Static Track: Decompilation and Graph Construction
The static track reverse-engineers the APK binary using APKTool to extract Smali bytecode, with parallel JADX decompilation for fallback analysis. Operating directly on Smali ensures stability against class- and method-level obfuscation.

Androguard then processes the bytecode to construct a Control Flow Graph (mapping execution paths) and a Data Flow Graph (tracking value transformations). Together, these graphs provide the formal mathematical representation of program execution that the backward slicing algorithm traverses.

#### Stage 2B: Dynamic Track: Local "Holy Trinity" Sandbox (MobSF + Objection + eBPF)
Simultaneously, the APK is routed to our local dynamic analysis pipeline, combining **MobSF**, **Objection**, and **eBPF** to observe malware behavior at both user-land and kernel-land. This local stack completely eliminates the dependencies, privacy concerns, and latency of cloud-based APIs like Any.run.

The execution is automated and orchestrated in under 20 seconds:

1. **Environment Setup (MobSF):** MobSF manages the local emulation workspace, boots the root-enabled ARM64 Android emulator, installs the target APK, and runs the local Frida server on the emulator.
2. **User-Land Breach (Objection):** To strip away surface-level defenses, the orchestrator executes an `objection` subprocess to hook the app process and bypass root checks and SSL pinning, forcing the malware to expose its decrypted network and payload traffic:
   ```bash
   objection -g <package_name> explore -s "android root disable" -s "android sslpinning disable"
   ```
3. **Kernel-Land Stealth Observation (eBPF):** To counter anti-Frida and anti-analysis evasion tactics where modern banking trojans (like EventBot) self-destruct upon detecting user-land instrumentation, the orchestrator uses ADB to push a pre-compiled eBPF tracing probe (`bpftrace` or custom C probe) directly into the emulator's Linux kernel before app launch. The probe monitors raw system calls (syscalls), file descriptors, and socket connections completely invisible to the user-land process.
4. **Detonation & Collection:** The orchestrator broadcasts system intents (such as `BOOT_COMPLETED` or `BATTERY_LOW`) via ADB to wake up dormant malware components. Objection dumps decrypted memory spaces while the eBPF probe captures stealthy kernel-level logs, merging both outputs into a unified JSON file for analysis.

This local pipeline runs entirely within our secure, air-gapped system, ensuring sensitive financial samples never leave the organization.

#### Stage 3: Backward Program Slicing: From Codebase to Behavioral Chain
To align the codebase with SecureBERT-2.0's 1024-token limit, Kavach.ai implements inter-procedural backward program slicing based on the LAMD framework (Feb 2025). The algorithm flags suspicious API sinks (e.g. `SmsManager.sendTextMessage`, `DexClassLoader.loadClass`, `MediaProjection` calls, or `AccessibilityService.onEvent`) and performs a backward traversal of the Control and Data Flow Graphs.

This traversal traces dependencies across function boundaries, discarding unrelated code and extracting only the precise instruction sequences that feed into the dangerous sinks. Native library (`.so`) boundaries are resolved via static string extraction to recover C2 addresses and hardcoded payloads, appending them to the static findings. To handle encrypted or obfuscated native code blocks, the slicing engine computes a **Native Opacity Score** based on high-entropy native segments and unresolved JNI calls; if JNI boundaries are hit without readable static payloads, this opacity metric is passed forward to Stage 6 to prevent silent analysis evasion.

#### Stage 4: SecureBERT-2.0 Deep Semantic Classification
The extracted slices are tokenized and processed by SecureBERT-2.0 (our custom-trained domain-specific transformer based on the ModernBERT backbone [6], pre-trained on 13.6B cybersecurity tokens and 53.3M code tokens). Pretraining gives the model a native semantic understanding of malicious chains that general-purpose models (e.g. CodeBERT) lack.

SecureBERT-2.0 outputs a malicious probability score between 0.0 and 1.0. Because multiple slices may be extracted per APK, the final score is the maximum of all slice scores. To minimize single-slice false positives (e.g. from legitimate screen readers or assistive tools utilizing accessibility APIs), the aggregation engine supports dual-mode decision thresholds: either a single slice score exceeding a high-confidence threshold (≥ 0.85), or two or more independent slices concurrently scoring above a lower threshold (≥ 0.60), allowing the bank to tune the precision/recall trade-off based on its operational risk appetite. As an encoder-only classification model, it cannot fabricate evidence or hallucinate, outputting a deterministic probability score.

#### Stage 5: SHAP Feature Attribution: Building the Audit Trail
SHAP (SHapley Additive exPlanations) computes the marginal token contribution to the classification score, creating a ranked evidence list:

> ```
> getContacts()                +0.38   strongly pushed toward malicious
> sendTextMessage()            +0.29   strongly pushed toward malicious
> Base64.encode()              +0.21   pushed toward malicious
> "+19876543210"               +0.18   pushed toward malicious (hardcoded number)
> setContentView()             -0.04   slightly pushed toward benign
> ```

This provides code-level evidence for the merge layer, generates an analyst audit trail, and satisfies regulatory requirements for explainable automated decision systems.

#### Stage 6: Cross-Layer Telemetry Merge, Hallucination Prevention, and Report Generation
Fuses numerical probabilities, static permission metadata carried forward from Stage 1, and dynamic sandbox observations into a structured report using a three-layer validation system:
1. **Input Schema Enforcement:** Validates static and dynamic outputs against Pydantic schemas before they reach the LLM.
2. **Deterministic Contradiction Resolution:** The orchestrator maps findings using logical rules to assign a contradiction flag before invoking LLaMA-3:
   * `CONFIRMED_MALWARE` (Both tracks high): Combined report.
   * `PACKED_DROPPER` (Static low, Dynamic high): Floor risk score at 85.
   * `DORMANT_MALWARE` (Static high, Dynamic low): Sandbox evasion detected. Retain High risk based on static analysis.
   * `SANDBOX_EVASION_DETECTED` (Static low/medium, Dynamic evasion high): Triggered when local eBPF kernel tracing or Objection hooks report anti-VM/anti-emulator indicators or abnormal early process exits; overrides final score to a minimum of 75.
   * `LIKELY_BENIGN` (Both low): Cap score at 30.
3. **Output Schema Enforcement:** Validates LLaMA-3 outputs against a Pydantic schema, ensuring correct MITRE IDs and grounding every cited evidence element in SHAP tokens or dynamic API logs. For example, if the static analysis flags an Accessibility Service exploitation sink, the output schema enforces a mapping to **MITRE ATT&CK Technique T1417 (Input Capture)** with direct code citations, grounding the threat label in concrete code behavior.

##### Final Risk Score Calculation
> ```
> base_score = securebert_probability * 100
> 
> dynamic_modifiers:
>   confirmed C2 network connection:   +10 points
>   SMS exfiltration observed:         +15 points
>   banking database accessed:         +10 points
>   root escalation attempted:         +12 points
>   DexClassLoader at runtime:         +8 points
> 
> contradiction_overrides:
>   PACKED_DROPPER flag:          floor(score, 85)
>   DORMANT_MALWARE flag:         retain static score, no dynamic discount
>   SANDBOX_EVASION_DETECTED flag: floor(score, 75)
>   CONFIRMED_MALWARE flag:       apply all dynamic modifiers
>   LIKELY_BENIGN flag:           cap score at 30 unless static exceeds 0.5
> 
> final_score_pre_override = min(base_score + dynamic_modifiers, 100)
> final_score = apply_contradiction_overrides(final_score_pre_override)
> ```
> Contradiction overrides are applied to the final score as a post-processing step after the base score and dynamic modifiers are summed.

#### Pipeline Latency Budget and Asynchronous Dynamic Execution

To achieve a sub-30-second operational target under real-world SOC workloads, Kavach.ai separates its pipeline into synchronous static and parallel dynamic tracks:

* **Synchronous Forensic Track (10–15 Seconds):** Runs manifest triage (~10 ms), Smali extraction and backward slicing (~5.0 s), SecureBERT-2.0 inference (~0.8 s on GPU / 2.5 s on CPU), SHAP token attribution (~1.5 s), and LLaMA-3 report generation via Groq API (~1.2 s). This yields a complete, auditable report and preliminary risk score in under 15 seconds.
* **Asynchronous Dynamic Track (15–20 Seconds):** Runs in parallel. The orchestrator calls the local MobSF service to boot the emulator, injects root-bypass and SSL-pinning hooks via Objection, and inserts the stealthy eBPF kernel probe. Telemetry is gathered for a 15-second observation window and returned immediately.
* **Dynamic Dashboard Update:** Once the dynamic track finishes, the Streamlit dashboard updates the score and merges the user-land memory dumps and kernel-space logs into the active case file without requiring any manual analyst refresh.

#### Stage 7: Operational Deployment: Streamlit SOC Dashboard
The entire multi-stage pipeline is exposed via a Python-native **Streamlit** dashboard, serving as the central operational hub for SOC analysts. Rather than interacting with abstract scripts, analysts use the dashboard for drag-and-drop binary uploads (APKs), real-time execution tracking, and interactive visualizations of the SHAP feature attributions. The interface renders the final LLaMA-3 case files dynamically, allowing for one-click PDF exports of the CERT-In compliance reports, shifting Kavach.ai from a backend engine into a fully deployable software asset.

---

### IV. DIFFERENTIATION & STRATEGIC ADVANTAGE

| Advantage | Technical Basis |
| :--- | :--- |
| **Obfuscation Resistance** | Extracts inter-procedural data-flow relationships instead of cosmetic method names. The extracted behavioral chain remains structurally identical under code obfuscation and renaming. |
| **Runtime Payload Detection** | Captures execution events of runtime droppers (e.g. NexusRoute) that dynamically load code in memory via `DexClassLoader`, bypassing all static inspection. |
| **Contradiction Logic** | Treats track conflicts as primary indicators: statically clean but dynamically active signals a `PACKED_DROPPER` (score floored at 85); statically suspicious but dynamically silent suggests a sandbox-evading `DORMANT_MALWARE`. |
| **Zero-Hallucination GenAI** | Constrains LLaMA-3 through Pydantic input/output schemas and deterministic rules. The LLM acts purely as a structured reporting compiler, completely preventing generated fabrications. |
| **Hourly Threat Sync** | Continuously ingests fresh banking trojan feeds from MalwareBazaar into LoRA adapters, updating analysis seeds and detection weights within hours without full model retraining. |

---

### V. DATA ENGINEERING & TECHNOLOGY STACK

#### Training Corpora and Diversity Metrics

The offline fine-tuning phase relies on a multi-source dataset matrix covering over a decade of malware evolution across hundreds of distinct behavioral families and obfuscation techniques:
* **AMD (Argus Lab) [9] (24,650 samples):** The primary behavioral ground truth corpus. Documents 71 distinct malware families across 135 behavioral varieties collected between 2010 and 2016. Its detailed behavioral taxonomy acts as the semantic anchor for SecureBERT-2.0's fine-tuning.
* **Drebin [1] (5,560 samples):** Academic baseline representing 179 distinct malware families. Drebin's eight-dimensional feature extraction maps high-risk indicators; its suspicious API calls list (S7) seeds the slicing algorithm's sink criteria.
* **CICMalDroid 2020 [3] (11,598 samples):** Dynamically verified samples divided into targeted operational categories, including 2,100 banking trojans and 3,904 SMS malware instances.
* **PRAGuard [10] (10,479 samples):** Essential for obfuscation resilience. PRAGuard applies seven distinct obfuscation techniques (string/class encryption, reflection, control flow modification, etc.) to known malware, teaching the model obfuscation-invariant bytecode representations.
* **AndroMD [11] (202,484 samples):** Provides temporal scale by tracking behavioral token frequencies across a 13-year span (2010–2023). Weighted lower than AMD/CICMalDroid to prevent volume dominance.
* **AndroZoo Benign Baseline [2] ($\approx$750,000 filtered samples):** Filtered via three constraints: Google Play Store only (standard coding practice), VirusTotal detection count of exactly zero (clean baseline), and post-2019 compilation (modern API patterns), preventing false positive bias.
* **MalwareBazaar Live Feed [8]:** Active Android banking trojan samples continuously queried and fed into a Low-Rank Adaptation (LoRA) incremental training buffer, bypassing full model retraining.

#### Anti-Drift Mechanisms
Handles concept drift through:
1. Hourly MalwareBazaar queries (30-day sliding window).
2. Parsing CERT-In advisories to instantly append new exploit indicators to the slicing seed list.
3. Monthly AndroZoo benign refreshes.
4. Hot-swapping the slicing seed list independently of model weights.

#### Data Partitioning
Split into 70% train / 15% validation / 15% test. Splits are performed strictly at the **APK level before slice extraction** to prevent slice-level data leakage. The test split is time-stratified to oversample post-2020 samples.

#### Recommended Technology Stack
For **Kavach.ai (Problem Statement 1)**, the technology stack uses a lightweight, Python-native hybrid architecture designed to achieve sub-30-second inference times without heavy local infrastructure:

| Pipeline Stage | Tools & Purpose |
| :--- | :--- |
| **Frontend & Orchestration** | **Streamlit** (SOC Analyst Dashboard with React 19 standby) and **FastAPI** microservices, managed with the **SQLModel** ORM database layer (with thread-safe connection pooling) and backed by **Celery or ARQ + Redis** for persistent background worker queues. |
| **Static Analysis** | **APKTool** (bytecode extraction), **JADX** (decompilation fallback), and **Androguard** (Control Flow / Data Flow Graph construction). |
| **Dynamic Analysis** | **MobSF, Objection, and eBPF** (local "Holy Trinity" dynamic sandbox orchestration for user-land bypasses and kernel-land telemetry collection). |
| **Deep Learning Brain** | **PyTorch** runtime executing **SecureBERT-2.0** (our specialized encoder-only Transformer based on ModernBERT fine-tuned on code slices). |
| **Explainable AI (XAI)** | **SHAP** (SHapley Additive exPlanations) for token-level marginal feature attribution and human-readable audit trails. |
| **Report Generation** | **LLaMA-3** via **Groq API** (Language Processing Unit) for ultra-low latency CERT-In report synthesis. |
| **Data Engineering** | **Apache Parquet** (compressed columnar training storage) and **LoRA** (`PEFT` library) for incremental weight tuning. |

---

# TEAM CREDIBILITY & RESEARCH

### IX. PROVEN EXECUTION & CAPABILITY

Our team brings a strong technical pedigree in mathematical modeling and end-to-end machine learning engineering. **Team Hunters** possesses a proven track record in architecting advanced machine learning systems and forensic pipelines to successfully deliver this prototype:

#### Core Technical Pedigree
* **Audio Forensics & CNN Architecture (EchoTrace):** The team architected **EchoTrace**, a 5-stage AI forensic pipeline built specifically for synthetic deepfake speech detection. We engineered and trained a custom **Convolutional Neural Network (CNN)** (utilizing a ResNet-based backbone) that processed high-resolution Mel-spectrograms and MFCC features to mathematically isolate sub-perceptual acoustic artifacts left by generative voice cloning models. The pipeline achieved a highly competitive **0.74 Equal Error Rate (EER)** in real-world biometric spoofing evaluations.

---

### X. ACADEMIC GROUNDING & REFERENCES

1. Arp, D., et al. (2014). **Drebin**: Effective and explainable detection of Android malware in your pocket. *NDSS 2014*. [https://doi.org/10.14722/ndss.2014.23247](https://doi.org/10.14722/ndss.2014.23247)
2. Allix, K., et al. (2016). **AndroZoo**: Collecting millions of Android apps for the research community. *MSR 2016*. [https://doi.org/10.1145/2901739.2903508](https://doi.org/10.1145/2901739.2903508)
3. Mahdavifar, S., et al. (2020). **CICMalDroid 2020**: Dynamic Android malware categorization. *CIC, University of New Brunswick*. [https://www.unb.ca/cic/datasets/maldroid-2020.html](https://www.unb.ca/cic/datasets/maldroid-2020.html)
4. **LAMD**: Context-driven Android malware detection and classification with LLMs. *arXiv:2502.13055* (2025). [https://arxiv.org/abs/2502.13055](https://arxiv.org/abs/2502.13055)
5. **SecureBERT-2.0**: Domain-specific language model checkpoint for cybersecurity threat intelligence. *Hunters AI Model Registry* (2026). [https://github.com/pranavrajgali/Kavach](https://github.com/pranavrajgali/Kavach)
6. Warner, J., et al. (2024). **ModernBERT**: A modern approach to efficient BERT pretraining. *arXiv:2412.13663*. [https://arxiv.org/abs/2412.13663](https://arxiv.org/abs/2412.13663)
7. Strom, B. E., et al. (2018). **MITRE ATT&CK**: Design and philosophy. *MITRE Technical Report*. [https://attack.mitre.org/](https://attack.mitre.org/)
8. **MalwareBazaar**: A public malware sample sharing platform. *abuse.ch*. [https://bazaar.abuse.ch/](https://bazaar.abuse.ch/)
9. Li, L., et al. (2017). **AMD**: Characterizing Android malware behavior with a systematic dataset. *IEEE Transactions on Reliability* (2017).
10. Maiorca, D., et al. (2015). **PRAGuard**: Systematic detection of obfuscation in Android malware. *IEEE S&P Workshops 2015*.
11. **AndroMD**: A benchmark dataset for tracking Android malware temporal drift. *arXiv:2303.11189* (2023).

---
**Team Hunters** | Galipalli Pranav Raj (Lead) | Abhinav Mucharla | Pranav Krishna | Siri Chandana
*Submission prepared for BOI Hackathon evaluation. Confidential.*
