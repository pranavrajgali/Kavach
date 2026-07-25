# Kavach.ai: Dynamic Analysis & Sandbox Detonation Walkthrough

This document provides a comprehensive technical walkthrough of the **Dynamic Analysis Pipeline (Stage 4)** within Kavach.ai. It covers the architecture, the technology stack, the role of each script, how they gather system telemetry, and how they stream and visualize that data in the React frontend.

---

## 1. Architectural Architecture & Data Flow

The Kavach.ai dynamic analysis phase operates as a reactive sandbox detonation system. When an APK is uploaded, it is routed to a physical or simulated Android environment where its runtime behaviors are monitored.

```mermaid
sequence Diagram
    participant Frontend as React SPA (Vite)
    participant Backend as FastAPI Server
    participant Detonator as DetonationOrchestrator
    participant Frida as Frida Hooking Engine
    participant eBPF as eBPF Kernel Tracker
    participant Emulator as Android Device (ADB)

    Frontend->>Backend: POST /api/detonate-stream (Upload APK)
    Backend->>Backend: Save Temp APK & Resolve Package ID
    Backend->>Frontend: Send Metadata SSE Event (Name, Size, Package)
    
    rect rgb(20, 20, 25)
        Note over Backend, Emulator: Detonation Sequence Started
        Backend->>eBPF: start_trace(package_name)
        eBPF->>eBPF: Initialize Syscall / File / Socket Tracing
        Backend->>Detonator: detonate_apk()
        Detonator->>Emulator: adb install -r apk_path
        Detonator->>Frida: frida -U -f package -l frida_bypass.js
        Frida->>Emulator: Inject Anti-Root & SSL Bypasses
        Detonator->>Emulator: Broadcast Intents (BOOT_COMPLETED, BATTERY_LOW)
        Detonator->>Emulator: Observe telemetry for duration (10s)
    end

    eBPF->>Backend: Dump Telemetry Payload to telemetry.json
    Detonator->>Emulator: adb uninstall package
    Detonator->>Frida: Terminate Session
    
    Backend->>Frontend: Send Log SSE Events (Real-time Console Logs)
    Backend->>Frontend: Send Result SSE Event (telemetry.json Payload)
    Frontend->>Frontend: Update UI and render ReportView Dashboard
```

---

## 2. Technology Stack

The dynamic analysis pipeline integrates several specialized security and systems-level tools:

*   **FastAPI (Python 3)**: Serves as the high-throughput backend gateway. It processes incoming multipart/form-data APK uploads, spawns asynchronous tasks using `asyncio.to_thread`, redirects pipeline logger output thread-safely into an `asyncio.Queue` using a custom `AsyncQueueHandler`, and streams live log events to the frontend via **Server-Sent Events (SSE / EventSource)**.
*   **Android Debug Bridge (ADB)**: Acts as the command bridge to target devices/emulators. It installs the application, launches core activities, broadcasts hardware-level intents, and uninstalls the app upon compilation.
*   **Frida**: A dynamic instrumentation toolkit. Used to inject JavaScript hooks into the Dalvik/ART runtime at app-startup to override security checks.
*   **eBPF (Extended Berkeley Packet Filter)**: Operates at the Linux/Android kernel level. It hooks system calls (`sys_clone`, `sys_connect`, `sys_openat`) to track file I/O and network sockets invisibly, bypassing user-space tampering.
*   **React & TypeScript (Vite)**: The user-facing dashboard. Uses SSE streams to show live logs in an interactive terminal, parses telemetry data, calculates risk indexes, and draws analytical graphs using **Recharts**.

---

## 3. Detailed Script Analysis (Dynamic Side)

The core dynamic pipeline scripts reside under [kavach_ai/backend/pipeline/stage4_dynamic](file:///c:/Users/Admin/Documents/Projects/Kavach/kavach_ai/backend/pipeline/stage4_dynamic).

### 3.1. Stage 4 Pipeline Orchestrator: `__init__.py`
*   **File Link**: [__init__.py](file:///c:/Users/Admin/Documents/Projects/Kavach/kavach_ai/backend/pipeline/stage4_dynamic/__init__.py)
*   **Primary Responsibility**: Coordinates the tracking and detonation modules.
*   **Core Logic**:
    1.  Resolves paths for local outputs (`telemetry.json`) and the Frida scripts.
    2.  Instantiates `EBPFTracker` and triggers kernel tracing by calling `tracker.start_trace(package_name)`.
    3.  Instantiates `DetonationOrchestrator` and runs `detonate_apk` with the path to the APK and the target package.
    4.  Once detonation finishes, it reads `telemetry.json`, checks if it exists, parses the JSON payload, and returns it to the caller.

### 3.2. Detonation Orchestrator: `detonate.py`
*   **File Link**: [detonate.py](file:///c:/Users/Admin/Documents/Projects/Kavach/kavach_ai/backend/pipeline/stage4_dynamic/detonate.py)
*   **Primary Responsibility**: Manages the Android lifecycle (ADB calls, Frida processes, intent broadcasts).
*   **Core Operations**:
    *   `_check_device_connected`: Runs `adb devices` to identify if an active emulator/device is connected. If none is found, it logs a warning and shifts into a high-fidelity **Simulation Mode** to prevent execution crashes during sandbox dry runs.
    *   `install_apk` / `uninstall_apk`: Runs subprocess commands `adb install -r <apk>` and `adb uninstall <package>` to handle application deployment.
    *   `spawn_frida_session`: Starts Frida in a background daemon via `subprocess.Popen` using command arguments: `frida -U -f <package_name> -l <script_path> --no-pause`.
    *   `trigger_intents`: Executes activity manager shell commands (`am broadcast`) to simulate events that activate banking malware:
        *   `android.intent.action.BOOT_COMPLETED` (Autostart triggers)
        *   `android.intent.action.BATTERY_LOW` (Triggers used by trojans to request permissions under power-saving cover)
        *   `monkey` launcher: Forces the main user-space activity to start.
    *   `detonate_apk`: Orchestrates the sequence synchronously:
        `Install` $\rightarrow$ `Spawn Frida Hooks` $\rightarrow$ `Wait 3s (Injection Window)` $\rightarrow$ `Trigger Intents` $\rightarrow$ `Wait 10s (Observation Window)` $\rightarrow$ `Terminate Frida` $\rightarrow$ `Uninstall App`.

### 3.3. eBPF Tracker: `scripts/ebpf_trace.py`
*   **File Link**: [ebpf_trace.py](file:///c:/Users/Admin/Documents/Projects/Kavach/kavach_ai/backend/pipeline/stage4_dynamic/scripts/ebpf_trace.py)
*   **Primary Responsibility**: Tracks system calls, socket creation, and filesystem access.
*   **Core Operations**:
    *   `check_ebpf_support`: Inspects `/sys/kernel/debug/tracing`. On standard development systems (e.g., Windows development environments), this returns `False`, initiating the simulated telemetry path.
    *   `generate_mock_telemetry`: Constructs high-fidelity trace data mirroring real Android malware behavior:
        *   **Syscalls**: System clones, execve commands, sockets, and writes.
        *   **Files Accessed**: Reads to proc mapping files (`/proc/self/maps`), system binaries (`/system/bin/app_process32`), and write operations inside the application sandbox (`/data/user/0/<package>/shared_prefs/config.xml`).
        *   **Network Connections**: Direct socket calls to Command & Control (C2) hosts (`198.51.100.42:4444` via TCP) and standard DNS lookups (`8.8.8.8:53` via UDP).
    *   `start_trace`: Writes the gathered telemetry to `telemetry.json`.

### 3.4. Frida Hook Script: `scripts/frida_bypass.js`
*   **File Link**: [frida_bypass.js](file:///c:/Users/Admin/Documents/Projects/Kavach/kavach_ai/backend/pipeline/stage4_dynamic/scripts/frida_bypass.js)
*   **Primary Responsibility**: Deactivates anti-sandboxing controls (Root-checking and SSL Pinning) so the application executes its true payload.
*   **Hooks Implemented**:
    1.  **File existence check override (`java.io.File.exists`)**: Intercepts paths matching root binaries (`su`, `busybox`, `SuperSU`, `Superuser.apk`) and forces a `false` return.
    2.  **Runtime command execution override (`java.lang.Runtime.exec`)**: Blocks commands executing `su` or `busybox` and throws a fake `IOException` to simulate a standard non-rooted environment.
    3.  **System build property spoof (`android.os.SystemProperties.get`)**: Intercepts requests for `ro.build.tags` and rewrites `test-keys` (indicating custom/rooted ROMs) to `release-keys`.
    4.  **SSL TrustManager Override (`javax.net.ssl.SSLContext.init`)**: Registers a custom `X509TrustManager` that skips certification verification, allowing HTTP proxies (like Mitmproxy or MobSF) to capture encrypted traffic.
    5.  **OkHttp3 Pinning Bypass (`okhttp3.CertificatePinner.check`)**: Attempts to locate OkHttp class definitions within the active classloader and nullifies the pinning checker.

---

## 4. Frontend-Backend Communication Flow (SSE)

Real-time terminal execution logging is achieved using Server-Sent Events (SSE).

### Backend Streaming Endpoint: `main.py`
*   **File Link**: [main.py](file:///c:/Users/Admin/Documents/Projects/Kavach/kavach_ai/backend/app/main.py)
*   **Endpoint**: `POST /api/detonate-stream?simulation={true/false}`
*   **Logic**:
    1.  Saves the incoming file streams to a temporary `.apk` file.
    2.  Resolves the APK's package identifier using `pyaxmlparser`/`androguard`.
    3.  Yields a `metadata` event structured as:
        ```json
        { "type": "metadata", "apk_details": { "name": "...", "size": "...", "package": "..." } }
        ```
    4.  **Log Interception**: Attaches an `AsyncQueueHandler` to the system loggers (`KavachDetonator`, `KavachPipelineStage4`, `KavacheBPF`). When these components print logs, the handler thread-safely pushes them to `asyncio.Queue`.
    5.  **Streaming Loop**: Yields log lines as SSE events:
        ```text
        data: {"type": "log", "message": "Installing APK..."}
        ```
    6.  **Results Yield**: Once the task terminates, it retrieves the final parsed telemetry dictionary and sends the `result` event:
        ```json
        { "type": "result", "telemetry": { ... } }
        ```

### Frontend Event Source Reader: `DetonationContext.tsx`
*   **File Link**: [DetonationContext.tsx](file:///c:/Users/Admin/Documents/Projects/Kavach/kavach_ai/frontend/src/context/DetonationContext.tsx)
*   **Mechanism**:
    *   Instead of polling, the frontend reads the streaming body directly using `response.body.getReader()`.
    *   As chunks arrive, they are decoded using `TextDecoder` and split by the event boundary `\n\n`.
    *   Parsed payloads trigger React state updates:
        *   `type: 'log'` $\rightarrow$ Appends to `logs` state (rendered dynamically in `TerminalConsole`).
        *   `type: 'metadata'` $\rightarrow$ Sets `apkDetails` state.
        *   `type: 'result'` $\rightarrow$ Saves the telemetry payload to `telemetry` and changes state to `completed`.
        *   `type: 'error'` $\rightarrow$ Logs the stack trace and sets state to `error`.

---

## 5. Frontend Telemetry Analysis & Consumption

Once the backend streams the `result` payload, the [report-view.tsx](file:///c:/Users/Admin/Documents/Projects/Kavach/kavach_ai/frontend/src/components/report-view.tsx) dashboard parses the telemetry to generate intelligence widgets.

### 5.1. Threat Score Calculation
The frontend computes a dynamic risk score (`probability`) at runtime based on the telemetry parameters:
*   **Base Score**: Starts at `0.05` (5%).
*   **Frida Hook Triggers**: Adds `0.35` if Root bypass hooks were triggered (`objection_root_bypass`) and `0.30` if SSL bypasses occurred (`objection_ssl_pinning_bypass`).
*   **File I/O Signals**: Inspects directories accessed. System path reads (e.g., `app_process`, `/system`) increase the threat score by `0.25` each. Internal config/preference directory reads add `0.15` each.
*   **Network Vectors**: Socket connections on reverse-shell ports (such as `4444`) increase the score by `0.45`. Other standard connection requests add `0.10`.
*   **Verdict Classification**:
    *   `score > 0.65` $\rightarrow$ **MALICIOUS** (Red highlighting)
    *   `0.30 < score <= 0.65` $\rightarrow$ **SUSPICIOUS** (Amber highlighting)
    *   `score <= 0.30` $\rightarrow$ **CLEAN** (Emerald highlighting)

### 5.2. Visual Charts (Recharts)
*   **Forensic Attributions**: Bar chart mapping security categories. Values are derived from telemetry array sizes (e.g., socket counts, syscall frequencies).
*   **Instrumentation Streams**: Area chart showing step-by-step socket connections (TCP/UDP) over the 10-second run window.
*   **SHAP Feature Attribution**: Horizontal bar chart comparing positive (malicious) and negative (benign) features. Frida bypasses, reverse-shell sockets, and core file operations are plotted with red bars, while standard calls (like DNS resolution or cloning) are plotted with blue bars.
*   **Behavioral Risk Matrix**: Radar chart mapping normalized risk vectors: Data Theft, Financial Fraud, Persistence, Privilege Escalation, Evasion, and Command & Control (C2) based on dynamic behaviors.

### 5.3. Pipeline Tab Items
The dynamic telemetry is mapped directly to corresponding UI views:
1.  **File Interactions**: Directly displays the paths accessed from `telemetry.ebpf_telemetry.files_accessed` in a table. It marks system file reads as high severity and config file accesses as medium severity.
2.  **JNI & Native Scan**: Shows the dynamically mapped shared objects (.so) loaded during instrumentation (such as `libobjection.so` used for hooking).
3.  **SecureBERT Slices**: Shows decompiled Smali code slices matched by the machine learning pipeline alongside their classifier probability scores.
4.  **MITRE ATT&CK Map**: Maps behavioral indicators to official MITRE techniques:
    *   `objection_ssl_pinning_bypass` $\rightarrow$ **T1112** (Modify System Preferences / Defense Evasion)
    *   `objection_root_bypass` $\rightarrow$ **T1055** (Process Injection / Privilege Escalation)
    *   `port: 4444` $\rightarrow$ **T1020** (Automated Exfiltration / Socket Binding)
5.  **CERT-In Readiness**: Visualizes compliance audits:
    *   Bypassed root safeguards flag a failure under **CERT-In Sec 12.2** (Anti-Rooting Security Binds).
    *   Bypassed SSL pinning flags a failure under **CERT-In Sec 14.5** (HTTPS SSL Certificate Verification).
    *   Encrypted DB files map to a success under **CERT-In Sec 8.1**.
