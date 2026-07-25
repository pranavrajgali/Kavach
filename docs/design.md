# Kavach.ai UI/UX Design Specification & Architecture

This document outlines the visual identity, styling framework, and interface architecture of **Kavach.ai**. It details the design system, grid patterns, charting specifications, and backend data bindings. This spec serves as a reference for slide decks, technical pitches, product briefings, and implementation guides.

---

## 1. Executive Vision: Modern SOC Intelligence
The interface of Kavach.ai is built to mimic state-of-the-art Security Operation Center (SOC) terminals. By transitioning from a prototype Streamlit view to a **React 19 single-page application (SPA)**, the frontend achieves:
* **Zero Layout Shifting**: Fixed widths, constrained bounds, and static sidebars prevent UI elements from shifting as data streams in.
* **Low-Latency Rendering**: Direct canvas rendering for charts allows large dynamic telemetry vectors to populate instantly.
* **Military-Grade Theme**: A high-contrast obsidian aesthetic with sharp corners, precise 1px borders, and curated color indicators.

```
+-------------------------------------------------------------------------+
| [Kavach Grid Logo]                                                      |
| THREAT ANALYSIS       Sandbox Forensic Dashboard                        |
| - Dynamic Sandbox     +-----------------------------------------------+ |
| - Static & JNI        | Verdict  | Size     | Bypasses | Signals      | |
| - BERT ML             +----------+----------+----------+--------------+ |
| - MITRE Map           | Forensic Attributions | Streams               | |
|                       | (Vertical Bar)        | (Step Area)           | |
| COMPLIANCE            +-----------------------+-----------------------+ |
| - Audit Reports       | SHAP Feature          | Behavioral Risk       | |
| - CERT-In Templates   | (Horizontal Red/Blue) | (Radar Matrix)        | |
| - Sandbox Health      +-----------------------+-----------------------+ |
|                       | Interactive Data Tabs:                        | |
| STATUS: Simulation    | [Files]  [JNI]  [BERT]  [MITRE]  [CERT-In]    | |
|                       +-----------------------------------------------+ |
+-------------------------------------------------------------------------+
```

---

## 2. The Design System (Tailwind CSS v4 Spec)

Kavach structures its design system variables inside the modern `@theme` directive in `src/index.css`.

### A. Color Palette Psychology
To ensure visual consistency and high contrast, the color system relies on five target variables:
* **Base Canvas Background**: `#09090b` (Deep Zinc dark backdrop).
* **Card Panels**: `#121215` (Slightly lighter zinc paneling to establish depth).
* **Borders & Dividers**: `#27272a` (Crisp 1px border lines).
* **Benign / Baseline Color**: `#1d4ed8` (Darker Cobalt Blue - maps to normal syscalls, security baselines, and safety scores).
* **Threat / Malicious Color**: `#b91c1c` (Darker Crimson Red - maps to root bypasses, signature detections, and risk attributions).

### B. Typography & Text Hierarchy
* **Primary Font**: `Inter` (sans-serif) loaded via system fallback.
* **Code/Telemetry Font**: `JetBrains Mono` or default monospace for decompiled code blocks and file paths.
* **Sizes**:
  - `Titles / Verdicts`: `24px` (`text-2xl`), font weight `800` (extra-bold).
  - `Subheaders / Chart Titles`: `14px` (`text-sm`), font weight `700` (bold).
  - `Body / Metadata Text`: `12px` (`text-xs`), font weight `500` (medium).
  - `Table Paths / Smali logs`: `10px` / `11px` (`text-[10px]`), font weight `400` (regular, mono).

### C. Sharp Corner Constraint (Rounded-None)
To create a clean grid interface, **all border-radii are overridden to 0px**. Rounded corners are removed in favor of sharp, flush bounds:
```css
:root {
  --radius-lg: 0px;
  --radius-md: 0px;
  --radius-sm: 0px;
  --radius: 0px;
}
```

---

## 3. Layout Grid Architecture

The page employs a **Locked Viewport Layout** preventing outer page scrolling:
```html
<div className="flex h-screen overflow-hidden bg-background text-foreground">
```

### A. Static Navigation Sidebar (Left Column)
* **Dimensions**: Width is locked to `w-64` (`16rem`) and configured to prevent compression under dynamic canvas resizing: `shrink-0`.
* **Behavior**: Static positioning. It does not scroll with main content.
* **Hierarchy**:
  1. **Branding Logo**: Flat text `Kavach` adjacent to a simple grid icon.
  2. **Threat Analysis Links**: Provides placeholders for Sandbox, Static Scan, ML Classifier, and MITRE Map.
  3. **Compliance Links**: Paths for Audit Reports, CERT-In Forms, and Sandbox System Health.
  4. **Dynamic Status Controller**: Tracks connection state (Simulation Mode vs Device Attached) via a dynamic status dot.
  5. **Changelog**: Holds latest updates.

### B. Independent Content Viewport (Right Column)
* **Scrolling**: The viewport container utilizes `flex-1 overflow-y-auto`, ensuring only the dashboard cards and lists scroll vertically when content overflows the screen boundary.
* **Layout**: Wrapped in a `max-w-[1400px] w-full mx-auto p-8` container.

---

## 4. Recharts Visualization Specifications

The dashboard integrates four analytical charts designed using SVG responsive containers.

### A. Forensic Attributions Bar Chart
* **Purpose**: Compares signal volumes across dynamic categories.
* **X-Axis Categories**: `Syscalls`, `File I/O`, `Sockets`, `Bypasses`, `Hooks`.
* **Fill Specification**: Uses a vertical linear gradient transitioning from white/silver to translucent dark gray:
  ```xml
  <linearGradient id="silverBar" x1="0" y1="0" x2="0" y2="1">
    <stop offset="0%" stopColor="#fafafa" stopOpacity={0.85} />
    <stop offset="100%" stopColor="#fafafa" stopOpacity={0.02} />
  </linearGradient>
  ```
* **Styling**: Flat corners (radius = 0), tick font size 10px, dark gray axis lines.

### B. Instrumentation Streams Step Area Chart
* **Purpose**: Displays system execution calls recorded over the 10-second run window.
* **X-Axis Phases**: `0s (Init)`, `2s (Install)`, `4s (Inject)`, `6s (Bypass)`, `8s (Intents)`, `10s (Trace)`.
* **Lines**:
  - **TCP Stream**: White line (`stroke="#fafafa"`, `strokeWidth={1.5}`) with a light blue fill gradient (`#3b82f6` at `0.2` opacity).
  - **UDP Stream**: Dark gray line (`stroke="#52525b"`) with zero fill.
* **Type**: `step` rendering (creating a stepped digital signal visual).

### C. SHAP Feature Attribution Horizontal Bar Chart
* **Purpose**: Illustrates token-level feature influence on the final model classification.
* **Y-Axis**: Extracted Smali feature hooks (e.g. `Frida Root Bypass`, `Rev Shell :4444`, `sys_clone`).
* **Visual Encoding (Red vs Blue)**:
  - Malicious inputs (positive contribution) = Crimson Red (`#b91c1c`).
  - Benign baselines (negative contribution) = Cobalt Blue (`#1d4ed8`).
* **Implementation Code**:
  ```tsx
  <Bar dataKey="value" radius={0}>
    {sortedShapData.map((entry, index) => (
      <Cell key={`cell-${index}`} fill={entry.value > 0 ? '#b91c1c' : '#1d4ed8'} />
    ))}
  </Bar>
  ```

### D. Behavioral Risk Matrix Polar Radar Chart
* **Purpose**: Profiles risk scores across six key mobile malware execution vectors.
* **6 Vectors**: `Data Theft`, `Financial Fraud`, `Persistence`, `Privilege Escalation`, `Evasion`, `Command & Control`.
* **Radar Fill**: Crimson Red (`#b91c1c`) boundary outline with a translucent crimson overlay (`fillOpacity={0.15}`).

---

## 5. Interactive Forensic Tabs

The bottom half of the dashboard contains an interactive **tab switcher** allowing users to drill down into the datasets compiled during the detonation process:

| Tab Name | Data Fields Displayed | Primary Metrics |
| :--- | :--- | :--- |
| **File Interactions** | Target system file paths, operation types, and dynamic security warning classes. | System Reads, Prefs writes. |
| **JNI & Native Scan** | Extracted compiled binaries (`.so`), arm64 vs armv7, and byte signature warnings. | Frida bypass libraries, decryption bridges. |
| **SecureBERT Slices** | Smali code instruction blocks isolated via backward program slicing sinks. | Class loader overrides, SMS handler hooks. |
| **MITRE ATT&CK Map** | Techniques, Tactics, and dynamic detonation triggers mapping back to MITRE matrix. | Evasion, Privilege Escalation codes. |
| **CERT-In Readiness** | Audit requirements, compliance parameters, and readiness checks. | Sec 12.2 and 14.5 compliance flags. |

---

## 6. Data Streaming & FastAPI Bridge Specs

To avoid interface blocking during analysis, the system decouples API and frontend execution states:
* **The Upload Vault**: When an APK is uploaded, the FastAPI backend records it in PostgreSQL and immediately issues a `Job ID` payload.
* **Dynamic Log Streaming**: The React frontend connects to a Server-Sent Events (SSE) `/api/detonate-stream?job_id={id}` endpoint.
* **The Log Terminal**: Dynamically captures stdout logs, parses indicators, and updates the UI milestone tree (e.g., *Initializing eBPF hooks*, *Injecting Frida*) in sync with the Recharts timelines.
* **Export Action**: Bundles the dynamically merged telemetry into a standard JSON file payload downloaded directly via browser-native streams.
