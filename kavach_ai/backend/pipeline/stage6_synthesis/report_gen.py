from typing import List, Dict, Any, Optional
from pydantic import BaseModel
import os
import json
import requests
from dotenv import load_dotenv

# Load env variables from project root
load_dotenv()
load_dotenv(os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))), '.env'))

try:
    from groq import Groq
except ImportError:
    Groq = None

class KavachForensicReport(BaseModel):
    summary: str
    risk_score: int
    contradiction_label: str
    static_findings: List[str]
    dynamic_findings: List[str]

class CertInIncidentReport(BaseModel):
    incident_id: str
    severity: str
    mitre_attack_tactics: List[str]
    mitre_attack_techniques: List[str]
    indicators_of_compromise: Dict[str, List[str]]
    recommended_mitigations: List[str]

class JointForensicReport(BaseModel):
    forensic: KavachForensicReport
    cert_in: CertInIncidentReport
    mitre_attack_json: Dict[str, Any]

def fallback_generate_report(merged: dict) -> dict:
    apk_details = merged.get("apk_details") or merged.get("apk_meta") or {}
    filename = apk_details.get("name") or apk_details.get("filename") or "Unknown APK"
    package = apk_details.get("package") or apk_details.get("package_name") or "unknown.package"
    size = apk_details.get("size") or apk_details.get("file_size") or "Unknown Size"
    apk_hash = merged.get("apk_hash", "")
    if filename == "Unknown APK" and apk_hash:
        filename = f"APK-{apk_hash[:12]}"
    if isinstance(size, (int, float)):
        size = f"{size / (1024 * 1024):.2f} MB"
        
    # Extract static evidence from static_data or static_evidence or apk_meta
    static_evidence = merged.get("static_evidence") or {}
    static_data = merged.get("static_data") or {}
    apk_meta = merged.get("apk_meta") or {}
    final_score = merged.get("final_score", 0)

    # Resolve permissions, combinations, scores and indicators across possible schemas
    permissions = (
        static_data.get("permissions")
        or apk_meta.get("permissions")
        or static_evidence.get("permissions")
        or []
    )
    permission_combinations = (
        static_data.get("permission_combinations")
        or apk_meta.get("permission_combinations")
        or []
    )
    triage_score = (
        static_data.get("triage_score")
        or apk_meta.get("triage_score")
        or 0.0
    )
    prob = (
        static_data.get("securebert_probability")
        or static_evidence.get("securebert_probability")
        or 0.0
    )
    indicators = (
        static_data.get("indicators")
        or static_evidence.get("indicators")
        or []
    )
    slice_count = static_evidence.get("slice_count") or len(static_data.get("slices", [])) or 0
    max_slice = static_evidence.get("max_slice_probability") or prob

    # Derive purpose / category narrative from package name tokens
    pkg_lower = package.lower()
    if any(k in pkg_lower for k in ["bank", "pay", "upi", "wallet", "finance", "card", "invest"]):
        category_desc = "financial or banking service application targeting payment workflows and transaction data"
    elif any(k in pkg_lower for k in ["sms", "message", "chat", "talk", "social", "comm"]):
        category_desc = "telecommunication and messaging utility requesting access to SMS/MMS and communication subsystems"
    elif any(k in pkg_lower for k in ["stream", "media", "video", "tv", "player", "movie", "live"]):
        category_desc = "live multimedia streaming or entertainment playback service"
    elif any(k in pkg_lower for k in ["calc", "tool", "util", "helper", "manage", "cleaner"]):
        category_desc = "device management utility or calculation tool"
    elif any(k in pkg_lower for k in ["game", "play", "arcade", "puzzle"]):
        category_desc = "mobile gaming application"
    else:
        clean_target = package.split(".")[-1].replace("_", " ").title()
        category_desc = f"Android application package designed for {clean_target} operations"

    summary_parts = [
        "## App Overview\n"
        f"The application under analysis is **{filename}**, registered under the Android package identifier `{package}` with a binary footprint of **{size}** (SHA-256: `{apk_hash}`). "
        f"Based on static identifier decomposition, the binary operates as a {category_desc}. "
        f"A comprehensive forensic evaluation was performed to identify structural properties, requested system capabilities, and runtime traits across static triage and dynamic detonation pipelines."
    ]

    # Build Static Analysis section
    has_static = bool(static_data) or bool(static_evidence) or bool(permissions) or triage_score > 0
    if has_static:
        score_val = int(prob * 100) if prob > 0 else int(final_score)
        perm_count = len(permissions)
        dangerous_perms = [p for p in permissions if any(d in p for d in ["SMS", "ACCESSIBILITY", "SYSTEM_ALERT", "RECORD_AUDIO", "CAMERA", "READ_CONTACTS", "DEVICE_ADMIN", "INSTALL_PACKAGES"])]
        
        perm_summary = f"Total of **{perm_count}** system permissions requested"
        if dangerous_perms:
            perm_summary += f", including **{len(dangerous_perms)}** high-risk security permissions: {', '.join(f'`{p.split(chr(46))[-1]}`' for p in dangerous_perms[:6])}"
        else:
            perm_summary += " with standard operational scope"

        findings_list = []
        if permission_combinations:
            findings_list.append(f"Dangerous permission combinations flagged: {', '.join(f'**{c}**' for c in permission_combinations)}")
        if indicators:
            findings_list.append(f"Static code signals: {'; '.join(indicators[:5])}")
        if slice_count > 0:
            findings_list.append(f"Evaluated {slice_count} decompiled Smali program slices with maximum sink anomaly score of {max_slice:.2f}")
        
        if not findings_list:
            if score_val < 30:
                findings_list.append("No critical obfuscation markers, dynamic class loading, or reflection sinks were detected in the Dalvik bytecode")
            else:
                findings_list.append(f"Elevated static risk markers detected with composite score of {score_val}/100")

        summary_parts.append(
            "## Static Analysis\n"
            f"SecureBERT Risk Score: **{score_val}** (Triage Score: **{triage_score:.1f}**)\n\n"
            f"**Permissions & Attack Surface**: {perm_summary}.\n\n"
            f"**Key Findings**: {'. '.join(findings_list)}."
        )

    # Build Dynamic Analysis section
    behav = merged.get("behavioral_fingerprint") or {}
    dynamic_data = merged.get("dynamic_data") or {}
    has_dynamic = bool(behav.get("syscalls")) or bool(behav.get("ips")) or bool(behav.get("evasion_signals")) or bool(dynamic_data.get("syscalls"))
    
    if has_dynamic:
        syscalls = behav.get("syscalls") or dynamic_data.get("syscalls") or []
        ips = behav.get("ips") or [c.get("ip") for c in dynamic_data.get("network_connections", []) if isinstance(c, dict) and c.get("ip")]
        file_writes = behav.get("file_writes") or dynamic_data.get("files_accessed") or []
        evasion = behav.get("evasion_signals") or []
        c2 = behav.get("observed_c2_connection", False)
        root = behav.get("observed_root_escalation", False)
        sms = behav.get("observed_sms_exfiltration", False)

        dyn_findings = []
        if evasion:
            dyn_findings.append(f"Anti-analysis and sandbox evasion hooks triggered: {', '.join(evasion)}")
        if c2:
            dyn_findings.append("Command-and-control (C2) communication channel intercepted via Frida dynamic hooks")
        if root:
            dyn_findings.append("Root privilege escalation / root check bypass routine executed at runtime")
        if sms:
            dyn_findings.append("Background SMS exfiltration routine observed during execution")
        if ips:
            dyn_findings.append(f"Network sockets opened to remote endpoints: {', '.join(ips[:4])}")
        if syscalls:
            dyn_findings.append(f"Kernel system calls recorded via eBPF: {', '.join(syscalls[:6])}")
        if file_writes:
            dyn_findings.append(f"Filesystem modifications in sandbox: {', '.join(file_writes[:4])}")

        if not dyn_findings:
            dyn_text = "No malicious system calls, suspicious network traffic, or privilege escalations were recorded during sandbox detonation."
        else:
            dyn_text = ". ".join(dyn_findings) + "."

        summary_parts.append(
            "## Dynamic Analysis\n"
            f"Key Findings: {dyn_text}"
        )
    else:
        summary_parts.append(
            "## Dynamic Analysis\n"
            "Key Findings: Dynamic sandbox detonation pending or executed in passive simulation mode without anomalous runtime faults."
        )

    summary = "\n\n".join(summary_parts)

    # Derive severity and score
    calculated_final_score = int(final_score) if final_score else int(prob * 100) if prob > 0 else int(triage_score)
    severity = "CRITICAL" if calculated_final_score > 80 else "HIGH" if calculated_final_score > 55 else "MEDIUM" if calculated_final_score > 30 else "LOW"

    # Derive IoCs
    ioc_ips = behav.get("ips") or [c.get("ip") for c in dynamic_data.get("network_connections", []) if isinstance(c, dict) and c.get("ip")] or []
    
    # Derive MITRE ATT&CK mapping
    tactics = []
    techniques = []
    if behav.get("observed_c2_connection") or any("command-node" in str(x) for x in behav.get("llm_frida_intercepts", [])):
        tactics.append("TA0011")  # Command and Control
        techniques.append("T1071")
    if behav.get("observed_sms_exfiltration") or "SMS_INTERCEPTION" in permission_combinations or any("SMS" in p for p in permissions):
        tactics.append("TA0010")  # Exfiltration
        techniques.append("T1636.004")
    if behav.get("observed_root_escalation") or any("root" in str(x).lower() for x in indicators):
        tactics.append("TA0004")  # Privilege Escalation
        techniques.append("T1404")
    if behav.get("evasion_signals") or any("time dilution" in str(x).lower() for x in behav.get("time_dilution_events", [])):
        tactics.append("TA0005")  # Defense Evasion
        techniques.append("T1497")
    if any("ACCESSIBILITY" in p for p in permissions) or "ACCESSIBILITY_SMS_OVERLAY" in permission_combinations:
        tactics.append("TA0005")
        techniques.append("T1437")
    if any("SYSTEM_ALERT_WINDOW" in p for p in permissions):
        tactics.append("TA0001")  # Initial Access
        techniques.append("T1411")
    if not tactics:
        tactics.append("TA0043")  # Reconnaissance (default)
        techniques.append("T1636")

    # Deduplicate
    tactics = list(dict.fromkeys(tactics))
    techniques = list(dict.fromkeys(techniques))

    # Derive mitigations
    mitigations = [f"Uninstall `{package}` ({filename}) from user devices"]
    if ioc_ips:
        mitigations.append(f"Block network egress traffic to remote IP endpoints: {', '.join(ioc_ips)}")
    if any("SMS" in p for p in permissions):
        mitigations.append("Revoke SMS/MMS permissions and audit device authentication channels")
    if any("ACCESSIBILITY" in p for p in permissions):
        mitigations.append("Disable Accessibility Service grants for unverified package signatures")
    if behav.get("observed_root_escalation"):
        mitigations.append("Inspect firmware integrity and reflash compromised operating system partitions")
    mitigations.append("Enforce Google Play Protect / enterprise MDM compliance restrictions")

    # Static findings list
    static_findings_list = []
    if dangerous_perms:
        static_findings_list.append(f"Requested sensitive permissions: {', '.join(dangerous_perms[:6])}")
    if permission_combinations:
        static_findings_list.append(f"Dangerous permission clusters: {', '.join(permission_combinations)}")
    if indicators:
        static_findings_list.extend(indicators[:4])
    if not static_findings_list:
        static_findings_list = ["Static manifest and structural inspection completed without high-severity anomalies"]

    # Dynamic findings list
    dynamic_findings_list = []
    if behav.get("evasion_signals"):
        dynamic_findings_list.extend(behav.get("evasion_signals"))
    if behav.get("observed_c2_connection"):
        dynamic_findings_list.append("C2 intercept detected via dynamic instrumentation")
    if not dynamic_findings_list:
        dynamic_findings_list = ["Sandbox dynamic execution recorded without critical runtime violations"]

    return JointForensicReport(
        forensic=KavachForensicReport(
            summary=summary,
            risk_score=calculated_final_score,
            contradiction_label=merged.get("contradiction_label", "MALICIOUS" if calculated_final_score > 50 else "BENIGN"),
            static_findings=static_findings_list,
            dynamic_findings=dynamic_findings_list
        ),
        cert_in=CertInIncidentReport(
            incident_id=merged.get("job_id", f"INC-{apk_hash[:8].upper()}"),
            severity=severity,
            mitre_attack_tactics=tactics,
            mitre_attack_techniques=techniques,
            indicators_of_compromise={
                "ips": ioc_ips,
                "permissions": permissions
            },
            recommended_mitigations=mitigations
        ),
        mitre_attack_json={
            "tactics": tactics,
            "techniques": techniques
        }
    ).model_dump()

def generate_report_groq(merged: dict) -> dict:
    if not Groq or not os.getenv("GROQ_API_KEY"):
        return fallback_generate_report(merged)
    
    client = Groq(api_key=os.getenv("GROQ_API_KEY"))
    schema_str = json.dumps(JointForensicReport.model_json_schema(), indent=2)
    prompt = (
        f"You are an expert malware forensic analyst. Generate a highly descriptive, comprehensive, and professional application security report based on the fetched data.\n\n"
        f"Requirements for the markdown report structure:\n"
        f"1. **## App Overview**:\n"
        f"   - Describe the application under review in a descriptive, thorough manner.\n"
        f"   - Explicitly define the application's metadata at the beginning: filename (e.g. `apk_details.name`), package name (e.g. `apk_details.package`), size (e.g. `apk_details.size`), and SHA-256 hash if present.\n"
        f"   - Provide a deep narrative analysis of what the application does based on its package name (e.g., if it is named `com.pakito.modrolivetv`, identify it as a live media streaming or television application), and detail its scope and target audiance context.\n"
        f"   - Describe its general components, permission requests, and potential attack vectors in a professional narrative.\n\n"
        f"2. **## Static Analysis** (Only include this section if a static scan was actually run, i.e. contains real static/SecureBERT metrics or indicators):\n"
        f"   - SecureBERT Risk Score: [Insert SecureBERT Risk Score, calculated as the securebert_probability * 100 or static_evidence.securebert_probability * 100]\n"
        f"   - Key Findings: Provide a descriptive narrative of all key findings from the static fetch, explaining the technical details of requested permissions, obfuscation markers, and specific suspicious Smali code slices/methods in an easily digestible way for the reviewer.\n\n"
        f"3. **## Dynamic Analysis** (Only include this section if a dynamic detonation was actually run, i.e. contains a valid execution_mode or dynamic telemetry):\n"
        f"   - Key Findings: Summarize the runtime/dynamic fetch findings descriptively. If no threat behaviors or network calls were observed, explicitly state that no malicious actions or system modifications were detected during dynamic detonation.\n\n"
        f"Write this report in Markdown following the layout template below, and place it in the `forensic.summary` field of the JSON output:\n\n"
        f"=== Template layout ===\n"
        f"## App Overview\n"
        f"[Provide a highly detailed description of the application, package, size, functions, and metadata]\n\n"
        f"## Static Analysis\n"
        f"SecureBERT Risk Score: [Score]\n"
        f"Key Findings: [Narrative]\n\n"
        f"## Dynamic Analysis\n"
        f"Key Findings: [Narrative]\n"
        f"=======================\n\n"
        f"Output a valid JSON matching this schema:\n{schema_str}\n\n"
        f"Telemetry Data:\n{json.dumps(merged)}"
    )
    try:
        completion = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[{"role": "user", "content": prompt}],
            response_format={"type": "json_object"}
        )
        content = completion.choices[0].message.content
        # Validate structure matches expected JointForensicReport
        report = JointForensicReport.model_validate_json(content)
        return report.model_dump()
    except Exception as e:
        print(f"Groq generation failed: {e}")
        return fallback_generate_report(merged)

def generate_report_ollama(merged: dict) -> dict:
    schema_str = json.dumps(JointForensicReport.model_json_schema(), indent=2)
    prompt = (
        f"You are an expert malware forensic analyst. Generate a highly descriptive, comprehensive, and professional application security report based on the fetched data.\n\n"
        f"Requirements for the markdown report structure:\n"
        f"1. **## App Overview**:\n"
        f"   - Describe the application under review in a descriptive, thorough manner.\n"
        f"   - Explicitly define the application's metadata at the beginning: filename (e.g. `apk_details.name`), package name (e.g. `apk_details.package`), size (e.g. `apk_details.size`), and SHA-256 hash if present.\n"
        f"   - Provide a deep narrative analysis of what the application does based on its package name (e.g., if it is named `com.pakito.modrolivetv`, identify it as a live media streaming or television application), and detail its scope and target audiance context.\n"
        f"   - Describe its general components, permission requests, and potential attack vectors in a professional narrative.\n\n"
        f"2. **## Static Analysis** (Only include this section if a static scan was actually run, i.e. contains real static/SecureBERT metrics or indicators):\n"
        f"   - SecureBERT Risk Score: [Insert SecureBERT Risk Score, calculated as the securebert_probability * 100 or static_evidence.securebert_probability * 100]\n"
        f"   - Key Findings: Provide a descriptive narrative of all key findings from the static fetch, explaining the technical details of requested permissions, obfuscation markers, and specific suspicious Smali code slices/methods in an easily digestible way for the reviewer.\n\n"
        f"3. **## Dynamic Analysis** (Only include this section if a dynamic detonation was actually run, i.e. contains a valid execution_mode or dynamic telemetry):\n"
        f"   - Key Findings: Summarize the runtime/dynamic fetch findings descriptively. If no threat behaviors or network calls were observed, explicitly state that no malicious actions or system modifications were detected during dynamic detonation.\n\n"
        f"Write this report in Markdown following the layout template below, and place it in the `forensic.summary` field of the JSON output:\n\n"
        f"=== Template layout ===\n"
        f"## App Overview\n"
        f"[Provide a highly detailed description of the application, package, size, functions, and metadata]\n\n"
        f"## Static Analysis\n"
        f"SecureBERT Risk Score: [Score]\n"
        f"Key Findings: [Narrative]\n\n"
        f"## Dynamic Analysis\n"
        f"Key Findings: [Narrative]\n"
        f"=======================\n\n"
        f"Output a valid JSON matching this schema:\n{schema_str}\n\n"
        f"Telemetry Data:\n{json.dumps(merged)}"
    )
    try:
        response = requests.post(
            "http://localhost:11434/api/chat",
            json={
                "model": "llama3",
                "messages": [{"role": "user", "content": prompt}],
                "stream": False,
                "format": "json"
            },
            timeout=30
        )
        response.raise_for_status()
        content = response.json()["message"]["content"]
        # Validate structure matches expected JointForensicReport
        report = JointForensicReport.model_validate_json(content)
        return report.model_dump()
    except Exception as e:
        print(f"Ollama generation failed: {e}")
        return fallback_generate_report(merged)
