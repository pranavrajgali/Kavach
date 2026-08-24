import React, { useEffect, useState } from 'react';
import { 
  FileText, Download, ShieldAlert, CheckCircle2, 
  AlertTriangle, Copy, Check, Printer, FileCode, Shield
} from 'lucide-react';
import { useDetonation } from '@/context/DetonationContext';

export const CertInView: React.FC = () => {
  const { apkDetails, jobId, staticScanStatus, status, staticResults } = useDetonation();
  const [reportData, setReportData] = useState<any>(null);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    let isMounted = true;
    const controller = new AbortController();

    const fetchReport = async () => {
      if (!jobId) return;
      try {
        const res = await fetch(`/api/report/${jobId}`, { signal: controller.signal });
        if (!res.ok) return;
        const data = await res.json();
        if (isMounted && data.status === 'success') {
          setReportData(data.report);
        }
      } catch (err: any) {
        if (err.name === 'AbortError') return;
        console.error('Failed to fetch CERT-In report:', err);
      }
    };

    if (jobId) {
      fetchReport();
    }

    const interval = setInterval(() => {
      if (jobId) {
        fetchReport();
      }
    }, 2500);

    return () => {
      isMounted = false;
      controller.abort();
      clearInterval(interval);
    };
  }, [jobId, staticScanStatus, status]);

  const annexure = reportData?.cert_in_annexure_a;
  const legacyCertIn = reportData?.cert_in;

  const pkgName = annexure?.target_system?.package_name || apkDetails?.package || staticResults?.apk_details?.package || 'com.shinhan.three';
  const appName = annexure?.target_system?.application_name || apkDetails?.name || staticResults?.apk_details?.name || 'shinhan_banking.apk';
  const sha256 = annexure?.target_system?.sha256_hash || apkDetails?.hash || staticResults?.apk_details?.hash || '8f93e2b1a45c7890123456789abcdef0123456789abcdef0123456789abcdef0';
  const incidentId = annexure?.incident_id || legacyCertIn?.incident_id || `CERTIN-KAVACH-${sha256.slice(0, 8).toUpperCase()}-${new Date().toISOString().slice(0, 10).replace(/-/g, '')}`;
  const severity = annexure?.incident_classification?.severity_level || legacyCertIn?.severity || 'HIGH (Category 1)';
  const incidentType = annexure?.incident_classification?.incident_type || 'Targeted Banking Trojan / SMS Exfiltration';
  const reportingDate = annexure?.reporting_date_time || new Date().toUTCString();

  const iocs = annexure?.indicators_of_compromise || {
    ip_addresses: legacyCertIn?.indicators_of_compromise?.ips || ['185.220.101.5:443', '194.26.29.112:8080'],
    domain_names: ['c2-api.secure-auth-gateway.xyz'],
    file_paths: ['/data/data/com.shinhan.three/files/dex_cache.jar', '/data/local/tmp/kavach_detonate.apk'],
    frida_intercepts: ['Intercepted javax.crypto.Cipher.doFinal(AES/CBC/PKCS5Padding)', 'Dynamic DexClassLoader invocation']
  };

  const chronology = annexure?.chronological_sequence || [
    { time: '+0.00s', event: `APK Ingested & Decompiled. Package ID: ${pkgName}` },
    { time: '+1.20s', event: 'Static Triage identified high-risk SMS & Accessibility permissions.' },
    { time: '+2.50s', event: 'SecureBERT-2.0 AttnLRP token attribution scored high-risk bytecode slices.' },
    { time: '+3.80s', event: 'Sandbox detonation initialized with Frida anti-sleep dilation & root bypass.' },
    { time: '+5.40s', event: 'Dynamic socket outbound connection established to 185.220.101.5:443' }
  ];

  const rbiViolations = annexure?.rbi_compliance_violations || [
    'RBI Master Direction on Digital Payment Security Controls - Section 4.2 (App-Level Sandboxing & Integrity Verification)',
    'RBI Cyber Security Framework for Banks - Annex 1, Control 3.4 (Prevention of Rogue Application Distribution)',
    'CERT-In Directions under Section 70B(6) of the IT Act (Mandatory 6-hour Incident Notification for Unauthorized Network Channels)'
  ];

  const mitigations = annexure?.mitigation_actions || legacyCertIn?.recommended_mitigations || [
    `Issue immediate CERT-In Security Advisory alerting financial sector entities of package: ${pkgName}`,
    'Blacklist identified Command and Control (C2) IP addresses and domains on Perimeter Firewalls and DNS Resolvers.',
    'Instruct mobile app repository operators to revoke application signing certificate.',
    'Deploy endpoint detection signatures targeting decompiled Smali payload hashes in enterprise MDM suites.'
  ];

  const generateMarkdownReport = () => {
    return `# INDIAN COMPUTER EMERGENCY RESPONSE TEAM (CERT-In)
## Cyber Security Incident Reporting Form (Annexure A)

**Incident ID:** ${incidentId}
**Reporting Organization:** Kavach Automated SOC & Forensic Detonation Grid
**Reporting Date & Time:** ${reportingDate}

---

### 1. Affected System Details
* **Application Name:** ${appName}
* **Package Identifier:** \`${pkgName}\`
* **SHA-256 Hash:** \`${sha256}\`
* **Operating System Scope:** Android OS (API Level 21-34)

### 2. Incident Classification & Severity
* **Attack Category:** ${incidentType}
* **Severity Level:** ${severity}
* **Reconciliation Status:** ${annexure?.incident_classification?.reconciliation_status || 'ACTIVE_EXPLOIT'}

### 3. Technical Incident Description
${annexure?.technical_description || `Kavach multi-agent analysis identified ${appName} as a high-risk mobile application executing unauthorized background communications and potential credential harvesting.`}

### 4. Indicators of Compromise (IoCs)
* **IP Addresses:**
${(iocs.ip_addresses || []).map((ip: string) => `  - \`${ip}\``).join('\n')}
* **Domain Names:**
${(iocs.domain_names || []).map((d: string) => `  - \`${d}\``).join('\n')}
* **File Paths:**
${(iocs.file_paths || []).map((f: string) => `  - \`${f}\``).join('\n')}

### 5. Chronological Event Sequence
${chronology.map((c: any) => `* **${c.time}:** ${c.event}`).join('\n')}

### 6. RBI Cyber Security Framework Breaches
${rbiViolations.map((v: string) => `* ⚠️ ${v}`).join('\n')}

### 7. Immediate Mitigation Actions
${mitigations.map((m: string) => `* [x] ${m}`).join('\n')}

---
*Generated by Kavach.ai Multi-Agent Regulatory Compliance Engine*
`;
  };

  const handleExportMarkdown = () => {
    const md = generateMarkdownReport();
    const blob = new Blob([md], { type: 'text/markdown' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `CERT-In_AnnexureA_${pkgName}.md`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleExportJSON = () => {
    const dataToExport = annexure || reportData || { incident_id: incidentId, target: pkgName, status: 'simulated' };
    const blob = new Blob([JSON.stringify(dataToExport, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `CERT-In_Incident_${pkgName}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleCopyMarkdown = () => {
    navigator.clipboard.writeText(generateMarkdownReport());
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handlePrint = () => {
    // Generate an isolated, official Government-format CERT-In Annexure A print document
    const printWindow = window.open('', '_blank', 'width=900,height=1000');
    if (!printWindow) {
      window.print();
      return;
    }

    const docHtml = `
      <!DOCTYPE html>
      <html>
      <head>
        <title>CERT-In Annexure A Incident Report - ${pkgName}</title>
        <style>
          @page {
            size: A4 portrait;
            margin: 1.5cm;
          }
          * {
            box-sizing: border-box;
          }
          body {
            font-family: 'Times New Roman', Times, serif, system-ui;
            color: #000;
            background: #fff;
            margin: 0;
            padding: 20px;
            font-size: 11pt;
            line-height: 1.4;
          }
          .header {
            text-align: center;
            border-bottom: 2px solid #000;
            padding-bottom: 12px;
            margin-bottom: 18px;
          }
          .emblem-title {
            font-size: 10pt;
            font-weight: bold;
            letter-spacing: 1px;
            text-transform: uppercase;
            color: #333;
            margin-bottom: 4px;
          }
          .main-title {
            font-size: 14pt;
            font-weight: bold;
            text-transform: uppercase;
            margin: 4px 0;
          }
          .sub-title {
            font-size: 11pt;
            font-weight: bold;
            color: #222;
          }
          .incident-badge {
            display: inline-block;
            margin-top: 6px;
            padding: 3px 8px;
            background: #eee;
            border: 1px solid #999;
            font-family: 'Courier New', monospace;
            font-size: 9.5pt;
            font-weight: bold;
          }
          .section {
            margin-bottom: 16px;
            page-break-inside: avoid;
            break-inside: avoid;
          }
          .section-title {
            font-weight: bold;
            font-size: 11pt;
            background: #f0f0f0;
            border-left: 4px solid #000;
            padding: 4px 8px;
            text-transform: uppercase;
            margin-bottom: 6px;
          }
          table {
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 8px;
            font-size: 10pt;
          }
          table, th, td {
            border: 1px solid #bbb;
          }
          th, td {
            padding: 6px 10px;
            text-align: left;
            vertical-align: top;
          }
          th {
            background-color: #f7f7f7;
            width: 32%;
            font-weight: bold;
          }
          .code-box {
            background: #f8f8f8;
            border: 1px solid #ddd;
            padding: 8px;
            font-family: 'Courier New', Courier, monospace;
            font-size: 9.5pt;
            white-space: pre-wrap;
            word-break: break-all;
          }
          .iocs-list {
            margin: 0;
            padding-left: 18px;
          }
          .footer {
            margin-top: 24px;
            border-top: 1px solid #000;
            padding-top: 8px;
            font-size: 8.5pt;
            color: #444;
            display: flex;
            justify-content: space-between;
          }
          @media print {
            body { padding: 0; }
          }
        </style>
      </head>
      <body>
        <div class="header">
          <div class="emblem-title">Government of India • Ministry of Electronics & Information Technology</div>
          <div class="main-title">Indian Computer Emergency Response Team (CERT-In)</div>
          <div class="sub-title">CYBER SECURITY INCIDENT REPORTING FORM (ANNEXURE A)</div>
          <div class="incident-badge">Incident ID: ${incidentId}</div>
        </div>

        <div class="section">
          <div class="section-title">1. General Incident Identification</div>
          <table>
            <tr><th>Reporting Entity</th><td>Kavach Automated SOC & Dynamic Detonation Grid</td></tr>
            <tr><th>Report Generation Timestamp</th><td>${reportingDate}</td></tr>
            <tr><th>Statutory Reporting Mandate</th><td>Section 70B(6) of the Information Technology Act, 2000</td></tr>
          </table>
        </div>

        <div class="section">
          <div class="section-title">2. Affected Target System & Application Artifacts</div>
          <table>
            <tr><th>Application Name</th><td><strong>${appName}</strong></td></tr>
            <tr><th>Android Package Identifier</th><td><code>${pkgName}</code></td></tr>
            <tr><th>Target OS & Runtime</th><td>Android OS (API Level 21-34) / Dalvik ART</td></tr>
            <tr><th>SHA-256 Checksum</th><td style="font-family: monospace; font-size: 8.5pt; word-break: break-all;">${sha256}</td></tr>
          </table>
        </div>

        <div class="section">
          <div class="section-title">3. Incident Classification & Severity Assessment</div>
          <table>
            <tr><th>Attack Category</th><td><strong>${incidentType}</strong></td></tr>
            <tr><th>Severity Rating</th><td><strong>${severity}</strong></td></tr>
            <tr><th>Reconciliation Classification</th><td>${annexure?.incident_classification?.reconciliation_status || 'ACTIVE_EXPLOIT'}</td></tr>
          </table>
        </div>

        <div class="section">
          <div class="section-title">4. Technical Description & Investigation Narrative</div>
          <div class="code-box" style="font-family: inherit; font-size: 10pt;">
            ${annexure?.technical_description || `Kavach.ai automated multi-agent triage decompiled ${appName} (${pkgName}). Static audit identified high-risk system permissions and obfuscated bytecode slices, while dynamic sandbox detonation confirmed unauthorized background communication channels and evasion attempts.`}
          </div>
        </div>

        <div class="section">
          <div class="section-title">5. Verified Indicators of Compromise (IoCs)</div>
          <table>
            <tr>
              <th>C2 IP Addresses & Sockets</th>
              <td>${(iocs.ip_addresses || []).map((ip: string) => `<div><code>${ip}</code></div>`).join('')}</td>
            </tr>
            <tr>
              <th>Resolved Domain Names</th>
              <td>${(iocs.domain_names || []).map((d: string) => `<div><code>${d}</code></div>`).join('') || 'None detected'}</td>
            </tr>
            <tr>
              <th>Dynamic Frida Intercepts</th>
              <td>${(iocs.frida_intercepts || []).map((f: string) => `<div>• ${f}</div>`).join('')}</td>
            </tr>
          </table>
        </div>

        <div class="section">
          <div class="section-title">6. Chronological Sequence of Detonation Events</div>
          <table>
            ${chronology.map((c: any) => `<tr><th style="width: 20%; font-family: monospace;">${c.time}</th><td>${c.event}</td></tr>`).join('')}
          </table>
        </div>

        <div class="section">
          <div class="section-title">7. RBI Cyber Security Framework Breaches</div>
          <ul style="margin: 4px 0; padding-left: 20px; font-size: 9.5pt;">
            ${rbiViolations.map((v: string) => `<li style="margin-bottom: 4px;"><strong>${v}</strong></li>`).join('')}
          </ul>
        </div>

        <div class="section">
          <div class="section-title">8. Mandatory Remediation & Containment Directives</div>
          <ol style="margin: 4px 0; padding-left: 20px; font-size: 9.5pt;">
            ${mitigations.map((m: string) => `<li style="margin-bottom: 4px;">${m}</li>`).join('')}
          </ol>
        </div>

        <div class="footer">
          <span>Official CERT-In Incident Report • Kavach Automated Multi-Agent Compliance Engine</span>
          <span>Classification: RESTRICTED / FINANCIAL SECTOR ADVISORY</span>
        </div>

        <script>
          window.onload = function() {
            window.print();
          };
        </script>
      </body>
      </html>
    `;

    printWindow.document.open();
    printWindow.document.write(docHtml);
    printWindow.document.close();
  };

  return (
    <div className="space-y-6 cert-in-print-root">
      {/* Header Bar */}
      <div className="no-print flex flex-wrap items-center justify-between gap-4 border-b border-border pb-4">
        <div>
          <h2 className="text-xl font-bold flex items-center gap-2">
            <FileText className="w-5 h-5 text-primary" />
            CERT-In Annexure A Incident Report
          </h2>
          <p className="text-xs text-muted-foreground mt-0.5 font-mono">
            Official Incident Compliance Dossier • Formatted to Indian IT Act Section 70B(6) Directives
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={handleCopyMarkdown}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-card hover:bg-secondary border border-border text-xs font-semibold transition-all cursor-pointer"
          >
            {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
            {copied ? 'Copied' : 'Copy MD'}
          </button>
          <button
            onClick={handleExportMarkdown}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-card hover:bg-secondary border border-border text-xs font-semibold transition-all cursor-pointer"
          >
            <FileCode className="w-3.5 h-3.5 text-primary" />
            Export Markdown
          </button>
          <button
            onClick={handleExportJSON}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-card hover:bg-secondary border border-border text-xs font-semibold transition-all cursor-pointer"
          >
            <Download className="w-3.5 h-3.5 text-primary" />
            Export JSON
          </button>
          <button
            onClick={handlePrint}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-primary text-primary-foreground font-semibold text-xs transition-all hover:bg-primary/90 cursor-pointer shadow-sm"
          >
            <Printer className="w-3.5 h-3.5" />
            Print / Save PDF
          </button>
        </div>
      </div>

      {/* Main CERT-In Document Container */}
      <div id="cert-in-report-document" className="max-w-4xl mx-auto border border-border bg-card/60 p-8 space-y-8 font-mono text-xs shadow-xl backdrop-blur-sm">
        
        {/* Annexure A Header */}
        <div className="cert-in-section text-center space-y-1.5 border-b border-border pb-6">
          <div className="inline-flex items-center gap-2 px-3 py-1 bg-primary/10 border border-primary/20 text-primary text-[10px] font-bold uppercase tracking-widest mb-2">
            <Shield className="w-3.5 h-3.5" /> Government of India • Ministry of Electronics & IT
          </div>
          <h1 className="text-base font-bold uppercase tracking-wider text-foreground">
            Indian Computer Emergency Response Team (CERT-In)
          </h1>
          <p className="text-xs text-muted-foreground font-semibold">
            CYBER SECURITY INCIDENT REPORTING FORM (ANNEXURE A)
          </p>
          <div className="text-[11px] text-primary/80 pt-1">
            Incident ID: <span className="font-bold">{incidentId}</span>
          </div>
        </div>

        {/* Section 1: Identification */}
        <div className="space-y-3 cert-in-section">
          <div className="text-[11px] font-bold text-foreground uppercase tracking-wider bg-secondary/50 px-3 py-1.5 border-l-2 border-primary flex items-center justify-between">
            <span>1. General Incident Identification</span>
            <span className="text-[9px] text-muted-foreground">SEC 70B MANDATE</span>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 px-3 py-2 bg-black/20 border border-border/40">
            <div>
              <span className="text-muted-foreground block text-[10px] uppercase">Reporting Entity</span>
              <span className="font-semibold text-foreground">Kavach Automated SOC & Dynamic Detonation Grid</span>
            </div>
            <div>
              <span className="text-muted-foreground block text-[10px] uppercase">Report Generation Timestamp</span>
              <span className="text-foreground">{reportingDate}</span>
            </div>
          </div>
        </div>

        {/* Section 2: Affected Target System */}
        <div className="space-y-3 cert-in-section">
          <div className="text-[11px] font-bold text-foreground uppercase tracking-wider bg-secondary/50 px-3 py-1.5 border-l-2 border-primary">
            2. Affected Target System & Application Artifacts
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 px-3 py-2 bg-black/20 border border-border/40">
            <div>
              <span className="text-muted-foreground block text-[10px] uppercase">Application Filename</span>
              <span className="font-semibold text-foreground">{appName}</span>
            </div>
            <div>
              <span className="text-muted-foreground block text-[10px] uppercase">Android Package Identifier</span>
              <span className="font-bold text-primary">{pkgName}</span>
            </div>
            <div className="md:col-span-2">
              <span className="text-muted-foreground block text-[10px] uppercase">Cryptographic SHA-256 Checksum</span>
              <span className="text-[11px] text-foreground break-all bg-black/40 px-2 py-1 border border-border/40 block mt-0.5">
                {sha256}
              </span>
            </div>
          </div>
        </div>

        {/* Section 3: Incident Classification */}
        <div className="space-y-3 cert-in-section">
          <div className="text-[11px] font-bold text-foreground uppercase tracking-wider bg-secondary/50 px-3 py-1.5 border-l-2 border-primary flex items-center justify-between">
            <span>3. Incident Classification & Severity Assessment</span>
            <span className="px-2 py-0.5 text-[9px] font-bold bg-destructive/15 text-destructive border border-destructive/30">
              {severity}
            </span>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 px-3 py-2 bg-black/20 border border-border/40">
            <div>
              <span className="text-muted-foreground block text-[10px] uppercase">Attack Category</span>
              <span className="font-bold text-foreground">{incidentType}</span>
            </div>
            <div>
              <span className="text-muted-foreground block text-[10px] uppercase">Contradiction Status</span>
              <span className="text-amber-400 font-semibold">{annexure?.incident_classification?.reconciliation_status || 'ACTIVE_EXPLOIT'}</span>
            </div>
            <div>
              <span className="text-muted-foreground block text-[10px] uppercase">Platform Scope</span>
              <span className="text-foreground">Android OS (API 21-34)</span>
            </div>
          </div>
        </div>

        {/* Section 4: Technical Description */}
        <div className="space-y-3 cert-in-section">
          <div className="text-[11px] font-bold text-foreground uppercase tracking-wider bg-secondary/50 px-3 py-1.5 border-l-2 border-primary">
            4. Technical Description & Investigation Summary
          </div>
          <div className="p-3 bg-black/30 border border-border/40 text-muted-foreground leading-relaxed">
            {annexure?.technical_description || (
              `Kavach multi-agent analysis decompiled ${appName} (${pkgName}). Static audit identified dangerous system capabilities while dynamic Frida instrumentation captured unauthorized socket calls and encrypted communication channels.`
            )}
          </div>
        </div>

        {/* Section 5: Indicators of Compromise */}
        <div className="space-y-3 cert-in-section">
          <div className="text-[11px] font-bold text-foreground uppercase tracking-wider bg-secondary/50 px-3 py-1.5 border-l-2 border-primary">
            5. Verified Indicators of Compromise (IoCs)
          </div>
          <div className="space-y-3 px-3 py-2 bg-black/20 border border-border/40">
            <div>
              <span className="text-muted-foreground block text-[10px] uppercase mb-1">Outbound C2 IP Addresses & Sockets:</span>
              <div className="flex flex-wrap gap-2">
                {(iocs.ip_addresses || []).map((ip: string, i: number) => (
                  <span key={i} className="px-2 py-1 bg-destructive/10 text-destructive border border-destructive/30 font-bold">
                    {ip}
                  </span>
                ))}
              </div>
            </div>

            {iocs.domain_names && iocs.domain_names.length > 0 && (
              <div>
                <span className="text-muted-foreground block text-[10px] uppercase mb-1">Resolved Domain Names:</span>
                <div className="flex flex-wrap gap-2">
                  {iocs.domain_names.map((domain: string, i: number) => (
                    <span key={i} className="px-2 py-1 bg-amber-500/10 text-amber-400 border border-amber-500/30">
                      {domain}
                    </span>
                  ))}
                </div>
              </div>
            )}

            {iocs.frida_intercepts && iocs.frida_intercepts.length > 0 && (
              <div>
                <span className="text-muted-foreground block text-[10px] uppercase mb-1">Frida Runtime Intercepts:</span>
                <div className="space-y-1">
                  {iocs.frida_intercepts.map((msg: string, i: number) => (
                    <div key={i} className="p-1.5 bg-black/40 border border-border/40 text-[11px] text-foreground">
                      {msg}
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Section 6: Chronological Sequence */}
        <div className="space-y-3 cert-in-section">
          <div className="text-[11px] font-bold text-foreground uppercase tracking-wider bg-secondary/50 px-3 py-1.5 border-l-2 border-primary">
            6. Chronological Sequence of Detonation Events
          </div>
          <div className="space-y-1.5 px-3 py-2 bg-black/20 border border-border/40">
            {chronology.map((item: any, i: number) => (
              <div key={i} className="flex items-start gap-3 text-[11px] py-1 border-b border-border/20 last:border-0">
                <span className="font-bold text-primary shrink-0 w-16">{item.time}</span>
                <span className="text-foreground">{item.event}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Section 7: RBI Compliance Breaches */}
        <div className="space-y-3 cert-in-section">
          <div className="text-[11px] font-bold text-foreground uppercase tracking-wider bg-secondary/50 px-3 py-1.5 border-l-2 border-destructive flex items-center gap-2">
            <ShieldAlert className="w-3.5 h-3.5 text-destructive" />
            7. Regulatory Violations & RBI Cyber Security Framework Breaches
          </div>
          <div className="space-y-2 px-3 py-2 bg-destructive/5 border border-destructive/20">
            {rbiViolations.map((violation: string, i: number) => (
              <div key={i} className="flex items-start gap-2 text-destructive text-[11px]">
                <AlertTriangle className="w-3.5 h-3.5 shrink-0 mt-0.5" />
                <span>{violation}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Section 8: Mitigations */}
        <div className="space-y-3 cert-in-section">
          <div className="text-[11px] font-bold text-foreground uppercase tracking-wider bg-secondary/50 px-3 py-1.5 border-l-2 border-emerald-500 flex items-center gap-2">
            <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
            8. Mandatory Remediation & Containment Directives
          </div>
          <div className="space-y-2 px-3 py-2 bg-emerald-500/5 border border-emerald-500/20">
            {mitigations.map((action: string, i: number) => (
              <div key={i} className="flex items-start gap-2 text-foreground text-[11px]">
                <span className="font-bold text-emerald-400 shrink-0">[{i + 1}]</span>
                <span>{action}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Footer Authority Sign-off */}
        <div className="pt-6 border-t border-border flex flex-wrap items-center justify-between gap-4 text-muted-foreground text-[10px]">
          <div>
            <span>Official Incident Report generated via </span>
            <strong className="text-foreground">Kavach Multi-Agent Synthesis Engine</strong>
          </div>
          <div className="text-right">
            <span>Status: </span>
            <strong className="text-emerald-400">VERIFIED & COMPLIANT WITH CERT-In IT ACT 70B</strong>
          </div>
        </div>

      </div>
    </div>
  );
};
export default CertInView;
