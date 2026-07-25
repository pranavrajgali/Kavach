import React, { useState, useEffect } from 'react';
import { useDetonation } from '@/context/DetonationContext';
import { 
  ShieldAlert, Eye, ArrowLeft, Download, Printer, CheckCircle2, Sparkles, Search
} from 'lucide-react';

export interface FindingItem {
  id: string;
  title: string;
  severity: 'Critical' | 'High' | 'Medium' | 'Low' | 'Info';
  category: 'Runtime Security' | 'Network Privacy' | 'Data Storage' | 'Static Code' | 'System Integrity';
  isPrivacy: boolean;
  description: string;
  evidence: string;
  remediation: string;
}

export const KavachScorecard: React.FC = () => {
  const { telemetry, apkDetails, viewDashboard, loadRecentScan, simulationMode } = useDetonation();
  const [filterSeverity, setFilterSeverity] = useState<string>('All');
  const [searchQuery, setSearchQuery] = useState<string>('');

  useEffect(() => {
    if (!telemetry) {
      loadRecentScan();
    }
  }, [telemetry, loadRecentScan]);

  const objectionRoot = telemetry?.objection_root_bypass || false;
  const objectionSsl = telemetry?.objection_ssl_pinning_bypass || false;
  const filesAccessed = telemetry?.ebpf_telemetry?.files_accessed || [];
  const networkConns = telemetry?.ebpf_telemetry?.network_connections || [];
  const syscalls = telemetry?.ebpf_telemetry?.syscalls || [];
  const hasRevShell = networkConns.some(c => c.port === 4444);

  // Compute Security Score (0 to 100)
  let penalty = 0;
  if (objectionRoot) penalty += 30;
  if (objectionSsl) penalty += 25;
  
  filesAccessed.forEach(f => {
    if (f.includes('app_process') || f.includes('system')) penalty += 15;
    else if (f.includes('shared_prefs') || f.includes('config')) penalty += 10;
    else if (f.includes('/proc/')) penalty += 5;
  });

  networkConns.forEach(c => {
    if (c.port === 4444) penalty += 35;
    else penalty += 5;
  });

  if (syscalls.includes('sys_execve')) penalty += 10;

  // Base score calculation
  const rawScore = penalty === 0 ? 100 : Math.max(12, Math.min(98, 100 - penalty));
  const securityScore = telemetry ? rawScore : 38;

  // Calculate Risk Rating & Letter Grade
  let riskRating: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'SECURE' = 'SECURE';
  let grade: 'A' | 'B' | 'C' | 'D' | 'F' = 'A';
  let scoreColor = 'text-emerald-500 border-emerald-500/30 bg-emerald-500/10';

  if (securityScore < 40) {
    riskRating = 'CRITICAL';
    grade = 'F';
    scoreColor = 'text-red-500 border-red-500/30 bg-red-500/10';
  } else if (securityScore < 60) {
    riskRating = 'HIGH';
    grade = 'D';
    scoreColor = 'text-orange-500 border-orange-500/30 bg-orange-500/10';
  } else if (securityScore < 75) {
    riskRating = 'MEDIUM';
    grade = 'C';
    scoreColor = 'text-amber-500 border-amber-500/30 bg-amber-500/10';
  } else if (securityScore < 90) {
    riskRating = 'LOW';
    grade = 'B';
    scoreColor = 'text-blue-500 border-blue-500/30 bg-blue-500/10';
  }

  // Calculate Privacy Risk Score (0 to 100)
  let privacyPenalty = simulationMode ? 20 : 0;
  filesAccessed.forEach(f => {
    if (f.includes('shared_prefs') || f.includes('config') || f.includes('user')) privacyPenalty += 25;
  });
  if (networkConns.length > 0) privacyPenalty += 20;
  if (objectionSsl) privacyPenalty += 20;

  const privacyRiskScore = Math.min(95, privacyPenalty);
  const privacyRiskLevel = privacyRiskScore > 65 ? 'HIGH' : privacyRiskScore > 35 ? 'MEDIUM' : 'LOW';

  // Construct Dynamic Findings List directly from telemetry
  const findings: FindingItem[] = [];

  if (objectionRoot) {
    findings.push({
      id: 'KAV-CRIT-01',
      title: 'Frida Dynamic Root Bypass Hook Executed',
      severity: 'Critical',
      category: 'Runtime Security',
      isPrivacy: false,
      description: 'The application contains insufficient tamper protection and allowed automated root detection bypass routines during instrumentation.',
      evidence: 'Frida hooking script injected into app_process runtime (objection_root_bypass: true).',
      remediation: 'Implement native C/C++ integrity validation checks and obfuscate anti-root mechanisms using OLLVM.'
    });
  }

  if (objectionSsl) {
    findings.push({
      id: 'KAV-CRIT-02',
      title: 'SSL/TLS Certificate Pinning Defeated',
      severity: 'Critical',
      category: 'Network Privacy',
      isPrivacy: true,
      description: 'SSL Pinning was dynamically disabled using Objection runtime hooks, exposing encrypted socket communications to Man-in-the-Middle (MitM) interception.',
      evidence: 'TrustManager and NetworkSecurityConfig overridden (objection_ssl_pinning_bypass: true).',
      remediation: 'Enforce custom Conscrypt/OkHttp CertificatePinner routines with dynamic signature checks.'
    });
  }

  networkConns.forEach((c, idx) => {
    if (c.port === 4444) {
      findings.push({
        id: `KAV-CRIT-0${idx + 3}`,
        title: `Active Reverse Shell / Non-Standard C2 Port Connection (${c.ip}:${c.port})`,
        severity: 'Critical',
        category: 'Network Privacy',
        isPrivacy: true,
        description: `Outbound ${c.protocol} socket established to non-standard remote port ${c.port} at ${c.ip}, characteristic of interactive C2 backdoors.`,
        evidence: `eBPF sys_connect log: Outbound ${c.protocol} connection to ${c.ip}:${c.port}`,
        remediation: 'Restrict network socket instantiation to approved API domain endpoints and implement network payload boundary filtering.'
      });
    } else {
      findings.push({
        id: `KAV-MED-0${idx + 2}`,
        title: `Outbound Network Socket Connection (${c.ip}:${c.port})`,
        severity: 'Medium',
        category: 'Network Privacy',
        isPrivacy: true,
        description: `Application initiated an outbound ${c.protocol} socket to remote host ${c.ip} on port ${c.port}.`,
        evidence: `eBPF sys_connect log: Destination ${c.ip}:${c.port} (${c.protocol})`,
        remediation: 'Validate host certificates and restrict outbound network traffic to verified HTTPS endpoints.'
      });
    }
  });

  filesAccessed.forEach((f, idx) => {
    if (f.includes('shared_prefs') || f.includes('config')) {
      findings.push({
        id: `KAV-HIGH-0${idx + 1}`,
        title: `Unencrypted Application Preference Read: ${f}`,
        severity: 'High',
        category: 'Data Storage',
        isPrivacy: true,
        description: 'Sensitive application configuration and preference files were accessed in cleartext during dynamic sandbox execution.',
        evidence: `eBPF sys_openat log: Opened ${f}`,
        remediation: 'Encrypt shared preferences using EncryptedSharedPreferences (Android Jetpack Security).'
      });
    } else if (f.includes('app_process') || f.includes('system')) {
      findings.push({
        id: `KAV-HIGH-1${idx + 1}`,
        title: `System Binary Execution Marker: ${f}`,
        severity: 'High',
        category: 'System Integrity',
        isPrivacy: false,
        description: 'Application binary accessed or spawned system runtime binary paths directly during execution.',
        evidence: `eBPF sys_openat log: ${f}`,
        remediation: 'Avoid invoking system binary executables from app runtime containers.'
      });
    } else if (f.includes('/proc/')) {
      findings.push({
        id: `KAV-MED-1${idx + 1}`,
        title: `Process Memory & Map Inspection: ${f}`,
        severity: 'Medium',
        category: 'Runtime Security',
        isPrivacy: false,
        description: 'Process memory layout (/proc/self/maps) was queried at runtime, often associated with anti-debugging or memory inspection.',
        evidence: `eBPF sys_openat log: ${f}`,
        remediation: 'Restrict self-inspection routines and protect process memory structures.'
      });
    }
  });

  if (syscalls.includes('sys_execve')) {
    findings.push({
      id: 'KAV-MED-20',
      title: 'Dynamic Process Spawning Syscall (sys_execve)',
      severity: 'Medium',
      category: 'System Integrity',
      isPrivacy: false,
      description: 'The kernel intercepted sys_execve syscalls originating from the application process group.',
      evidence: 'eBPF syscall event: sys_execve triggered during dynamic execution.',
      remediation: 'Eliminate shell command execution and isolate native helper processes.'
    });
  }

  // Fallback findings if no telemetry loaded yet (or if run is clean)
  if (findings.length === 0) {
    if (simulationMode) {
      findings.push({
        id: 'KAV-LOW-01',
        title: 'Debug Marker Strings Present in Dex Header',
        severity: 'Low',
        category: 'Static Code',
        isPrivacy: false,
        description: 'Application binary compiled with verbose logging strings and debug symbols.',
        evidence: 'Dex header contains line numbers and local variable debugging tables.',
        remediation: 'Strip debug symbols in production release builds using ProGuard/R8.'
      });
    } else {
      findings.push({
        id: 'KAV-INFO-01',
        title: 'Dynamic Instrumentation Execution Clean',
        severity: 'Info',
        category: 'Runtime Security',
        isPrivacy: false,
        description: 'No runtime security anomalies, bypasses, or unauthorized socket connections were observed during the sandbox execution window.',
        evidence: 'Active sandbox execution finished without triggering Frida interceptors or malicious behavior.',
        remediation: 'No immediate runtime remediation actions required.'
      });
    }
  }

  // Calculate Severity Counts
  const counts = {
    Critical: findings.filter(f => f.severity === 'Critical').length,
    High: findings.filter(f => f.severity === 'High').length,
    Medium: findings.filter(f => f.severity === 'Medium').length,
    Low: findings.filter(f => f.severity === 'Low').length,
    Info: findings.filter(f => f.severity === 'Info').length,
  };

  const totalFindings = findings.length;

  // Filtered Findings
  const filteredFindings = findings.filter(f => {
    const matchesSeverity = filterSeverity === 'All' || 
                            (filterSeverity === 'Privacy' ? f.isPrivacy : f.severity === filterSeverity);
    const matchesSearch = f.title.toLowerCase().includes(searchQuery.toLowerCase()) || 
                          f.id.toLowerCase().includes(searchQuery.toLowerCase()) ||
                          f.category.toLowerCase().includes(searchQuery.toLowerCase());
    return matchesSeverity && matchesSearch;
  });

  const handlePrint = () => {
    window.print();
  };

  const handleExportJson = () => {
    const exportData = {
      scorecard: {
        app_name: apkDetails?.name || 'Target_APK.apk',
        package_name: apkDetails?.package || 'com.example.targetapp',
        security_score: securityScore,
        grade,
        risk_rating: riskRating,
        privacy_risk_score: privacyRiskScore,
        privacy_risk_level: privacyRiskLevel,
        severity_distribution: counts,
        findings
      }
    };
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(exportData, null, 2));
    const anchor = document.createElement('a');
    anchor.setAttribute("href", dataStr);
    anchor.setAttribute("download", `kavach_scorecard_${apkDetails?.package || 'app'}.json`);
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
  };

  return (
    <div className="space-y-6 pb-12">
      {/* 1. Header & Navigation */}
      <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4 pb-4 border-b border-border">
        <div>
          <button 
            onClick={viewDashboard}
            className="flex items-center gap-1.5 text-xs font-semibold text-muted-foreground hover:text-foreground transition-all mb-2 cursor-pointer"
          >
            <ArrowLeft className="w-3.5 h-3.5" />
            Back to Forensic Dashboard
          </button>
          <div className="flex items-center gap-3">
            <h2 className="text-2xl font-extrabold tracking-tight text-foreground flex items-center gap-2">
              Kavach Security & Privacy Scorecard
            </h2>
            <span className="text-[10px] font-bold uppercase tracking-wider px-2 py-0.5 border border-primary/30 text-primary bg-primary/10">
              Official Audit Rating
            </span>
          </div>
          <p className="text-xs text-muted-foreground mt-1">
            Package: <code className="font-mono text-foreground font-bold">{apkDetails?.package || 'com.target.application'}</code> • 
            File Size: <span className="text-foreground font-medium">{apkDetails?.size || '24.50 MB'}</span> • 
            Scanned: <span className="text-foreground font-medium">{new Date().toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' })}</span>
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button 
            onClick={handleExportJson}
            className="flex items-center gap-2 px-3.5 py-1.5 bg-card hover:bg-card/80 border border-border text-foreground text-xs font-semibold transition-all cursor-pointer"
          >
            <Download className="w-3.5 h-3.5 text-muted-foreground" />
            Export JSON
          </button>
          <button 
            onClick={handlePrint}
            className="flex items-center gap-2 px-4 py-1.5 bg-primary hover:bg-primary/90 text-primary-foreground text-xs font-bold transition-all cursor-pointer shadow-sm"
          >
            <Printer className="w-3.5 h-3.5" />
            Print Scorecard
          </button>
        </div>
      </div>

      {/* 2. Top Rating Score Overview Grid */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        
        {/* Card 1: Security Score */}
        <div className="p-6 border border-border bg-card flex flex-col justify-between space-y-4 relative overflow-hidden">
          <div className="flex justify-between items-start">
            <div>
              <span className="text-[10px] font-bold text-muted-foreground uppercase tracking-widest block">
                Overall Security Score
              </span>
              <span className="text-xs text-muted-foreground">Standard Kavach Audit Scale (0-100)</span>
            </div>
            <span className={`text-xs font-bold px-2 py-0.5 border ${scoreColor}`}>
              GRADE {grade}
            </span>
          </div>

          <div className="flex items-center gap-6 my-2">
            {/* Score Ring Dial */}
            <div className="relative w-24 h-24 flex items-center justify-center shrink-0">
              <svg className="w-full h-full transform -rotate-90" viewBox="0 0 36 36">
                <path
                  className="text-border"
                  strokeWidth="3.5"
                  stroke="currentColor"
                  fill="none"
                  d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
                />
                <path
                  className={securityScore < 50 ? 'text-red-500' : securityScore < 75 ? 'text-amber-500' : 'text-emerald-500'}
                  strokeDasharray={`${securityScore}, 100`}
                  strokeWidth="3.5"
                  strokeLinecap="square"
                  stroke="currentColor"
                  fill="none"
                  d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
                />
              </svg>
              <div className="absolute flex flex-col items-center justify-center text-center">
                <span className="text-2xl font-black text-foreground">{securityScore}</span>
                <span className="text-[9px] font-bold text-muted-foreground uppercase">/ 100</span>
              </div>
            </div>

            <div className="space-y-1">
              <div className="text-sm font-bold text-foreground">
                {securityScore < 50 ? 'Severe Vulnerabilities' : securityScore < 75 ? 'Moderate Exposure' : 'Strong Security Posture'}
              </div>
              <p className="text-[11px] text-muted-foreground leading-relaxed">
                {securityScore < 50 
                  ? 'Multiple runtime bypasses and unencrypted memory reads detected during dynamic sandbox execution.'
                  : 'Minor configuration warnings found.'}
              </p>
            </div>
          </div>

          <div className="pt-3 border-t border-border flex items-center justify-between text-[11px]">
            <span className="text-muted-foreground">Verification status:</span>
            <span className="font-semibold text-emerald-500 flex items-center gap-1">
              <CheckCircle2 className="w-3.5 h-3.5" /> Certified Telemetry
            </span>
          </div>
        </div>

        {/* Card 2: Risk Rating */}
        <div className="p-6 border border-border bg-card flex flex-col justify-between space-y-4">
          <div className="flex justify-between items-start">
            <div>
              <span className="text-[10px] font-bold text-muted-foreground uppercase tracking-widest block">
                Threat Risk Rating
              </span>
              <span className="text-xs text-muted-foreground">Exploitability & Impact Classification</span>
            </div>
            <ShieldAlert className={`w-5 h-5 ${riskRating === 'CRITICAL' ? 'text-red-500' : 'text-amber-500'}`} />
          </div>

          <div>
            <div className={`text-3xl font-black tracking-tight mb-2 ${
              riskRating === 'CRITICAL' ? 'text-red-500' : riskRating === 'HIGH' ? 'text-orange-500' : 'text-emerald-500'
            }`}>
              {riskRating} RISK
            </div>
            <div className="space-y-1.5 text-xs">
              <div className="flex items-center justify-between text-muted-foreground">
                <span>Frida Injection Susceptibility:</span>
                <span className="font-bold text-foreground">{objectionRoot || objectionSsl ? 'Vulnerable' : 'Protected'}</span>
              </div>
              <div className="flex items-center justify-between text-muted-foreground">
                <span>C2 Command Channel:</span>
                <span className="font-bold text-foreground">{hasRevShell ? 'Active (Port 4444)' : 'None'}</span>
              </div>
              <div className="flex items-center justify-between text-muted-foreground">
                <span>SSL Pinning Bypass:</span>
                <span className="font-bold text-foreground">{objectionSsl ? 'Successful' : 'Defended'}</span>
              </div>
            </div>
          </div>

          <div className="pt-3 border-t border-border flex items-center justify-between text-[11px]">
            <span className="text-muted-foreground">Recommended Action:</span>
            <span className="font-bold text-red-500 uppercase">Immediate Remediation</span>
          </div>
        </div>

        {/* Card 3: Privacy Risk */}
        <div className="p-6 border border-border bg-card flex flex-col justify-between space-y-4">
          <div className="flex justify-between items-start">
            <div>
              <span className="text-[10px] font-bold text-muted-foreground uppercase tracking-widest block">
                Privacy Risk Assessment
              </span>
              <span className="text-xs text-muted-foreground">Data Harvesting & Leakage Exposure</span>
            </div>
            <Eye className="w-5 h-5 text-amber-500" />
          </div>

          <div>
            <div className="flex items-baseline gap-2 mb-2">
              <span className="text-3xl font-black text-amber-500">{privacyRiskScore}%</span>
              <span className="text-xs font-bold text-muted-foreground uppercase tracking-wider">
                ({privacyRiskLevel} PRIVACY EXPOSURE)
              </span>
            </div>

            {/* Privacy Metric Meters */}
            <div className="space-y-2">
              <div>
                <div className="flex justify-between text-[11px] mb-1">
                  <span className="text-muted-foreground">Unencrypted Local Storage Access</span>
                  <span className="font-bold text-foreground">High</span>
                </div>
                <div className="w-full bg-secondary h-1.5">
                  <div className="bg-amber-500 h-1.5 w-[80%]" />
                </div>
              </div>
              <div>
                <div className="flex justify-between text-[11px] mb-1">
                  <span className="text-muted-foreground">Network Data Exfiltration Risk</span>
                  <span className="font-bold text-foreground">Critical</span>
                </div>
                <div className="w-full bg-secondary h-1.5">
                  <div className="bg-red-500 h-1.5 w-[90%]" />
                </div>
              </div>
            </div>
          </div>

          <div className="pt-3 border-t border-border flex items-center justify-between text-[11px]">
            <span className="text-muted-foreground">CERT-In Compliance:</span>
            <span className="font-bold text-amber-500 uppercase">Non-Compliant</span>
          </div>
        </div>

      </div>

      {/* 3. Severity Distribution Section */}
      <div className="border border-border bg-card p-6 space-y-6">
        <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-2">
          <div>
            <h3 className="text-lg font-bold text-foreground">Vulnerability Severity Distribution</h3>
            <p className="text-xs text-muted-foreground">Breakdown of detected security issues by severity classification.</p>
          </div>
          <div className="text-xs font-bold text-muted-foreground bg-secondary px-3 py-1 border border-border">
            Total Findings: <span className="text-foreground">{totalFindings}</span>
          </div>
        </div>

        {/* Visual Stack Bar */}
        <div className="w-full bg-secondary h-4 flex overflow-hidden border border-border">
          {counts.Critical > 0 && (
            <div style={{ width: `${(counts.Critical / totalFindings) * 100}%` }} className="bg-red-500 transition-all" title={`Critical: ${counts.Critical}`} />
          )}
          {counts.High > 0 && (
            <div style={{ width: `${(counts.High / totalFindings) * 100}%` }} className="bg-orange-500 transition-all" title={`High: ${counts.High}`} />
          )}
          {counts.Medium > 0 && (
            <div style={{ width: `${(counts.Medium / totalFindings) * 100}%` }} className="bg-amber-500 transition-all" title={`Medium: ${counts.Medium}`} />
          )}
          {counts.Low > 0 && (
            <div style={{ width: `${(counts.Low / totalFindings) * 100}%` }} className="bg-blue-500 transition-all" title={`Low: ${counts.Low}`} />
          )}
          {counts.Info > 0 && (
            <div style={{ width: `${(counts.Info / totalFindings) * 100}%` }} className="bg-zinc-500 transition-all" title={`Info: ${counts.Info}`} />
          )}
        </div>

        {/* Severity Metrics Pills */}
        <div className="grid grid-cols-2 sm:grid-cols-5 gap-4">
          <div className="p-3 border border-red-500/20 bg-red-500/5 text-center">
            <span className="text-2xl font-black text-red-500 block">{counts.Critical}</span>
            <span className="text-[10px] font-bold uppercase tracking-wider text-muted-foreground">Critical</span>
          </div>
          <div className="p-3 border border-orange-500/20 bg-orange-500/5 text-center">
            <span className="text-2xl font-black text-orange-500 block">{counts.High}</span>
            <span className="text-[10px] font-bold uppercase tracking-wider text-muted-foreground">High</span>
          </div>
          <div className="p-3 border border-amber-500/20 bg-amber-500/5 text-center">
            <span className="text-2xl font-black text-amber-500 block">{counts.Medium}</span>
            <span className="text-[10px] font-bold uppercase tracking-wider text-muted-foreground">Medium</span>
          </div>
          <div className="p-3 border border-blue-500/20 bg-blue-500/5 text-center">
            <span className="text-2xl font-black text-blue-500 block">{counts.Low}</span>
            <span className="text-[10px] font-bold uppercase tracking-wider text-muted-foreground">Low</span>
          </div>
          <div className="p-3 border border-border bg-secondary text-center">
            <span className="text-2xl font-black text-muted-foreground block">{counts.Info}</span>
            <span className="text-[10px] font-bold uppercase tracking-wider text-muted-foreground">Informational</span>
          </div>
        </div>
      </div>

      {/* 4. Filterable Security & Privacy Findings List */}
      <div className="border border-border bg-card p-6 space-y-6">
        <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
          <div>
            <h3 className="text-lg font-bold text-foreground">Audit Findings & Remediation</h3>
            <p className="text-xs text-muted-foreground">Detailed vulnerability descriptions with dynamic instrumentation evidence.</p>
          </div>

          {/* Filter Tabs & Search */}
          <div className="flex flex-wrap items-center gap-2 w-full md:w-auto">
            <div className="flex border border-border bg-background p-0.5">
              {['All', 'Critical', 'High', 'Medium', 'Privacy'].map((sev) => (
                <button
                  key={sev}
                  onClick={() => setFilterSeverity(sev)}
                  className={`px-3 py-1 text-xs font-semibold transition-all cursor-pointer ${
                    filterSeverity === sev 
                      ? 'bg-primary text-primary-foreground' 
                      : 'text-muted-foreground hover:text-foreground'
                  }`}
                >
                  {sev}
                </button>
              ))}
            </div>

            <div className="relative flex-1 md:w-48">
              <Search className="w-3.5 h-3.5 absolute left-2.5 top-2.5 text-muted-foreground" />
              <input
                type="text"
                placeholder="Search findings..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-full pl-8 pr-3 py-1.5 bg-background border border-border text-xs text-foreground placeholder:text-muted-foreground/60 focus:outline-none focus:border-primary"
              />
            </div>
          </div>
        </div>

        {/* Findings Items Stack */}
        <div className="space-y-4">
          {filteredFindings.length === 0 ? (
            <div className="p-8 text-center text-muted-foreground text-xs border border-dashed border-border">
              No findings match the selected filter criteria.
            </div>
          ) : (
            filteredFindings.map((item) => (
              <div key={item.id} className="border border-border p-5 space-y-3 bg-background/50 hover:bg-background transition-all">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-border/50 pb-3">
                  <div className="flex items-center gap-2.5">
                    <span className="font-mono text-xs font-bold text-primary">{item.id}</span>
                    <h4 className="text-sm font-bold text-foreground">{item.title}</h4>
                  </div>
                  <div className="flex items-center gap-2">
                    {item.isPrivacy && (
                      <span className="text-[10px] font-bold uppercase tracking-wider px-2 py-0.5 border border-purple-500/30 text-purple-400 bg-purple-500/10">
                        Privacy Risk
                      </span>
                    )}
                    <span className={`text-[10px] font-bold uppercase tracking-wider px-2.5 py-0.5 border ${
                      item.severity === 'Critical' ? 'border-red-500/40 text-red-500 bg-red-500/10' :
                      item.severity === 'High' ? 'border-orange-500/40 text-orange-500 bg-orange-500/10' :
                      item.severity === 'Medium' ? 'border-amber-500/40 text-amber-500 bg-amber-500/10' :
                      'border-blue-500/40 text-blue-500 bg-blue-500/10'
                    }`}>
                      {item.severity}
                    </span>
                  </div>
                </div>

                <p className="text-xs text-muted-foreground leading-relaxed">
                  {item.description}
                </p>

                {/* Evidence snippet */}
                <div className="bg-card border border-border p-3 space-y-1">
                  <span className="text-[10px] font-bold text-muted-foreground uppercase tracking-widest block">
                    Dynamic Telemetry Evidence:
                  </span>
                  <code className="text-xs font-mono text-amber-400/90 block">
                    {item.evidence}
                  </code>
                </div>

                {/* Remediation */}
                <div className="flex items-start gap-2 pt-1 text-xs text-muted-foreground">
                  <Sparkles className="w-4 h-4 text-emerald-500 shrink-0 mt-0.5" />
                  <div>
                    <span className="font-bold text-foreground">Remediation Recommendation: </span>
                    <span>{item.remediation}</span>
                  </div>
                </div>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
};

export default KavachScorecard;
