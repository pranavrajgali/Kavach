import React, { useState, useMemo } from 'react';
import { useDetonation } from '@/context/DetonationContext';
import { 
  ShieldAlert, Eye, ArrowLeft, Download, Printer, Search
} from 'lucide-react';

export interface FindingItem {
  id: string;
  title: string;
  severity: 'Critical' | 'High' | 'Medium' | 'Low' | 'Info';
  category: 'Runtime Security' | 'Network Privacy' | 'Data Storage' | 'Static Code' | 'System Integrity';
  isPrivacy: boolean;
  description: string;
  evidence: string;
}

export const KavachScorecard: React.FC = () => {
  const { telemetry, staticResults, apkDetails, viewDashboard, simulationMode } = useDetonation();
  const [filterSeverity, setFilterSeverity] = useState<string>('All');
  const [searchQuery, setSearchQuery] = useState<string>('');

  const { securityScore, grade, riskRating, privacyRiskScore, privacyRiskLevel, findings } = useMemo(() => {
    const objectionRoot = telemetry?.objection_root_bypass || false;
    const objectionSsl = telemetry?.objection_ssl_pinning_bypass || false;
    const filesAccessed = telemetry?.ebpf_telemetry?.files_accessed || [];
    const networkConns = telemetry?.ebpf_telemetry?.network_connections || [];
    const syscalls = telemetry?.ebpf_telemetry?.syscalls || [];

    const mlVerdict = staticResults?.ml_metrics?.verdict || 'BENIGN';
    const mlProb = staticResults?.ml_metrics?.malicious_probability || 0;
    const abusedCombinations = staticResults?.triage?.permission_combinations || [];
    const permissionsList = staticResults?.triage?.permissions || [];

    // Compute Security Score (0 to 100)
    let penalty = 0;
    
    // Dynamic Penalties
    if (objectionRoot) penalty += 30;
    if (objectionSsl) penalty += 25;
    
    filesAccessed.forEach((f: string) => {
      if (f.includes('app_process') || f.includes('system') || f.includes('su')) {
        penalty += 15;
      } else if (f.includes('/proc/')) {
        penalty += 5;
      }
    });

    networkConns.forEach((c: any) => {
      if (c.port === 4444) {
        penalty += 35;
      } else if (![80, 443, 8080, 53].includes(c.port)) {
        penalty += 5;
      }
    });

    if (syscalls.includes('sys_execve') && objectionRoot) {
      penalty += 10;
    }

    // Static Penalties
    if (mlProb > 0.8) penalty += 35;
    else if (mlProb > 0.5) penalty += 20;

    penalty += abusedCombinations.length * 10;

    // Base score calculation
    const rawScore = penalty === 0 ? 100 : Math.max(12, Math.min(98, 100 - penalty));
    const finalSecurityScore = (telemetry || staticResults) ? rawScore : 38;

    // Calculate Risk Rating & Letter Grade
    let currentRiskRating: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'SECURE' = 'SECURE';
    let currentGrade: 'A' | 'B' | 'C' | 'D' | 'F' = 'A';

    if (finalSecurityScore < 40) {
      currentRiskRating = 'CRITICAL';
      currentGrade = 'F';
    } else if (finalSecurityScore < 60) {
      currentRiskRating = 'HIGH';
      currentGrade = 'D';
    } else if (finalSecurityScore < 75) {
      currentRiskRating = 'MEDIUM';
      currentGrade = 'C';
    } else if (finalSecurityScore < 90) {
      currentRiskRating = 'LOW';
      currentGrade = 'B';
    }

    // Calculate Privacy Risk Score (0 to 100)
    // Simulation mode itself is not a privacy finding.
    let privacyPenalty = 0;
    filesAccessed.forEach((f: string) => {
      if (f.includes('shared_prefs') || f.includes('config') || f.includes('user')) privacyPenalty += 25;
    });
    if (networkConns.length > 0) privacyPenalty += 20;
    if (objectionSsl) privacyPenalty += 25;

    // Static Privacy Penalties
    const dangerousPerms = ['READ_SMS', 'SEND_SMS', 'RECORD_AUDIO', 'CAMERA', 'READ_CONTACTS', 'ACCESS_FINE_LOCATION'];
    permissionsList.forEach((perm: string) => {
      if (dangerousPerms.some(dp => perm.includes(dp))) {
        privacyPenalty += 15;
      }
    });

    const finalPrivacyRiskScore = Math.min(100, Math.max(0, privacyPenalty));
    const finalPrivacyRiskLevel = finalPrivacyRiskScore > 75 ? 'CRITICAL' : finalPrivacyRiskScore > 50 ? 'HIGH' : finalPrivacyRiskScore > 25 ? 'MEDIUM' : 'LOW';

    // Construct Findings List
    const fList: FindingItem[] = [];

    // --- Dynamic Findings ---
    if (objectionRoot) {
      fList.push({
        id: 'KAV-DYN-01',
        title: 'Frida Dynamic Root Bypass Hook Executed',
        severity: 'Critical',
        category: 'Runtime Security',
        isPrivacy: false,
        description: 'The application contains insufficient tamper protection and allowed automated root detection bypass routines during instrumentation.',
        evidence: 'Frida hooking script injected into app_process runtime.'
      });
    }

    if (objectionSsl) {
      fList.push({
        id: 'KAV-DYN-02',
        title: 'SSL/TLS Certificate Pinning Defeated',
        severity: 'Critical',
        category: 'Network Privacy',
        isPrivacy: true,
        description: 'SSL Pinning was dynamically disabled using Objection runtime hooks, exposing encrypted socket communications.',
        evidence: 'TrustManager and NetworkSecurityConfig overridden.'
      });
    }

    if (telemetry?.time_dilution_bypass) {
      fList.push({
        id: 'KAV-DYN-03',
        title: 'Anti-Analysis Time Dilution Sleep Gate Defused',
        severity: 'High',
        category: 'Runtime Security',
        isPrivacy: false,
        description: 'Chronos Time Dilution engine intercepted and compressed sleep delay loops to force evasive malware detonation.',
        evidence: `Thread.sleep / SystemClock.sleep hooks compressed ${telemetry?.time_dilution_count || 1} sleep gate(s) to 10ms.`
      });
    }

    if (telemetry?.llm_frida_intercepts && telemetry.llm_frida_intercepts.length > 0) {
      fList.push({
        id: 'KAV-DYN-04',
        title: 'LLMFrida Synthesized Interceptors Captured Memory Payloads',
        severity: 'Critical',
        category: 'Runtime Security',
        isPrivacy: true,
        description: 'Dynamic hooks synthesized by Groq Qwen-2.5-Coder intercepted live decrypted strings and reflection targets.',
        evidence: telemetry.llm_frida_intercepts[0]
      });
    }

    networkConns.forEach((c: any, idx: number) => {
      if (c.port === 4444) {
        fList.push({
          id: `KAV-NET-${idx}`,
          title: `Active Reverse Shell / Non-Standard C2 Port Connection (${c.ip}:${c.port})`,
          severity: 'Critical',
          category: 'Network Privacy',
          isPrivacy: true,
          description: `Outbound ${c.protocol} socket established to non-standard remote port ${c.port} at ${c.ip}.`,
          evidence: `eBPF sys_connect log: Outbound ${c.protocol} connection to ${c.ip}:${c.port}`
        });
      }
    });

    // --- Static Findings ---
    if (mlProb > 0.8) {
      fList.push({
        id: 'KAV-STAT-01',
        title: `Malicious Code Segments Detected (Prob: ${(mlProb * 100).toFixed(1)}%)`,
        severity: 'Critical',
        category: 'Static Code',
        isPrivacy: false,
        description: 'SecureBERT identified highly malicious bytecode segments typical of banking trojans or spyware.',
        evidence: `ML Verdict: ${mlVerdict} with high confidence.`
      });
    }

    abusedCombinations.forEach((combo: string, idx: number) => {
      fList.push({
        id: `KAV-PERM-${idx}`,
        title: `Suspicious Permission Combination: ${combo}`,
        severity: 'High',
        category: 'Static Code',
        isPrivacy: true,
        description: 'Application requests a combination of permissions often abused for data exfiltration or device takeover.',
        evidence: `Static manifest analysis found ${combo}.`
      });
    });

    if (fList.length === 0) {
      fList.push({
        id: 'KAV-INFO-00',
        title: 'No Critical Threats Detected',
        severity: 'Info',
        category: 'System Integrity',
        isPrivacy: false,
        description: 'The holistic static and dynamic scan revealed no critical anomalies.',
        evidence: 'Both SecureBERT inference and eBPF runtime hooks reported clean.'
      });
    }

    return {
      securityScore: finalSecurityScore,
      grade: currentGrade,
      riskRating: currentRiskRating,
      privacyRiskScore: finalPrivacyRiskScore,
      privacyRiskLevel: finalPrivacyRiskLevel,
      findings: fList
    };
  }, [telemetry, staticResults, simulationMode]);

  const filteredFindings = useMemo(() => {
    return findings.filter(f => {
      const matchesSeverity = filterSeverity === 'All' || 
                              (filterSeverity === 'Privacy' ? f.isPrivacy : f.severity === filterSeverity);
      const matchesSearch = f.title.toLowerCase().includes(searchQuery.toLowerCase()) || 
                            f.id.toLowerCase().includes(searchQuery.toLowerCase()) ||
                            f.category.toLowerCase().includes(searchQuery.toLowerCase());
      return matchesSeverity && matchesSearch;
    });
  }, [findings, filterSeverity, searchQuery]);

  const hasAnalysis = Boolean(telemetry || staticResults);

  if (!hasAnalysis) {
    return (
      <div className="flex flex-col items-center justify-center gap-3 py-24 text-center">
        <ShieldAlert className="w-10 h-10 text-muted-foreground/50" />
        <h2 className="text-lg font-bold">No current APK analysis</h2>
        <p className="max-w-md text-sm text-muted-foreground">Run a static scan or dynamic sandbox analysis first. The scorecard will not load a saved telemetry fixture from an earlier APK.</p>
      </div>
    );
  }

  const handlePrint = () => window.print();

  const handleExportJson = () => {
    const exportData = { scorecard: { securityScore, grade, riskRating, privacyRiskScore, findings } };
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(exportData, null, 2));
    const anchor = document.createElement('a');
    anchor.setAttribute("href", dataStr);
    anchor.setAttribute("download", `kavach_scorecard_${apkDetails?.package || 'app'}.json`);
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
  };

  const scoreColor = 
    securityScore < 40 ? 'text-destructive border-destructive shadow-[0_0_15px_rgba(239,68,68,0.3)]' :
    securityScore < 70 ? 'text-orange-500 border-orange-500 shadow-[0_0_15px_rgba(249,115,22,0.3)]' :
    'text-emerald-400 border-emerald-400 shadow-[0_0_15px_rgba(52,211,153,0.3)]';

  return (
    <div className="space-y-6 pb-12 animate-in fade-in zoom-in-95 duration-300">
      {/* Load Google Fonts */}
      <link rel="preconnect" href="https://fonts.googleapis.com" />
      <link rel="preconnect" href="https://fonts.gstatic.com" crossOrigin="anonymous" />
      <link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;700&family=JetBrains+Mono:wght@400;500;700&display=swap" rel="stylesheet" />

      {/* Header */}
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 pb-4 border-b border-zinc-800 no-print">
        <div>
          <button 
            onClick={viewDashboard}
            className="flex items-center gap-1.5 text-[10px] font-bold uppercase tracking-widest text-zinc-500 hover:text-zinc-300 transition-all mb-2 cursor-pointer font-['Space_Grotesk']"
          >
            <ArrowLeft className="w-3.5 h-3.5" />
            Back to Dashboard
          </button>
          <div className="flex items-center gap-3">
            <h2 className="text-xl font-bold tracking-tight text-zinc-100 flex items-center gap-2 font-['Space_Grotesk'] uppercase">
              Holistic Security & Privacy Scorecard
            </h2>
            <span className="text-[9px] font-extrabold uppercase tracking-widest px-2 py-0.5 border border-primary/20 text-primary bg-primary/10 rounded-none font-['Space_Grotesk']">
              Certified Audit
            </span>
          </div>
        </div>

        <div className="flex items-center gap-2 font-['Space_Grotesk']">
          <button 
            onClick={handleExportJson}
            className="flex items-center gap-2 px-3.5 py-1.5 bg-[#0D0E10] hover:bg-[#15171C] border border-zinc-800 text-zinc-300 text-[10px] font-bold tracking-wider transition-all cursor-pointer rounded-none"
          >
            <Download className="w-3.5 h-3.5" />
            EXPORT JSON
          </button>
          <button 
            onClick={handlePrint}
            className="flex items-center gap-2 px-4 py-1.5 bg-primary hover:bg-primary/95 text-primary-foreground text-[10px] font-bold tracking-wider transition-all cursor-pointer rounded-none"
          >
            <Printer className="w-3.5 h-3.5" />
            PRINT REPORT
          </button>
        </div>
      </div>

      {/* Top Grid */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        
        {/* Overall Security Score */}
        <div className="p-6 border border-zinc-800 bg-[#0D0E10] flex flex-col justify-between rounded-none transition-all hover:border-zinc-700/80">
          <div className="flex justify-between items-start">
            <div className="space-y-0.5">
              <span className="text-[10px] font-bold text-zinc-500 uppercase tracking-widest block font-['Space_Grotesk']">Overall Security Score</span>
              <span className="text-[9px] font-mono text-zinc-600 uppercase tracking-wider block">Static & Dynamic Fusion</span>
            </div>
            <span className={`text-[9px] font-bold px-2 py-0.5 border bg-[#080809] rounded-none font-['Space_Grotesk'] tracking-widest ${scoreColor}`}>
              GRADE {grade}
            </span>
          </div>

          <div className="relative w-24 h-24 flex items-center justify-center mx-auto my-4">
            <svg className="w-full h-full transform -rotate-90" viewBox="0 0 36 36">
              <path className="text-zinc-900" strokeWidth="2" stroke="currentColor" fill="none" d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831" />
              <path 
                className={securityScore < 50 ? 'text-destructive' : securityScore < 75 ? 'text-orange-500' : 'text-emerald-400'}
                strokeDasharray={`${securityScore}, 100`} 
                strokeWidth="2.5" stroke="currentColor" fill="none" 
                d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831" 
              />
            </svg>
            <div className="absolute flex flex-col items-center">
              <span className="text-2xl font-bold text-zinc-100 font-['Space_Grotesk']">{securityScore}</span>
            </div>
          </div>

          <div className="space-y-1.5 text-center">
            <div className="text-xs font-bold text-zinc-200 font-['Space_Grotesk'] uppercase tracking-wider">
              {securityScore < 50 ? 'Severe Vulnerabilities' : securityScore < 75 ? 'Moderate Exposure' : 'Strong Security Posture'}
            </div>
            <p className="text-[10px] text-zinc-500 leading-relaxed font-['JetBrains_Mono'] max-w-xs mx-auto">
              Aggregated from SecureBERT ML static inference and eBPF dynamic telemetry hooks.
            </p>
          </div>
        </div>

        {/* Risk Rating */}
        <div className="p-6 border border-zinc-800 bg-[#0D0E10] flex flex-col justify-between rounded-none transition-all hover:border-zinc-700/80">
          <div className="flex justify-between items-start">
            <div className="space-y-0.5">
              <span className="text-[10px] font-bold text-zinc-500 uppercase tracking-widest block font-['Space_Grotesk']">Threat Risk Rating</span>
              <span className="text-[9px] font-mono text-zinc-600 uppercase tracking-wider block">Exploitability Assessment</span>
            </div>
            <ShieldAlert className={`w-4 h-4 ${riskRating === 'CRITICAL' ? 'text-destructive' : riskRating === 'HIGH' ? 'text-orange-500' : 'text-emerald-400'}`} />
          </div>

          <div className="text-center my-4">
            <div className={`text-2xl font-bold tracking-widest font-['Space_Grotesk'] ${
              riskRating === 'CRITICAL' ? 'text-destructive' : 
              riskRating === 'HIGH' ? 'text-orange-500' : 
              'text-emerald-400'
            }`}>
              {riskRating} RISK
            </div>
          </div>

          <div className="space-y-2 text-[10px] uppercase tracking-wider font-bold text-zinc-500 font-['JetBrains_Mono'] pt-2 border-t border-zinc-900">
            <div className="flex items-center justify-between pb-1">
              <span>Code Toxicity:</span>
              <span className={`text-[9px] font-bold px-1.5 py-0.5 border ${
                staticResults 
                  ? 'border-emerald-500/20 text-emerald-400 bg-emerald-500/10' 
                  : 'border-zinc-800 text-zinc-600 bg-zinc-900/50'
              }`}>
                {staticResults ? 'ANALYZED' : 'PENDING'}
              </span>
            </div>
            <div className="flex items-center justify-between">
              <span>Runtime Hooks:</span>
              <span className={`text-[9px] font-bold px-1.5 py-0.5 border ${
                telemetry 
                  ? 'border-emerald-500/20 text-emerald-400 bg-emerald-500/10' 
                  : 'border-zinc-800 text-zinc-600 bg-zinc-900/50'
              }`}>
                {telemetry ? 'TRACED' : 'PENDING'}
              </span>
            </div>
          </div>
        </div>

        {/* Privacy Risk */}
        <div className="p-6 border border-zinc-800 bg-[#0D0E10] flex flex-col justify-between rounded-none transition-all hover:border-zinc-700/80">
          <div className="flex justify-between items-start">
            <div className="space-y-0.5">
              <span className="text-[10px] font-bold text-zinc-500 uppercase tracking-widest block font-['Space_Grotesk']">Privacy Exposure</span>
              <span className="text-[9px] font-mono text-zinc-600 uppercase tracking-wider block">Data Harvesting Potential</span>
            </div>
            <Eye className="w-4 h-4 text-purple-400" />
          </div>

          <div className="text-center my-4">
            <span className="text-3xl font-bold text-purple-400 font-['Space_Grotesk'] tracking-tight block">
              {privacyRiskScore}%
            </span>
          </div>

          <div className="space-y-3 pt-2 border-t border-zinc-900 font-['JetBrains_Mono']">
            <div>
              <div className="flex justify-between text-[10px] uppercase font-bold text-zinc-500 mb-1.5">
                <span>Exposure Level</span>
                <span className={`${
                  privacyRiskLevel === 'CRITICAL' || privacyRiskLevel === 'HIGH' ? 'text-purple-400' : 'text-zinc-300'
                }`}>{privacyRiskLevel}</span>
              </div>
              <div className="w-full bg-zinc-900 h-1 rounded-none overflow-hidden">
                <div className="bg-gradient-to-r from-purple-500 to-fuchsia-500 h-1 transition-all" style={{ width: `${privacyRiskScore}%` }} />
              </div>
            </div>
          </div>
        </div>

      </div>

      {/* Findings Panel */}
      <div className="border border-zinc-800 bg-[#0D0E10] p-6 rounded-none">
        <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4 mb-6">
          <div>
            <h3 className="text-sm font-bold text-zinc-200 uppercase tracking-wider font-['Space_Grotesk']">Audit Findings log</h3>
          </div>
          <div className="flex flex-wrap items-center gap-3 font-['Space_Grotesk']">
            <div className="flex border border-zinc-800 bg-[#080809] p-0.5 text-[9px] font-bold tracking-widest">
              {['All', 'Critical', 'High', 'Medium', 'Privacy'].map((sev) => (
                <button
                  key={sev}
                  onClick={() => setFilterSeverity(sev)}
                  className={`px-3 py-1 cursor-pointer transition-all ${
                    filterSeverity === sev ? 'bg-primary text-primary-foreground font-extrabold' : 'text-zinc-500 hover:text-zinc-300 hover:bg-zinc-900/50'
                  }`}
                >
                  {sev.toUpperCase()}
                </button>
              ))}
            </div>
            <div className="relative font-['JetBrains_Mono']">
              <Search className="w-3.5 h-3.5 absolute left-3 top-2.5 text-zinc-600" />
              <input
                type="text"
                placeholder="SEARCH..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-48 pl-9 pr-3 py-1.5 bg-[#080809] border border-zinc-800 text-[10px] text-zinc-300 font-semibold focus:outline-none focus:border-primary transition-all rounded-none uppercase tracking-wider"
              />
            </div>
          </div>
        </div>

        <div className="space-y-4">
          {filteredFindings.length === 0 ? (
            <div className="p-8 text-center text-zinc-500 text-[10px] font-bold font-mono uppercase tracking-widest border border-dashed border-zinc-800 bg-[#080809]/50">
              No matching findings found in current telemetry execution.
            </div>
          ) : (
            filteredFindings.map((item) => {
              // Left border logic based on severity
              const severityBorder = 
                item.severity === 'Critical' ? 'border-l-4 border-l-red-500' :
                item.severity === 'High' ? 'border-l-4 border-l-orange-500' :
                item.severity === 'Medium' ? 'border-l-4 border-l-amber-500' :
                'border-l-4 border-l-blue-500';

              return (
                <div key={item.id} className={`border border-zinc-850 p-5 bg-[#15171C]/25 hover:bg-[#15171C]/45 transition-all group backdrop-blur-md ${severityBorder}`}>
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-zinc-900/50 pb-3">
                    <div className="flex items-center gap-3">
                      <span className="font-mono text-[9px] font-bold text-primary bg-primary/10 px-2 py-0.5 border border-primary/20">{item.id}</span>
                      <h4 className="text-xs font-bold text-zinc-200 group-hover:text-primary transition-colors font-['Space_Grotesk'] uppercase tracking-wide">{item.title}</h4>
                    </div>
                    <div className="flex items-center gap-2 shrink-0 font-['Space_Grotesk']">
                      {item.isPrivacy && (
                        <span className="text-[8px] font-bold uppercase tracking-wider px-2 py-0.5 border border-purple-500/20 text-purple-400 bg-purple-500/10">Privacy Risk</span>
                      )}
                      <span className={`text-[8px] font-bold uppercase tracking-wider px-2 py-0.5 border ${
                        item.severity === 'Critical' ? 'border-red-500/20 text-red-400 bg-red-500/10' :
                        item.severity === 'High' ? 'border-orange-500/20 text-orange-400 bg-orange-500/10' :
                        item.severity === 'Medium' ? 'border-amber-500/20 text-amber-400 bg-amber-500/10' :
                        'border-blue-500/20 text-blue-400 bg-blue-500/10'
                      }`}>
                        {item.severity}
                      </span>
                    </div>
                  </div>
                  
                  <p className="text-[11px] font-['JetBrains_Mono'] leading-relaxed text-zinc-400 mt-3">
                    {item.description}
                  </p>
                  
                  <div className="mt-3 bg-[#080809] border border-zinc-900/80 p-3">
                    <span className="text-[8px] font-bold text-zinc-500 uppercase tracking-widest mb-1.5 block font-['Space_Grotesk']">Evidence</span>
                    <code className="text-[10px] font-mono text-emerald-400 break-all leading-normal whitespace-pre-wrap">{item.evidence}</code>
                  </div>
                </div>
              );
            })
          )}
        </div>
      </div>
    </div>
  );
};

export default KavachScorecard;
