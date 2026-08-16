import React, { useEffect, useState } from 'react';
import { useDetonation } from '@/context/DetonationContext';
import { FileText, Download, ShieldAlert, Cpu, Activity, Lightbulb } from 'lucide-react';

const renderMarkdown = (text: string, theme: 'light' | 'dark') => {
  if (!text) return null;
  const lines = text.split('\n');
  const elements: React.ReactNode[] = [];
  let currentList: React.ReactNode[] = [];

  const renderInline = (str: string) => {
    const codeParts = str.split(/(`.*?`)/g);
    return codeParts.map((part, index) => {
      if (part.startsWith('`') && part.endsWith('`')) {
        return (
          <code 
            key={`code-${index}`} 
            className={`px-1.5 py-0.5 font-mono text-[10px] font-semibold rounded border ${
              theme === 'light'
                ? 'bg-slate-100 border-slate-200 text-slate-800'
                : 'bg-zinc-900 border-zinc-800 text-zinc-200'
            }`}
          >
            {part.slice(1, -1)}
          </code>
        );
      }
      
      const boldParts = part.split(/(\*\*.*?\*\*)/g);
      return boldParts.map((bPart, bIndex) => {
        if (bPart.startsWith('**') && bPart.endsWith('**')) {
          return (
            <strong 
              key={`bold-${index}-${bIndex}`} 
              className={`font-bold ${theme === 'light' ? 'text-slate-900' : 'text-white'}`}
            >
              {bPart.slice(2, -2)}
            </strong>
          );
        }
        return bPart;
      });
    });
  };

  const flushList = (key: number) => {
    if (currentList.length > 0) {
      elements.push(
        <ul 
          key={`list-${key}`} 
          className={`list-disc pl-5 my-2 space-y-1 text-[11px] font-['JetBrains_Mono'] ${
            theme === 'light' ? 'text-slate-700' : 'text-zinc-300'
          }`}
        >
          {currentList}
        </ul>
      );
      currentList = [];
    }
  };

  lines.forEach((line, idx) => {
    const trimmed = line.trim();
    if (trimmed.startsWith('## ')) {
      flushList(idx);
      elements.push(
        <h4 
          key={idx} 
          className={`text-sm font-bold mt-4 mb-2 first:mt-0 font-['Space_Grotesk'] tracking-wider ${
            theme === 'light' ? 'text-slate-900' : 'text-white'
          }`}
        >
          {renderInline(trimmed.substring(3))}
        </h4>
      );
    } else if (trimmed.startsWith('### ')) {
      flushList(idx);
      elements.push(
        <h5 
          key={idx} 
          className={`text-xs font-bold mt-3 mb-1 font-['Space_Grotesk'] tracking-wider ${
            theme === 'light' ? 'text-slate-900' : 'text-white'
          }`}
        >
          {renderInline(trimmed.substring(4))}
        </h5>
      );
    } else if (trimmed.startsWith('* ') || trimmed.startsWith('- ')) {
      currentList.push(
        <li 
          key={idx} 
          className={`leading-relaxed text-[11px] font-['JetBrains_Mono'] ${
            theme === 'light' ? 'text-slate-700' : 'text-zinc-300'
          }`}
        >
          {renderInline(trimmed.substring(2))}
        </li>
      );
    } else if (trimmed === '') {
      flushList(idx);
      elements.push(<div key={idx} className="h-2" />);
    } else {
      flushList(idx);
      elements.push(
        <p 
          key={idx} 
          className={`text-[11px] font-['JetBrains_Mono'] leading-relaxed my-1 ${
            theme === 'light' ? 'text-slate-700' : 'text-zinc-300'
          }`}
        >
          {renderInline(line)}
        </p>
      );
    }
  });

  flushList(lines.length);
  return <div className="space-y-1">{elements}</div>;
};

export const KavachReportView: React.FC = () => {
  const { jobId, staticResults, apkDetails, staticScanStatus, status } = useDetonation();
  const [reportData, setReportData] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [reportTheme, setReportTheme] = useState<'dark' | 'light'>('light');

  useEffect(() => {
    let isMounted = true;
    const controller = new AbortController();

    // A report view remains mounted when the analyst starts another APK. Clear
    // the previous payload before the new job id is available so it can never
    // be rendered under the new target's metadata.
    setReportData(null);
    setLoading(Boolean(jobId));

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
        console.error('Failed to fetch Kavach AI report:', err);
      } finally {
        if (isMounted) setLoading(false);
      }
    };

    if (jobId) fetchReport();

    // Poll for report completion if report is missing or currently in preliminary state
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

  let executiveSummary = reportData?.executive_summary || reportData?.forensic?.summary;
  if (!executiveSummary && reportData?.contradiction_label) {
    executiveSummary = `Kavach AI completed the analysis. The threat verdict is classified as ${reportData.contradiction_label} with a final security risk score of ${reportData.final_score}/100.`;
  }

  // For static findings/narrative
  let staticNarrative = reportData?.static_analysis_narrative;
  if (!staticNarrative && reportData?.forensic?.static_findings) {
    staticNarrative = Array.isArray(reportData.forensic.static_findings)
      ? reportData.forensic.static_findings.join('\n')
      : reportData.forensic.static_findings;
  } else if (!staticNarrative && reportData?.static_evidence?.indicators) {
    staticNarrative = `Static indicators detected:\n` + reportData.static_evidence.indicators.map((ind: string) => `• ${ind}`).join('\n');
  }
  
  // For dynamic findings/narrative
  let behavioralNarrative = reportData?.behavioral_analysis_narrative;
  if (!behavioralNarrative && reportData?.forensic?.dynamic_findings) {
    behavioralNarrative = Array.isArray(reportData.forensic.dynamic_findings)
      ? reportData.forensic.dynamic_findings.join('\n')
      : reportData.forensic.dynamic_findings;
  } else if (!behavioralNarrative && reportData?.behavioral_fingerprint) {
    const bf = reportData.behavioral_fingerprint;
    const parts = [];
    if (bf.syscalls && bf.syscalls.length > 0) {
      parts.push(`Monitored system calls:\n${bf.syscalls.slice(0, 10).map((s: string) => `• ${s}`).join('\n')}`);
    }
    if (bf.ips && bf.ips.length > 0) {
      parts.push(`Observed connections to remote hosts:\n${bf.ips.map((ip: string) => `• ${ip}`).join('\n')}`);
    }
    if (bf.evasion_signals && bf.evasion_signals.length > 0) {
      parts.push(`Evasion mechanisms triggered:\n${bf.evasion_signals.map((es: string) => `• ${es}`).join('\n')}`);
    }
    behavioralNarrative = parts.length > 0 ? parts.join('\n\n') : undefined;
  }

  const remediationRecommendations = reportData?.remediation_recommendations || reportData?.cert_in?.recommended_mitigations;

  const mitreTactics = reportData?.cert_in?.mitre_attack_tactics || reportData?.mitre_attack_json?.tactics || [];
  const mitreTechniques = reportData?.cert_in?.mitre_attack_techniques || reportData?.mitre_attack_json?.techniques || [];

  const isPreliminary = reportData?.status === 'preliminary' || (!executiveSummary && !staticNarrative && !behavioralNarrative);

  if (!jobId) {
    return <div className="p-8 text-center text-muted-foreground">No Report Available (No Job ID)</div>;
  }

  if (loading) {
    return <div className="p-8 text-center text-muted-foreground">Generating Kavach AI Report...</div>;
  }

  // Resolve APK details dynamically for metadata table on Page 1
  const apkName = staticResults?.apk_details?.name || apkDetails?.name || reportData?.apk_details?.name || reportData?.forensic?.name || 'app-release.apk';
  const apkPackage = staticResults?.apk_details?.package || apkDetails?.package || reportData?.apk_details?.package || reportData?.forensic?.package || 'com.example.app';
  const apkSize = staticResults?.apk_details?.size || apkDetails?.size || reportData?.apk_details?.size || reportData?.forensic?.size || 'Unknown Size';
  const apkHash = staticResults?.apk_details?.hash || reportData?.apk_details?.hash || reportData?.forensic?.hash || 'Unknown Hash';

  return (
    <div className="space-y-6">
      {/* Load Google Fonts */}
      <link rel="preconnect" href="https://fonts.googleapis.com" />
      <link rel="preconnect" href="https://fonts.gstatic.com" crossOrigin="anonymous" />
      <link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;700&family=JetBrains+Mono:wght@400;500;700&display=swap" rel="stylesheet" />

      {/* Styles for A4 screen emulation, custom fonts, and printing */}
      <style dangerouslySetInnerHTML={{ __html: `
        @media print {
          /* Hide all navigation, panels, sidebars, buttons, etc. */
          body * {
            visibility: hidden !important;
          }
          /* Show only the A4 report pages */
          #kavach-a4-page-1, #kavach-a4-page-1 *,
          #kavach-a4-page-2, #kavach-a4-page-2 * {
            visibility: visible !important;
          }
          #kavach-a4-page-1 {
            position: absolute !important;
            left: 0 !important;
            top: 0 !important;
            width: 210mm !important;
            height: 297mm !important;
            padding: 20mm !important;
            margin: 0 !important;
            border: none !important;
            box-shadow: none !important;
            background: white !important;
            color: black !important;
          }
          #kavach-a4-page-2 {
            position: absolute !important;
            left: 0 !important;
            top: 297mm !important; /* Force onto second page when printed */
            width: 210mm !important;
            min-height: 297mm !important;
            padding: 20mm !important;
            margin: 0 !important;
            border: none !important;
            box-shadow: none !important;
            background: white !important;
            color: black !important;
            break-before: page !important;
            page-break-before: always !important;
          }
          /* Force text and borders to display clearly on white paper */
          .print-light-text {
            color: #0f172a !important;
          }
          .print-light-sub {
            color: #475569 !important;
          }
          .print-light-border {
            border-color: #cbd5e1 !important;
          }
          .print-light-bg {
            background-color: #f1f5f9 !important;
          }
        }
        @page {
          size: A4;
          margin: 0;
        }
      `}} />

      {/* Control bar: Theme toggle & Action buttons (hidden when printing) */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between border-b border-border pb-4 gap-3 no-print">
        <h2 className="text-xl font-bold flex items-center gap-2">
          <FileText className="w-5 h-5 text-primary" />
          Generative AI Analysis Report
        </h2>
        
        <div className="flex items-center gap-3">
          {/* Theme Selector */}
          <div className="flex bg-card border border-border p-0.5 rounded-none text-xs font-['Space_Grotesk']">
            <button
              onClick={() => setReportTheme('light')}
              className={`px-3 py-1 font-semibold transition-all cursor-pointer ${
                reportTheme === 'light'
                  ? 'bg-primary text-primary-foreground font-bold'
                  : 'text-muted-foreground hover:text-foreground'
              }`}
            >
              LIGHT
            </button>
            <button
              onClick={() => setReportTheme('dark')}
              className={`px-3 py-1 font-semibold transition-all cursor-pointer ${
                reportTheme === 'dark'
                  ? 'bg-primary text-primary-foreground font-bold'
                  : 'text-muted-foreground hover:text-foreground'
              }`}
            >
              DARK
            </button>
          </div>

          {/* Export PDF Button */}
          <button 
            onClick={() => window.print()}
            className="flex items-center gap-2 px-3 py-1.5 bg-primary/10 hover:bg-primary/20 text-primary border border-primary/20 text-xs font-semibold font-['Space_Grotesk'] tracking-wider transition-all cursor-pointer"
          >
            <Download className="w-4 h-4" />
            EXPORT PDF
          </button>
        </div>
      </div>

      {reportData ? (
        isPreliminary ? (
          <div className="border border-dashed border-border bg-card/30 p-8 text-center text-muted-foreground flex flex-col items-center justify-center space-y-4 no-print">
            <ShieldAlert className="w-12 h-12 text-primary/60 animate-pulse" />
            <div className="space-y-1">
              <h4 className="font-bold text-foreground">AI Forensic Report is Pending</h4>
              <p className="text-xs max-w-md">
                The generative analysis report has not been compiled yet. Please run a **Static Scan** or **Dynamic Sandbox Detonation** on your APK to generate the AI analysis report.
              </p>
            </div>
          </div>
        ) : (
          /* Multi-Page Report Container on Screen */
          <div className="w-full overflow-x-auto py-4 space-y-8 no-print:bg-[#080809]">
            
            {/* PAGE 1 */}
            <div 
              id="kavach-a4-page-1"
              className={`w-full max-w-[210mm] min-h-[297mm] p-[15mm] md:p-[20mm] mx-auto border transition-all duration-200 shadow-md flex flex-col justify-between ${
                reportTheme === 'light'
                  ? 'bg-white text-slate-800 border-zinc-200 print-light-text'
                  : 'bg-[#0D0E10] text-[#D1D5DB] border-zinc-800'
              }`}
            >
              <div className="space-y-6">
                {/* Header Profile */}
                <div className={`border-b pb-4 flex justify-between items-end ${reportTheme === 'light' ? 'border-zinc-200 print-light-border' : 'border-zinc-800'}`}>
                  <div className="space-y-1">
                    <h1 className={`text-2xl font-bold tracking-tight uppercase font-['Space_Grotesk'] ${reportTheme === 'light' ? 'text-slate-900 print-light-text' : 'text-[#EDEDED]'}`}>
                      Kavach AI Security Report
                    </h1>
                    <p className="text-[9px] font-mono text-muted-foreground tracking-widest uppercase print-light-sub">
                      Forensic Verdict Report & ATT&CK Compliance Matrix
                    </p>
                  </div>
                  <div className="text-right space-y-0.5 text-[9px] text-muted-foreground font-mono print-light-sub">
                    <div>JOB ID: {jobId}</div>
                    <div>DATE: {new Date().toLocaleDateString()}</div>
                  </div>
                </div>

                {/* Target Profile Table */}
                <div className={`border p-4 space-y-3 rounded-none ${reportTheme === 'light' ? 'bg-slate-50 border-slate-200' : 'bg-[#15171C]/50 border-zinc-800'}`}>
                  <span className={`font-['Space_Grotesk'] font-bold text-xs uppercase tracking-wider block ${reportTheme === 'light' ? 'text-slate-900' : 'text-[#EDEDED]'}`}>
                    Target Artifact Profile
                  </span>
                  <div className="grid grid-cols-4 gap-y-2 text-[11px] font-['JetBrains_Mono']">
                    <div className={`font-semibold ${reportTheme === 'light' ? 'text-slate-500' : 'text-zinc-500'}`}>Filename:</div>
                    <div className={`col-span-3 font-medium break-all ${reportTheme === 'light' ? 'text-slate-800' : 'text-[#D1D5DB]'}`}>{apkName}</div>
                    
                    <div className={`font-semibold ${reportTheme === 'light' ? 'text-slate-500' : 'text-zinc-500'}`}>Package:</div>
                    <div className="col-span-3 font-medium break-all text-primary">{apkPackage}</div>
                    
                    <div className={`font-semibold ${reportTheme === 'light' ? 'text-slate-500' : 'text-zinc-500'}`}>File Size:</div>
                    <div className={`col-span-3 font-medium ${reportTheme === 'light' ? 'text-slate-800' : 'text-[#D1D5DB]'}`}>{apkSize}</div>
                    
                    <div className={`font-semibold ${reportTheme === 'light' ? 'text-slate-500' : 'text-zinc-500'}`}>SHA-256:</div>
                    <div className={`col-span-3 font-medium break-all ${reportTheme === 'light' ? 'text-slate-800' : 'text-[#D1D5DB]'}`}>{apkHash}</div>
                  </div>
                </div>

                {/* Executive Summary */}
                {executiveSummary && (
                  <div className={`border p-5 space-y-3 rounded-none ${reportTheme === 'light' ? 'bg-slate-50 border-slate-200' : 'bg-[#15171C]/50 border-zinc-800'}`}>
                    <h3 className={`text-sm font-bold flex items-center gap-2 font-['Space_Grotesk'] uppercase tracking-wider ${reportTheme === 'light' ? 'text-slate-900' : 'text-[#EDEDED]'}`}>
                      <ShieldAlert className="w-4 h-4 text-primary" /> Executive Summary
                    </h3>
                    <div className="text-[11px] font-['JetBrains_Mono'] leading-relaxed">
                      {renderMarkdown(executiveSummary, reportTheme)}
                    </div>
                  </div>
                )}

                {/* MITRE Mapping */}
                {(mitreTactics.length > 0 || mitreTechniques.length > 0) && (
                  <div className={`border p-5 space-y-3 rounded-none ${reportTheme === 'light' ? 'bg-slate-50 border-slate-200' : 'bg-[#15171C]/50 border-zinc-800'}`}>
                    <h3 className={`text-sm font-bold flex items-center gap-2 font-['Space_Grotesk'] uppercase tracking-wider ${reportTheme === 'light' ? 'text-slate-900' : 'text-[#EDEDED]'}`}>
                      🛡️ MITRE ATT&CK Mapping
                    </h3>
                    <div className="space-y-3 text-[11px] font-['JetBrains_Mono']">
                      {mitreTactics.length > 0 && (
                        <div className="flex flex-col sm:flex-row sm:items-center gap-1.5">
                          <span className={`font-bold text-[10px] uppercase tracking-wider w-20 ${reportTheme === 'light' ? 'text-slate-500' : 'text-zinc-500'}`}>Tactics:</span>
                          <div className="flex flex-wrap gap-1.5">
                            {mitreTactics.map((t: string, idx: number) => (
                              <span key={idx} className="bg-red-500/10 text-red-500 border border-red-500/20 px-2 py-0.5 text-[9px] font-bold">
                                {t}
                              </span>
                            ))}
                          </div>
                        </div>
                      )}
                      {mitreTechniques.length > 0 && (
                        <div className="flex flex-col sm:flex-row sm:items-center gap-1.5">
                          <span className={`font-bold text-[10px] uppercase tracking-wider w-20 ${reportTheme === 'light' ? 'text-slate-500' : 'text-zinc-500'}`}>Techniques:</span>
                          <div className="flex flex-wrap gap-1.5">
                            {mitreTechniques.map((t: string, idx: number) => (
                              <span key={idx} className="bg-amber-500/10 text-amber-600 border border-amber-500/20 px-2 py-0.5 text-[9px] font-bold">
                                {t}
                              </span>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  </div>
                )}
              </div>

              {/* Page 1 Footer */}
              <div className={`border-t pt-3 flex justify-between items-center text-[9px] font-mono ${reportTheme === 'light' ? 'border-slate-200 text-slate-400' : 'border-zinc-800 text-zinc-500'}`}>
                <div>Kavach.ai Analytical Platform</div>
                <div>Page 1 of 2</div>
              </div>
            </div>

            {/* PAGE 2 */}
            <div 
              id="kavach-a4-page-2"
              className={`w-full max-w-[210mm] min-h-[297mm] p-[15mm] md:p-[20mm] mx-auto border transition-all duration-200 shadow-md flex flex-col justify-between ${
                reportTheme === 'light'
                  ? 'bg-white text-slate-800 border-zinc-200 print-light-text'
                  : 'bg-[#0D0E10] text-[#D1D5DB] border-zinc-800'
              }`}
            >
              <div className="space-y-6">
                {/* Header Profile - Duplicate for page 2 */}
                <div className={`border-b pb-4 flex justify-between items-end ${reportTheme === 'light' ? 'border-zinc-200 print-light-border' : 'border-zinc-800'}`}>
                  <div className="space-y-0.5">
                    <h2 className={`text-lg font-bold tracking-tight uppercase font-['Space_Grotesk'] ${reportTheme === 'light' ? 'text-slate-900 print-light-text' : 'text-[#EDEDED]'}`}>
                      Kavach AI Security Report
                    </h2>
                    <p className="text-[8px] font-mono text-muted-foreground tracking-widest uppercase print-light-sub">
                      Section II: Static & Behavioral Forensic Analysis
                    </p>
                  </div>
                  <div className="text-right text-[9px] text-muted-foreground font-mono print-light-sub">
                    <div>JOB ID: {jobId}</div>
                  </div>
                </div>

                {/* Static Analysis Narrative */}
                {staticNarrative && (
                  <div className={`border p-5 space-y-3 rounded-none ${reportTheme === 'light' ? 'bg-slate-50 border-slate-200' : 'bg-[#15171C]/50 border-zinc-800'}`}>
                    <h3 className={`text-sm font-bold flex items-center gap-2 font-['Space_Grotesk'] uppercase tracking-wider ${reportTheme === 'light' ? 'text-slate-900 print-light-text' : 'text-[#EDEDED]'}`}>
                      <Cpu className="w-4 h-4 text-primary" /> Static Analysis Narrative
                    </h3>
                    <div className="text-[11px] font-['JetBrains_Mono'] leading-relaxed">
                      {renderMarkdown(staticNarrative, reportTheme)}
                    </div>
                  </div>
                )}

                {/* Behavioral Analysis Narrative */}
                {behavioralNarrative && (
                  <div className={`border p-5 space-y-3 rounded-none ${reportTheme === 'light' ? 'bg-slate-50 border-slate-200' : 'bg-[#15171C]/50 border-zinc-800'}`}>
                    <h3 className={`text-sm font-bold flex items-center gap-2 font-['Space_Grotesk'] uppercase tracking-wider ${reportTheme === 'light' ? 'text-slate-900 print-light-text' : 'text-[#EDEDED]'}`}>
                      <Activity className="w-4 h-4 text-primary" /> Behavioral Analysis Narrative
                    </h3>
                    <div className="text-[11px] font-['JetBrains_Mono'] leading-relaxed">
                      {renderMarkdown(behavioralNarrative, reportTheme)}
                    </div>
                  </div>
                )}

                {/* Remediation Recommendations */}
                {remediationRecommendations && (
                  <div className={`border p-5 space-y-3 rounded-none ${reportTheme === 'light' ? 'bg-slate-50 border-slate-200' : 'bg-[#15171C]/50 border-zinc-800'}`}>
                    <h3 className={`text-sm font-bold flex items-center gap-2 font-['Space_Grotesk'] uppercase tracking-wider ${reportTheme === 'light' ? 'text-slate-900 print-light-text' : 'text-[#EDEDED]'}`}>
                      <Lightbulb className="w-4 h-4 text-primary" /> Remediation Recommendations
                    </h3>
                    <ul className={`list-disc pl-5 text-[11px] font-['JetBrains_Mono'] space-y-1 ${reportTheme === 'light' ? 'text-slate-700' : 'text-zinc-300'}`}>
                      {Array.isArray(remediationRecommendations) 
                        ? remediationRecommendations.map((rec: string, i: number) => <li key={i}>{rec}</li>)
                        : <li className="whitespace-pre-wrap">{remediationRecommendations}</li>}
                    </ul>
                  </div>
                )}
              </div>

              {/* Page 2 Footer */}
              <div className={`border-t pt-3 flex justify-between items-center text-[9px] font-mono ${reportTheme === 'light' ? 'border-slate-200 text-slate-400' : 'border-zinc-800 text-zinc-500'}`}>
                <div>Compiled by Kavach AI Security Engine. Authorized for distribution.</div>
                <div>Page 2 of 2</div>
              </div>
            </div>

          </div>
        )
      ) : (
        <div className="p-8 text-center text-muted-foreground no-print">Report generation failed or no data returned.</div>
      )}
    </div>
  );
};
