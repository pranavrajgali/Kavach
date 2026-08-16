import React, { useState, useEffect } from 'react';
import { useDetonation } from '@/context/DetonationContext';
import { 
  Download, 
  FileSearch, 
  Network, 
  Globe, 
  ShieldCheck, 
  Crosshair, 
  Search,
  Zap,
  Clock,
  Radio,
  Key,
  Eye
} from 'lucide-react';

export const ReportView: React.FC = () => {
  const { telemetry, apkDetails, reset, logs = [] } = useDetonation();
  const [activeTab, setActiveTab] = useState<'files' | 'sockets' | 'dns' | 'permissions' | 'mitre' | 'evasion'>('evasion');
  const [threatIntel, setThreatIntel] = useState<Record<string, any>>({});
  const [searchQuery, setSearchQuery] = useState<string>('');

  const objectionRoot = telemetry?.objection_root_bypass || false;
  const objectionSsl = telemetry?.objection_ssl_pinning_bypass || false;
  const timeDilutionBypass = telemetry?.time_dilution_bypass || false;
  const timeDilutionCount = telemetry?.time_dilution_count || (timeDilutionBypass ? 1 : 0);
  const timeDilutionEvents = telemetry?.time_dilution_events || [];
  const llmFridaIntercepts = telemetry?.llm_frida_intercepts || [];
  const fuzzedIntents = telemetry?.fuzzed_intents || [];
  const filesAccessed = telemetry?.ebpf_telemetry?.files_accessed || [];
  const networkConns = telemetry?.ebpf_telemetry?.network_connections || [];
  const dnsResolutions = telemetry?.ebpf_telemetry?.dns_resolutions || [];
  const permissionsExercised = telemetry?.ebpf_telemetry?.permissions_exercised || [];
  const executionMode = telemetry?.execution_mode || 'SIMULATION_FALLBACK';

  useEffect(() => {
    const hostsToQuery: string[] = [];
    networkConns.forEach((c) => {
      if (c.ip) hostsToQuery.push(c.ip);
    });
    dnsResolutions.forEach((d) => {
      if (d.domain) hostsToQuery.push(d.domain);
    });

    const uniqueHosts = Array.from(new Set(hostsToQuery));
    uniqueHosts.forEach(async (host) => {
      if (threatIntel[host]) return;
      try {
        const res = await fetch(`/api/threat-intel?host=${encodeURIComponent(host)}`);
        if (res.ok) {
          const data = await res.json();
          setThreatIntel((prev) => ({ ...prev, [host]: data }));
        }
      } catch (e) {
        console.error("Failed to fetch threat intel for", host, e);
      }
    });
  }, [telemetry, networkConns, dnsResolutions]);

  const getEventTime = (patterns: string[], defaultTime: string) => {
    const idx = logs.findIndex((log) =>
      patterns.some((p) => log.toLowerCase().includes(p.toLowerCase()))
    );
    if (idx !== -1) {
      return `T + ${(idx * 0.8).toFixed(1)}s`;
    }
    return defaultTime;
  };

  const renderStatusBadge = (host: string) => {
    const intel = threatIntel[host];
    if (!intel) return <span className="bg-zinc-800 text-zinc-500 text-[9px] px-1.5 py-0.5 font-bold uppercase border border-zinc-700">CHECKING</span>;

    if (intel.status === 'malicious') {
      return (
        <span className="bg-red-500/10 text-red-500 border border-red-500/20 px-2 py-0.5 text-[9px] font-bold uppercase rounded-none">
          malicious
        </span>
      );
    }
    if (intel.status === 'suspicious') {
      return (
        <span className="bg-amber-500/10 text-amber-500 border border-amber-500/20 px-2 py-0.5 text-[9px] font-bold uppercase rounded-none">
          suspicious
        </span>
      );
    }
    return (
      <span className="bg-emerald-500/10 text-emerald-500 border border-emerald-500/20 px-2 py-0.5 text-[9px] font-bold uppercase rounded-none">
        good
      </span>
    );
  };

  const renderGeoDetails = (host: string) => {
    const intel = threatIntel[host];
    if (!intel) {
      return <span className="text-muted-foreground/60 italic text-[11px]">Resolving details...</span>;
    }
    const geo = intel.geolocation || {};
    return (
      <div className="space-y-0.5 text-[11px] leading-relaxed text-muted-foreground font-mono">
        <div>IP: <span className="text-foreground font-semibold">{intel.resolved_ip || host}</span></div>
        <div>Country: <span className="text-foreground">{geo.country || 'Unknown'}</span></div>
        {geo.region && geo.region !== "Unknown" && <div>Region: <span className="text-foreground">{geo.region}</span></div>}
        {geo.city && geo.city !== "Unknown" && <div>City: <span className="text-foreground">{geo.city}</span></div>}
        {geo.latitude ? (
          <>
            <div>Latitude: <span className="text-foreground">{geo.latitude}</span></div>
            <div>Longitude: <span className="text-foreground">{geo.longitude}</span></div>
          </>
        ) : null}
        {geo.isp && geo.isp !== "Unknown" && <div>ISP/Org: <span className="text-foreground">{geo.isp}</span></div>}
        {intel.google_maps_url && (
          <div className="mt-1 font-sans">
            View: <a
              href={intel.google_maps_url}
              target="_blank"
              rel="noopener noreferrer"
              className="text-primary hover:underline font-bold text-[11px]"
            >
              Google Map
            </a>
          </div>
        )}
      </div>
    );
  };

  // ── Dynamic Threat Score ──
  let score = 0.05;
  if (objectionRoot) score += 0.35;
  if (objectionSsl) score += 0.30;
  filesAccessed.forEach(f => {
    if (f.includes('app_process') || f.includes('system') || f.includes('su')) {
      score += 0.20;
    } else if (f.includes('Bot') || f.includes('zlock') || f.includes('contacts')) {
      score += 0.10;
    } else if (f.includes('shared_prefs') || f.includes('config')) {
      score += 0.02;
    }
  });
  networkConns.forEach(c => {
    if (c.port === 4444) {
      score += 0.45;
    } else if ([80, 443, 8080, 53].includes(c.port)) {
      score += 0.05;
    } else {
      score += 0.05;
    }
  });

  const probability = Math.min(0.99, Math.max(0.02, score));

  // Dynamic verdict: never say "CLEAN"
  let dynamicVerdictText = 'No malicious behavior observed in this run';
  let dynamicVerdictColor = 'text-zinc-400';

  const hasDynamicEvidence = filesAccessed.length > 0 || networkConns.length > 0 || objectionRoot || objectionSsl;

  if (probability > 0.65) {
    dynamicVerdictText = 'MALICIOUS';
    dynamicVerdictColor = 'text-red-500';
  } else if (probability > 0.30) {
    dynamicVerdictText = 'SUSPICIOUS';
    dynamicVerdictColor = 'text-amber-500';
  } else if (hasDynamicEvidence) {
    dynamicVerdictText = 'LOW RISK';
    dynamicVerdictColor = 'text-blue-400';
  }




  const downloadTelemetry = () => {
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(telemetry, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute("href", dataStr);
    downloadAnchor.setAttribute("download", `forensic_report_${apkDetails?.package || 'apk'}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  // ── File classification helper ──
  const classifyFile = (path: string): { op: string; ctx: string; ctxColor: string } => {
    const filename = path.split('/').pop() || path;
    if (filename.startsWith('Bot') || filename === 'contacts' || filename === 'app_stat') {
      return { op: 'Write', ctx: 'Bot Exfiltration', ctxColor: 'text-red-500 font-semibold' };
    }
    if (filename === 'zlock' || filename === 'HG' || filename === 'i' || filename === 'c') {
      return { op: 'Read/Write', ctx: 'Trojan State', ctxColor: 'text-amber-500 font-semibold' };
    }
    if (path.includes('app_process') || path.includes('system') || path.includes('su')) {
      return { op: 'Read', ctx: 'System Binary', ctxColor: 'text-red-500 font-semibold' };
    }
    if (path.includes('shared_prefs') || path.includes('config')) {
      return { op: 'Read/Write', ctx: 'App Config', ctxColor: 'text-amber-500 font-semibold' };
    }
    return { op: 'Access', ctx: 'General', ctxColor: 'text-muted-foreground' };
  };

  // ── Tab config ──
  const tabs = [
    { id: 'evasion' as const, label: 'Evasion Defusal & AI Hooks', icon: Zap },
    { id: 'files' as const, label: 'File I/O', icon: FileSearch },
    { id: 'sockets' as const, label: 'Network Sockets', icon: Network },
    { id: 'dns' as const, label: 'DNS Lookups', icon: Globe },
    { id: 'permissions' as const, label: 'Runtime Permissions', icon: ShieldCheck },
    { id: 'mitre' as const, label: 'MITRE ATT&CK', icon: Crosshair },
  ];

  return (
    <div className="space-y-6">
      {/* Title & Actions */}
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
        <div>
          <h2 className="text-xl font-bold text-foreground">Sandbox Forensic Dashboard</h2>
          <p className="text-xs text-muted-foreground mt-1">Real-time instrumentation, system triggers, and telemetry.</p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={downloadTelemetry}
            className="flex items-center gap-2 px-4 py-2 bg-primary hover:bg-primary/95 text-primary-foreground font-semibold rounded-none text-xs transition-all cursor-pointer shadow-sm"
          >
            <Download className="w-4 h-4" />
            Export Forensic Profile
          </button>
        </div>
      </div>

      {/* ═══ Row 1: Split Verdicts + KPI Metrics ═══ */}
      <div className="border border-border rounded-none bg-card overflow-hidden grid grid-cols-1 md:grid-cols-3 divide-y md:divide-y-0 md:divide-x divide-border">
        
        {/* Dynamic Analysis Verdict */}
        <div className={`p-6 space-y-4 border-l-2 ${probability > 0.65 ? 'border-red-500/60' : probability > 0.30 ? 'border-amber-500/60' : 'border-blue-500/40'}`}>
          <span className="text-[10px] font-bold text-muted-foreground uppercase tracking-wider block">
            Dynamic Threat Verdict
          </span>
          <div className="space-y-1">
            <div className="flex items-center gap-2 flex-wrap">
              <div className={`text-2xl font-extrabold tracking-tight ${dynamicVerdictColor}`}>
                {dynamicVerdictText}
              </div>
              <span className={`px-2 py-0.5 text-[9px] font-mono font-bold tracking-wide uppercase border rounded-none ${
                probability > 0.65 
                  ? 'bg-red-500/10 text-red-500 border-red-500/20' 
                  : probability > 0.30 
                    ? 'bg-amber-500/10 text-amber-500 border-amber-500/20' 
                    : 'bg-blue-500/10 text-blue-400 border-blue-500/20'
              }`}>
                {probability > 0.65 ? 'CRITICAL RISK' : probability > 0.30 ? 'SUSPICIOUS' : 'MINIMAL'}
              </span>
            </div>
            <div className="flex items-center gap-1.5 text-[11px] text-muted-foreground pt-1">
              <span>Sandbox State: </span>
              <span className={`px-1.5 py-0.5 text-[9px] font-mono font-bold border rounded-none ${
                executionMode === 'LIVE_ADB_FRIDA' 
                  ? 'bg-emerald-500/10 text-emerald-500 border-emerald-500/10' 
                  : 'bg-zinc-800 text-zinc-400 border-zinc-700'
              }`}>
                {executionMode === 'LIVE_ADB_FRIDA' ? 'LIVE ADB (PIXEL 3)' : 'EMULATOR SIMULATION'}
              </span>
            </div>
          </div>
        </div>

        {/* API Hooks Active */}
        <div className="p-6 space-y-4">
          <span className="text-[10px] font-bold text-muted-foreground uppercase tracking-wider block">
            API Hooks Active
          </span>
          <div className="space-y-1">
            <div className="text-2xl font-extrabold tracking-tight text-foreground">
              {objectionRoot || objectionSsl ? "7 Hooks" : "0 Hooks"}
            </div>
            <div className="flex items-center gap-1 text-[11px] text-muted-foreground">
              <span className="text-red-500 font-bold">▲ Active</span>
              <span>instrumentation hooks</span>
            </div>
          </div>
        </div>

        {/* Intercepted Signals */}
        <div className="p-6 space-y-4">
          <span className="text-[10px] font-bold text-muted-foreground uppercase tracking-wider block">
            Intercepted Signals
          </span>
          <div className="space-y-1">
            <div className="text-2xl font-extrabold tracking-tight text-foreground">
              {filesAccessed.length + networkConns.length}
            </div>
            <div className="flex items-center gap-1 text-[11px] text-muted-foreground">
              <span className="text-foreground font-medium">{filesAccessed.length}</span> files
              <span className="text-border mx-0.5">·</span>
              <span className="text-foreground font-medium">{networkConns.length}</span> sockets
            </div>
          </div>
        </div>

      </div>

      {/* ═══ Row 2: Detonation Timeline & Geolocation / Malware Checks ═══ */}
      <div className="border-x border-b border-border rounded-none bg-card overflow-hidden grid grid-cols-1 lg:grid-cols-2 divide-y lg:divide-y-0 lg:divide-x divide-border">
        
        {/* Detonation Event Timeline */}
        <div className="p-6 space-y-4">
          <div>
            <div className="flex items-center justify-between">
              <span className="text-sm font-bold text-foreground">Detonation Event Timeline</span>
              <span className={`text-[10px] font-semibold px-2 py-0.5 rounded-none border ${
                executionMode === 'LIVE_ADB_FRIDA' 
                  ? 'text-emerald-500 bg-emerald-500/10 border-emerald-500/20' 
                  : 'text-zinc-400 bg-zinc-500/10 border-zinc-500/20'
              }`}>
                {executionMode === 'LIVE_ADB_FRIDA' ? 'LIVE ADB' : 'SIMULATED'}
              </span>
            </div>
            <p className="text-[11px] text-muted-foreground mt-1">Chronological log of activities intercepted during sandbox detonation.</p>
          </div>
          
          <div className="space-y-4 h-[230px] overflow-y-auto pr-2 pt-2 scrollbar-thin text-xs">
            <div className="relative border-l border-border pl-4 ml-2 space-y-4 font-sans">
              {/* Event 1 */}
              <div className="relative">
                <span className="absolute -left-[21px] top-1 w-2.5 h-2.5 rounded-full bg-emerald-500 border-2 border-background"></span>
                <span className="text-[9px] font-mono text-muted-foreground">
                  {getEventTime(['installing', 'extracting package'], 'T + 1.2s')}
                </span>
                <h5 className="font-semibold text-foreground">APK Installed & Permissions Pre-granted</h5>
                <p className="text-[10px] text-muted-foreground leading-relaxed">System Alert Window set to ALLOW. Device administrator activated.</p>
              </div>
              {/* Event 2 */}
              <div className="relative">
                <span className="absolute -left-[21px] top-1 w-2.5 h-2.5 rounded-full bg-blue-500 border-2 border-background"></span>
                <span className="text-[9px] font-mono text-muted-foreground">
                  {getEventTime(['spawning frida', 'frida process', 'hooks injected'], 'T + 2.4s')}
                </span>
                <h5 className="font-semibold text-foreground">Frida Injection Spawning Process</h5>
                <p className="text-[10px] text-muted-foreground leading-relaxed">Attached to process. Root checking and SSL certification bypass hooks active.</p>
              </div>
              {/* Event 3 */}
              <div className="relative">
                <span className="absolute -left-[21px] top-1 w-2.5 h-2.5 rounded-full bg-purple-500 border-2 border-background"></span>
                <span className="text-[9px] font-mono text-muted-foreground">
                  {getEventTime(['waking up', 'boot_completed', 'intents'], 'T + 4.8s')}
                </span>
                <h5 className="font-semibold text-foreground">Intents Dispatched (BOOT_COMPLETED)</h5>
                <p className="text-[10px] text-muted-foreground leading-relaxed">Broadcast intents sent with stopped-packages flag to wake receivers.</p>
              </div>
              {/* Event 4 */}
              <div className="relative">
                <span className={`absolute -left-[21px] top-1 w-2.5 h-2.5 rounded-full border-2 border-background ${networkConns.length > 0 ? 'bg-red-500' : 'bg-zinc-500'}`}></span>
                <span className="text-[9px] font-mono text-muted-foreground">
                  {getEventTime(['outbound socket', 'c2 beaconing', 'tracing kernel'], 'T + 5.6s')}
                </span>
                <h5 className="font-semibold text-foreground">
                  {networkConns.length > 0 ? 'Outbound Socket Connection Detected' : 'Observation Window (No Outbound Sockets)'}
                </h5>
                <p className="text-[10px] text-muted-foreground leading-relaxed">
                  {networkConns.length > 0 
                    ? `C2 beaconing to ${networkConns[0].ip}:${networkConns[0].port} (${networkConns[0].protocol}).`
                    : "No outbound network connections captured during this detonation window."}
                </p>
              </div>
            </div>
          </div>
        </div>

        {/* Domain Geolocation & Malware Check */}
        <div className="p-6 space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div>
              <span className="text-sm font-bold text-foreground">Domain Malware & Geolocation Check</span>
              <p className="text-[11px] text-muted-foreground mt-0.5">Real-time geo IP translation and URLhaus blacklist lookup.</p>
            </div>
            
            <div className="relative">
              <Search className="w-3.5 h-3.5 text-muted-foreground absolute left-2.5 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                placeholder="Search..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="pl-8 pr-3 py-1 bg-zinc-900 border border-border text-foreground text-xs rounded-none focus:outline-none focus:border-primary w-full sm:w-40 font-medium"
              />
            </div>
          </div>

          <div className="overflow-y-auto max-h-[230px] pr-2 pt-2 scrollbar-thin text-xs">
            <table className="w-full text-left leading-normal">
              <thead>
                <tr className="text-muted-foreground border-b border-border">
                  <th className="pb-3 font-medium">Domain / IP</th>
                  <th className="pb-3 font-medium">Status</th>
                  <th className="pb-3 font-medium text-right">Geolocation Details</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border/60">
                {(() => {
                  const allHosts = Array.from(new Set([
                    ...networkConns.map((c) => c.ip),
                    ...dnsResolutions.map((d) => d.domain)
                  ])).filter(Boolean);

                  const filteredHosts = allHosts.filter(h => 
                    h.toLowerCase().includes(searchQuery.toLowerCase())
                  );

                  if (filteredHosts.length === 0) {
                    return (
                      <tr>
                        <td colSpan={3} className="py-12 text-muted-foreground/60 italic text-center">
                          {allHosts.length === 0 
                            ? "No remote hosts or resolution requests captured."
                            : "No matching hosts found for search query."}
                        </td>
                      </tr>
                    );
                  }

                  return filteredHosts.map((host, idx) => (
                    <tr key={idx} className="hover:bg-accent/10 transition-colors">
                      <td className="py-4 font-mono font-semibold text-foreground max-w-[140px] truncate">
                        {host}
                      </td>
                      <td className="py-4">
                        {renderStatusBadge(host)}
                      </td>
                      <td className="py-4 text-right">
                        {renderGeoDetails(host)}
                      </td>
                    </tr>
                  ));
                })()}
              </tbody>
            </table>
          </div>
        </div>

      </div>


      {/* ═══ Evidence Tabs ═══ */}
      <div className="border-x border-b border-border bg-background flex divide-x divide-border text-[10px] font-bold uppercase tracking-widest overflow-hidden rounded-none">
        {tabs.map(tab => {
          const Icon = tab.icon;
          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`flex-1 py-3 px-4 transition-all text-center cursor-pointer whitespace-nowrap flex items-center justify-center gap-1.5 ${
                activeTab === tab.id ? 'bg-secondary text-primary border-b-2 border-primary' : 'text-muted-foreground hover:bg-muted hover:text-foreground'
              }`}
            >
              <Icon className="w-3 h-3" />
              {tab.label}
            </button>
          );
        })}
      </div>

      {/* ═══ Evidence Panel ═══ */}
      <div className="border-x border-b border-border rounded-none bg-card overflow-hidden p-6">

        {/* ── Evasion Defusal & AI Hooks Tab ── */}
        {activeTab === 'evasion' && (
          <div className="space-y-6">
            <div>
              <span className="text-sm font-bold text-foreground">Active Evasion Defusal & Dynamic AI Interceptors</span>
              <p className="text-[11px] text-muted-foreground mt-0.5">
                Real-time sleep gate compression, IPC broadcast triggers, and static-to-dynamic LLM Frida memory dumps.
              </p>
            </div>

            {/* 4-Column Evasion Defusal Matrix */}
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
              <div className="p-3 border border-amber-500/30 bg-amber-500/5 space-y-1">
                <div className="flex items-center justify-between">
                  <span className="text-[10px] uppercase font-bold text-amber-400 flex items-center gap-1">
                    <Clock className="w-3.5 h-3.5" />
                    Time Dilution
                  </span>
                  <span className="text-[9px] font-mono px-1.5 py-0.5 bg-amber-500/20 text-amber-300 font-bold border border-amber-500/40">
                    DEFUSED
                  </span>
                </div>
                <div className="text-xs font-semibold text-foreground">
                  {timeDilutionCount > 0 ? `${timeDilutionCount} Sleep Gate(s) Compressed` : 'Active Protection'}
                </div>
                <div className="text-[10px] text-muted-foreground">
                  Scaled Thread.sleep() &gt;50ms down to 10ms to bypass observation delays.
                </div>
              </div>

              <div className="p-3 border border-blue-500/30 bg-blue-500/5 space-y-1">
                <div className="flex items-center justify-between">
                  <span className="text-[10px] uppercase font-bold text-blue-400 flex items-center gap-1">
                    <Radio className="w-3.5 h-3.5" />
                    Apex IPC Fuzzing
                  </span>
                  <span className="text-[9px] font-mono px-1.5 py-0.5 bg-blue-500/20 text-blue-300 font-bold border border-blue-500/40">
                    TRIGGERED
                  </span>
                </div>
                <div className="text-xs font-semibold text-foreground">
                  {fuzzedIntents.length > 0 ? `${fuzzedIntents.length} IPC Triggers Fired` : 'BOOT_COMPLETED & Receivers'}
                </div>
                <div className="text-[10px] text-muted-foreground">
                  FLAG_INCLUDE_STOPPED_PACKAGES (0x00000020) forced dormant listeners to detonate.
                </div>
              </div>

              <div className="p-3 border border-emerald-500/30 bg-emerald-500/5 space-y-1">
                <div className="flex items-center justify-between">
                  <span className="text-[10px] uppercase font-bold text-emerald-400 flex items-center gap-1">
                    <ShieldCheck className="w-3.5 h-3.5" />
                    Anti-Root Guard
                  </span>
                  <span className="text-[9px] font-mono px-1.5 py-0.5 bg-emerald-500/20 text-emerald-300 font-bold border border-emerald-500/40">
                    {objectionRoot ? 'BYPASSED' : 'ACTIVE'}
                  </span>
                </div>
                <div className="text-xs font-semibold text-foreground">
                  {objectionRoot ? 'SU & Build Tags Spoofed' : 'Standard Runtime'}
                </div>
                <div className="text-[10px] text-muted-foreground">
                  Neutralized integrity checks and su binary scans in ART VM.
                </div>
              </div>

              <div className="p-3 border border-cyan-500/30 bg-cyan-500/5 space-y-1">
                <div className="flex items-center justify-between">
                  <span className="text-[10px] uppercase font-bold text-cyan-400 flex items-center gap-1">
                    <Zap className="w-3.5 h-3.5" />
                    SSL Pinning
                  </span>
                  <span className="text-[9px] font-mono px-1.5 py-0.5 bg-cyan-500/20 text-cyan-300 font-bold border border-cyan-500/40">
                    {objectionSsl ? 'BYPASSED' : 'ACTIVE'}
                  </span>
                </div>
                <div className="text-xs font-semibold text-foreground">
                  {objectionSsl ? 'TrustAllCerts Injected' : 'TLS Verification'}
                </div>
                <div className="text-[10px] text-muted-foreground">
                  Disabled certificate pinning to inspect encrypted command channels.
                </div>
              </div>
            </div>

            {/* Synthesized Interceptors & Dumped Memory */}
            <div className="space-y-3 pt-2">
              <div className="flex items-center justify-between">
                <span className="text-xs font-bold uppercase tracking-wider text-foreground flex items-center gap-1.5">
                  <Key className="w-3.5 h-3.5 text-cyan-400" />
                  LLMFrida Synthesized Interceptors & Decrypted Memory Dumps
                </span>
                <span className="text-[10px] font-mono text-muted-foreground">
                  Groq Qwen-2.5 Synthesizer
                </span>
              </div>

              <div className="bg-zinc-950 border border-border divide-y divide-border/60">
                {llmFridaIntercepts.length === 0 ? (
                  <div className="p-4 text-xs text-muted-foreground/60 italic text-center">
                    No custom obfuscated crypto sinks intercepted in this run.
                  </div>
                ) : (
                  llmFridaIntercepts.map((intercept, idx) => (
                    <div key={idx} className="p-3 flex items-start gap-2.5 font-mono text-xs">
                      <Eye className="w-3.5 h-3.5 text-cyan-400 shrink-0 mt-0.5" />
                      <div className="space-y-1">
                        <span className="text-cyan-300 font-semibold block">{intercept}</span>
                        <span className="text-[10px] text-muted-foreground">Captured at runtime via dynamic Dalvik memory hook</span>
                      </div>
                    </div>
                  ))
                )}
                {timeDilutionEvents.length > 0 && timeDilutionEvents.map((evt, idx) => (
                  <div key={`td-${idx}`} className="p-3 flex items-start gap-2.5 font-mono text-xs">
                    <Clock className="w-3.5 h-3.5 text-amber-400 shrink-0 mt-0.5" />
                    <div className="space-y-1">
                      <span className="text-amber-300 font-semibold block">{evt}</span>
                      <span className="text-[10px] text-muted-foreground">Chronos Time Dilution defusal log</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* ── File I/O Tab ── */}
        {activeTab === 'files' && (
          <>
            <div className="mb-4">
              <span className="text-sm font-bold text-foreground">File Operations Intercepted</span>
              <p className="text-[11px] text-muted-foreground mt-0.5">All filesystem reads and writes captured by Frida hooks during sandbox execution.</p>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs leading-normal">
                <thead>
                  <tr className="text-muted-foreground border-b border-border">
                    <th className="pb-3 font-medium">Target Path</th>
                    <th className="pb-3 font-medium">Operation</th>
                    <th className="pb-3 font-medium text-right">Security Context</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border/60">
                  {filesAccessed.length === 0 ? (
                    <tr>
                      <td colSpan={3} className="py-8 text-muted-foreground/60 italic text-center">
                        No file operations captured in this detonation window.
                      </td>
                    </tr>
                  ) : (
                    filesAccessed.map((file, idx) => {
                      const { op, ctx, ctxColor } = classifyFile(file);
                      return (
                        <tr key={idx} className="hover:bg-accent/10 transition-colors">
                          <td className="py-3 font-mono text-[11px] max-w-sm truncate text-foreground">{file}</td>
                          <td className="py-3 text-muted-foreground">{op}</td>
                          <td className={`py-3 text-right ${ctxColor}`}>{ctx}</td>
                        </tr>
                      );
                    })
                  )}
                </tbody>
              </table>
            </div>
          </>
        )}

        {/* ── Network Sockets Tab ── */}
        {activeTab === 'sockets' && (
          <>
            <div className="mb-4">
              <span className="text-sm font-bold text-foreground">TCP/UDP Socket Connections</span>
              <p className="text-[11px] text-muted-foreground mt-0.5">All outbound socket connections opened during sandbox execution, including connection status.</p>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs leading-normal">
                <thead>
                  <tr className="text-muted-foreground border-b border-border">
                    <th className="pb-3 font-medium">Destination</th>
                    <th className="pb-3 font-medium">Protocol</th>
                    <th className="pb-3 font-medium">Connection Status</th>
                    <th className="pb-3 font-medium text-right">Assessment</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border/60">
                  {networkConns.length === 0 ? (
                    <tr>
                      <td colSpan={4} className="py-8 text-muted-foreground/60 italic text-center">
                        No outbound socket connections captured. This does not rule out network activity — the app may use deferred or event-triggered C2 channels.
                      </td>
                    </tr>
                  ) : (
                    networkConns.map((conn, idx) => {
                      const status = conn.status || 'connected';
                      const statusColor = status === 'connected' ? 'text-red-500' : status === 'attempted' ? 'text-amber-500' : 'text-zinc-400';
                      const statusLabel = status === 'connected' ? 'ESTABLISHED' : status === 'attempted' ? 'ATTEMPTED' : 'REFUSED';
                      return (
                        <tr key={idx} className="hover:bg-accent/10 transition-colors">
                          <td className="py-3 font-mono text-[11px] text-foreground font-semibold">{conn.ip}:{conn.port}</td>
                          <td className="py-3 text-muted-foreground">{conn.protocol}</td>
                          <td className="py-3">
                            <span className={`${statusColor} font-semibold text-[10px]`}>{statusLabel}</span>
                          </td>
                          <td className="py-3 text-right">
                            <span className="bg-red-500/10 text-red-500 border border-red-500/20 px-2 py-0.5 text-[9px] font-bold uppercase rounded-none">
                              {conn.port === 4444 ? 'reverse shell' : 'c2 beacon'}
                            </span>
                          </td>
                        </tr>
                      );
                    })
                  )}
                </tbody>
              </table>
            </div>
          </>
        )}

        {/* ── DNS Lookups Tab ── */}
        {activeTab === 'dns' && (
          <>
            <div className="mb-4">
              <span className="text-sm font-bold text-foreground">DNS Resolution Attempts</span>
              <p className="text-[11px] text-muted-foreground mt-0.5">All DNS queries attempted during sandbox execution — including failed and unresolved lookups (NXDOMAIN).</p>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs leading-normal">
                <thead>
                  <tr className="text-muted-foreground border-b border-border">
                    <th className="pb-3 font-medium">Domain Queried</th>
                    <th className="pb-3 font-medium">Resolved IP</th>
                    <th className="pb-3 font-medium text-right">Resolution Status</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border/60">
                  {dnsResolutions.length === 0 ? (
                    <tr>
                      <td colSpan={3} className="py-8 text-muted-foreground/60 text-center">
                        <div className="italic">No DNS resolution data captured in this run.</div>
                        <div className="text-[10px] mt-1 text-muted-foreground/40">DNS interception requires extended Frida hooks on system resolver APIs.</div>
                      </td>
                    </tr>
                  ) : (
                    dnsResolutions.map((dns, idx) => {
                      const statusColor = dns.status === 'resolved' ? 'text-emerald-500' : dns.status === 'nxdomain' ? 'text-red-500' : 'text-amber-500';
                      const statusLabel = dns.status === 'resolved' ? 'RESOLVED' : dns.status === 'nxdomain' ? 'NXDOMAIN' : dns.status.toUpperCase();
                      return (
                        <tr key={idx} className="hover:bg-accent/10 transition-colors">
                          <td className="py-3 font-mono text-[11px] text-foreground font-semibold">{dns.domain}</td>
                          <td className="py-3 font-mono text-[11px] text-muted-foreground">{dns.resolved_ip || '—'}</td>
                          <td className="py-3 text-right">
                            <span className={`${statusColor} font-semibold text-[10px]`}>{statusLabel}</span>
                          </td>
                        </tr>
                      );
                    })
                  )}
                </tbody>
              </table>
            </div>
          </>
        )}

        {/* ── Runtime Permissions Tab ── */}
        {activeTab === 'permissions' && (
          <>
            <div className="mb-4">
              <span className="text-sm font-bold text-foreground">Runtime Permissions Exercised</span>
              <p className="text-[11px] text-muted-foreground mt-0.5">Permissions actually exercised during sandbox execution vs. merely declared in the manifest.</p>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs leading-normal">
                <thead>
                  <tr className="text-muted-foreground border-b border-border">
                    <th className="pb-3 font-medium">Permission</th>
                    <th className="pb-3 font-medium text-right">Status</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border/60">
                  {permissionsExercised.length === 0 ? (
                    <tr>
                      <td colSpan={2} className="py-8 text-muted-foreground/60 text-center">
                        <div className="italic">No runtime permission exercise data captured in this run.</div>
                        <div className="text-[10px] mt-1 text-muted-foreground/40">Permission usage monitoring requires extended Frida hooks on Android permission APIs.</div>
                      </td>
                    </tr>
                  ) : (
                    permissionsExercised.map((perm, idx) => (
                      <tr key={idx} className="hover:bg-accent/10 transition-colors">
                        <td className="py-3 font-mono text-[11px] text-foreground">{perm}</td>
                        <td className="py-3 text-right">
                          <span className="bg-amber-500/10 text-amber-500 border border-amber-500/20 px-2 py-0.5 text-[9px] font-bold uppercase rounded-none">
                            exercised at runtime
                          </span>
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </>
        )}

        {/* ── MITRE ATT&CK Tab ── */}
        {activeTab === 'mitre' && (
          <>
            <div className="mb-4">
              <span className="text-sm font-bold text-foreground">MITRE ATT&CK Mapping</span>
              <p className="text-[11px] text-muted-foreground mt-0.5">Identified tactics and techniques from dynamic runtime telemetry.</p>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs leading-normal">
                <thead>
                  <tr className="text-muted-foreground border-b border-border">
                    <th className="pb-3 font-medium">Technique ID</th>
                    <th className="pb-3 font-medium">Tactic Name</th>
                    <th className="pb-3 font-medium text-right">Detonation Trigger</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border/60">
                  {(() => {
                    const dynamicTechniques: { id: string; tactic: string; trigger: string }[] = [];
                    if (objectionSsl) {
                      dynamicTechniques.push({
                        id: "T1112",
                        tactic: "Defense Evasion / Mod Preferences",
                        trigger: "Frida SSL Pinning Bypass"
                      });
                    }
                    if (objectionRoot) {
                      dynamicTechniques.push({
                        id: "T1055",
                        tactic: "Privilege Escalation / Injection",
                        trigger: "Frida Root Guard Bypass"
                      });
                    }
                    networkConns.forEach((c) => {
                      if (c.port === 4444) {
                        dynamicTechniques.push({
                          id: "T1020",
                          tactic: "Exfiltration / Sockets Bind",
                          trigger: `Reverse Shell Port :${c.port} binding`
                        });
                      } else {
                        dynamicTechniques.push({
                          id: "T1071",
                          tactic: "Command & Control / App Layer Protocol",
                          trigger: `Outbound C2 to ${c.ip}:${c.port}`
                        });
                      }
                    });
                    filesAccessed.forEach(f => {
                      if (f.includes('Bot') || f.includes('contacts')) {
                        dynamicTechniques.push({
                          id: "T1005",
                          tactic: "Collection / Data from Local System",
                          trigger: `Bot config I/O: ${f.split('/').pop()}`
                        });
                      }
                    });

                    if (dynamicTechniques.length === 0) {
                      return (
                        <tr>
                          <td colSpan={3} className="py-8 text-muted-foreground/60 italic text-center">
                            No MITRE ATT&CK techniques mapped from this execution run.
                          </td>
                        </tr>
                      );
                    }

                    return dynamicTechniques.map((tech, idx) => (
                      <tr key={idx} className="hover:bg-accent/10 transition-colors">
                        <td className="py-3 font-mono text-[11px] text-red-500">{tech.id}</td>
                        <td className="py-3 text-muted-foreground">{tech.tactic}</td>
                        <td className="py-3 text-right text-muted-foreground">{tech.trigger}</td>
                      </tr>
                    ));
                  })()}
                </tbody>
              </table>
            </div>
          </>
        )}

      </div>

      {/* Detonate Another button */}
      <div className="flex justify-end pt-4">
        <button
          onClick={reset}
          className="flex items-center gap-2 px-4 py-2 border border-border bg-secondary hover:bg-secondary/80 text-foreground font-semibold rounded-none text-xs transition-all cursor-pointer"
        >
          Detonate Another APK
        </button>
      </div>

    </div>
  );
};
export default ReportView;
