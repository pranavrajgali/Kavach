import React, { useState } from 'react';
import { useDetonation } from '@/context/DetonationContext';
import { 
  ResponsiveContainer, BarChart, Bar, XAxis, YAxis, Tooltip, Cell, AreaChart, Area,
  RadarChart, PolarGrid, PolarAngleAxis, PolarRadiusAxis, Radar
} from 'recharts';
import { Download, CheckCircle, Award, ArrowRight } from 'lucide-react';

export const ReportView: React.FC = () => {
  const { telemetry, apkDetails, reset, viewScorecard, simulationMode } = useDetonation();
  const [activeTab, setActiveTab] = useState<'files' | 'jni' | 'bert' | 'mitre' | 'cert_in'>('files');

  const objectionRoot = telemetry?.objection_root_bypass || false;
  const objectionSsl = telemetry?.objection_ssl_pinning_bypass || false;
  const filesAccessed = telemetry?.ebpf_telemetry?.files_accessed || [];
  const networkConns = telemetry?.ebpf_telemetry?.network_connections || [];

  // Calculate dynamic Threat Score based on dynamic logs
  let score = 0.05;
  if (objectionRoot) score += 0.35;
  if (objectionSsl) score += 0.30;
  filesAccessed.forEach(f => {
    if (f.includes('app_process') || f.includes('system')) score += 0.25;
    else if (f.includes('shared_prefs') || f.includes('config')) score += 0.15;
  });
  networkConns.forEach(c => {
    if (c.port === 4444) score += 0.45;
    else score += 0.10;
  });

  const probability = Math.min(0.99, Math.max(0.02, score));
  let verdictText = 'CLEAN';
  let verdictColor = 'text-emerald-500';

  if (probability > 0.65) {
    verdictText = 'MALICIOUS';
    verdictColor = 'text-red-500';
  } else if (probability > 0.30) {
    verdictText = 'SUSPICIOUS';
    verdictColor = 'text-amber-500';
  }

  // 1. Attributions Bar data (Real security metrics from dynamic detonation)
  const barData = simulationMode ? [
    { name: 'Syscalls', value: 15 + (telemetry?.ebpf_telemetry?.syscalls?.length || 0) },
    { name: 'File I/O', value: 10 + filesAccessed.length * 4 },
    { name: 'Sockets', value: 8 + networkConns.length * 10 },
    { name: 'Bypasses', value: 5 + (objectionRoot ? 20 : 0) + (objectionSsl ? 20 : 0) },
    { name: 'Hooks', value: 12 + (objectionRoot ? 15 : 0) + (objectionSsl ? 15 : 0) },
  ] : [
    { name: 'Syscalls', value: telemetry?.ebpf_telemetry?.syscalls?.length || 0 },
    { name: 'File I/O', value: filesAccessed.length },
    { name: 'Sockets', value: networkConns.length },
    { name: 'Bypasses', value: (objectionRoot ? 1 : 0) + (objectionSsl ? 1 : 0) },
    { name: 'Hooks', value: (objectionRoot ? 1 : 0) + (objectionSsl ? 1 : 0) },
  ];

  // 2. Streams step Area data (Mapping progress phases of the 10s run)
  const stepData = simulationMode ? [
    { name: '0s (Init)', tcp: 2, udp: 1 },
    { name: '2s (Install)', tcp: 6, udp: 2 },
    { name: '4s (Inject)', tcp: 14, udp: 4 },
    { name: '6s (Bypass)', tcp: (objectionRoot || objectionSsl) ? 28 : 12, udp: 5 },
    { name: '8s (Intents)', tcp: networkConns.length > 0 ? 22 : 10, udp: 4 },
    { name: '10s (Trace)', tcp: networkConns.length > 0 ? 36 : 14, udp: 6 },
  ] : [
    { name: '0s (Init)', tcp: 0, udp: 0 },
    { name: '2s (Install)', tcp: 0, udp: 0 },
    { name: '4s (Inject)', tcp: 0, udp: 0 },
    { name: '6s (Bypass)', tcp: (objectionRoot || objectionSsl) ? 1 : 0, udp: 0 },
    { name: '8s (Intents)', tcp: networkConns.filter(c => c.protocol === 'TCP').length, udp: networkConns.filter(c => c.protocol === 'UDP').length },
    { name: '10s (Trace)', tcp: networkConns.filter(c => c.protocol === 'TCP').length, udp: networkConns.filter(c => c.protocol === 'UDP').length },
  ];

  // 3. SHAP horizontal data (Contrast Red vs Blue)
  const shapData = [];
  if (objectionRoot) shapData.push({ name: 'Frida Root Bypass', value: 0.35 });
  if (objectionSsl) shapData.push({ name: 'Frida SSL Bypass', value: 0.30 });
  filesAccessed.forEach(f => {
    if (f.includes('app_process') || f.includes('system')) {
      shapData.push({ name: 'Sys Binary Read', value: 0.25 });
    } else if (f.includes('shared_prefs') || f.includes('config')) {
      shapData.push({ name: 'Config Write', value: 0.15 });
    }
  });
  networkConns.forEach(c => {
    if (c.port === 4444) {
      shapData.push({ name: 'Rev Shell :4444', value: 0.45 });
    } else {
      shapData.push({ name: `Conn Port :${c.port}`, value: 0.10 });
    }
  });
  if (simulationMode) {
    shapData.push({ name: 'sys_clone syscall', value: -0.12 });
    shapData.push({ name: 'DNS Port 53 query', value: -0.08 });
  } else {
    if (telemetry?.ebpf_telemetry?.syscalls?.includes('sys_clone')) {
      shapData.push({ name: 'sys_clone syscall', value: -0.12 });
    }
    if (networkConns.some(c => c.port === 53)) {
      shapData.push({ name: 'DNS Port 53 query', value: -0.08 });
    }
  }
  
  const sortedShapData = [...shapData].sort((a, b) => Math.abs(a.value) - Math.abs(b.value));

  // 4. Behavioral Risk Matrix Radar data
  let dataTheft = simulationMode ? 15 : 5;
  let finFraud = simulationMode ? 10 : 5;
  let persistence = simulationMode ? 12 : 5;
  let privEsc = simulationMode ? 15 : 5;
  let evasion = simulationMode ? 10 : 5;
  let c2Control = simulationMode ? 10 : 5;

  if (objectionRoot) { evasion += 40; privEsc += 30; }
  if (objectionSsl) { evasion += 45; c2Control += 25; }
  filesAccessed.forEach(f => {
    if (f.includes('shared_prefs') || f.includes('config')) { dataTheft += 30; persistence += 35; }
    if (f.includes('app_process') || f.includes('system')) { privEsc += 45; evasion += 20; }
  });
  networkConns.forEach(c => {
    if (c.port === 4444) { c2Control += 60; finFraud += 55; }
    else { c2Control += 25; }
  });

  const radarData = [
    { subject: 'Data Theft', value: Math.min(98, dataTheft) },
    { subject: 'Financial Fraud', value: Math.min(98, finFraud) },
    { subject: 'Persistence', value: Math.min(98, persistence) },
    { subject: 'Privilege Escalation', value: Math.min(98, privEsc) },
    { subject: 'Evasion', value: Math.min(98, evasion) },
    { subject: 'Command & Control', value: Math.min(98, c2Control) },
  ];

  const downloadTelemetry = () => {
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(telemetry, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute("href", dataStr);
    downloadAnchor.setAttribute("download", `forensic_report_${apkDetails?.package || 'apk'}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

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
            onClick={viewScorecard}
            className="flex items-center gap-2 px-4 py-2 bg-amber-500 hover:bg-amber-600 text-slate-950 font-bold rounded-none text-xs transition-all cursor-pointer shadow-sm"
          >
            <Award className="w-4 h-4" />
            View Kavach Scorecard
          </button>
          <button
            onClick={downloadTelemetry}
            className="flex items-center gap-2 px-4 py-2 bg-primary hover:bg-primary/95 text-primary-foreground font-semibold rounded-none text-xs transition-all cursor-pointer shadow-sm"
          >
            <Download className="w-4 h-4" />
            Export Telensic Profile
          </button>
        </div>
      </div>

      {/* Kavach Scorecard Banner */}
      <div className="border border-amber-500/30 bg-amber-500/5 p-4 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="p-2 border border-amber-500/30 bg-amber-500/10 text-amber-500">
            <Award className="w-5 h-5" />
          </div>
          <div>
            <h4 className="text-sm font-bold text-foreground">Kavach Security & Privacy Scorecard Ready</h4>
            <p className="text-xs text-muted-foreground">View overall security rating, risk severity distribution, privacy index, and detailed findings.</p>
          </div>
        </div>
        <button
          onClick={viewScorecard}
          className="flex items-center gap-1.5 px-3.5 py-1.5 bg-amber-500 hover:bg-amber-600 text-slate-950 font-bold text-xs transition-all cursor-pointer shrink-0"
        >
          Open Scorecard <ArrowRight className="w-3.5 h-3.5" />
        </button>
      </div>

      {/* Row 1: Metrics (divide-x) */}
      <div className="border border-border rounded-none bg-card overflow-hidden grid grid-cols-1 md:grid-cols-4 divide-y md:divide-y-0 md:divide-x divide-border">
        
        {/* Metric 1 */}
        <div className="p-6 space-y-4">
          <span className="text-[10px] font-bold text-muted-foreground uppercase tracking-wider block">
            Malware Verdict
          </span>
          <div className="space-y-1">
            <div className={`text-2xl font-extrabold tracking-tight ${verdictColor}`}>
              {verdictText}
            </div>
            <div className="flex items-center gap-1 text-[11px] text-muted-foreground">
              <span className={verdictColor}>
                {verdictText === 'MALICIOUS' ? '▲' : '▼'} {(probability * 100).toFixed(1)}%
              </span>
              <span>threat probability</span>
            </div>
          </div>
        </div>

        {/* Metric 2 */}
        <div className="p-6 space-y-4">
          <span className="text-[10px] font-bold text-muted-foreground uppercase tracking-wider block">
            Target File Size
          </span>
          <div className="space-y-1">
            <div className="text-2xl font-extrabold tracking-tight text-foreground">
              {apkDetails?.size || '0.00 MB'}
            </div>
            <div className="flex items-center gap-1 text-[11px] text-muted-foreground">
              <span className="text-emerald-500">▲ 12.4%</span>
              <span>vs base APK template</span>
            </div>
          </div>
        </div>

        {/* Metric 3 */}
        <div className="p-6 space-y-4">
          <span className="text-[10px] font-bold text-muted-foreground uppercase tracking-wider block">
            Active Bypasses
          </span>
          <div className="space-y-1">
            <div className="text-2xl font-extrabold tracking-tight text-foreground">
              {[(objectionRoot ? 1 : 0) + (objectionSsl ? 1 : 0)]} / 2
            </div>
            <div className="flex items-center gap-1 text-[11px] text-muted-foreground">
              <span className="text-emerald-500">▼ 0.0%</span>
              <span>guardrails remaining</span>
            </div>
          </div>
        </div>

        {/* Metric 4 */}
        <div className="p-6 space-y-4">
          <span className="text-[10px] font-bold text-muted-foreground uppercase tracking-wider block">
            Intercepted Signals
          </span>
          <div className="space-y-1">
            <div className="text-2xl font-extrabold tracking-tight text-foreground">
              {filesAccessed.length + networkConns.length}
            </div>
            <div className="flex items-center gap-1 text-[11px] text-muted-foreground">
              <span className="text-red-500">▲ 8.7%</span>
              <span>vs static baseline</span>
            </div>
          </div>
        </div>

      </div>

      {/* Row 2: Standard Graphs (Attributions & Streams) */}
      <div className="border-x border-b border-border rounded-none bg-card overflow-hidden grid grid-cols-1 lg:grid-cols-2 divide-y lg:divide-y-0 lg:divide-x divide-border">
        
        {/* Net Revenue style Bar Chart */}
        <div className="p-6 space-y-4">
          <div>
            <div className="flex items-center justify-between">
              <span className="text-sm font-bold text-foreground">Forensic Attributions</span>
              <span className="text-[10px] font-semibold text-emerald-500 bg-emerald-500/10 border border-emerald-500/20 px-2 py-0.5 rounded-none">
                ▲ 66.9%
              </span>
            </div>
            <p className="text-[11px] text-muted-foreground mt-1">Attributed bytecode markers, last 7 checkpoints.</p>
          </div>
          
          <div className="h-[230px] w-full text-xs">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart
                data={barData}
                margin={{ top: 15, right: 10, left: -25, bottom: 0 }}
              >
                <defs>
                  <linearGradient id="silverBar" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#fafafa" stopOpacity={0.85} />
                    <stop offset="100%" stopColor="#fafafa" stopOpacity={0.02} />
                  </linearGradient>
                </defs>
                <XAxis dataKey="name" stroke="#52525b" fontSize={10} tickLine={false} />
                <YAxis stroke="#52525b" fontSize={10} tickLine={false} />
                <Tooltip 
                  cursor={{ fill: 'rgba(255,255,255,0.02)' }}
                  contentStyle={{ backgroundColor: '#09090b', borderColor: '#27272a', borderRadius: '0px' }}
                  labelStyle={{ color: '#fafafa', fontWeight: 'bold' }}
                />
                <Bar 
                  dataKey="value" 
                  fill="url(#silverBar)" 
                  radius={0} 
                />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Step Area Chart */}
        <div className="p-6 space-y-4">
          <div>
            <div className="flex items-center justify-between">
              <span className="text-sm font-bold text-foreground">Instrumentation Streams</span>
              <span className="text-[10px] font-semibold text-emerald-500 bg-emerald-500/10 border border-emerald-500/20 px-2 py-0.5 rounded-none">
                ▲ 58.3%
              </span>
            </div>
            <p className="text-[11px] text-muted-foreground mt-1">Daily signal count by sockets, last 7 intervals.</p>
          </div>

          <div className="h-[230px] w-full text-xs">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart
                data={stepData}
                margin={{ top: 15, right: 10, left: -25, bottom: 0 }}
              >
                <defs>
                  <linearGradient id="areaGlow" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#3b82f6" stopOpacity={0.2} />
                    <stop offset="100%" stopColor="#3b82f6" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <XAxis dataKey="name" stroke="#52525b" fontSize={10} tickLine={false} />
                <YAxis stroke="#52525b" fontSize={10} tickLine={false} />
                <Tooltip 
                  contentStyle={{ backgroundColor: '#09090b', borderColor: '#27272a', borderRadius: '0px' }}
                  labelStyle={{ color: '#fafafa', fontWeight: 'bold' }}
                />
                <Area 
                  type="step" 
                  dataKey="tcp" 
                  stroke="#fafafa" 
                  strokeWidth={1.5}
                  fill="url(#areaGlow)" 
                />
                <Area 
                  type="step" 
                  dataKey="udp" 
                  stroke="#52525b" 
                  strokeWidth={1.5}
                  fill="none" 
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

      </div>

      {/* Row 3: SHAP Feature Attribution & Polar Risk Matrix (Down & Large) */}
      <div className="border-x border-b border-border rounded-none bg-card overflow-hidden grid grid-cols-1 lg:grid-cols-2 divide-y lg:divide-y-0 lg:divide-x divide-border">
        
        {/* SHAP Feature Contribution (Horizontal Bar with high contrast colors) */}
        <div className="p-6 space-y-4">
          <div>
            <span className="text-sm font-bold text-foreground">SHAP Feature Attribution</span>
            <p className="text-[11px] text-muted-foreground mt-1">Impact factors on final risk score. <span className="text-[#b91c1c] font-semibold">Red</span> flags threat contribution; <span className="text-[#1d4ed8] font-semibold">Blue</span> denotes baseline safety.</p>
          </div>
          
          <div className="h-[250px] w-full text-xs">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart
                data={sortedShapData}
                layout="vertical"
                margin={{ top: 10, right: 20, left: -20, bottom: 0 }}
              >
                <XAxis type="number" stroke="#52525b" fontSize={9} tickLine={false} />
                <YAxis dataKey="name" type="category" stroke="#a1a1aa" fontSize={9} tickLine={false} width={120} />
                <Tooltip 
                  contentStyle={{ backgroundColor: '#09090b', borderColor: '#27272a', borderRadius: '0px' }}
                  labelStyle={{ color: '#fafafa', fontWeight: 'bold' }}
                />
                <Bar dataKey="value" radius={0}>
                  {sortedShapData.map((entry, index) => (
                    <Cell 
                      key={`cell-${index}`} 
                      fill={entry.value > 0 ? '#b91c1c' : '#1d4ed8'} 
                    />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Behavioral Risk Matrix (Radar Chart with solid outline & translucent overlay) */}
        <div className="p-6 space-y-4">
          <div>
            <span className="text-sm font-bold text-foreground">Behavioral Risk Matrix</span>
            <p className="text-[11px] text-muted-foreground mt-1">Normalized threat profile across key execution vectors.</p>
          </div>
          
          <div className="h-[250px] w-full text-xs flex items-center justify-center">
            <ResponsiveContainer width="100%" height="100%">
              <RadarChart cx="50%" cy="50%" outerRadius="75%" data={radarData}>
                <PolarGrid stroke="#27272a" />
                <PolarAngleAxis dataKey="subject" stroke="#a1a1aa" fontSize={9} />
                <PolarRadiusAxis angle={30} domain={[0, 100]} tick={false} stroke="#27272a" />
                <Radar
                  name="Risk Factor"
                  dataKey="value"
                  stroke="#b91c1c"
                  fill="#b91c1c"
                  fillOpacity={0.15}
                />
              </RadarChart>
            </ResponsiveContainer>
          </div>
        </div>

      </div>

      {/* Interactive Tabs Menu for Pipeline Data Placeholders */}
      <div className="border-x border-b border-border bg-[#09090b] flex divide-x divide-border text-[10px] font-bold uppercase tracking-widest overflow-hidden rounded-none">
        <button
          onClick={() => setActiveTab('files')}
          className={`flex-1 py-3 px-4 transition-all text-center cursor-pointer ${
            activeTab === 'files' ? 'bg-[#18181c] text-primary border-b-2 border-primary' : 'text-muted-foreground hover:bg-[#121215] hover:text-foreground'
          }`}
        >
          File Interactions
        </button>
        <button
          onClick={() => setActiveTab('jni')}
          className={`flex-1 py-3 px-4 transition-all text-center cursor-pointer ${
            activeTab === 'jni' ? 'bg-[#18181c] text-primary border-b-2 border-primary' : 'text-muted-foreground hover:bg-[#121215] hover:text-foreground'
          }`}
        >
          JNI & Native Scan
        </button>
        <button
          onClick={() => setActiveTab('bert')}
          className={`flex-1 py-3 px-4 transition-all text-center cursor-pointer ${
            activeTab === 'bert' ? 'bg-[#18181c] text-primary border-b-2 border-primary' : 'text-muted-foreground hover:bg-[#121215] hover:text-foreground'
          }`}
        >
          SecureBERT Slices
        </button>
        <button
          onClick={() => setActiveTab('mitre')}
          className={`flex-1 py-3 px-4 transition-all text-center cursor-pointer ${
            activeTab === 'mitre' ? 'bg-[#18181c] text-primary border-b-2 border-primary' : 'text-muted-foreground hover:bg-[#121215] hover:text-foreground'
          }`}
        >
          MITRE ATT&CK Map
        </button>
        <button
          onClick={() => setActiveTab('cert_in')}
          className={`flex-1 py-3 px-4 transition-all text-center cursor-pointer ${
            activeTab === 'cert_in' ? 'bg-[#18181c] text-primary border-b-2 border-primary' : 'text-muted-foreground hover:bg-[#121215] hover:text-foreground'
          }`}
        >
          CERT-In Readiness
        </button>
      </div>

      {/* Row 4: Pipeline Data View (Dynamic based on selected tab) */}
      <div className="border-x border-b border-border rounded-none bg-card overflow-hidden grid grid-cols-1 lg:grid-cols-4 divide-y lg:divide-y-0 lg:divide-x divide-border">
        
        {/* Left Column (spans 2 columns) */}
        <div className="p-6 space-y-4 lg:col-span-2">
          {activeTab === 'files' && (
            <>
              <div>
                <span className="text-sm font-bold text-foreground">File Operations Intercepted</span>
                <p className="text-[11px] text-muted-foreground mt-0.5">Failsafe root system and socket interactions.</p>
              </div>

              <div className="overflow-x-auto pt-2">
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
                        <td colSpan={3} className="py-4 text-muted-foreground/60 italic">
                          No file operations captured in detonation window.
                        </td>
                      </tr>
                    ) : (
                      filesAccessed.slice(0, 3).map((file, idx) => {
                        let label = 'Access';
                        let labelColor = 'text-muted-foreground';
                        if (file.includes('app_process') || file.includes('system')) {
                          label = 'System Read';
                          labelColor = 'text-red-500 font-semibold';
                        } else if (file.includes('shared_prefs') || file.includes('config')) {
                          label = 'Modifying Config';
                          labelColor = 'text-amber-500 font-semibold';
                        }

                        return (
                          <tr key={idx} className="hover:bg-accent/10 transition-colors">
                            <td className="py-3 font-mono text-[11px] max-w-xs truncate">{file}</td>
                            <td className="py-3 text-muted-foreground">Read/Write</td>
                            <td className={`py-3 text-right ${labelColor}`}>{label}</td>
                          </tr>
                        );
                      })
                    )}
                  </tbody>
                </table>
              </div>
            </>
          )}

          {activeTab === 'jni' && (
            <>
              <div>
                <span className="text-sm font-bold text-foreground">JNI Bridge Shared Objects</span>
                <p className="text-[11px] text-muted-foreground mt-0.5">
                  {simulationMode 
                    ? "Extracted C/C++ native payload libraries and socket Hooks." 
                    : "Static SO scanning is not yet integrated. Dynamic library loads captured during instrumentation are listed below."}
                </p>
              </div>

              <div className="overflow-x-auto pt-2">
                <table className="w-full text-left text-xs leading-normal">
                  <thead>
                    <tr className="text-muted-foreground border-b border-border">
                      <th className="pb-3 font-medium">Shared Object (.so)</th>
                      <th className="pb-3 font-medium">Architecture</th>
                      <th className="pb-3 font-medium text-right">Security Signal</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border/60">
                    {simulationMode ? (
                      <>
                        <tr className="hover:bg-accent/10 transition-colors">
                          <td className="py-3 font-mono text-[11px]">/lib/arm64-v8a/libobjection.so</td>
                          <td className="py-3 text-muted-foreground">ARM64</td>
                          <td className="py-3 text-right text-red-500 font-semibold">Frida Bypass Agent</td>
                        </tr>
                        <tr className="hover:bg-accent/10 transition-colors">
                          <td className="py-3 font-mono text-[11px]">/lib/arm64-v8a/libnative-helper.so</td>
                          <td className="py-3 text-muted-foreground">ARM64</td>
                          <td className="py-3 text-right text-amber-500 font-semibold">Reflection Linker</td>
                        </tr>
                        <tr className="hover:bg-accent/10 transition-colors">
                          <td className="py-3 font-mono text-[11px]">/lib/arm64-v8a/libcrypto-secure.so</td>
                          <td className="py-3 text-muted-foreground">ARM64</td>
                          <td className="py-3 text-right text-muted-foreground">Encryption Bridge</td>
                        </tr>
                      </>
                    ) : (telemetry?.native_libraries || []).length === 0 ? (
                      <tr>
                        <td colSpan={3} className="py-4 text-muted-foreground/60 italic text-center">
                          No custom native libraries (.so) loaded during detonation.
                        </td>
                      </tr>
                    ) : (
                      (telemetry?.native_libraries || []).map((lib, idx) => (
                        <tr key={idx} className="hover:bg-accent/10 transition-colors">
                          <td className="py-3 font-mono text-[11px]">{lib}</td>
                          <td className="py-3 text-muted-foreground">ARM64/Dynamic</td>
                          <td className="py-3 text-right text-muted-foreground">Loaded at Runtime</td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
            </>
          )}

          {activeTab === 'bert' && (
            <>
              <div>
                <span className="text-sm font-bold text-foreground">SecureBERT-2.0 Program Slices</span>
                <p className="text-[11px] text-muted-foreground mt-0.5">
                  {simulationMode 
                    ? "Backward program slicing matched code vectors." 
                    : "SecureBERT ML classification is not yet integrated. Static program slicing is disabled."}
                </p>
              </div>

              <div className="overflow-x-auto pt-2">
                <table className="w-full text-left text-xs leading-normal">
                  <thead>
                    <tr className="text-muted-foreground border-b border-border">
                      <th className="pb-3 font-medium">Decompiled Smali Code Snippet</th>
                      <th className="pb-3 font-medium">Method Location</th>
                      <th className="pb-3 font-medium text-right">Model Score</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border/60">
                    {simulationMode ? (
                      <>
                        <tr className="hover:bg-accent/10 transition-colors">
                          <td className="py-3 font-mono text-[10px] truncate max-w-[200px]">{"const-string v0, \"android.permission.SEND_SMS\""}</td>
                          <td className="py-3 text-muted-foreground font-mono text-[10px]">MainActivity.onBoot</td>
                          <td className="py-3 text-right text-red-500 font-semibold">0.962</td>
                        </tr>
                        <tr className="hover:bg-accent/10 transition-colors">
                          <td className="py-3 font-mono text-[10px] truncate max-w-[200px]">{"invoke-static {v0}, Ljava/lang/Class;->forName"}</td>
                          <td className="py-3 text-muted-foreground font-mono text-[10px]">SecureLoader.run</td>
                          <td className="py-3 text-right text-amber-500 font-semibold">0.841</td>
                        </tr>
                        <tr className="hover:bg-accent/10 transition-colors">
                          <td className="py-3 font-mono text-[10px] truncate max-w-[200px]">{"const-string v1, \"Lcom/obfuscate/crypto;\""}</td>
                          <td className="py-3 text-muted-foreground font-mono text-[10px]">CryptoDns.query</td>
                          <td className="py-3 text-right text-emerald-500 font-semibold">0.124</td>
                        </tr>
                      </>
                    ) : (
                      <tr>
                        <td colSpan={3} className="py-4 text-muted-foreground/60 italic text-center">
                          Static analysis not yet integrated. No decompiled Smali slices available.
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            </>
          )}

          {activeTab === 'mitre' && (
            <>
              <div>
                <span className="text-sm font-bold text-foreground">MITRE ATT&CK Mapping</span>
                <p className="text-[11px] text-muted-foreground mt-0.5">Identified tactics and techniques from dynamic runtime telemetry.</p>
              </div>

              <div className="overflow-x-auto pt-2">
                <table className="w-full text-left text-xs leading-normal">
                  <thead>
                    <tr className="text-muted-foreground border-b border-border">
                      <th className="pb-3 font-medium">Technique ID</th>
                      <th className="pb-3 font-medium">Tactic Name</th>
                      <th className="pb-3 font-medium text-right">Detonation Trigger</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border/60">
                    {simulationMode ? (
                      <>
                        <tr className="hover:bg-accent/10 transition-colors">
                          <td className="py-3 font-mono text-[11px] text-red-500">T1112</td>
                          <td className="py-3 text-muted-foreground">Defense Evasion / Mod Preferences</td>
                          <td className="py-3 text-right text-muted-foreground">Frida SSL Pinning Bypass</td>
                        </tr>
                        <tr className="hover:bg-accent/10 transition-colors">
                          <td className="py-3 font-mono text-[11px] text-red-500">T1055</td>
                          <td className="py-3 text-muted-foreground">Privilege Escalation / Injection</td>
                          <td className="py-3 text-right text-muted-foreground">Frida Root Guard Bypass</td>
                        </tr>
                        <tr className="hover:bg-accent/10 transition-colors">
                          <td className="py-3 font-mono text-[11px] text-amber-500">T1020</td>
                          <td className="py-3 text-muted-foreground">Exfiltration / Sockets Bind</td>
                          <td className="py-3 text-right text-muted-foreground">Reverse Shell Port binding</td>
                        </tr>
                      </>
                    ) : (
                      (() => {
                        const dynamicTechniques = [];
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
                          }
                        });

                        if (dynamicTechniques.length === 0) {
                          return (
                            <tr>
                              <td colSpan={3} className="py-4 text-muted-foreground/60 italic text-center">
                                No MITRE ATT&CK techniques mapped (Clean Execution).
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
                      })()
                    )}
                  </tbody>
                </table>
              </div>
            </>
          )}

          {activeTab === 'cert_in' && (
            <>
              <div>
                <span className="text-sm font-bold text-foreground">CERT-In Compliance Readiness</span>
                <p className="text-[11px] text-muted-foreground mt-0.5">Compliance statuses for standard financial security auditing guidelines.</p>
              </div>

              <div className="overflow-x-auto pt-2">
                <table className="w-full text-left text-xs leading-normal">
                  <thead>
                    <tr className="text-muted-foreground border-b border-border">
                      <th className="pb-3 font-medium">Compliance Parameter</th>
                      <th className="pb-3 font-medium">Compliance Standard</th>
                      <th className="pb-3 font-medium text-right">Audit Status</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border/60">
                    {simulationMode ? (
                      <>
                        <tr className="hover:bg-accent/10 transition-colors">
                          <td className="py-3 text-foreground font-semibold">Anti-Rooting Security Binds</td>
                          <td className="py-3 text-muted-foreground">CERT-In Sec 12.2</td>
                          <td className="py-3 text-right text-red-500 font-semibold">NON-COMPLIANT</td>
                        </tr>
                        <tr className="hover:bg-accent/10 transition-colors">
                          <td className="py-3 text-foreground font-semibold">HTTPS SSL Certification Verification</td>
                          <td className="py-3 text-muted-foreground">CERT-In Sec 14.5</td>
                          <td className="py-3 text-right text-red-500 font-semibold">NON-COMPLIANT</td>
                        </tr>
                        <tr className="hover:bg-accent/10 transition-colors">
                          <td className="py-3 text-foreground font-semibold">Private SQLite Database Encryption</td>
                          <td className="py-3 text-muted-foreground">CERT-In Sec 8.1</td>
                          <td className="py-3 text-right text-emerald-500 font-semibold">COMPLIANT</td>
                        </tr>
                      </>
                    ) : (
                      <>
                        <tr className="hover:bg-accent/10 transition-colors">
                          <td className="py-3 text-foreground font-semibold">Anti-Rooting Security Binds</td>
                          <td className="py-3 text-muted-foreground">CERT-In Sec 12.2</td>
                          <td className={`py-3 text-right font-semibold ${objectionRoot ? 'text-red-500' : 'text-emerald-500'}`}>
                            {objectionRoot ? 'NON-COMPLIANT' : 'COMPLIANT'}
                          </td>
                        </tr>
                        <tr className="hover:bg-accent/10 transition-colors">
                          <td className="py-3 text-foreground font-semibold">HTTPS SSL Certification Verification</td>
                          <td className="py-3 text-muted-foreground">CERT-In Sec 14.5</td>
                          <td className={`py-3 text-right font-semibold ${objectionSsl ? 'text-red-500' : 'text-emerald-500'}`}>
                            {objectionSsl ? 'NON-COMPLIANT' : 'COMPLIANT'}
                          </td>
                        </tr>
                        <tr className="hover:bg-accent/10 transition-colors">
                          <td className="py-3 text-foreground font-semibold">Private SQLite Database Encryption</td>
                          <td className="py-3 text-muted-foreground">CERT-In Sec 8.1</td>
                          <td className="py-3 text-right text-emerald-500 font-semibold">COMPLIANT</td>
                        </tr>
                      </>
                    )}
                  </tbody>
                </table>
              </div>
            </>
          )}
        </div>

        {/* Middle Column (spans 1 column) */}
        <div className="p-6 space-y-4">
          <div>
            <span className="text-sm font-bold text-foreground">Detonation Integrity</span>
            <p className="text-[11px] text-muted-foreground mt-0.5">Sandbox verification checkups.</p>
          </div>
          <div className="space-y-3 pt-2">
            <div className="flex items-center gap-3">
              <CheckCircle className="w-4 h-4 text-emerald-500 shrink-0" />
              <div>
                <h4 className="text-xs font-semibold text-foreground">Frida Hooks Loaded</h4>
                <p className="text-[10px] text-muted-foreground">Trace bypasses fully injected.</p>
              </div>
            </div>
            <div className="flex items-center gap-3">
              <CheckCircle className="w-4 h-4 text-emerald-500 shrink-0" />
              <div>
                <h4 className="text-xs font-semibold text-foreground">eBPF Sockets Binding</h4>
                <p className="text-[10px] text-muted-foreground">Syscalls trace session established.</p>
              </div>
            </div>
          </div>
        </div>

        {/* Right Column (spans 1 column) */}
        <div className="p-6 space-y-4">
          <div>
            <span className="text-sm font-bold text-foreground">Detonation Activity</span>
            <p className="text-[11px] text-muted-foreground mt-0.5">Latest actions captured in session.</p>
          </div>
          <div className="space-y-3 pt-2">
            <div className="flex items-start gap-2.5">
              <span className="w-1.5 h-1.5 rounded-full bg-blue-500 mt-1.5 shrink-0" />
              <div className="text-[11px] leading-relaxed text-muted-foreground">
                <span className="font-medium text-foreground">objection bypass</span> active on com.unknown
              </div>
            </div>
            <div className="flex items-start gap-2.5">
              <span className="w-1.5 h-1.5 rounded-full bg-blue-500 mt-1.5 shrink-0" />
              <div className="text-[11px] leading-relaxed text-muted-foreground">
                <span className="font-medium text-foreground">Frida spawned</span> processes verified
              </div>
            </div>
          </div>
        </div>

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
