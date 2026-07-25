import React, { useEffect, useRef } from 'react';
import { useDetonation } from '@/context/DetonationContext';
import { Terminal } from 'lucide-react';

export const TerminalConsole: React.FC = () => {
  const { logs, apkDetails } = useDetonation();
  const terminalEndRef = useRef<HTMLDivElement>(null);

  // Auto-scroll terminal logs to bottom on new additions
  useEffect(() => {
    terminalEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [logs]);

  // Dynamic checkpoint resolver based on log content
  const checkEvent = (patterns: string[]) => {
    return logs.some((log) => patterns.some((p) => log.toLowerCase().includes(p.toLowerCase())));
  };

  const steps = [
    { label: 'APK Parse & Load', time: '0.0s', active: checkEvent(['receiving', 'extracting', 'package']) },
    { label: 'Emulator Installation', time: '1.2s', active: checkEvent(['installing', 'device', 'emulator-']) },
    { label: 'Frida Server Spawn', time: '2.5s', active: checkEvent(['frida', 'hooks']) },
    { label: 'Objection Safeguards Bypass', time: '4.1s', active: checkEvent(['objection', 'root', 'ssl']) },
    { label: 'Receivers Detonation', time: '5.8s', active: checkEvent(['trojan', 'intents', 'boot_completed']) },
    { label: 'Telemetry Logs Synced', time: '10.0s', active: checkEvent(['complete', 'syncing', 'telemetry']) },
  ];

  return (
    <div className="space-y-6">
      {/* 1. Header Details KPI Row */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="border border-border rounded-lg p-4 bg-card">
          <span className="text-[10px] font-bold text-muted-foreground uppercase tracking-wider block mb-1">
            Target Artifact
          </span>
          <span className="text-xs font-mono text-foreground font-semibold truncate block">
            {apkDetails?.name || 'Loading...'}
          </span>
        </div>
        <div className="border border-border rounded-lg p-4 bg-card">
          <span className="text-[10px] font-bold text-muted-foreground uppercase tracking-wider block mb-1">
            File Size
          </span>
          <span className="text-xs font-semibold text-foreground block">
            {apkDetails?.size || 'Computing...'}
          </span>
        </div>
        <div className="border border-border rounded-lg p-4 bg-card">
          <span className="text-[10px] font-bold text-muted-foreground uppercase tracking-wider block mb-1">
            Package Identifier
          </span>
          <span className="text-xs font-mono text-primary font-semibold block truncate">
            {apkDetails?.package || 'Extracting...'}
          </span>
        </div>
        <div className="border border-border rounded-lg p-4 bg-card">
          <span className="text-[10px] font-bold text-muted-foreground uppercase tracking-wider block mb-1">
            Analysis Status
          </span>
          <div className="flex items-center gap-2 mt-0.5">
            <span className="w-2 h-2 rounded-full bg-cyan-500 animate-ping" />
            <span className="text-xs font-bold text-cyan-500 uppercase tracking-wide">
              DETONATING
            </span>
          </div>
        </div>
      </div>

      {/* 2. Main 2-Column Progress Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-[1fr_320px] gap-6">
        
        {/* Log Terminal (Obsidian Glass style) */}
        <div className="border border-border rounded-lg bg-[#070709] flex flex-col h-[350px]">
          {/* Terminal Header */}
          <div className="flex items-center justify-between px-4 py-2 border-b border-border bg-[#0d0d11]">
            <div className="flex items-center gap-2">
              <Terminal className="w-3.5 h-3.5 text-muted-foreground" />
              <span className="text-[10px] uppercase font-bold tracking-wider text-muted-foreground">
                Execution Logging Output
              </span>
            </div>
            <div className="flex items-center gap-1.5">
              <span className="w-2 h-2 rounded-full bg-red-500/30" />
              <span className="w-2 h-2 rounded-full bg-yellow-500/30" />
              <span className="w-2 h-2 rounded-full bg-green-500/30" />
            </div>
          </div>
          
          {/* Scrollable Log Output */}
          <div className="flex-1 p-4 overflow-y-auto font-mono text-xs text-[#d1d5db] space-y-1.5 leading-relaxed selection:bg-primary/20">
            {logs.length === 0 ? (
              <div className="text-muted-foreground/45 italic">Waiting for analysis logs...</div>
            ) : (
              logs.map((log, idx) => {
                let colorClass = 'text-[#d1d5db]';
                if (log.toLowerCase().includes('[error]')) colorClass = 'text-red-400';
                else if (log.toLowerCase().includes('[warn]')) colorClass = 'text-amber-400';
                else if (log.toLowerCase().includes('[sim]') || log.toLowerCase().includes('[info]')) colorClass = 'text-blue-400';
                else if (log.toLowerCase().includes('success')) colorClass = 'text-emerald-400';
                
                return (
                  <div key={idx} className={colorClass}>
                    <span className="text-muted-foreground/30 select-none mr-2">{(idx + 1).toString().padStart(2, '0')}</span>
                    {log}
                  </div>
                );
              })
            )}
            <div ref={terminalEndRef} />
          </div>
        </div>

        {/* Dynamic Timeline Checkpoints Tree */}
        <div className="border border-border rounded-lg p-6 bg-card flex flex-col justify-between">
          <div>
            <span className="text-[10px] font-bold text-muted-foreground uppercase tracking-widest block mb-4">
              Detonation Timeline
            </span>

            {/* Vertical connector progress line */}
            <div className="relative pl-6 space-y-5">
              <div className="absolute left-1.5 top-2 bottom-2 w-0.5 bg-border" />
              
              {steps.map((step, idx) => (
                <div key={idx} className="relative flex items-center justify-between">
                  {/* Circle progress indicators */}
                  <div 
                    className={`absolute left-[-24px] w-3 h-3 rounded-full border-2 transition-all duration-300 ${
                      step.active 
                        ? 'bg-primary border-primary ring-4 ring-primary/10 shadow-[0_0_8px_rgba(59,130,246,0.5)]' 
                        : 'bg-card border-border'
                    }`} 
                  />
                  <span className={`text-xs font-medium transition-all ${step.active ? 'text-foreground font-semibold' : 'text-muted-foreground'}`}>
                    {step.label}
                  </span>
                  <span className="text-[10px] text-muted-foreground/60 font-mono">
                    {step.time}
                  </span>
                </div>
              ))}
            </div>
          </div>

          <div className="text-[10px] text-muted-foreground/50 leading-relaxed border-t border-border/60 pt-4 mt-6">
            Observing bytecode behaviors in real-time. Do not abort session until telemetry sync finishes.
          </div>
        </div>

      </div>
    </div>
  );
};
export default TerminalConsole;
