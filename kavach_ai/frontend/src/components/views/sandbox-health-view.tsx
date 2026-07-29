import React from 'react';
import { Activity, Server, Database, CheckCircle2, XCircle, Terminal } from 'lucide-react';
import { useDetonation } from '@/context/DetonationContext';

export const SandboxHealthView: React.FC = () => {
  const { isAdbConnected, simulationMode } = useDetonation();

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between border-b border-border pb-4">
        <h2 className="text-xl font-bold flex items-center gap-2">
          <Activity className="w-5 h-5 text-primary" />
          Sandbox System Health
        </h2>
        <span className="px-2 py-1 text-xs font-semibold bg-primary/10 text-primary border border-primary/20">
          Local Environment
        </span>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {/* Status Indicators */}
        <div className="col-span-1 space-y-4">
          <div className="p-4 border border-border bg-card/30 flex items-center justify-between">
            <div className="flex items-center gap-3">
              <Server className="w-4 h-4 text-muted-foreground" />
              <span className="text-sm font-semibold">ADB Daemon</span>
            </div>
            {isAdbConnected || simulationMode ? (
              <CheckCircle2 className="w-5 h-5 text-emerald-500" />
            ) : (
              <XCircle className="w-5 h-5 text-destructive" />
            )}
          </div>
          
          <div className="p-4 border border-border bg-card/30 flex items-center justify-between">
            <div className="flex items-center gap-3">
              <Activity className="w-4 h-4 text-muted-foreground" />
              <span className="text-sm font-semibold">Frida Server</span>
            </div>
            <CheckCircle2 className="w-5 h-5 text-emerald-500" />
          </div>

          <div className="p-4 border border-border bg-card/30 flex items-center justify-between">
            <div className="flex items-center gap-3">
              <Database className="w-4 h-4 text-muted-foreground" />
              <span className="text-sm font-semibold">eBPF Probes</span>
            </div>
            <CheckCircle2 className="w-5 h-5 text-emerald-500" />
          </div>
        </div>

        {/* Emulator Telemetry Gauges */}
        <div className="col-span-1 md:col-span-2 grid grid-cols-2 gap-4">
          <div className="p-4 border border-border bg-card/30 flex flex-col items-center justify-center h-32">
            <span className="text-3xl font-bold text-foreground">34%</span>
            <span className="text-xs text-muted-foreground uppercase tracking-wider mt-1">CPU Usage</span>
          </div>
          <div className="p-4 border border-border bg-card/30 flex flex-col items-center justify-center h-32">
            <span className="text-3xl font-bold text-foreground">1.2 GB</span>
            <span className="text-xs text-muted-foreground uppercase tracking-wider mt-1">RAM (Genymotion)</span>
          </div>
        </div>

        {/* Worker Process Logs */}
        <div className="col-span-1 md:col-span-3 border border-border bg-black/60 rounded-none overflow-hidden flex flex-col h-64">
          <div className="flex items-center gap-2 px-4 py-2 border-b border-border bg-card/50">
            <Terminal className="w-4 h-4 text-muted-foreground" />
            <span className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">Worker Console</span>
          </div>
          <div className="p-4 font-mono text-xs text-muted-foreground space-y-1 overflow-y-auto flex-1">
            <div className="text-emerald-500">[2026-07-28 14:00:10] INFO: kavach.worker.manager - Sandbox environment initialized.</div>
            <div>[2026-07-28 14:00:11] INFO: adb.client - Waiting for device connection...</div>
            <div className="text-emerald-500">[2026-07-28 14:00:12] INFO: adb.client - Device emulator-5554 connected.</div>
            <div>[2026-07-28 14:00:12] INFO: frida.manager - Injecting kavach_agent.js into zygote64.</div>
            <div>[2026-07-28 14:00:15] INFO: ebpf.tracer - Attaching kprobes to tcp_v4_connect...</div>
            <div className="text-amber-500">[2026-07-28 14:00:16] WARN: ebpf.tracer - High syscall volume detected from PID 1142.</div>
            <div className="text-emerald-500">[2026-07-28 14:00:16] INFO: kavach.worker.manager - Ready to accept detonation jobs.</div>
          </div>
        </div>
      </div>
    </div>
  );
};
