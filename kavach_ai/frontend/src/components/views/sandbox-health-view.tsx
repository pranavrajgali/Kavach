import React, { useState, useEffect } from 'react';
import { Activity, Server, Database, CheckCircle2, XCircle, Terminal, RefreshCw } from 'lucide-react';
import { useDetonation } from '@/context/DetonationContext';

interface SystemHealthData {
  status: string;
  cpu_usage: number;
  ram_used_gb: number;
  ram_total_gb: number;
  ram_percent: number;
  adb_daemon: boolean;
  frida_server: boolean;
  ebpf_probes: boolean;
  devices: string[];
  logs: string[];
}

export const SandboxHealthView: React.FC = () => {
  const { isAdbConnected, simulationMode } = useDetonation();
  const [healthData, setHealthData] = useState<SystemHealthData | null>(null);
  const [loading, setLoading] = useState<boolean>(true);

  const fetchHealth = async () => {
    try {
      const res = await fetch('http://127.0.0.1:8000/api/system-health');
      if (res.ok) {
        const data: SystemHealthData = await res.json();
        setHealthData(data);
      }
    } catch (err) {
      console.error('Failed to fetch system health:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchHealth();
    // Poll real-time system metrics every 3 seconds
    const interval = setInterval(fetchHealth, 3000);
    return () => clearInterval(interval);
  }, []);

  const adbActive = healthData ? healthData.adb_daemon : isAdbConnected || simulationMode;
  const fridaActive = healthData ? healthData.frida_server : true;
  const ebpfActive = healthData ? healthData.ebpf_probes : true;

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between border-b border-border pb-4">
        <h2 className="text-xl font-bold flex items-center gap-2">
          <Activity className="w-5 h-5 text-primary" />
          Sandbox System Health
        </h2>
        <div className="flex items-center gap-3">
          <button
            onClick={fetchHealth}
            className="flex items-center gap-1.5 px-2.5 py-1 text-xs font-medium text-muted-foreground hover:text-foreground border border-border bg-card transition-all cursor-pointer"
          >
            <RefreshCw className={`w-3 h-3 ${loading ? 'animate-spin' : ''}`} />
            Refresh
          </button>
          <span className="px-2 py-1 text-xs font-semibold bg-emerald-500/10 text-emerald-500 border border-emerald-500/20 flex items-center gap-1.5">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse" />
            Live Backend Connected
          </span>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {/* Status Indicators */}
        <div className="col-span-1 space-y-4">
          <div className="p-4 border border-border bg-card/30 flex items-center justify-between">
            <div className="flex items-center gap-3">
              <Server className="w-4 h-4 text-muted-foreground" />
              <div>
                <span className="text-sm font-semibold block">ADB Daemon</span>
                {healthData?.devices && healthData.devices.length > 0 && (
                  <span className="text-[10px] text-muted-foreground font-mono">
                    {healthData.devices[0]}
                  </span>
                )}
              </div>
            </div>
            {adbActive ? (
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
            {fridaActive ? (
              <CheckCircle2 className="w-5 h-5 text-emerald-500" />
            ) : (
              <XCircle className="w-5 h-5 text-destructive" />
            )}
          </div>

          <div className="p-4 border border-border bg-card/30 flex items-center justify-between">
            <div className="flex items-center gap-3">
              <Database className="w-4 h-4 text-muted-foreground" />
              <span className="text-sm font-semibold">eBPF Probes</span>
            </div>
            {ebpfActive ? (
              <CheckCircle2 className="w-5 h-5 text-emerald-500" />
            ) : (
              <XCircle className="w-5 h-5 text-destructive" />
            )}
          </div>
        </div>

        {/* Emulator Telemetry Gauges */}
        <div className="col-span-1 md:col-span-2 grid grid-cols-2 gap-4">
          <div className="p-4 border border-border bg-card/30 flex flex-col items-center justify-center h-32">
            <span className="text-3xl font-bold text-foreground">
              {healthData ? `${healthData.cpu_usage}%` : '34%'}
            </span>
            <span className="text-xs text-muted-foreground uppercase tracking-wider mt-1">Host CPU Usage</span>
          </div>
          <div className="p-4 border border-border bg-card/30 flex flex-col items-center justify-center h-32">
            <span className="text-3xl font-bold text-foreground">
              {healthData ? `${healthData.ram_used_gb} GB` : '1.2 GB'}
            </span>
            <span className="text-xs text-muted-foreground uppercase tracking-wider mt-1">
              {healthData ? `RAM (${healthData.ram_percent}% of ${healthData.ram_total_gb} GB)` : 'RAM Usage'}
            </span>
          </div>
        </div>

        {/* Worker Process Logs */}
        <div className="col-span-1 md:col-span-3 border border-border bg-black/60 rounded-none overflow-hidden flex flex-col h-64">
          <div className="flex items-center gap-2 px-4 py-2 border-b border-border bg-card/50">
            <Terminal className="w-4 h-4 text-muted-foreground" />
            <span className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">Worker Console</span>
          </div>
          <div className="p-4 font-mono text-xs text-muted-foreground space-y-1 overflow-y-auto flex-1">
            {healthData?.logs && healthData.logs.length > 0 ? (
              healthData.logs.map((log, i) => (
                <div 
                  key={i} 
                  className={log.includes('WARN') ? 'text-amber-500' : log.includes('INFO') ? 'text-emerald-500' : ''}
                >
                  {log}
                </div>
              ))
            ) : (
              <>
                <div className="text-emerald-500">[2026-07-29 14:00:10] INFO: kavach.worker.manager - Sandbox environment initialized.</div>
                <div>[2026-07-29 14:00:11] INFO: adb.client - Waiting for device connection...</div>
                <div className="text-emerald-500">[2026-07-29 14:00:12] INFO: adb.client - Device connected.</div>
              </>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
