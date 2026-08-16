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
  const [backendConnected, setBackendConnected] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  const fetchHealth = async () => {
    try {
      const res = await fetch('/api/system-health');
      if (!res.ok) {
        throw new Error(`Health endpoint returned ${res.status}`);
      }
      const data: SystemHealthData = await res.json();
      setHealthData(data);
      setBackendConnected(true);
      setError(null);
    } catch (err) {
      setBackendConnected(false);
      setError(err instanceof Error ? err.message : 'Failed to fetch system health');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchHealth();
    const interval = setInterval(fetchHealth, 3000);
    return () => clearInterval(interval);
  }, []);

  const adbActive = healthData ? healthData.adb_daemon : isAdbConnected;
  const fridaActive = healthData ? healthData.frida_server : false;
  const ebpfActive = healthData ? healthData.ebpf_probes : false;

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
          <span className={`px-2 py-1 text-xs font-semibold border flex items-center gap-1.5 ${
            backendConnected
              ? 'bg-emerald-500/10 text-emerald-500 border-emerald-500/20'
              : 'bg-destructive/10 text-destructive border-destructive/20'
          }`}>
            <span className={`w-1.5 h-1.5 rounded-full ${backendConnected ? 'bg-emerald-500 animate-pulse' : 'bg-destructive'}`} />
            {backendConnected ? 'Live Backend Connected' : 'Backend Unreachable'}
          </span>
        </div>
      </div>

      {simulationMode && (
        <div className="border border-amber-500/20 bg-amber-500/5 px-4 py-3 text-xs text-amber-400">
          Simulation mode is enabled. Dynamic Sandbox will emit artifact-keyed telemetry without requiring an attached ADB device.
        </div>
      )}

      {error && !backendConnected && (
        <div className="border border-destructive/20 bg-destructive/5 px-4 py-3 text-xs text-destructive">
          {error}. Start the API on port 8000, then refresh this page.
        </div>
      )}

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
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

        <div className="col-span-1 md:col-span-2 grid grid-cols-2 gap-4">
          <div className="p-4 border border-border bg-card/30 flex flex-col items-center justify-center h-32">
            <span className="text-3xl font-bold text-foreground">
              {healthData ? `${healthData.cpu_usage}%` : '—'}
            </span>
            <span className="text-xs text-muted-foreground uppercase tracking-wider mt-1">Host CPU Usage</span>
          </div>
          <div className="p-4 border border-border bg-card/30 flex flex-col items-center justify-center h-32">
            <span className="text-3xl font-bold text-foreground">
              {healthData ? `${healthData.ram_used_gb} GB` : '—'}
            </span>
            <span className="text-xs text-muted-foreground uppercase tracking-wider mt-1">
              {healthData ? `RAM (${healthData.ram_percent}% of ${healthData.ram_total_gb} GB)` : 'RAM Usage'}
            </span>
          </div>
        </div>

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
              <div>Waiting for backend health logs...</div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
