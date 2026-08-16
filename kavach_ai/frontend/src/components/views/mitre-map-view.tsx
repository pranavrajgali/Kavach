import React from 'react';
import { ShieldAlert, Crosshair } from 'lucide-react';
import { useDetonation } from '@/context/DetonationContext';

export const MitreMapView: React.FC = () => {
  const { staticResults, telemetry } = useDetonation();
  const staticSignals = [
    ...(staticResults?.triage.permissions || []),
    ...(staticResults?.triage.permission_combinations || []),
    ...(staticResults?.triage.manifest_indicators || []),
    ...(staticResults?.triage.code_signals || []),
    ...(staticResults?.triage.dynamic_loading_indicators || []),
    ...(staticResults?.triage.reflection_indicators || []),
  ].join(' ').toLowerCase();
  const runtimeSignals = [
    ...(telemetry?.ebpf_telemetry.syscalls || []),
    ...(telemetry?.ebpf_telemetry.files_accessed || []),
    ...(telemetry?.ebpf_telemetry.network_connections || []).map((connection) => `${connection.ip}:${connection.port}`),
    ...(telemetry?.llm_frida_intercepts || []),
    ...(telemetry?.time_dilution_events || []),
  ].join(' ').toLowerCase();
  const has = (source: string, ...signals: string[]) => signals.some((signal) => source.includes(signal));
  const detected = new Set<string>();

  if (has(staticSignals, 'dexclassloader', 'loadclass', 'reflection', 'class.forname')) detected.add('T1631: Obfuscated Files/Info');
  if (has(staticSignals, 'sms', 'read_sms', 'receive_sms', 'send_sms', 'sendtextmessage')) {
    detected.add('T1636: Access SMS Data');
  }
  if (has(runtimeSignals, 'connect', 'socket', ':443', ':80')) detected.add('T1639: Exfiltration Over C2 Channel');
  if (has(runtimeSignals, 'sleep', 'time dilution', 'root', 'ssl pinning')) detected.add('T1629: Impair Defenses');

  const tactics = [
    { name: "Initial Access", techniques: ["T1626: Supply Chain Compromise", "T1456: Drive-by Compromise"] },
    { name: "Execution", techniques: ["T1624: Event-Triggered Execution", "T1625: Native API", "T1633: Scheduled Task/Job"] },
    { name: "Persistence", techniques: ["T1624: Event-Triggered Execution", "T1627: Hijack Execution Flow"] },
    { name: "Privilege Escalation", techniques: ["T1628: Exploitation for Privilege Escalation"] },
    { name: "Defense Evasion", techniques: ["T1629: Impair Defenses", "T1630: Indicator Removal", "T1631: Obfuscated Files/Info"] },
    { name: "Credential Access", techniques: ["T1632: Credentials from Password Stores", "T1636: Access SMS Data"] },
    { name: "Collection", techniques: ["T1635: Location Tracking", "T1636: Access SMS Data", "T1637: Capture Audio"] },
    { name: "Exfiltration", techniques: ["T1638: Exfiltration Over Alternative Protocol", "T1639: Exfiltration Over C2 Channel"] }
  ];

  const detectionCount = detected.size;

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between border-b border-border pb-4">
        <h2 className="text-xl font-bold flex items-center gap-2">
          <ShieldAlert className="w-5 h-5 text-primary" />
          MITRE ATT&CK Matrix for Mobile
        </h2>
        <span className="px-2 py-1 text-xs font-semibold bg-destructive/10 text-destructive border border-destructive/20">
          {detectionCount} Detection{detectionCount === 1 ? '' : 's'}
        </span>
      </div>

      {!staticResults && !telemetry && (
        <div className="border border-blue-500/20 bg-blue-500/5 p-4 text-xs text-blue-400">
          Run a static scan or sandbox detonation to populate this matrix with evidence from the current APK. No demo detections are shown.
        </div>
      )}

      <div className="overflow-x-auto pb-4">
        <div className="flex gap-4 min-w-max">
          {tactics.map((tactic, i) => (
            <div key={i} className="w-56 space-y-2">
              <div className="bg-secondary/50 border border-border p-2 text-center text-xs font-bold uppercase tracking-wider">
                {tactic.name}
              </div>
              <div className="space-y-2">
                {tactic.techniques.map((tech, j) => {
                  const isDetected = detected.has(tech);
                  return (
                    <div
                      key={j}
                      className={`p-3 text-xs border cursor-pointer transition-all ${
                        isDetected
                          ? 'border-destructive bg-destructive/10 text-destructive font-medium hover:bg-destructive/20'
                          : 'border-border bg-card/30 text-muted-foreground hover:bg-card/60'
                      }`}
                    >
                      <div className="flex items-start gap-2">
                        {isDetected && <Crosshair className="w-3.5 h-3.5 mt-0.5 shrink-0" />}
                        <span>{tech}</span>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
