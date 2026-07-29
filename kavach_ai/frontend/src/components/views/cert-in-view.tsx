import React from 'react';
import { FileText, Download, CheckSquare } from 'lucide-react';
import { useDetonation } from '@/context/DetonationContext';

export const CertInView: React.FC = () => {
  const { apkDetails } = useDetonation();

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between border-b border-border pb-4">
        <h2 className="text-xl font-bold flex items-center gap-2">
          <FileText className="w-5 h-5 text-primary" />
          CERT-In Incident Report
        </h2>
        <button className="flex items-center gap-2 px-3 py-1.5 bg-primary/10 hover:bg-primary/20 text-primary border border-primary/20 text-xs font-semibold transition-all">
          <Download className="w-4 h-4" />
          Export PDF
        </button>
      </div>

      <div className="max-w-3xl border border-border bg-card/30 p-8 space-y-8 font-mono text-sm mx-auto">
        <div className="text-center space-y-2 border-b border-border pb-6">
          <h1 className="text-lg font-bold uppercase tracking-widest text-foreground">Indian Computer Emergency Response Team (CERT-In)</h1>
          <p className="text-muted-foreground">Cyber Security Incident Reporting Form</p>
        </div>

        <div className="space-y-6">
          <div className="grid grid-cols-3 gap-4 border-b border-border/50 pb-4">
            <div className="col-span-1 text-muted-foreground font-semibold">1. Incident Date & Time:</div>
            <div className="col-span-2 text-foreground">{new Date().toLocaleString()}</div>
          </div>
          
          <div className="grid grid-cols-3 gap-4 border-b border-border/50 pb-4">
            <div className="col-span-1 text-muted-foreground font-semibold">2. Type of Incident:</div>
            <div className="col-span-2 text-foreground flex items-center gap-2">
              <CheckSquare className="w-4 h-4 text-primary" /> Malicious Code (Malware / Spyware / Trojan)
            </div>
          </div>

          <div className="grid grid-cols-3 gap-4 border-b border-border/50 pb-4">
            <div className="col-span-1 text-muted-foreground font-semibold">3. Target System Details:</div>
            <div className="col-span-2 space-y-1">
              <div><span className="text-muted-foreground">OS:</span> Android 11.0 (API 30)</div>
              <div><span className="text-muted-foreground">App Name:</span> {apkDetails?.name || 'Unknown APK'}</div>
              <div><span className="text-muted-foreground">Package ID:</span> {apkDetails?.package || 'com.unknown.package'}</div>
            </div>
          </div>

          <div className="grid grid-cols-3 gap-4 pb-4">
            <div className="col-span-1 text-muted-foreground font-semibold">4. Indicators of Compromise (IoCs):</div>
            <div className="col-span-2 space-y-2 text-xs">
              <div className="bg-black/40 p-2 border border-border">
                <span className="text-destructive font-semibold">Network:</span> Attempted connection to 103.45.XX.XX:8080 (TCP)
              </div>
              <div className="bg-black/40 p-2 border border-border">
                <span className="text-destructive font-semibold">Host:</span> Dynamic loading of hidden DEX payloads via `DexClassLoader`.
              </div>
              <div className="bg-black/40 p-2 border border-border">
                <span className="text-destructive font-semibold">Behavior:</span> Automated interception and exfiltration of SMS messages.
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
