import React, { useState } from 'react';
import { Settings, Sliders, Clock, ShieldCheck, Save } from 'lucide-react';
import { useDetonation } from '@/context/DetonationContext';

export const SettingsView: React.FC = () => {
  const { detonationDuration, setDetonationDuration } = useDetonation();
  const [highConfThreshold, setHighConfThreshold] = useState(0.85);
  const [concurringThreshold, setConcurringThreshold] = useState(0.60);
  const [dexScanEnabled, setDexScanEnabled] = useState(true);
  const [jniScanEnabled, setJniScanEnabled] = useState(true);
  const [reflectionFallbackEnabled, setReflectionFallbackEnabled] = useState(false);

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between border-b border-border pb-4">
        <h2 className="text-xl font-bold flex items-center gap-2">
          <Settings className="w-5 h-5 text-primary" />
          Pipeline Settings
        </h2>
        <button className="flex items-center gap-2 px-4 py-2 bg-primary text-primary-foreground text-sm font-semibold hover:bg-primary/90 transition-all">
          <Save className="w-4 h-4" /> Save Configuration
        </button>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
        
        {/* ML Thresholds */}
        <div className="space-y-6">
          <h3 className="text-sm font-bold uppercase tracking-widest flex items-center gap-2 text-muted-foreground">
            <Sliders className="w-4 h-4" /> SecureBERT Thresholds
          </h3>
          <div className="p-6 border border-border bg-card/30 space-y-6">
            <div className="space-y-3">
              <div className="flex justify-between items-center text-sm">
                <label className="font-semibold text-foreground">High-Confidence Single Slice</label>
                <span className="text-primary font-mono">{highConfThreshold.toFixed(2)}</span>
              </div>
              <input 
                type="range" min="0.5" max="0.99" step="0.01" 
                value={highConfThreshold} onChange={(e) => setHighConfThreshold(parseFloat(e.target.value))}
                className="w-full accent-primary" 
              />
              <p className="text-xs text-muted-foreground">Threshold for a single slice to classify the entire APK as malicious.</p>
            </div>

            <div className="space-y-3 pt-4 border-t border-border/50">
              <div className="flex justify-between items-center text-sm">
                <label className="font-semibold text-foreground">Concurring Double Slice</label>
                <span className="text-primary font-mono">{concurringThreshold.toFixed(2)}</span>
              </div>
              <input 
                type="range" min="0.4" max="0.9" step="0.01" 
                value={concurringThreshold} onChange={(e) => setConcurringThreshold(parseFloat(e.target.value))}
                className="w-full accent-primary" 
              />
              <p className="text-xs text-muted-foreground">Threshold required when two or more slices concur on a malicious classification.</p>
            </div>
          </div>
        </div>

        {/* Runtime Settings */}
        <div className="space-y-6">
          <h3 className="text-sm font-bold uppercase tracking-widest flex items-center gap-2 text-muted-foreground">
            <Clock className="w-4 h-4" /> Execution Parameters
          </h3>
          <div className="p-6 border border-border bg-card/30 space-y-6">
            <div className="space-y-3">
              <div className="flex justify-between items-center text-sm">
                <label className="font-semibold text-foreground">Detonation Timer (Seconds)</label>
                <span className="text-primary font-mono">{detonationDuration}s</span>
              </div>
              <div className="flex gap-2">
                {[15, 30, 60, 120].map(val => (
                  <button 
                    key={val} onClick={() => setDetonationDuration(val)}
                    className={`flex-1 py-2 text-xs font-semibold border ${detonationDuration === val ? 'bg-primary text-primary-foreground border-primary' : 'bg-transparent text-muted-foreground border-border hover:border-primary/50'}`}
                  >
                    {val}s
                  </button>
                ))}
              </div>
              <p className="text-xs text-muted-foreground">How long the emulator runs the application before collecting final telemetry.</p>
            </div>
          </div>
        </div>

        {/* Fallbacks */}
        <div className="space-y-6 lg:col-span-2">
          <h3 className="text-sm font-bold uppercase tracking-widest flex items-center gap-2 text-muted-foreground">
            <ShieldCheck className="w-4 h-4" /> Analysis Fallbacks & Toggles
          </h3>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <label className={`p-4 border cursor-pointer flex flex-col gap-2 transition-all ${dexScanEnabled ? 'border-primary bg-primary/5' : 'border-border bg-card/30'}`}>
              <div className="flex items-center justify-between">
                <span className="text-sm font-semibold text-foreground">Dynamic Class Scan</span>
                <input type="checkbox" checked={dexScanEnabled} onChange={e => setDexScanEnabled(e.target.checked)} className="accent-primary w-4 h-4" />
              </div>
              <span className="text-xs text-muted-foreground">Scan for DexClassLoader usage to detect dynamically loaded secondary payloads.</span>
            </label>

            <label className={`p-4 border cursor-pointer flex flex-col gap-2 transition-all ${jniScanEnabled ? 'border-primary bg-primary/5' : 'border-border bg-card/30'}`}>
              <div className="flex items-center justify-between">
                <span className="text-sm font-semibold text-foreground">Static JNI Checks</span>
                <input type="checkbox" checked={jniScanEnabled} onChange={e => setJniScanEnabled(e.target.checked)} className="accent-primary w-4 h-4" />
              </div>
              <span className="text-xs text-muted-foreground">Perform native library (.so) exports analysis for standard malware hooks.</span>
            </label>

            <label className={`p-4 border cursor-pointer flex flex-col gap-2 transition-all ${reflectionFallbackEnabled ? 'border-primary bg-primary/5' : 'border-border bg-card/30'}`}>
              <div className="flex items-center justify-between">
                <span className="text-sm font-semibold text-foreground">Reflection Density</span>
                <input type="checkbox" checked={reflectionFallbackEnabled} onChange={e => setReflectionFallbackEnabled(e.target.checked)} className="accent-primary w-4 h-4" />
              </div>
              <span className="text-xs text-muted-foreground">Fallback to reflection density scoring if static analysis fails to decompile properly.</span>
            </label>
          </div>
        </div>

      </div>
    </div>
  );
};
