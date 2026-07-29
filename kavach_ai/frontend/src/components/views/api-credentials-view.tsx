import React, { useState } from 'react';
import { CreditCard, Key, Eye, EyeOff, Save, Link as LinkIcon, Database } from 'lucide-react';

export const ApiCredentialsView: React.FC = () => {
  const [showGroqKey, setShowGroqKey] = useState(false);
  const [showVtKey, setShowVtKey] = useState(false);
  const [groqKey, setGroqKey] = useState('gsk_**************************************');
  const [vtKey, setVtKey] = useState('');

  return (
    <div className="space-y-8">
      <div className="flex items-center justify-between border-b border-border pb-4">
        <h2 className="text-xl font-bold flex items-center gap-2">
          <CreditCard className="w-5 h-5 text-primary" />
          API Credentials & Integrations
        </h2>
        <button className="flex items-center gap-2 px-4 py-2 bg-primary text-primary-foreground text-sm font-semibold hover:bg-primary/90 transition-all">
          <Save className="w-4 h-4" /> Save Credentials
        </button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
        
        {/* Third-Party APIs */}
        <div className="space-y-6">
          <h3 className="text-sm font-bold uppercase tracking-widest flex items-center gap-2 text-muted-foreground">
            <LinkIcon className="w-4 h-4" /> External Services
          </h3>
          
          <div className="p-6 border border-border bg-card/30 space-y-4">
            <div className="space-y-2">
              <label className="text-sm font-semibold text-foreground flex items-center justify-between">
                <span>Groq API Key (LLaMA-3 Reporting)</span>
                <span className="text-xs text-emerald-500 font-medium bg-emerald-500/10 px-2 py-0.5 border border-emerald-500/20">Configured</span>
              </label>
              <div className="relative">
                <input 
                  type={showGroqKey ? 'text' : 'password'}
                  value={groqKey}
                  onChange={(e) => setGroqKey(e.target.value)}
                  className="w-full bg-black/50 border border-border px-3 py-2 text-sm text-foreground focus:outline-none focus:border-primary font-mono"
                />
                <button 
                  type="button"
                  onClick={() => setShowGroqKey(!showGroqKey)}
                  className="absolute right-3 top-2.5 text-muted-foreground hover:text-foreground"
                >
                  {showGroqKey ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
              <p className="text-xs text-muted-foreground">Used for generating automated human-readable forensic reports.</p>
            </div>
          </div>

          <div className="p-6 border border-border bg-card/30 space-y-4">
            <div className="space-y-2">
              <label className="text-sm font-semibold text-foreground flex items-center justify-between">
                <span>VirusTotal API Key</span>
                <span className="text-xs text-muted-foreground font-medium bg-secondary px-2 py-0.5 border border-border">Not Configured</span>
              </label>
              <div className="relative">
                <input 
                  type={showVtKey ? 'text' : 'password'}
                  value={vtKey}
                  onChange={(e) => setVtKey(e.target.value)}
                  placeholder="Paste your VT API key here..."
                  className="w-full bg-black/50 border border-border px-3 py-2 text-sm text-foreground focus:outline-none focus:border-primary font-mono"
                />
                <button 
                  type="button"
                  onClick={() => setShowVtKey(!showVtKey)}
                  className="absolute right-3 top-2.5 text-muted-foreground hover:text-foreground"
                >
                  {showVtKey ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
              <p className="text-xs text-muted-foreground">Optional. Used to fetch cloud reputation flags for dropped payloads.</p>
            </div>
          </div>
        </div>

        {/* Database Connection */}
        <div className="space-y-6">
          <h3 className="text-sm font-bold uppercase tracking-widest flex items-center gap-2 text-muted-foreground">
            <Database className="w-4 h-4" /> Local Storage
          </h3>
          
          <div className="p-6 border border-border bg-card/30 space-y-4">
            <div className="flex items-center justify-between">
              <div className="space-y-1">
                <div className="text-sm font-semibold text-foreground">PostgreSQL Status</div>
                <div className="text-xs text-muted-foreground">Store malware samples and analysis runs.</div>
              </div>
              <div className="px-3 py-1 bg-emerald-500/10 text-emerald-500 border border-emerald-500/20 text-xs font-semibold flex items-center gap-2">
                <div className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse"></div>
                Connected
              </div>
            </div>
            
            <div className="bg-black/50 p-4 border border-border/50 text-xs font-mono space-y-2 mt-4">
              <div className="flex justify-between">
                <span className="text-muted-foreground">Host:</span>
                <span className="text-foreground">localhost:5432</span>
              </div>
              <div className="flex justify-between">
                <span className="text-muted-foreground">Database:</span>
                <span className="text-foreground">kavach_db</span>
              </div>
              <div className="flex justify-between">
                <span className="text-muted-foreground">Active Connections:</span>
                <span className="text-foreground">4</span>
              </div>
              <div className="flex justify-between">
                <span className="text-muted-foreground">Latency:</span>
                <span className="text-emerald-500">2ms</span>
              </div>
            </div>
          </div>
        </div>

      </div>
    </div>
  );
};
