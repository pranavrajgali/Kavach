import React, { useState } from 'react';
import { useDetonation } from '@/context/DetonationContext';
import { 
  Cpu, FileCode, AlertTriangle, ChevronDown, 
  Activity, Sliders, Info, Play, Server, Sparkles
} from 'lucide-react';
import { 
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, 
  ResponsiveContainer, Cell, LineChart, Line 
} from 'recharts';


const renderHighlightedCode = (snippet: string, relevanceTokens: any[]) => {
  if (!relevanceTokens || relevanceTokens.length === 0) {
    return <span>{snippet}</span>;
  }
  
  // Create a map of token -> relevance for fast lookup
  const relevanceMap: Record<string, number> = {};
  let maxWeight = 0.0001;
  relevanceTokens.forEach(([tok, val]) => {
    const t = tok.trim();
    if (t) {
      relevanceMap[t.toLowerCase()] = val;
      if (val > maxWeight) maxWeight = val;
    }
  });

  // Split the snippet by spaces, tabs, newlines, and operators to preserve format
  const tokens = snippet.split(/(\s+|<-|->|[{}():;,])/g);
  
  return tokens.map((token, tIdx) => {
    if (!token) return null;
    const cleanToken = token.trim().toLowerCase();
    const weight = relevanceMap[cleanToken];
    
    if (weight && weight > 0.0001) {
      const intensity = weight / maxWeight;
      const bgColor = `rgba(239, 68, 68, ${Math.min(0.1 + intensity * 0.45, 0.6)})`;
      const textColor = '#fca5a5'; // Light red text for dark mode contrast
      return (
        <span 
          key={tIdx} 
          className="font-bold px-0.5 rounded-[2px] cursor-help transition-all border-b border-red-500/20"
          style={{ backgroundColor: bgColor, color: textColor }}
          title={`Attention LRP Relevance Score: ${weight.toFixed(6)}`}
        >
          {token}
        </span>
      );
    }
    return <span key={tIdx}>{token}</span>;
  });
};

export const BertClassifierView: React.FC = () => {
  const { staticResults, availableModels } = useDetonation();
  const mlData = staticResults?.ml_metrics;
  const isSampleData = !staticResults;

  // Never substitute demo findings for an APK that has not been scanned.
  const prob = mlData?.malicious_probability ?? 0;
  const isMalicious = mlData?.verdict === 'MALICIOUS';
  const modelId = mlData?.model_id || 'securebert-full-weighted';
  const sliceCount = mlData?.slice_count ?? mlData?.slice_evaluations?.length ?? 0;

  const sliceEvals = mlData?.slice_evaluations || [];

  const [openAccordion, setOpenAccordion] = useState<number | null>(0);

  // States for interactive slice tester
  const [customSlice, setCustomSlice] = useState('');
  const [selectedModel, setSelectedModel] = useState(modelId);
  const [customResult, setCustomResult] = useState<any>(null);
  const [loadingCustom, setLoadingCustom] = useState(false);
  const [customError, setCustomError] = useState<string | null>(null);

  // Derive SHAP data for chart
  const shapData = sliceEvals.map((se: any, i: number) => ({
    name: `Slice ${se.slice_index || i + 1}`,
    impact: Number((se.malicious_probability * 100).toFixed(1)),
    isMalicious: se.malicious_probability >= 0.5,
    snippet: se.code_snippet
  })).sort((a: any, b: any) => b.impact - a.impact);

  // Derive Threat Distribution data
  const distributionData = [...sliceEvals]
    .sort((a, b) => (a.slice_index || 0) - (b.slice_index || 0))
    .map((se: any, i: number) => ({
      name: `S${se.slice_index || i + 1}`,
      probability: Math.round(se.malicious_probability * 100),
    }));

  // SVG Gauge calculations
  const radius = 50;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (prob * circumference);

  // Custom classification handler
  const handleCustomClassify = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!customSlice.trim()) return;

    setLoadingCustom(true);
    setCustomError(null);
    setCustomResult(null);

    try {
      const res = await fetch(`/api/classify-slice?slice_text=${encodeURIComponent(customSlice)}&model_id=${encodeURIComponent(selectedModel)}`, {
        method: 'POST'
      });
      if (!res.ok) {
        throw new Error(await res.text() || 'Failed to classify slice');
      }
      const data = await res.json();
      if (data.status === 'success') {
        setCustomResult(data.results);
      } else {
        setCustomError(data.message || 'Error occurred during classification');
      }
    } catch (err: any) {
      setCustomError(err.message || 'Network error');
    } finally {
      setLoadingCustom(false);
    }
  };

  return (
    <div className="flex flex-col space-y-8 animate-in fade-in zoom-in-95 duration-300">
      
      {/* Disclaimer Banner for Sample Data */}
      {isSampleData && (
        <div className="flex items-center gap-3 px-4 py-3 border border-blue-500/20 bg-blue-500/5 text-blue-400 text-xs">
          <Info className="w-4 h-4 shrink-0" />
          <div>
            <span className="font-bold">Viewing Sample Metrics:</span> No APK has been scanned yet. Real static features and slice evaluation details will appear here once a static scan is run from the <span className="font-semibold underline">Static Analysis</span> tab. You can still test the model using the custom slice tester below.
          </div>
        </div>
      )}

      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-end justify-between gap-4 border-b border-border pb-6">
        <div className="space-y-1">
          <h2 className="text-2xl font-semibold tracking-tight flex items-center gap-2 text-foreground">
            <Cpu className="w-5 h-5 text-muted-foreground" />
            BERT ML Classifier
          </h2>
          <p className="text-xs text-muted-foreground">
            Neural network classification metrics and slice evaluations.
          </p>
        </div>
        <div className="flex items-center gap-3 text-xs">
          <div className="flex flex-col items-end">
            <span className="text-muted-foreground uppercase tracking-wider font-semibold">Model</span>
            <span className="font-semibold font-mono text-foreground">{modelId}</span>
          </div>
          <div className="h-8 w-px bg-border mx-1"></div>
          <div className="flex flex-col items-end">
            <span className="text-muted-foreground uppercase tracking-wider font-semibold">Architecture</span>
            <span className="font-semibold text-foreground">SecureBERT-2.0</span>
          </div>
        </div>
      </div>

      {/* ── Top Row: 4 Metric Cards (Flat) ── */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Card 1: Verdict */}
        <div className="border border-border bg-card p-5 flex flex-col justify-between h-[100px]">
          <span className="text-[10px] font-bold text-muted-foreground uppercase tracking-widest block">
            Classification Verdict
          </span>
          <div className="flex items-center justify-between mt-1">
            <span className={`text-2xl font-black ${isMalicious ? 'text-destructive' : 'text-emerald-500'}`}>
              {mlData ? (isMalicious ? 'MALICIOUS' : 'BENIGN') : 'PENDING'}
            </span>
            <span className={`text-[10px] font-bold px-2 py-0.5 border ${
              isMalicious 
                ? 'bg-destructive/10 text-destructive border-destructive/20' 
                : 'bg-emerald-500/10 text-emerald-500 border-emerald-500/20'
            }`}>
              {mlData ? (isMalicious ? 'High Risk' : 'Secure') : 'No scan'}
            </span>
          </div>
        </div>

        {/* Card 2: Threat Probability */}
        <div className="border border-border bg-card p-5 flex flex-col justify-between h-[100px]">
          <span className="text-[10px] font-bold text-muted-foreground uppercase tracking-widest block">
            Threat Probability
          </span>
          <div className="flex items-center justify-between mt-1">
            <span className="text-2xl font-black text-foreground">
              {(prob * 100).toFixed(1)}%
            </span>
            <span className="text-xs text-muted-foreground font-mono">
              Threshold &gt;= 50%
            </span>
          </div>
        </div>

        {/* Card 3: Slices Scanned */}
        <div className="border border-border bg-card p-5 flex flex-col justify-between h-[100px]">
          <span className="text-[10px] font-bold text-muted-foreground uppercase tracking-widest block">
            Program Slices Analyzed
          </span>
          <div className="flex items-center justify-between mt-1">
            <span className="text-2xl font-black text-foreground">
              {sliceCount}
            </span>
            <span className="text-[10px] text-muted-foreground font-semibold bg-secondary px-2 py-0.5">
              Capped at Max 15
            </span>
          </div>
        </div>

        {/* Card 4: Hardware Target */}
        <div className="border border-border bg-card p-5 flex flex-col justify-between h-[100px]">
          <span className="text-[10px] font-bold text-muted-foreground uppercase tracking-widest block">
            Inference Target
          </span>
          <div className="flex items-center justify-between mt-1">
            <span className="text-2xl font-black text-blue-400">
              CUDA GPU
            </span>
            <span className="text-[10px] text-blue-400/80 font-bold px-2 py-0.5 border border-blue-500/20 bg-blue-500/5">
              Active
            </span>
          </div>
        </div>
      </div>

      {/* ── Middle Row Grid: Analytics Dashboard ── */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        
        {/* Left Column (col-span-4): Threat Gauge & Diagnostics */}
        <div className="lg:col-span-4 border border-border bg-card flex flex-col justify-between">
          <div className="p-4 border-b border-border bg-secondary/30 flex items-center justify-between">
            <span className="text-xs font-bold text-foreground">Threat Score Gauge</span>
            <Server className="w-3.5 h-3.5 text-muted-foreground" />
          </div>
          
          {/* Radial Score Gauge */}
          <div className="flex-1 flex flex-col items-center justify-center p-6 space-y-4">
            <div className="relative w-32 h-32 flex items-center justify-center">
              <svg className="w-full h-full transform -rotate-90">
                <circle
                  cx="64"
                  cy="64"
                  r={radius}
                  className="stroke-secondary fill-none"
                  strokeWidth="8"
                />
                <circle
                  cx="64"
                  cy="64"
                  r={radius}
                  className={`fill-none transition-all duration-1000 ease-out ${
                    isMalicious ? 'stroke-destructive' : 'stroke-emerald-500'
                  }`}
                  strokeWidth="8"
                  strokeDasharray={circumference}
                  strokeDashoffset={strokeDashoffset}
                  strokeLinecap="square"
                />
              </svg>
              <div className="absolute inset-0 flex flex-col items-center justify-center">
                <span className="text-2xl font-black text-foreground">{(prob * 100).toFixed(0)}%</span>
                <span className="text-[9px] font-bold uppercase tracking-wider text-muted-foreground">Threat</span>
              </div>
            </div>
            
            <div className="text-center">
              <span className={`text-xs font-bold ${isMalicious ? 'text-destructive' : 'text-emerald-500'}`}>
                {mlData ? (isMalicious ? 'MALICIOUS ACTIVITY DETECTED' : 'CLEAN BACKBONE VERDICT') : 'AWAITING APK SCAN'}
              </span>
            </div>
          </div>

          {/* Technical Diagnostics */}
          <div className="border-t border-border p-4 bg-secondary/20 space-y-2">
            <span className="text-[10px] font-bold text-muted-foreground uppercase tracking-widest block mb-1">
              Model Diagnostics
            </span>
            <div className="space-y-1.5 text-xs">
              <div className="flex justify-between">
                <span className="text-muted-foreground">Base Model:</span>
                <span className="font-semibold text-foreground font-mono">SecureBERT2.0-base</span>
              </div>
              <div className="flex justify-between">
                <span className="text-muted-foreground">Parameters:</span>
                <span className="font-semibold text-foreground font-mono">110M Params</span>
              </div>
              <div className="flex justify-between">
                <span className="text-muted-foreground">Adapter Type:</span>
                <span className="font-semibold text-foreground font-mono">PEFT / LoRA</span>
              </div>
              <div className="flex justify-between">
                <span className="text-muted-foreground">Context Size:</span>
                <span className="font-semibold text-foreground font-mono">512 tokens</span>
              </div>
            </div>
          </div>
        </div>

        {/* Middle Column (col-span-5): Threat Distribution Curve */}
        <div className="lg:col-span-5 border border-border bg-card flex flex-col">
          <div className="p-4 border-b border-border bg-secondary/30 flex items-center justify-between">
            <span className="text-xs font-bold text-foreground">Threat Distribution Curve</span>
            <Activity className="w-3.5 h-3.5 text-muted-foreground" />
          </div>
          <div className="p-6 flex-1 flex flex-col justify-center">
            <div className="h-[180px] w-full text-xs">
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={distributionData} margin={{ top: 5, right: 10, left: -20, bottom: 5 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1f1f23" vertical={false} />
                  <XAxis dataKey="name" stroke="#52525b" tickLine={false} tick={{ fontSize: 9 }} />
                  <YAxis stroke="#52525b" domain={[0, 100]} tickLine={false} tick={{ fontSize: 9 }} />
                  <Tooltip 
                    content={({ active, payload }) => {
                      if (active && payload && payload.length) {
                        return (
                          <div className="bg-popover text-popover-foreground border border-border p-2 text-xs">
                            <p className="font-bold">{payload[0].payload.name}</p>
                            <p className="text-destructive font-mono">Threat: {payload[0].value}%</p>
                          </div>
                        );
                      }
                      return null;
                    }}
                  />
                  <Line 
                    type="monotone" 
                    dataKey="probability" 
                    stroke="#ef4444" 
                    strokeWidth={2.5}
                    dot={{ r: 4, stroke: '#ef4444', strokeWidth: 1, fill: '#09090b' }}
                    activeDot={{ r: 6, stroke: '#ef4444', strokeWidth: 1 }}
                  />
                </LineChart>
              </ResponsiveContainer>
            </div>
            <p className="text-[10px] text-muted-foreground text-center mt-3">
              Distribution of threat probability across program slices. Peaks represent high risk code sinks.
            </p>
          </div>
        </div>

        {/* Right Column (col-span-3): LRP Importance Chart */}
        <div className="lg:col-span-3 border border-border bg-card flex flex-col">
          <div className="p-4 border-b border-border bg-secondary/30 flex items-center justify-between">
            <span className="text-xs font-bold text-foreground">LRP Slice Threat Relevance</span>
            <Sliders className="w-3.5 h-3.5 text-muted-foreground" />
          </div>
          <div className="p-4 flex-1 flex flex-col justify-center">
            <div className="h-[180px] w-full text-xs">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={shapData} layout="vertical" margin={{ top: 0, right: 5, left: -25, bottom: 0 }}>
                  <XAxis type="number" domain={[0, 100]} hide />
                  <YAxis dataKey="name" type="category" axisLine={false} tickLine={false} tick={{ fill: '#a1a1aa', fontSize: 9 }} width={60} />
                  <Tooltip 
                    content={({ active, payload }) => {
                      if (active && payload && payload.length) {
                        return (
                          <div className="bg-popover text-popover-foreground border border-border p-2 text-xs max-w-[200px]">
                            <p className="font-semibold">{payload[0].payload.name}</p>
                            <p className="text-xs text-muted-foreground truncate">{payload[0].payload.snippet}</p>
                            <p className="font-bold text-primary mt-1">Impact: {payload[0].value}%</p>
                          </div>
                        );
                      }
                      return null;
                    }}
                  />
                  <Bar dataKey="impact" barSize={10}>
                    {shapData.map((entry: any, index: number) => (
                      <Cell key={`cell-${index}`} fill={entry.isMalicious ? '#ef4444' : '#10b981'} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
            <p className="text-[10px] text-muted-foreground text-center mt-3">
              Attention-based Layer-wise Relevance Propagation (LRP) slice weights. Red indicates positive (malicious) relevance; green represents benign fallback traits.
            </p>
          </div>
        </div>

      </div>

      {/* ── Bottom Row Grid: Interactive Tester & Slices List ── */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        
        {/* Left Card: Interactive Slice Classifier Playground (col-span-6) */}
        <div className="lg:col-span-6 border border-border bg-card flex flex-col justify-between">
          <div>
            <div className="p-4 border-b border-border bg-secondary/30 flex items-center justify-between">
              <span className="text-xs font-bold text-foreground flex items-center gap-1.5">
                <Sparkles className="w-3.5 h-3.5 text-blue-400" />
                Interactive Slice Tester (Playground)
              </span>
              <span className="text-[9px] font-bold bg-blue-500/10 text-blue-400 border border-blue-500/20 px-2 py-0.5">
                Real-Time
              </span>
            </div>
            
            <form onSubmit={handleCustomClassify} className="p-6 space-y-4">
              <div>
                <label className="text-[10px] font-bold text-muted-foreground uppercase tracking-widest block mb-2">
                  Model Adapter
                </label>
                <select
                  value={selectedModel}
                  onChange={(e) => setSelectedModel(e.target.value)}
                  className="w-full bg-secondary border border-border px-3 py-2 text-xs font-medium text-foreground rounded-none focus:outline-none focus:ring-1 focus:ring-primary"
                >
                  {availableModels.map((m) => (
                    <option key={m.id} value={m.id}>
                      {m.name}
                    </option>
                  ))}
                </select>
              </div>

              <div>
                <label className="text-[10px] font-bold text-muted-foreground uppercase tracking-widest block mb-2">
                  Java / Smali Code Slice
                </label>
                <textarea
                  value={customSlice}
                  onChange={(e) => setCustomSlice(e.target.value)}
                  placeholder="e.g., Landroid/telephony/SmsManager;->sendTextMessage <- Lcom/evil/Payload;->execute"
                  rows={4}
                  className="w-full bg-[#09090b] border border-border px-3 py-2 text-xs font-mono text-zinc-300 rounded-none focus:outline-none focus:ring-1 focus:ring-primary placeholder-zinc-700"
                />
              </div>

              <button
                type="submit"
                disabled={loadingCustom || !customSlice.trim()}
                className="w-full flex items-center justify-center gap-2 bg-primary hover:bg-primary/95 text-primary-foreground font-bold py-2 text-xs transition-all disabled:opacity-50 disabled:cursor-not-allowed cursor-pointer"
              >
                <Play className="w-3 h-3 fill-current" />
                {loadingCustom ? 'Running BERT Inference...' : 'Classify Custom Slice'}
              </button>
            </form>
          </div>

          {/* Results Output Block */}
          <div className="border-t border-border p-6 bg-secondary/10 min-h-[140px] flex flex-col justify-center">
            {customResult ? (
              <div className="space-y-4 animate-in fade-in duration-200">
                <div className="flex justify-between items-center">
                  <span className="text-[10px] font-bold text-muted-foreground uppercase tracking-widest">
                    Classification Result
                  </span>
                  <span className={`text-[10px] font-bold px-2 py-0.5 border ${
                    customResult.verdict === 'MALICIOUS'
                      ? 'bg-destructive/10 text-destructive border-destructive/20'
                      : 'bg-emerald-500/10 text-emerald-500 border-emerald-500/20'
                  }`}>
                    {customResult.verdict}
                  </span>
                </div>
                
                <div className="grid grid-cols-2 gap-4">
                  <div className="border border-border bg-card p-3">
                    <span className="text-[9px] text-muted-foreground uppercase tracking-wider block">
                      Malicious Probability
                    </span>
                    <span className="text-xl font-black text-foreground">
                      {(customResult.malicious_probability * 100).toFixed(2)}%
                    </span>
                  </div>
                  <div className="border border-border bg-card p-3">
                    <span className="text-[9px] text-muted-foreground uppercase tracking-wider block">
                      Model Confidence
                    </span>
                    <span className="text-xl font-black text-foreground">
                      {(customResult.confidence_score * 100).toFixed(2)}%
                    </span>
                  </div>
                </div>
              </div>
            ) : customError ? (
              <div className="text-xs text-destructive border border-destructive/20 bg-destructive/5 p-4">
                <AlertTriangle className="w-4 h-4 text-destructive mb-1" />
                <span className="font-bold">Error:</span> {customError}
              </div>
            ) : (
              <div className="flex flex-col items-center justify-center text-center py-6 text-muted-foreground space-y-1">
                <Sliders className="w-6 h-6 text-muted-foreground/40 mb-1" />
                <span className="text-xs font-bold">Waiting for input</span>
                <p className="text-[10px] max-w-[280px]">
                  Input code slices above to query the neural network's classifier layers.
                </p>
              </div>
            )}
          </div>
        </div>

        {/* Right Card: Evaluated Program Slices (col-span-6) */}
        <div className="lg:col-span-6 border border-border bg-card flex flex-col">
          <div className="p-4 border-b border-border bg-secondary/30 flex items-center justify-between">
            <span className="text-xs font-bold text-foreground flex items-center gap-1.5">
              <FileCode className="w-3.5 h-3.5 text-muted-foreground" />
              Evaluated Program Slices
            </span>
            <span className="text-[10px] font-bold text-muted-foreground bg-secondary px-2.5 py-0.5">
              {sliceCount} Slices
            </span>
          </div>
          
          <div className="p-4 flex-1 overflow-y-auto max-h-[460px]">
            {sliceEvals.length === 0 ? (
              <div className="flex flex-col items-center justify-center h-full text-xs text-muted-foreground py-12">
                No program slices evaluated.
              </div>
            ) : (
              <div className="space-y-3">
                {sliceEvals.map((se: any, idx: number) => {
                  const isOpen = openAccordion === idx;
                  const val = se.malicious_probability;
                  const isMal = val >= 0.5;
                  
                  return (
                    <div key={idx} className="border border-border/80 bg-secondary/10">
                      <button
                        onClick={() => setOpenAccordion(isOpen ? null : idx)}
                        className="w-full flex items-center justify-between p-3.5 hover:bg-secondary/40 transition-colors text-left focus:outline-none"
                      >
                        <div className="flex items-center gap-3">
                          <span className="text-xs font-bold text-foreground">
                            Slice {se.slice_index || idx + 1}
                          </span>
                          <span className={`text-[10px] px-2 py-0.5 font-bold border ${
                            isMal 
                              ? 'bg-destructive/10 text-destructive border-destructive/20' 
                              : 'bg-emerald-500/10 text-emerald-500 border-emerald-500/20'
                          }`}>
                            {(val * 100).toFixed(1)}% Threat
                          </span>
                        </div>
                        <ChevronDown className={`w-3.5 h-3.5 text-muted-foreground transition-transform duration-200 ${isOpen ? 'rotate-180' : ''}`} />
                      </button>
                      
                      {isOpen && (
                        <div className="px-3.5 pb-3.5 pt-0 animate-in slide-in-from-top-2 fade-in duration-200">
                          <div className="bg-[#09090b] border border-border p-3 overflow-x-auto">
                            <pre className="text-xs leading-relaxed font-mono text-zinc-300 whitespace-pre-wrap break-all">
                              <code>{renderHighlightedCode(se.code_snippet, se.relevance_tokens)}</code>
                            </pre>
                          </div>
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        </div>

      </div>

    </div>
  );
};

export default BertClassifierView;
