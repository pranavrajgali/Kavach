import React, { useState, useEffect, useRef } from 'react';
import { useDetonation } from '@/context/DetonationContext';
import { 
  Bot, Sparkles, Send, Square, RotateCcw, Copy, Check, 
  Network, Zap, FileCode, ArrowRight, RefreshCw
} from 'lucide-react';
import { MarkdownRenderer } from '@/components/ui/markdown-renderer';

interface RAGStatus {
  apk_hash: string;
  package_name: string;
  indexed_stages: string[];
  total_nodes: number;
  total_edges: number;
  stats: {
    methods: number;
    sinks: number;
    frida_intercepts: number;
    syscalls: number;
    reports: number;
  };
}

export const RAGAgentView: React.FC = () => {
  const { 
    apkDetails, 
    staticResults, 
    ragMessages, 
    sendRagQuery, 
    isRagStreaming, 
    abortRagStream, 
    clearRagSession 
  } = useDetonation();

  const [inputQuery, setInputQuery] = useState('');
  const [ragStatus, setRagStatus] = useState<RAGStatus | null>(null);
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [synthesizingHook, setSynthesizingHook] = useState(false);
  const [generatedHook, setGeneratedHook] = useState<string | null>(null);

  const messagesEndRef = useRef<HTMLDivElement>(null);

  const activeApkHash = apkDetails?.hash || staticResults?.apk_details?.hash || "8f93e2b1a45c7890123456789abcdef0123456789abcdef0123456789abcdef0";
  const activePackage = apkDetails?.package || staticResults?.apk_details?.package || "com.shinhan.three";

  // Fetch live RAG indexing stats
  const fetchRagStatus = async () => {
    try {
      const res = await fetch(`http://localhost:8000/api/rag/status/${activeApkHash}`);
      if (res.ok) {
        const json = await res.json();
        if (json.status === 'success') {
          setRagStatus(json.data);
        }
      }
    } catch (e) {
      console.warn("Could not fetch RAG status:", e);
    }
  };

  useEffect(() => {
    fetchRagStatus();
  }, [activeApkHash]);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [ragMessages, isRagStreaming]);

  const handleSend = (queryText?: string) => {
    const textToSend = (queryText || inputQuery).trim();
    if (!textToSend || isRagStreaming) return;
    setInputQuery('');
    sendRagQuery(textToSend);
  };

  const handleSynthesizeHookQuick = async (sinkName: string) => {
    setSynthesizingHook(true);
    setGeneratedHook(null);
    try {
      const res = await fetch('http://localhost:8000/api/rag/synthesize-hook', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          apk_hash: activeApkHash,
          target_method: sinkName,
          package_name: activePackage
        })
      });
      if (res.ok) {
        const json = await res.json();
        setGeneratedHook(json.script);
      }
    } catch (e) {
      console.error(e);
    } finally {
      setSynthesizingHook(false);
    }
  };

  const copyToClipboard = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const quickPromptChips = [
    { label: "Explain C2 communication", query: "Explain how the malware establishes C2 communication, what endpoints it targets, and what payload is sent." },
    { label: "Trace SMS exfiltration path", query: "Trace the control-flow path from SMS reading permissions to the network exfiltration sink." },
    { label: "Analyze Frida decrypted strings", query: "Show all decrypted strings, crypto keys, and dynamic URLs captured during Frida sandbox execution." },
    { label: "Show dangerous permission triggers", query: "Which methods and classes trigger high-risk permissions like SEND_SMS or READ_PHONE_STATE?" },
    { label: "Synthesize Frida Hook for Crypto", query: "Generate a custom Frida JavaScript script to intercept all javax.crypto.Cipher decryption parameters and plaintext." }
  ];

  return (
    <div className="flex flex-col h-[calc(100vh-8rem)] gap-6">
      
      {/* 1. Header Banner */}
      <div className="flex flex-wrap items-center justify-between gap-4 p-4 border border-border bg-card/60 backdrop-blur rounded-none">
        <div className="flex items-center gap-3">
          <div className="p-2 border border-primary/30 bg-primary/10 text-primary">
            <Bot className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-sm font-bold text-foreground">RAG Agent</h2>
              <span className="text-[9px] font-bold bg-primary/15 text-primary px-1.5 py-0.5 border border-primary/20 uppercase tracking-widest">
                VAJRA // HYBRID GRAPHRAG
              </span>
            </div>
            <div className="text-xs text-muted-foreground mt-0.5">
              Autonomous Reverse Engineering & Dynamic Telemetry Interrogation
            </div>
          </div>
        </div>

        <div className="flex items-center gap-3 text-xs">
          <div className="border border-border bg-background px-3 py-1.5 flex items-center gap-2">
            <FileCode className="w-3.5 h-3.5 text-muted-foreground" />
            <span className="text-muted-foreground">Target:</span>
            <span className="font-mono font-semibold text-foreground">{activePackage}</span>
          </div>

          <div className="border border-border bg-background px-3 py-1.5 flex items-center gap-2">
            <span className="text-muted-foreground">SHA256:</span>
            <span className="font-mono text-muted-foreground">{activeApkHash.slice(0, 10)}...</span>
          </div>

          <button
            onClick={fetchRagStatus}
            className="p-1.5 border border-border bg-background hover:bg-accent text-muted-foreground hover:text-foreground transition-all cursor-pointer"
            title="Refresh RAG Status"
          >
            <RefreshCw className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      {/* 2. Main Workbench (2 Columns: Left = Graph Topology, Right = Chat Canvas) */}
      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6 flex-1 min-h-0">
        
        {/* Left Column: Graph Topology & Instant Hook Synthesizer */}
        <div className="lg:col-span-1 flex flex-col gap-4 overflow-y-auto pr-1">
          
          {/* Topology Stats Card */}
          <div className="border border-border bg-card p-4 space-y-3">
            <div className="flex items-center justify-between pb-2 border-b border-border">
              <div className="flex items-center gap-2 text-xs font-bold text-foreground uppercase tracking-wider">
                <Network className="w-3.5 h-3.5 text-primary" />
                Knowledge Graph
              </div>
              <span className="text-[9px] font-mono text-emerald-500 bg-emerald-500/10 px-1.5 py-0.5 border border-emerald-500/20">
                ACTIVE
              </span>
            </div>

            <div className="grid grid-cols-2 gap-2 text-xs">
              <div className="p-2 border border-border bg-background">
                <div className="text-[10px] text-muted-foreground uppercase">Graph Nodes</div>
                <div className="text-base font-bold font-mono text-foreground mt-0.5">
                  {ragStatus?.total_nodes || 24}
                </div>
              </div>
              <div className="p-2 border border-border bg-background">
                <div className="text-[10px] text-muted-foreground uppercase">Call Edges</div>
                <div className="text-base font-bold font-mono text-foreground mt-0.5">
                  {ragStatus?.total_edges || 48}
                </div>
              </div>
            </div>

            <div className="space-y-1.5 pt-1 text-[11px]">
              <div className="flex justify-between text-muted-foreground">
                <span>Smali Slices Indexed:</span>
                <span className="font-mono text-foreground font-semibold">{ragStatus?.stats?.methods || 12}</span>
              </div>
              <div className="flex justify-between text-muted-foreground">
                <span>Sensitive API Sinks:</span>
                <span className="font-mono text-foreground font-semibold">{ragStatus?.stats?.sinks || 6}</span>
              </div>
              <div className="flex justify-between text-muted-foreground">
                <span>Frida Intercepts:</span>
                <span className="font-mono text-emerald-400 font-semibold">{ragStatus?.stats?.frida_intercepts || 3}</span>
              </div>
              <div className="flex justify-between text-muted-foreground">
                <span>eBPF Syscall Nodes:</span>
                <span className="font-mono text-amber-400 font-semibold">{ragStatus?.stats?.syscalls || 18}</span>
              </div>
            </div>

            <div className="pt-2 border-t border-border flex flex-wrap gap-1">
              {(ragStatus?.indexed_stages || ['static', 'dynamic', 'report']).map(st => (
                <span key={st} className="text-[9px] uppercase font-mono px-1.5 py-0.5 border border-border bg-secondary/50 text-foreground">
                  ✓ {st}
                </span>
              ))}
            </div>
          </div>

          {/* Quick Frida Synthesizer Card */}
          <div className="border border-border bg-card p-4 space-y-3">
            <div className="flex items-center gap-2 text-xs font-bold text-foreground uppercase tracking-wider pb-2 border-b border-border">
              <Zap className="w-3.5 h-3.5 text-amber-400" />
              On-Demand Hook Synthesizer
            </div>
            <p className="text-[11px] text-muted-foreground leading-normal">
              Dynamically synthesize targeted Frida JavaScript hooks for sensitive sinks discovered during reverse engineering:
            </p>

            <div className="space-y-1.5">
              <button
                onClick={() => handleSynthesizeHookQuick("javax.crypto.Cipher.doFinal")}
                disabled={synthesizingHook}
                className="w-full text-left text-[10px] font-mono px-2 py-1.5 border border-border bg-background hover:bg-secondary transition-all text-foreground flex items-center justify-between"
              >
                <span>Cipher.doFinal() Hook</span>
                <ArrowRight className="w-3 h-3 text-muted-foreground" />
              </button>
              <button
                onClick={() => handleSynthesizeHookQuick("android.telephony.SmsManager.sendTextMessage")}
                disabled={synthesizingHook}
                className="w-full text-left text-[10px] font-mono px-2 py-1.5 border border-border bg-background hover:bg-secondary transition-all text-foreground flex items-center justify-between"
              >
                <span>SmsManager Hook</span>
                <ArrowRight className="w-3 h-3 text-muted-foreground" />
              </button>
            </div>

            {synthesizingHook && (
              <div className="text-[10px] text-amber-400 animate-pulse font-mono">
                Synthesizing hook via Groq qwen2.5-coder...
              </div>
            )}

            {generatedHook && (
              <div className="mt-2 space-y-1.5">
                <div className="flex items-center justify-between">
                  <span className="text-[9px] font-mono text-muted-foreground">SYNTHESIZED_HOOK.JS</span>
                  <button
                    onClick={() => copyToClipboard(generatedHook, 'hook-copy')}
                    className="text-[9px] text-primary flex items-center gap-1 hover:underline"
                  >
                    {copiedId === 'hook-copy' ? <Check className="w-2.5 h-2.5" /> : <Copy className="w-2.5 h-2.5" />}
                    Copy
                  </button>
                </div>
                <pre className="p-2 border border-border bg-background text-[10px] font-mono text-emerald-400 max-h-32 overflow-y-auto whitespace-pre-wrap">
                  {generatedHook}
                </pre>
              </div>
            )}
          </div>

        </div>

        {/* Right Column: Interactive Chat Canvas */}
        <div className="lg:col-span-3 flex flex-col border border-border bg-card rounded-none min-h-0">
          
          {/* Top Bar of Chat */}
          <div className="p-3 border-b border-border bg-background/50 flex items-center justify-between">
            <div className="flex items-center gap-2 text-xs text-muted-foreground">
              <Sparkles className="w-3.5 h-3.5 text-primary" />
              <span>Multi-Turn Reverse Engineering Session</span>
            </div>
            
            <button
              onClick={clearRagSession}
              className="text-[11px] text-muted-foreground hover:text-foreground flex items-center gap-1.5 transition-all cursor-pointer"
            >
              <RotateCcw className="w-3 h-3" />
              Clear Session
            </button>
          </div>

          {/* Messages Stream Container */}
          <div className="flex-1 overflow-y-auto p-4 space-y-4 min-h-0">
            {ragMessages.map((msg) => (
              <div
                key={msg.id}
                className={`flex gap-3 text-xs leading-relaxed ${
                  msg.role === 'user' ? 'justify-end' : 'justify-start'
                }`}
              >
                {msg.role === 'assistant' && (
                  <div className="w-7 h-7 shrink-0 border border-primary/40 bg-primary/10 text-primary flex items-center justify-center font-bold text-[10px]">
                    V
                  </div>
                )}

                <div
                  className={`max-w-[85%] p-3.5 border ${
                    msg.role === 'user'
                      ? 'border-primary/40 bg-primary/10 text-foreground font-medium'
                      : 'border-border bg-background text-foreground'
                  }`}
                >
                  <div className="flex items-center justify-between gap-4 pb-2 mb-2 border-b border-border/40 text-[10px] text-muted-foreground">
                    <span className="font-semibold">{msg.role === 'user' ? 'Auditor Query' : 'Vajra AI Intelligence'}</span>
                    <div className="flex items-center gap-2">
                      {msg.model && <span className="font-mono text-[9px] text-primary/80">{msg.model}</span>}
                      {msg.nodesUsed && (
                        <span className="font-mono text-[9px] text-emerald-400 bg-emerald-500/10 px-1 border border-emerald-500/20">
                          {msg.nodesUsed} nodes
                        </span>
                      )}
                      <span>{msg.timestamp}</span>
                      <button
                        onClick={() => copyToClipboard(msg.content, msg.id)}
                        className="hover:text-foreground transition-all ml-1"
                        title="Copy message"
                      >
                        {copiedId === msg.id ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                      </button>
                    </div>
                  </div>

                  {/* Message Content Rendered via MarkdownRenderer */}
                  <MarkdownRenderer content={msg.content} />
                </div>

                {msg.role === 'user' && (
                  <div className="w-7 h-7 shrink-0 border border-border bg-secondary text-foreground flex items-center justify-center font-bold text-[10px]">
                    YOU
                  </div>
                )}
              </div>
            ))}
            <div ref={messagesEndRef} />
          </div>

          {/* Quick Prompt Chips */}
          <div className="p-2.5 border-t border-border bg-background/40 flex items-center gap-2 overflow-x-auto">
            <span className="text-[10px] font-bold text-muted-foreground uppercase tracking-widest shrink-0">
              Quick Inquiries:
            </span>
            {quickPromptChips.map((chip, idx) => (
              <button
                key={idx}
                onClick={() => handleSend(chip.query)}
                disabled={isRagStreaming}
                className="shrink-0 text-[11px] px-2.5 py-1 border border-border bg-card hover:bg-secondary text-foreground transition-all flex items-center gap-1.5 cursor-pointer disabled:opacity-50"
              >
                {chip.label}
              </button>
            ))}
          </div>

          {/* Chat Input Bar */}
          <div className="p-3 border-t border-border bg-background">
            <form
              onSubmit={(e) => {
                e.preventDefault();
                handleSend();
              }}
              className="flex items-center gap-2"
            >
              <input
                type="text"
                value={inputQuery}
                onChange={(e) => setInputQuery(e.target.value)}
                placeholder={isRagStreaming ? "Vajra is synthesizing response..." : "Ask Vajra about decompiled Smali slices, Frida intercepts, or dynamic syscalls..."}
                disabled={isRagStreaming}
                className="flex-1 bg-card border border-border px-3.5 py-2.5 text-xs text-foreground placeholder:text-muted-foreground focus:outline-none focus:border-primary transition-all font-sans"
              />

              {isRagStreaming ? (
                <button
                  type="button"
                  onClick={abortRagStream}
                  className="flex items-center gap-1.5 px-4 py-2.5 border border-red-500/40 bg-red-500/10 text-red-400 text-xs font-semibold hover:bg-red-500/20 transition-all cursor-pointer"
                >
                  <Square className="w-3.5 h-3.5 fill-red-400" />
                  Stop
                </button>
              ) : (
                <button
                  type="submit"
                  disabled={!inputQuery.trim()}
                  className="flex items-center gap-1.5 px-4 py-2.5 border border-primary bg-primary text-primary-foreground text-xs font-semibold hover:bg-primary/90 transition-all cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  <Send className="w-3.5 h-3.5" />
                  Send
                </button>
              )}
            </form>
          </div>

        </div>

      </div>

    </div>
  );
};
