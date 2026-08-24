import React, { useState, useEffect, useRef } from 'react';
import { useDetonation } from '@/context/DetonationContext';
import { 
  Bot, Send, Square, X, ChevronUp, 
  RotateCcw, Copy, Check
} from 'lucide-react';
import { MarkdownRenderer } from '@/components/ui/markdown-renderer';

export const VajraAssistantDrawer: React.FC = () => {
  const { 
    apkDetails, 
    staticResults, 
    ragMessages,
    sendRagQuery,
    isRagStreaming,
    abortRagStream,
    clearRagSession
  } = useDetonation();

  const [isOpen, setIsOpen] = useState(false);
  const [inputQuery, setInputQuery] = useState('');
  const [copiedId, setCopiedId] = useState<string | null>(null);

  const messagesEndRef = useRef<HTMLDivElement>(null);

  const activePackage = apkDetails?.package || staticResults?.apk_details?.package || "com.shinhan.three";

  useEffect(() => {
    if (isOpen) {
      messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
    }
  }, [ragMessages, isOpen, isRagStreaming]);

  const handleSend = (queryText?: string) => {
    const textToSend = (queryText || inputQuery).trim();
    if (!textToSend || isRagStreaming) return;
    setInputQuery('');
    sendRagQuery(textToSend);
  };

  const copyToClipboard = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const quickChips = [
    "Explain C2 communication",
    "Trace SMS exfiltration",
    "Show Frida decrypted strings"
  ];

  return (
    <div className="fixed bottom-6 right-6 z-50 flex flex-col items-end">
      
      {/* Floating Trigger Button (when closed) */}
      {!isOpen && (
        <button
          onClick={() => setIsOpen(true)}
          className="flex items-center gap-2.5 px-4 py-3 border border-primary/50 bg-card/90 backdrop-blur text-foreground hover:border-primary shadow-2xl transition-all cursor-pointer group"
        >
          <div className="p-1 border border-primary/40 bg-primary/10 text-primary">
            <Bot className="w-4 h-4" />
          </div>
          <div className="text-left">
            <div className="text-xs font-bold text-foreground flex items-center gap-1.5">
              <span>RAG Agent</span>
              <span className="text-[8px] bg-primary/20 text-primary px-1 font-mono uppercase">VAJRA</span>
            </div>
            <div className="text-[9px] text-muted-foreground">Ask questions on active scan</div>
          </div>
          <ChevronUp className="w-3.5 h-3.5 text-muted-foreground group-hover:text-foreground transition-all ml-1" />
        </button>
      )}

      {/* Expandable Glassmorphism Drawer (when open) */}
      {isOpen && (
        <div className="w-[460px] h-[580px] border border-border bg-card/95 backdrop-blur-xl shadow-2xl flex flex-col overflow-hidden animate-in fade-in slide-in-from-bottom-5 duration-200 rounded-none">
          
          {/* Header */}
          <div className="p-3.5 border-b border-border bg-background/80 flex items-center justify-between">
            <div className="flex items-center gap-2.5">
              <div className="p-1 border border-primary/40 bg-primary/10 text-primary">
                <Bot className="w-4 h-4" />
              </div>
              <div>
                <div className="flex items-center gap-2">
                  <span className="text-xs font-bold text-foreground">RAG Agent</span>
                  <span className="text-[8px] font-mono bg-primary/20 text-primary px-1 uppercase">VAJRA HYBRID</span>
                </div>
                <div className="text-[10px] text-muted-foreground font-mono truncate max-w-[200px]">
                  {activePackage}
                </div>
              </div>
            </div>

            <div className="flex items-center gap-1.5">
              <button
                onClick={clearRagSession}
                className="p-1 text-muted-foreground hover:text-foreground hover:bg-secondary transition-all cursor-pointer"
                title="Clear Chat"
              >
                <RotateCcw className="w-3.5 h-3.5" />
              </button>
              <button
                onClick={() => setIsOpen(false)}
                className="p-1 text-muted-foreground hover:text-foreground hover:bg-secondary transition-all cursor-pointer"
                title="Close Drawer"
              >
                <X className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>

          {/* Messages Body */}
          <div className="flex-1 overflow-y-auto p-3.5 space-y-3 min-h-0 text-xs">
            {ragMessages.map((msg) => (
              <div
                key={msg.id}
                className={`flex gap-2.5 ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}
              >
                {msg.role === 'assistant' && (
                  <div className="w-6 h-6 shrink-0 border border-primary/40 bg-primary/10 text-primary flex items-center justify-center font-bold text-[9px]">
                    V
                  </div>
                )}

                <div
                  className={`max-w-[88%] p-3 border text-xs leading-relaxed ${
                    msg.role === 'user'
                      ? 'border-primary/40 bg-primary/10 text-foreground font-medium'
                      : 'border-border bg-background text-foreground'
                  }`}
                >
                  <div className="flex items-center justify-between gap-2 pb-1.5 mb-1.5 border-b border-border/30 text-[9px] text-muted-foreground">
                    <span className="font-semibold">{msg.role === 'user' ? 'You' : 'Vajra AI'}</span>
                    <div className="flex items-center gap-1.5">
                      <span>{msg.timestamp}</span>
                      <button
                        onClick={() => copyToClipboard(msg.content, msg.id)}
                        className="hover:text-foreground cursor-pointer"
                      >
                        {copiedId === msg.id ? <Check className="w-2.5 h-2.5 text-emerald-400" /> : <Copy className="w-2.5 h-2.5" />}
                      </button>
                    </div>
                  </div>

                  {/* Message Content Rendered via MarkdownRenderer */}
                  <MarkdownRenderer content={msg.content} />
                </div>

                {msg.role === 'user' && (
                  <div className="w-6 h-6 shrink-0 border border-border bg-secondary text-foreground flex items-center justify-center font-bold text-[9px]">
                    U
                  </div>
                )}
              </div>
            ))}
            <div ref={messagesEndRef} />
          </div>

          {/* Quick Prompt Chips */}
          <div className="p-2 border-t border-border bg-background/50 flex items-center gap-1.5 overflow-x-auto">
            {quickChips.map((chip, idx) => (
              <button
                key={idx}
                onClick={() => handleSend(chip)}
                disabled={isRagStreaming}
                className="shrink-0 text-[10px] px-2 py-0.5 border border-border bg-card hover:bg-secondary text-muted-foreground hover:text-foreground transition-all cursor-pointer disabled:opacity-50"
              >
                {chip}
              </button>
            ))}
          </div>

          {/* Input Bar */}
          <div className="p-2.5 border-t border-border bg-background">
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
                placeholder={isRagStreaming ? "Synthesizing..." : "Ask Vajra about active findings..."}
                disabled={isRagStreaming}
                className="flex-1 bg-card border border-border px-3 py-2 text-xs text-foreground placeholder:text-muted-foreground focus:outline-none focus:border-primary transition-all font-sans"
              />

              {isRagStreaming ? (
                <button
                  type="button"
                  onClick={abortRagStream}
                  className="px-3 py-2 border border-red-500/40 bg-red-500/10 text-red-400 text-xs font-semibold hover:bg-red-500/20 transition-all cursor-pointer"
                >
                  <Square className="w-3 h-3 fill-red-400" />
                </button>
              ) : (
                <button
                  type="submit"
                  disabled={!inputQuery.trim()}
                  className="px-3 py-2 border border-primary bg-primary text-primary-foreground text-xs font-semibold hover:bg-primary/90 transition-all cursor-pointer disabled:opacity-50"
                >
                  <Send className="w-3 h-3" />
                </button>
              )}
            </form>
          </div>

        </div>
      )}

    </div>
  );
};
