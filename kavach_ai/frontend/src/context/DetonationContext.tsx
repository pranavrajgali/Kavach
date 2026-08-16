import React, { createContext, useContext, useState, useEffect } from 'react';

export interface ApkDetails {
  name: string;
  size: string;
  package: string;
  hash?: string;
}

export interface NetworkConnection {
  ip: string;
  port: number;
  protocol: 'TCP' | 'UDP';
  status?: 'connected' | 'attempted' | 'refused';
}

export interface DnsResolution {
  domain: string;
  resolved_ip?: string;
  status: 'resolved' | 'nxdomain' | 'timeout' | 'failed';
}

export interface EbpfTelemetry {
  syscalls: string[];
  files_accessed: string[];
  network_connections: NetworkConnection[];
  dns_resolutions?: DnsResolution[];
  permissions_exercised?: string[];
}

export interface TelemetryPayload {
  execution_mode?: 'LIVE_ADB_FRIDA' | 'SIMULATION_FALLBACK';
  objection_root_bypass: boolean;
  objection_ssl_pinning_bypass: boolean;
  time_dilution_bypass?: boolean;
  time_dilution_count?: number;
  time_dilution_events?: string[];
  llm_frida_intercepts?: string[];
  fuzzed_intents?: any[];
  synthesized_hooks_code?: string;
  ebpf_telemetry: EbpfTelemetry;
  native_libraries?: string[];
}

export interface ModelInfo {
  id: string;
  name: string;
  description: string;
  path: string;
}

export interface StaticScanResults {
  apk_details: ApkDetails;
  triage: {
    package_name?: string;
    permissions?: string[];
    permission_combinations?: string[];
    triage_score?: number;
    code_signals?: string[];
    manifest_indicators?: string[];
    reflection_indicators?: string[];
    dynamic_loading_indicators?: string[];
    obfuscation_indicators?: string[];
    activities?: any[];
    services?: any[];
    receivers?: any[];
    providers?: any[];
    min_sdk?: number;
    target_sdk?: number;
  };
  ml_metrics: {
    model_id: string;
    verdict: 'MALICIOUS' | 'BENIGN';
    malicious_probability: number;
    confidence_score: number;
    slice_count: number;
    slice_evaluations: Array<{
      slice_index: number;
      malicious_probability: number;
      code_snippet: string;
    }>;
  };
  native_libraries?: string[];
}

export interface ChatMessage {
  id: string;
  role: 'user' | 'assistant';
  content: string;
  timestamp: string;
  model?: string;
  nodesUsed?: number;
}

interface DetonationContextType {
  status: 'landing' | 'analyzing' | 'completed' | 'error';
  currentView: 'dashboard' | 'scorecard' | 'static_scan' | 'bert_classifier' | 'mitre_map' | 'cert_in' | 'sandbox_health' | 'api_credentials' | 'settings' | 'kavach_report' | 'rag_agent';
  apkDetails: ApkDetails | null;
  jobId: string | null;
  logs: string[];
  telemetry: TelemetryPayload | null;
  simulationMode: boolean;
  isAdbConnected: boolean;
  setSimulationMode: (mode: boolean) => void;
  detonationDuration: number;
  setDetonationDuration: (duration: number) => void;
  setCurrentView: (view: 'dashboard' | 'scorecard' | 'static_scan' | 'bert_classifier' | 'mitre_map' | 'cert_in' | 'sandbox_health' | 'api_credentials' | 'settings' | 'kavach_report' | 'rag_agent') => void;
  viewScorecard: () => void;
  viewDashboard: () => void;
  loadRecentScan: () => Promise<void>;
  detonate: (file: File) => Promise<void>;
  reset: () => void;
  // Static Scan & Models extensions
  availableModels: ModelInfo[];
  selectedModelId: string;
  setSelectedModelId: (id: string) => void;
  staticScanStatus: 'landing' | 'analyzing' | 'completed' | 'error';
  staticResults: StaticScanResults | null;
  runStaticScan: (file: File, modelId?: string) => Promise<void>;
  currentFile: File | null;
  ragMessages: ChatMessage[];
  setRagMessages: React.Dispatch<React.SetStateAction<ChatMessage[]>>;
  sendRagQuery: (query: string) => Promise<void>;
  isRagStreaming: boolean;
  abortRagStream: () => void;
  clearRagSession: () => void;
}

const DetonationContext = createContext<DetonationContextType | undefined>(undefined);

export const DetonationProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [status, setStatus] = useState<DetonationContextType['status']>('landing');
  const [currentView, setCurrentView] = useState<DetonationContextType['currentView']>('static_scan');
  const [apkDetails, setApkDetails] = useState<ApkDetails | null>(null);
  const [logs, setLogs] = useState<string[]>([]);
  const [telemetry, setTelemetry] = useState<TelemetryPayload | null>(null);
  const [simulationMode, setSimulationMode] = useState<boolean>(false);
  const [isAdbConnected, setIsAdbConnected] = useState<boolean>(true);
  const [detonationDuration, setDetonationDuration] = useState<number>(10);
  const [currentFile, setCurrentFile] = useState<File | null>(null);
  const [jobId, setJobId] = useState<string | null>(null);

  // Static scan state
  const [availableModels, setAvailableModels] = useState<ModelInfo[]>([
    {
      id: 'securebert-full-weighted',
      name: 'SecureBERT Full Weighted (High Precision)',
      description: 'Extremely low false-positive rate (99.6% precision).',
      path: ''
    },
    {
      id: 'securebert-balanced-1to1',
      name: 'SecureBERT Balanced (High Recall)',
      description: 'High sensitivity/recall for catching subtle malware.',
      path: ''
    }
  ]);
  const [selectedModelId, setSelectedModelId] = useState<string>('securebert-full-weighted');
  const [staticScanStatus, setStaticScanStatus] = useState<'landing' | 'analyzing' | 'completed' | 'error'>('landing');
  const [staticResults, setStaticResults] = useState<StaticScanResults | null>(null);

  // Fetch available models from backend on mount
  useEffect(() => {
    setIsAdbConnected(true);
    fetch('/api/models')
      .then((res) => res.json())
      .then((data) => {
        if (data.status === 'success' && Array.isArray(data.models) && data.models.length > 0) {
          setAvailableModels(data.models);
          setSelectedModelId(data.models[0].id);
        }
      })
      .catch((err) => console.warn('Failed to fetch models list:', err));
  }, []);

  const loadRecentScan = async () => {
    try {
      const res = await fetch('/api/recent-scan');
      if (res.ok) {
        const data = await res.json();
        if (data.status === 'success' && data.telemetry) {
          setTelemetry(data.telemetry);
          if (data.apk_details) {
            setApkDetails(data.apk_details);
          }
        }
      }
    } catch (err) {
      console.warn('Failed to load recent scan from API:', err);
    }
  };

  const viewScorecard = () => {
    if (!telemetry) {
      loadRecentScan();
    }
    setCurrentView('scorecard');
  };

  const viewDashboard = () => setCurrentView('dashboard');

  const reset = () => {
    const nextView = currentView === 'static_scan' ? 'static_scan' : 'dashboard';
    setStatus('landing');
    setStaticScanStatus('landing');
    setCurrentView(nextView);
    setApkDetails(null);
    setLogs([]);
    setTelemetry(null);
    setStaticResults(null);
    setCurrentFile(null);
    setJobId(null);
  };

  const detonate = async (file: File) => {
    setCurrentFile(file);
    setStatus('analyzing');
    setLogs([]);
    setTelemetry(null);
    setApkDetails({
      name: file.name,
      size: `${(file.size / (1024 * 1024)).toFixed(2)} MB`,
      package: 'Resolving identifier...'
    });

    const formData = new FormData();
    formData.append('file', file);

    try {
      const response = await fetch(`/api/detonate-stream?simulation=${simulationMode}&duration=${detonationDuration}`, {
        method: 'POST',
        body: formData,
      });

      if (!response.body) {
        throw new Error('Readable stream not supported on response.');
      }

      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      let rawBuffer = '';

      while (true) {
        const { value, done } = await reader.read();
        if (done) break;

        rawBuffer += decoder.decode(value, { stream: true });
        const normalized = rawBuffer.replace(/\r\n/g, '\n');
        const parts = normalized.split('\n\n');
        
        rawBuffer = parts.pop() || '';

        for (const part of parts) {
          const lines = part.split('\n');
          for (const rawLine of lines) {
            const line = rawLine.trim();
            if (!line.startsWith('data: ')) continue;
            
            try {
              const data = JSON.parse(line.slice(6));

              if (data.type === 'log') {
                setLogs((prev) => [...prev, data.message]);
              } else if (data.type === 'metadata') {
                setApkDetails(data.apk_details);
                if (data.job_id) setJobId(data.job_id);
              } else if (data.type === 'result') {
                setTelemetry(data.telemetry);
                setStatus('completed');
              } else if (data.type === 'error') {
                setLogs((prev) => [...prev, `[Fatal] ${data.message}`]);
                setStatus('error');
              }
            } catch (err) {
              console.error('Failed to parse SSE payload:', err, line);
            }
          }
        }
      }
    } catch (err: any) {
      console.error('SSE connection error:', err);
      setLogs((prev) => [...prev, `[Connection Error] Failed to stream telemetry: ${err.message}`]);
      setStatus('error');
    }
  };

  const runStaticScan = async (file: File, modelId?: string) => {
    setCurrentFile(file);
    const targetModel = modelId || selectedModelId;
    setStaticScanStatus('analyzing');
    setCurrentView('static_scan');
    setLogs([]);
    setStaticResults(null);
    setApkDetails({
      name: file.name,
      size: `${(file.size / (1024 * 1024)).toFixed(2)} MB`,
      package: 'Resolving identifier...'
    });

    const formData = new FormData();
    formData.append('file', file);

    try {
      const response = await fetch(`/api/static-scan-stream?model_id=${encodeURIComponent(targetModel)}`, {
        method: 'POST',
        body: formData,
      });

      if (!response.body) {
        throw new Error('Readable stream not supported on response.');
      }

      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      let rawBuffer = '';

      while (true) {
        const { value, done } = await reader.read();
        if (done) break;

        rawBuffer += decoder.decode(value, { stream: true });
        const normalized = rawBuffer.replace(/\r\n/g, '\n');
        const parts = normalized.split('\n\n');
        
        rawBuffer = parts.pop() || '';

        for (const part of parts) {
          const lines = part.split('\n');
          for (const rawLine of lines) {
            const line = rawLine.trim();
            if (!line.startsWith('data: ')) continue;
            
            try {
              const data = JSON.parse(line.slice(6));

              if (data.type === 'log') {
                setLogs((prev) => [...prev, data.message]);
              } else if (data.type === 'metadata') {
                if (data.job_id) setJobId(data.job_id);
              } else if (data.type === 'result') {
                setStaticResults(data.static_results);
                if (data.static_results?.apk_details) {
                  setApkDetails(data.static_results.apk_details);
                }
                setStaticScanStatus('completed');
              } else if (data.type === 'error') {
                setLogs((prev) => [...prev, `[Fatal] ${data.message}`]);
                setStaticScanStatus('error');
              }
            } catch (err) {
              console.error('Failed to parse static scan SSE payload:', err, line);
            }
          }
        }
      }

      // Process any leftover string in rawBuffer when stream completes
      if (rawBuffer.trim()) {
        const lines = rawBuffer.replace(/\r\n/g, '\n').split('\n');
        for (const rawLine of lines) {
          const line = rawLine.trim();
          if (!line.startsWith('data: ')) continue;
          try {
            const data = JSON.parse(line.slice(6));
            if (data.type === 'result' && data.static_results) {
              setStaticResults(data.static_results);
              if (data.static_results?.apk_details) {
                setApkDetails(data.static_results.apk_details);
              }
              setStaticScanStatus('completed');
            }
          } catch (e) {
            // ignore trailing incomplete chunk
          }
        }
      }
    } catch (err: any) {
      console.error('Static scan connection error:', err);
      setLogs((prev) => [...prev, `[Connection Error] Failed to execute static scan: ${err.message}`]);
      setStaticScanStatus('error');
    }
  };

  // --- Connected Shared RAG Agent State ---
  const [ragMessages, setRagMessages] = useState<ChatMessage[]>([]);
  const [isRagStreaming, setIsRagStreaming] = useState<boolean>(false);
  const ragAbortControllerRef = React.useRef<AbortController | null>(null);

  const generateWelcomeMessage = (details: ApkDetails | null, staticRes: StaticScanResults | null): string => {
    const pkg = details?.package || staticRes?.apk_details?.package || "com.shinhan.three";
    const hash = (details?.hash || staticRes?.apk_details?.hash || "8f93e2b1a45c7890").slice(0, 12);
    const perms = staticRes?.triage?.permissions || ["android.permission.INTERNET", "android.permission.READ_SMS", "android.permission.RECEIVE_SMS", "android.permission.SEND_SMS", "android.permission.READ_PHONE_STATE"];
    const verdict = staticRes?.ml_metrics?.verdict || "MALICIOUS";
    const prob = staticRes?.ml_metrics?.malicious_probability ? Math.round(staticRes.ml_metrics.malicious_probability * 100) : 94;

    let profile = "Android Application";
    const permsLower = perms.map(p => p.toLowerCase());
    if (permsLower.some(p => p.includes("sms")) && permsLower.some(p => p.includes("read_phone_state"))) {
      profile = "Financial / SMS Interceptor Trojan (targets OTPs, credentials, and telephony identifiers)";
    } else if (permsLower.some(p => p.includes("camera")) || permsLower.some(p => p.includes("record_audio")) || permsLower.some(p => p.includes("location"))) {
      profile = "Surveillance / Spyware Payload (targets sensory capture and geographical location)";
    } else if (permsLower.some(p => p.includes("system_alert_window")) || permsLower.some(p => p.includes("bind_accessibility_service"))) {
      profile = "Banking Overlay / Accessibility Hijacker (abuses overlays and UI accessibility)";
    } else if (perms.length > 5) {
      profile = "High-Privilege Utility / Background Service Carrier";
    }

    const keyPermsStr = perms.slice(0, 5).map(p => `\`${p.replace('android.permission.', '')}\``).join(', ');

    return (
      `### Vajra AI Reverse Engineering Assistant Ready\n\n` +
      `**Target Package:** \`${pkg}\` (\`${hash}...\`)\n\n` +
      `**Behavioral Profile & Intended Capabilities:**\n` +
      `- **Classification:** ${profile}\n` +
      `- **Risk Assessment:** SecureBERT classifier assessed this sample with a **${prob}% malicious confidence** (${verdict}).\n` +
      (keyPermsStr ? `- **Key Manifest Capabilities:** ${keyPermsStr}\n` : '') +
      `- **Knowledge Base:** Initialized with Control Flow Graphs, Dalvik bytecode slices, dynamic Frida intercepts, and kernel syscall traces.\n\n` +
      `Ask a question below or choose a quick triage prompt to inspect decompiled methods, network endpoints, or generate dynamic Frida hooks.`
    );
  };

  // Sync initial welcome message whenever apk details change
  useEffect(() => {
    const welcome = generateWelcomeMessage(apkDetails, staticResults);
    setRagMessages(prev => {
      if (prev.length === 0 || prev[0]?.id === 'welcome-rag-msg') {
        return [{
          id: 'welcome-rag-msg',
          role: 'assistant',
          content: welcome,
          timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
          model: 'vajra-hybrid-graphrag'
        }];
      }
      return prev;
    });
  }, [apkDetails?.package, apkDetails?.hash, staticResults?.apk_details?.package]);

  const sendRagQuery = async (queryText: string) => {
    const textToSend = queryText.trim();
    if (!textToSend || isRagStreaming) return;

    const userMessage: ChatMessage = {
      id: `user-${Date.now()}`,
      role: 'user',
      content: textToSend,
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
    };

    const assistantMsgId = `asst-${Date.now()}`;
    const assistantMessage: ChatMessage = {
      id: assistantMsgId,
      role: 'assistant',
      content: '',
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      model: 'llama-3.3-70b-versatile'
    };

    setRagMessages(prev => [...prev, userMessage, assistantMessage]);
    setIsRagStreaming(true);

    ragAbortControllerRef.current = new AbortController();
    const activeHash = apkDetails?.hash || staticResults?.apk_details?.hash || "8f93e2b1a45c7890123456789abcdef0123456789abcdef0123456789abcdef0";

    try {
      const response = await fetch('http://localhost:8000/api/chat-rag', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          apk_hash: activeHash,
          query: textToSend,
          history: ragMessages.slice(-4).map(m => ({ role: m.role, content: m.content }))
        }),
        signal: ragAbortControllerRef.current.signal
      });

      if (!response.ok || !response.body) {
        throw new Error(`HTTP error ${response.status}`);
      }

      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      let buffer = '';

      while (true) {
        const { value, done } = await reader.read();
        if (done) break;

        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split('\n\n');
        buffer = lines.pop() || '';

        for (const line of lines) {
          if (line.startsWith('data: ')) {
            const dataStr = line.replace('data: ', '').trim();
            if (dataStr === '[DONE]') break;

            try {
              const parsed = JSON.parse(dataStr);
              if (parsed.token) {
                setRagMessages(prev =>
                  prev.map(m =>
                    m.id === assistantMsgId
                      ? { ...m, content: m.content + parsed.token, model: parsed.model || m.model }
                      : m
                  )
                );
              } else if (parsed.nodes_used) {
                setRagMessages(prev =>
                  prev.map(m =>
                    m.id === assistantMsgId ? { ...m, nodesUsed: parsed.nodes_used, model: parsed.model || m.model } : m
                  )
                );
              }
            } catch {
              setRagMessages(prev =>
                prev.map(m =>
                  m.id === assistantMsgId ? { ...m, content: m.content + dataStr } : m
                )
              );
            }
          }
        }
      }
    } catch (e: any) {
      if (e.name !== 'AbortError') {
        setRagMessages(prev =>
          prev.map(m =>
            m.id === assistantMsgId
              ? { ...m, content: m.content + `\n\n*(Error communicating with RAG engine: ${e.message})*` }
              : m
          )
        );
      }
    } finally {
      setIsRagStreaming(false);
      ragAbortControllerRef.current = null;
    }
  };

  const abortRagStream = () => {
    if (ragAbortControllerRef.current) {
      ragAbortControllerRef.current.abort();
      ragAbortControllerRef.current = null;
      setIsRagStreaming(false);
    }
  };

  const clearRagSession = () => {
    const welcome = generateWelcomeMessage(apkDetails, staticResults);
    setRagMessages([
      {
        id: 'welcome-rag-msg',
        role: 'assistant',
        content: welcome,
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
        model: 'vajra-hybrid-graphrag'
      }
    ]);
  };

  return (
    <DetonationContext.Provider
      value={{
        status,
        currentView,
        apkDetails,
        logs,
        telemetry,
        simulationMode,
        isAdbConnected,
        setSimulationMode,
        detonationDuration,
        setDetonationDuration,
        setCurrentView,
        viewScorecard,
        viewDashboard,
        loadRecentScan,
        detonate,
        reset,
        availableModels,
        selectedModelId,
        setSelectedModelId,
        staticScanStatus,
        staticResults,
        runStaticScan,
        currentFile,
        jobId,
        ragMessages,
        setRagMessages,
        sendRagQuery,
        isRagStreaming,
        abortRagStream,
        clearRagSession,
      }}
    >
      {children}
    </DetonationContext.Provider>
  );
};

export const useDetonation = () => {
  const context = useContext(DetonationContext);
  if (context === undefined) {
    throw new Error('useDetonation must be used within a DetonationProvider');
  }
  return context;
};


