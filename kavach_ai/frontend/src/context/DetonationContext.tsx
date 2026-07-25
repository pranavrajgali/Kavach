import React, { createContext, useContext, useState, useEffect } from 'react';

export interface ApkDetails {
  name: string;
  size: string;
  package: string;
}

export interface NetworkConnection {
  ip: string;
  port: number;
  protocol: 'TCP' | 'UDP';
}

export interface EbpfTelemetry {
  syscalls: string[];
  files_accessed: string[];
  network_connections: NetworkConnection[];
}

export interface TelemetryPayload {
  objection_root_bypass: boolean;
  objection_ssl_pinning_bypass: boolean;
  ebpf_telemetry: EbpfTelemetry;
  native_libraries?: string[];
}

interface DetonationContextType {
  status: 'landing' | 'analyzing' | 'completed' | 'error';
  currentView: 'dashboard' | 'scorecard';
  apkDetails: ApkDetails | null;
  logs: string[];
  telemetry: TelemetryPayload | null;
  simulationMode: boolean;
  isAdbConnected: boolean;
  setSimulationMode: (mode: boolean) => void;
  setCurrentView: (view: 'dashboard' | 'scorecard') => void;
  viewScorecard: () => void;
  viewDashboard: () => void;
  loadRecentScan: () => Promise<void>;
  detonate: (file: File) => Promise<void>;
  reset: () => void;
}

const DetonationContext = createContext<DetonationContextType | undefined>(undefined);

export const DetonationProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [status, setStatus] = useState<DetonationContextType['status']>('landing');
  const [currentView, setCurrentView] = useState<'dashboard' | 'scorecard'>('dashboard');
  const [apkDetails, setApkDetails] = useState<ApkDetails | null>(null);
  const [logs, setLogs] = useState<string[]>([]);
  const [telemetry, setTelemetry] = useState<TelemetryPayload | null>(null);
  const [simulationMode, setSimulationMode] = useState<boolean>(false);
  const [isAdbConnected, setIsAdbConnected] = useState<boolean>(true);

  // Poll for emulator connection status on mount (simple mock)
  useEffect(() => {
    // Under typical local setups, Genymotion ADB interface is connected.
    // Set isAdbConnected based on static state or simulation mode
    setIsAdbConnected(true);
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
    setStatus('landing');
    setCurrentView('dashboard');
    setApkDetails(null);
    setLogs([]);
    setTelemetry(null);
  };

  const detonate = async (file: File) => {
    setStatus('analyzing');
    setCurrentView('dashboard');
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
      const response = await fetch(`/api/detonate-stream?simulation=${simulationMode}`, {
        method: 'POST',
        body: formData,
      });

      if (!response.body) {
        throw new Error('Readable stream not supported on response.');
      }

      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      let buffer = '';

      while (true) {
        const { value, done } = await reader.read();
        if (done) break;

        buffer += decoder.decode(value, { stream: true });
        const parts = buffer.split('\n\n');
        
        // Keep the last partial event in the buffer
        buffer = parts.pop() || '';

        for (const part of parts) {
          const line = part.trim();
          if (!line.startsWith('data: ')) continue;
          
          try {
            const rawData = line.slice(6);
            const data = JSON.parse(rawData);

            if (data.type === 'log') {
              setLogs((prev) => [...prev, data.message]);
            } else if (data.type === 'metadata') {
              setApkDetails(data.apk_details);
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
    } catch (err: any) {
      console.error('SSE connection error:', err);
      setLogs((prev) => [...prev, `[Connection Error] Failed to stream telemetry: ${err.message}`]);
      setStatus('error');
    }
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
        setCurrentView,
        viewScorecard,
        viewDashboard,
        loadRecentScan,
        detonate,
        reset,
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
