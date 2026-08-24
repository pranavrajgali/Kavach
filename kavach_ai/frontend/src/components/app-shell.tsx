import React from 'react';
import { useDetonation } from '@/context/DetonationContext';
import { 
  LayoutGrid, RefreshCw,
  FileCode, FileText, Award
} from 'lucide-react';
import { VajraAssistantDrawer } from '@/components/vajra-assistant-drawer';
import kavachLogo from '@/assets/kavach.png';

interface AppShellProps {
  children: React.ReactNode;
}

export const AppShell: React.FC<AppShellProps> = ({ children }) => {
  const { 
    status, staticScanStatus,
    simulationMode, setSimulationMode, isAdbConnected, reset, 
    currentView, viewScorecard, viewDashboard, setCurrentView,
    detonationDuration, setDetonationDuration
  } = useDetonation();

  return (
    <div className="flex h-screen overflow-hidden bg-background text-foreground font-sans selection:bg-primary/20">
      {/* 1. Left Fixed Sidebar */}
      <aside className="w-64 shrink-0 border-r border-border bg-card flex flex-col justify-between rounded-none overflow-y-auto max-h-screen scrollbar-thin">
        
        {/* Top Section */}
        <div>
          {/* Logo Section */}
          <div className="flex items-center gap-3 px-6 py-4 border-b border-border">
            <img 
              src={kavachLogo} 
              alt="Kavach Logo" 
              className="w-7 h-7 object-contain shrink-0 rounded"
            />
            <div>
              <h1 className="font-extrabold text-[15px] tracking-wide text-foreground font-['Plus_Jakarta_Sans',sans-serif] uppercase">
                Kavach
              </h1>
              <span className="text-[9px] text-muted-foreground block font-mono">SOC Forensic Detonator</span>
            </div>
          </div>

          {/* Navigation Options */}
          <div className="mt-6 px-4">
            <span className="text-[10px] font-bold text-muted-foreground uppercase tracking-widest px-3 block mb-2">
              Threat Analysis
            </span>
            <nav className="space-y-0.5">
              <button 
                onClick={() => setCurrentView('static_scan')}
                className={`w-full flex items-center gap-3 px-3 py-2 text-xs font-semibold transition-all text-left rounded-none cursor-pointer ${
                  currentView === 'static_scan'
                    ? 'bg-primary/10 text-primary border-r-2 border-primary'
                    : 'text-muted-foreground hover:text-foreground hover:bg-secondary/50'
                }`}
              >
                <FileCode className="w-3.5 h-3.5" />
                Static Analysis & ML
              </button>
              <button 
                onClick={viewDashboard}
                className={`w-full flex items-center gap-3 px-3 py-2 text-xs font-semibold transition-all text-left rounded-none cursor-pointer ${
                  currentView === 'dashboard'
                    ? 'bg-primary/10 text-primary border-r-2 border-primary'
                    : 'text-muted-foreground hover:text-foreground hover:bg-secondary/50'
                }`}
              >
                <LayoutGrid className="w-3.5 h-3.5" />
                Dynamic Sandbox
              </button>
            </nav>

            <span className="text-[10px] font-bold text-muted-foreground uppercase tracking-widest px-3 block mt-6 mb-2">
              Compliance & Auditing
            </span>
            <nav className="space-y-0.5">
              <button 
                onClick={viewScorecard}
                className={`w-full flex items-center justify-between px-3 py-2 text-xs font-semibold transition-all text-left rounded-none cursor-pointer ${
                  currentView === 'scorecard'
                    ? 'bg-primary/10 text-primary border-r-2 border-primary'
                    : 'text-muted-foreground hover:text-foreground hover:bg-secondary/50'
                }`}
              >
                <div className="flex items-center gap-3">
                  <Award className="w-3.5 h-3.5" />
                  Kavach Scorecard
                </div>
                <span className="text-[8px] font-bold bg-primary/15 text-primary/80 px-1.5 py-px uppercase tracking-wider">
                  LIVE
                </span>
              </button>
              <button 
                onClick={() => setCurrentView('cert_in')}
                className={`w-full flex items-center gap-3 px-3 py-2 text-xs font-semibold transition-all text-left rounded-none cursor-pointer ${
                  currentView === 'cert_in'
                    ? 'bg-primary/10 text-primary border-r-2 border-primary'
                    : 'text-muted-foreground hover:text-foreground hover:bg-secondary/50'
                }`}
              >
                <FileText className="w-3.5 h-3.5 text-primary" />
                CERT-In Annexure A
              </button>
              <button 
                onClick={() => setCurrentView('kavach_report')}
                className={`w-full flex items-center gap-3 px-3 py-2 text-xs font-semibold transition-all text-left rounded-none cursor-pointer ${
                  currentView === 'kavach_report'
                    ? 'bg-primary/10 text-primary border-r-2 border-primary'
                    : 'text-muted-foreground hover:text-foreground hover:bg-secondary/50'
                }`}
              >
                <FileText className="w-3.5 h-3.5" />
                AI Forensic Report
              </button>
            </nav>
          </div>
        </div>

        {/* Bottom Section: Sandbox Controller */}
        <div>
          <div className="p-4 border-t border-border bg-card space-y-3">
            <div className="p-3 border border-border bg-card space-y-3 rounded-none">
              <span className="text-[10px] font-semibold text-muted-foreground uppercase block">
                Sandbox Environment
              </span>
              
              <div className="flex items-center gap-2">
                <span className={`w-2 h-2 rounded-full ${simulationMode ? 'bg-amber-500 animate-pulse' : isAdbConnected ? 'bg-emerald-500' : 'bg-red-500'}`} />
                <span className="text-[10px] font-medium text-foreground">
                  {simulationMode ? 'Simulation Active' : isAdbConnected ? 'Device Connected' : 'No Devices Attached'}
                </span>
              </div>

              <label className="flex items-center gap-2 pt-2 border-t border-border cursor-pointer select-none">
                <input
                  type="checkbox"
                  checked={simulationMode}
                  onChange={(e) => setSimulationMode(e.target.checked)}
                  className="w-3 h-3 rounded-none border-border bg-background text-primary accent-primary"
                />
                <span className="text-[10px] font-medium text-muted-foreground hover:text-foreground transition-all">
                  Enable Simulation Mode
                </span>
              </label>

              {/* Detonation Duration Selector */}
              <div className="pt-2 border-t border-border space-y-1.5">
                <span className="text-[9px] font-semibold text-muted-foreground uppercase block">
                  Detonation Duration
                </span>
                <div className="grid grid-cols-3 gap-1 bg-background p-0.5 border border-border">
                  {[10, 30, 60].map((sec) => (
                    <button
                      key={sec}
                      type="button"
                      onClick={() => setDetonationDuration(sec)}
                      className={`text-[9px] font-medium py-1 px-1.5 transition-all text-center cursor-pointer ${
                        detonationDuration === sec
                          ? 'bg-primary text-primary-foreground font-semibold'
                          : 'text-muted-foreground hover:text-foreground bg-transparent'
                      }`}
                    >
                      {sec}s
                    </button>
                  ))}
                </div>
              </div>
            </div>

            <div className="text-[9px] text-muted-foreground/60 text-center font-mono">
              Bank of India Hackathon 2026
            </div>
          </div>
        </div>

      </aside>

      {/* 2. Main Content Area */}
      <div className="flex-1 flex flex-col min-w-0 overflow-y-auto">
        {/* Navbar */}
        <header className="h-14 shrink-0 border-b border-border bg-card/30 backdrop-blur px-8 flex items-center justify-between">
          <div className="flex items-center gap-2 text-xs text-muted-foreground">
            <span>Kavach</span>
            <span>/</span>
            <span className="text-foreground font-medium">Dashboard</span>
          </div>

          {/* Reset Workspace button */}
          {(status !== 'landing' || staticScanStatus !== 'landing') && (
            <button
              onClick={reset}
              className="flex items-center gap-2 px-3 py-1.5 border border-border hover:bg-accent text-xs font-semibold transition-all rounded-none"
            >
              <RefreshCw className="w-3 h-3" />
              Reset Detonator
            </button>
          )}
        </header>

        {/* Content Wrapper */}
        <main className="flex-1 p-8 max-w-[1400px] w-full mx-auto">
          {children}
        </main>
      </div>

      {/* Floating Persistent Vajra AI Assistant Drawer */}
      <VajraAssistantDrawer />
    </div>
  );
};
export default AppShell;
