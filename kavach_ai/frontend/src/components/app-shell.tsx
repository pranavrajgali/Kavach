import React from 'react';
import { useDetonation } from '@/context/DetonationContext';
import { 
  LayoutGrid, Settings, RefreshCw, CreditCard, HelpCircle, BookOpen,
  FileCode, ShieldAlert, Cpu, FileText, Activity, Award
} from 'lucide-react';

interface AppShellProps {
  children: React.ReactNode;
}

export const AppShell: React.FC<AppShellProps> = ({ children }) => {
  const { 
    simulationMode, setSimulationMode, isAdbConnected, reset, 
    currentView, viewScorecard, viewDashboard 
  } = useDetonation();

  return (
    <div className="flex h-screen overflow-hidden bg-background text-foreground font-sans selection:bg-primary/20">
      {/* 1. Left Fixed Sidebar */}
      <aside className="w-64 shrink-0 border-r border-border bg-card flex flex-col justify-between rounded-none">
        
        {/* Top Section */}
        <div>
          {/* Logo Section */}
          <div className="flex items-center gap-2.5 px-6 py-5 border-b border-border">
            <LayoutGrid className="w-4 h-4 text-foreground shrink-0" />
            <h1 className="font-bold text-sm tracking-tight text-foreground">Kavach</h1>
          </div>

          {/* Navigation Options */}
          <div className="mt-6 px-4">
            <span className="text-[10px] font-bold text-muted-foreground uppercase tracking-widest px-3 block mb-2">
              Threat Analysis
            </span>
            <nav className="space-y-0.5">
              <button 
                onClick={viewDashboard}
                className={`w-full flex items-center gap-3 px-3 py-1.5 text-xs font-semibold transition-all text-left rounded-none cursor-pointer ${
                  currentView === 'dashboard'
                    ? 'bg-primary/10 text-primary'
                    : 'text-muted-foreground hover:text-foreground hover:bg-secondary/50'
                }`}
              >
                <LayoutGrid className="w-3.5 h-3.5" />
                Dynamic Sandbox
              </button>
              <div className="flex items-center gap-3 px-3 py-1.5 text-xs font-medium text-muted-foreground cursor-not-allowed text-left">
                <FileCode className="w-3.5 h-3.5" />
                Static & JNI Scan
              </div>
              <div className="flex items-center gap-3 px-3 py-1.5 text-xs font-medium text-muted-foreground cursor-not-allowed text-left">
                <Cpu className="w-3.5 h-3.5" />
                BERT ML Classifier
              </div>
              <div className="flex items-center gap-3 px-3 py-1.5 text-xs font-medium text-muted-foreground cursor-not-allowed text-left">
                <ShieldAlert className="w-3.5 h-3.5" />
                MITRE ATT&CK Map
              </div>
            </nav>

            <span className="text-[10px] font-bold text-muted-foreground uppercase tracking-widest px-3 block mt-5 mb-2">
              Compliance & Auditing
            </span>
            <nav className="space-y-0.5">
              <button 
                onClick={viewScorecard}
                className={`w-full flex items-center justify-between px-3 py-1.5 text-xs font-semibold transition-all text-left rounded-none cursor-pointer ${
                  currentView === 'scorecard'
                    ? 'bg-amber-500/10 text-amber-500 border-l-2 border-amber-500'
                    : 'text-muted-foreground hover:text-foreground hover:bg-secondary/50'
                }`}
              >
                <div className="flex items-center gap-3">
                  <Award className="w-3.5 h-3.5" />
                  Kavach Scorecard
                </div>
                <span className="text-[9px] font-extrabold bg-amber-500/20 text-amber-500 px-1.5 py-0.2 uppercase">
                  NEW
                </span>
              </button>
              <div className="flex items-center gap-3 px-3 py-1.5 text-xs font-medium text-muted-foreground cursor-not-allowed text-left">
                <FileText className="w-3.5 h-3.5" />
                CERT-In Templates
              </div>
              <div className="flex items-center gap-3 px-3 py-1.5 text-xs font-medium text-muted-foreground cursor-not-allowed text-left">
                <Activity className="w-3.5 h-3.5" />
                Sandbox System Health
              </div>
            </nav>

            <span className="text-[10px] font-bold text-muted-foreground uppercase tracking-widest px-3 block mt-5 mb-2">
              Administration
            </span>
            <nav className="space-y-0.5">
              <div className="flex items-center gap-3 px-3 py-1.5 text-xs font-medium text-muted-foreground cursor-not-allowed text-left">
                <Settings className="w-3.5 h-3.5" />
                Settings
              </div>
              <div className="flex items-center gap-3 px-3 py-1.5 text-xs font-medium text-muted-foreground cursor-not-allowed text-left">
                <CreditCard className="w-3.5 h-3.5" />
                API Credentials
              </div>
            </nav>
          </div>
        </div>

        {/* Bottom Section */}
        <div>
          {/* Changelog & Updates */}
          <div className="px-6 py-4 border-t border-border">
            <span className="text-[9px] font-bold text-muted-foreground uppercase tracking-widest block mb-2">
              CHANGELOG
            </span>
            <div className="space-y-1">
              <div className="text-[11px] font-bold text-foreground">Product update</div>
              <div className="text-[10px] text-muted-foreground leading-normal">
                Performance boosts and UI polish.
              </div>
              <a href="#" className="text-[10px] text-muted-foreground underline hover:text-foreground block mt-1">
                Learn more
              </a>
            </div>
            
            {/* Documentation Links */}
            <div className="mt-4 space-y-2 pt-3 border-t border-border/40">
              <div className="flex items-center gap-2.5 text-[11px] text-muted-foreground hover:text-foreground transition-all cursor-pointer">
                <HelpCircle className="w-3.5 h-3.5" />
                Help Center
              </div>
              <div className="flex items-center gap-2.5 text-[11px] text-muted-foreground hover:text-foreground transition-all cursor-pointer">
                <BookOpen className="w-3.5 h-3.5" />
                Documentation
              </div>
            </div>
          </div>

          {/* Sandbox Status Controller */}
          <div className="p-4 border-t border-border bg-[#0d0d10] space-y-3">
            <div className="p-3 border border-border bg-card space-y-3 rounded-none">
              <span className="text-[10px] font-semibold text-muted-foreground uppercase block">
                Sandbox Status
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
            </div>

            <div className="text-[9px] text-muted-foreground/60 text-center">
              &copy; 2026 Kavach LLC
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
          {status !== 'landing' && (
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
    </div>
  );
};
export default AppShell;
