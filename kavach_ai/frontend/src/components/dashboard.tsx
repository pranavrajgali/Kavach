import React from 'react';
import { useDetonation } from '@/context/DetonationContext';
import { UploadPanel } from '@/components/upload-panel';
import { TerminalConsole } from '@/components/terminal-console';
import { ReportView } from '@/components/report-view';
import { KavachScorecard } from '@/components/kavach-scorecard';
import { StaticView } from '@/components/static-view';
import { BertClassifierView } from '@/components/views/bert-classifier-view';
import { MitreMapView } from '@/components/views/mitre-map-view';
import { CertInView } from '@/components/views/cert-in-view';
import { SandboxHealthView } from '@/components/views/sandbox-health-view';
import { SettingsView } from '@/components/views/settings-view';
import { ApiCredentialsView } from '@/components/views/api-credentials-view';
import { AlertCircle } from 'lucide-react';

export const Dashboard: React.FC = () => {
  const { status, currentView, reset, logs } = useDetonation();

  if (currentView === 'scorecard') {
    return <KavachScorecard />;
  }

  if (currentView === 'static_scan') {
    return <StaticView />;
  }

  if (currentView === 'bert_classifier') {
    return <BertClassifierView />;
  }

  if (currentView === 'mitre_map') {
    return <MitreMapView />;
  }

  if (currentView === 'cert_in') {
    return <CertInView />;
  }

  if (currentView === 'sandbox_health') {
    return <SandboxHealthView />;
  }

  if (currentView === 'settings') {
    return <SettingsView />;
  }

  if (currentView === 'api_credentials') {
    return <ApiCredentialsView />;
  }

  switch (status) {
    case 'landing':
      return <UploadPanel />;
    case 'analyzing':
      return <TerminalConsole />;
    case 'completed':
      return <ReportView />;
    case 'error':
      return (
        <div className="flex flex-col items-center justify-center p-12 text-center border border-destructive/20 bg-destructive/5 rounded-lg max-w-2xl mx-auto my-12">
          <AlertCircle className="w-12 h-12 text-destructive mb-4" />
          <h3 className="text-lg font-bold text-foreground mb-2">Detonation Encountered a Critical Error</h3>
          <p className="text-sm text-muted-foreground mb-6 max-h-60 overflow-y-auto font-mono text-left bg-black/40 p-4 rounded w-full">
            {logs[logs.length - 1] || 'Sandbox run failed.'}
          </p>
          <button
            onClick={reset}
            className="px-4 py-2 bg-primary hover:bg-primary/90 text-primary-foreground font-semibold rounded text-sm transition-all"
          >
            ← Detonate Another APK
          </button>
        </div>
      );
    default:
      return null;
  }
};
export default Dashboard;
