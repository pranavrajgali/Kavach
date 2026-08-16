import React, { useEffect, useState } from 'react';
import { FileText, Download, CheckSquare } from 'lucide-react';
import { useDetonation } from '@/context/DetonationContext';

export const CertInView: React.FC = () => {
  const { apkDetails, jobId, staticScanStatus, status } = useDetonation();
  const [reportData, setReportData] = useState<any>(null);

  useEffect(() => {
    let isMounted = true;
    const controller = new AbortController();
    // Never keep a prior APK's compliance data visible while a new job loads.
    setReportData(null);

    const fetchReport = async () => {
      if (!jobId) return;
      try {
        const res = await fetch(`/api/report/${jobId}`, { signal: controller.signal });
        if (!res.ok) return;
        const data = await res.json();
        if (isMounted && data.status === 'success') {
          setReportData(data.report);
        }
      } catch (err: any) {
        if (err.name === 'AbortError') return;
        console.error('Failed to fetch CERT-In report:', err);
      }
    };

    if (jobId) {
      fetchReport();
    }

    const interval = setInterval(() => {
      if (jobId) {
        fetchReport();
      }
    }, 2500);

    return () => {
      isMounted = false;
      controller.abort();
      clearInterval(interval);
    };
  }, [jobId, staticScanStatus, status]);

  if (!jobId) {
    return <div className="p-8 text-center text-muted-foreground">No CERT-In report is available until an APK analysis creates a job.</div>;
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between border-b border-border pb-4">
        <h2 className="text-xl font-bold flex items-center gap-2">
          <FileText className="w-5 h-5 text-primary" />
          CERT-In Incident Report
        </h2>
        <button className="flex items-center gap-2 px-3 py-1.5 bg-primary/10 hover:bg-primary/20 text-primary border border-primary/20 text-xs font-semibold transition-all">
          <Download className="w-4 h-4" />
          Export PDF
        </button>
      </div>

      <div className="max-w-3xl border border-border bg-card/30 p-8 space-y-8 font-mono text-sm mx-auto">
        <div className="text-center space-y-2 border-b border-border pb-6">
          <h1 className="text-lg font-bold uppercase tracking-widest text-foreground">Indian Computer Emergency Response Team (CERT-In)</h1>
          <p className="text-muted-foreground">Cyber Security Incident Reporting Form</p>
        </div>

        <div className="space-y-6">
          <div className="grid grid-cols-3 gap-4 border-b border-border/50 pb-4">
            <div className="col-span-1 text-muted-foreground font-semibold">1. Incident Date & Time:</div>
            <div className="col-span-2 text-foreground">{new Date().toLocaleString()}</div>
          </div>
          
          <div className="grid grid-cols-3 gap-4 border-b border-border/50 pb-4">
            <div className="col-span-1 text-muted-foreground font-semibold">2. Type of Incident:</div>
            <div className="col-span-2 text-foreground flex items-center gap-2">
              <CheckSquare className="w-4 h-4 text-primary" /> {reportData?.incident_type || 'Awaiting verified analysis'}
            </div>
          </div>

          <div className="grid grid-cols-3 gap-4 border-b border-border/50 pb-4">
            <div className="col-span-1 text-muted-foreground font-semibold">3. Target System Details:</div>
            <div className="col-span-2 space-y-1">
              <div><span className="text-muted-foreground">OS:</span> Android 11.0 (API 30)</div>
              <div><span className="text-muted-foreground">App Name:</span> {apkDetails?.name || 'Unknown APK'}</div>
              <div><span className="text-muted-foreground">Package ID:</span> {apkDetails?.package || 'com.unknown.package'}</div>
              <div><span className="text-muted-foreground">Threat Level:</span> {reportData?.threat_level || 'Unknown'}</div>
            </div>
          </div>

          <div className="grid grid-cols-3 gap-4 pb-4 border-b border-border/50">
            <div className="col-span-1 text-muted-foreground font-semibold">4. Indicators of Compromise (IoCs):</div>
            <div className="col-span-2 space-y-2 text-xs">
              {reportData?.indicators_of_compromise ? (
                Array.isArray(reportData.indicators_of_compromise) ? (
                  reportData.indicators_of_compromise.map((ioc: any, i: number) => (
                    <div key={i} className="bg-black/40 p-2 border border-border">
                      {typeof ioc === 'string' ? ioc : JSON.stringify(ioc)}
                    </div>
                  ))
                ) : (
                  <div className="bg-black/40 p-2 border border-border">
                    {JSON.stringify(reportData.indicators_of_compromise)}
                  </div>
                )
              ) : <div className="text-muted-foreground">Awaiting verified indicators for this APK.</div>}
            </div>
          </div>

          {reportData?.compliance_violations && (
            <div className="grid grid-cols-3 gap-4 pb-4">
              <div className="col-span-1 text-muted-foreground font-semibold">5. Compliance Violations:</div>
              <div className="col-span-2 space-y-2 text-xs">
                {Array.isArray(reportData.compliance_violations) ? (
                  reportData.compliance_violations.map((violation: string, i: number) => (
                    <div key={i} className="bg-black/40 p-2 border border-border text-destructive">
                      {violation}
                    </div>
                  ))
                ) : (
                  <div className="bg-black/40 p-2 border border-border text-destructive">
                    {reportData.compliance_violations}
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
