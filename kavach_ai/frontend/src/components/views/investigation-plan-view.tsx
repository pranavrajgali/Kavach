import React, { useState } from 'react';
import { Bot, CheckCircle2, CircleDotDashed, FlaskConical, RefreshCw, ShieldCheck } from 'lucide-react';
import { useDetonation } from '@/context/DetonationContext';

type EvidenceState = 'observed' | 'dormant_capability' | 'hypothesis';

interface EvidenceRef {
  source: 'static' | 'runtime';
  detail: string;
}

interface Hypothesis {
  id: string;
  claim: string;
  state: EvidenceState;
  confidence: 'low' | 'medium' | 'high';
  rationale: string;
  static_evidence: EvidenceRef[];
  runtime_evidence: EvidenceRef[];
  sandbox_goal: string;
  expected_runtime_evidence: string[];
  next_step: string;
}

interface InvestigationPlan {
  generated_by: 'groq' | 'evidence_rules';
  evidence_policy: string;
  limitations: string[];
  hypotheses: Hypothesis[];
}

const stateStyle: Record<EvidenceState, string> = {
  observed: 'border-emerald-500/30 bg-emerald-500/10 text-emerald-500',
  dormant_capability: 'border-amber-500/30 bg-amber-500/10 text-amber-500',
  hypothesis: 'border-sky-500/30 bg-sky-500/10 text-sky-500',
};

const stateLabel: Record<EvidenceState, string> = {
  observed: 'Observed',
  dormant_capability: 'Dormant capability',
  hypothesis: 'Hypothesis',
};

export const InvestigationPlanView: React.FC = () => {
  const { staticResults, telemetry, apkDetails } = useDetonation();
  const [plan, setPlan] = useState<InvestigationPlan | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const generatePlan = async () => {
    setLoading(true);
    setError(null);
    try {
      const response = await fetch('/api/investigation-plan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ static_results: staticResults || {}, telemetry: telemetry || {} }),
      });
      if (!response.ok) throw new Error(`Planner returned ${response.status}`);
      setPlan(await response.json());
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unable to generate the investigation plan.');
    } finally {
      setLoading(false);
    }
  };

  const hasEvidence = Boolean(staticResults || telemetry);

  return (
    <div className="space-y-6">
      <section className="border border-primary/20 bg-primary/[0.03] p-6 space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-4">
          <div className="space-y-2 max-w-3xl">
            <div className="flex items-center gap-2 text-primary">
              <Bot className="w-5 h-5" />
              <span className="text-xs font-bold uppercase tracking-[0.16em]">GenAI investigation loop</span>
            </div>
            <h2 className="text-2xl font-bold tracking-tight">Turn signals into bounded sandbox experiments</h2>
            <p className="text-sm text-muted-foreground leading-relaxed">
              The planner links static signals to a minimal next experiment, then keeps each conclusion labelled as an observed behavior, dormant capability, or unverified hypothesis.
            </p>
            {apkDetails && <p className="text-xs font-mono text-muted-foreground">TARGET: {apkDetails.name}</p>}
          </div>
          <button
            onClick={generatePlan}
            disabled={loading || !hasEvidence}
            className="shrink-0 inline-flex items-center justify-center gap-2 border border-primary bg-primary px-4 py-2 text-xs font-bold text-primary-foreground transition-colors hover:bg-primary/90 disabled:cursor-not-allowed disabled:opacity-50"
          >
            {loading ? <RefreshCw className="w-4 h-4 animate-spin" /> : <FlaskConical className="w-4 h-4" />}
            {loading ? 'BUILDING PLAN…' : 'GENERATE PLAN'}
          </button>
        </div>
        {!hasEvidence && <p className="text-xs text-amber-500">Run a static scan or sandbox detonation first so the planner has evidence to evaluate.</p>}
      </section>

      {error && <div className="border border-destructive/30 bg-destructive/5 p-4 text-sm text-destructive">{error}</div>}

      {plan && (
        <>
          <section className="border border-border bg-card p-4 flex items-start gap-3">
            <ShieldCheck className="w-5 h-5 text-primary mt-0.5 shrink-0" />
            <div>
              <h3 className="text-sm font-bold">Evidence policy</h3>
              <p className="text-xs text-muted-foreground mt-1">{plan.evidence_policy}</p>
              <p className="text-[10px] text-muted-foreground mt-2 uppercase tracking-wider">Plan language: {plan.generated_by === 'groq' ? 'GenAI-assisted, evidence-bounded' : 'Evidence rules fallback'}</p>
            </div>
          </section>

          <div className="grid gap-4 xl:grid-cols-3">
            {plan.hypotheses.map((item) => (
              <article key={item.id} className="border border-border bg-card p-5 space-y-4">
                <div className="flex items-start justify-between gap-3">
                  <span className={`inline-flex items-center gap-1.5 border px-2 py-1 text-[10px] font-bold uppercase tracking-wider ${stateStyle[item.state]}`}>
                    {item.state === 'observed' ? <CheckCircle2 className="w-3 h-3" /> : <CircleDotDashed className="w-3 h-3" />}
                    {stateLabel[item.state]}
                  </span>
                  <span className="text-[10px] uppercase text-muted-foreground">{item.confidence} confidence</span>
                </div>
                <div>
                  <h3 className="font-bold leading-snug">{item.claim}</h3>
                  <p className="text-xs text-muted-foreground mt-2 leading-relaxed">{item.rationale}</p>
                </div>
                <div className="space-y-2 text-xs">
                  <p className="font-semibold text-foreground">Evidence chain</p>
                  {[...item.static_evidence, ...item.runtime_evidence].length ? (
                    <ul className="space-y-1.5 text-muted-foreground">
                      {[...item.static_evidence, ...item.runtime_evidence].map((evidence, index) => (
                        <li key={`${evidence.source}-${index}`} className="flex gap-2"><span className="font-mono text-[10px] uppercase text-primary">{evidence.source}</span><span>{evidence.detail}</span></li>
                      ))}
                    </ul>
                  ) : <p className="text-muted-foreground">No direct evidence yet.</p>}
                </div>
                <div className="border-t border-border pt-3 space-y-2 text-xs">
                  <p><span className="font-semibold">Sandbox goal:</span> <span className="text-muted-foreground">{item.sandbox_goal}</span></p>
                  <p className="font-semibold">Expected evidence</p>
                  <ul className="list-disc pl-4 text-muted-foreground space-y-1">
                    {item.expected_runtime_evidence.map((expected) => <li key={expected}>{expected}</li>)}
                  </ul>
                  <p className="text-primary font-medium pt-1">{item.next_step}</p>
                </div>
              </article>
            ))}
          </div>

          <p className="text-xs text-muted-foreground border-l-2 border-border pl-3">{plan.limitations.join(' ')}</p>
        </>
      )}
    </div>
  );
};
