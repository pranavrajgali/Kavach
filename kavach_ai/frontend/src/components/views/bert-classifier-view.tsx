import React from 'react';
import { Cpu, FileCode, CheckCircle, AlertTriangle } from 'lucide-react';

export const BertClassifierView: React.FC = () => {
  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between border-b border-border pb-4">
        <h2 className="text-xl font-bold flex items-center gap-2">
          <Cpu className="w-5 h-5 text-primary" />
          BERT ML Classifier
        </h2>
        <span className="px-2 py-1 text-xs font-semibold bg-primary/10 text-primary border border-primary/20">SecureBERT-2.0</span>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {/* Score Gauge Placeholder */}
        <div className="p-6 border border-border bg-card/30 flex flex-col items-center justify-center space-y-4">
          <h3 className="text-sm font-semibold text-muted-foreground uppercase tracking-widest">Malicious Probability</h3>
          <div className="relative w-40 h-40 flex items-center justify-center rounded-full border-4 border-destructive/20 border-t-destructive animate-[spin_4s_linear_infinite]">
            <div className="absolute inset-2 bg-card rounded-full flex flex-col items-center justify-center animate-[spin_4s_linear_reverse_infinite]">
              <span className="text-4xl font-bold text-destructive">0.89</span>
            </div>
          </div>
          <span className="text-xs text-destructive font-medium flex items-center gap-1">
            <AlertTriangle className="w-3 h-3" /> High Confidence
          </span>
        </div>

        {/* Backwards Slices Viewer */}
        <div className="col-span-1 md:col-span-2 p-6 border border-border bg-card/30 space-y-4">
          <h3 className="text-sm font-semibold text-muted-foreground uppercase tracking-widest flex items-center gap-2">
            <FileCode className="w-4 h-4" />
            Backwards Program Slices
          </h3>
          <div className="bg-black/50 p-4 border border-border/50 font-mono text-xs text-muted-foreground space-y-2 h-40 overflow-y-auto">
            <div className="text-primary-foreground">Slice 1: Landroid/telephony/SmsManager;-&gt;sendTextMessage</div>
            <div className="pl-4">{"<-"} Lcom/evil/malware/Payload;-&gt;execute(Ljava/lang/String;)V</div>
            <div className="pl-8">{"<-"} Lcom/evil/malware/MainActivity;-&gt;onCreate(Landroid/os/Bundle;)V</div>
            <div className="mt-2 text-primary-foreground">Slice 2: Ldalvik/system/DexClassLoader;-&gt;{"<init>"}</div>
            <div className="pl-4">{"<-"} Lcom/evil/malware/DynamicLoader;-&gt;loadClasses()V</div>
          </div>
        </div>

        {/* SHAP Explanations Chart Placeholder */}
        <div className="col-span-1 md:col-span-3 p-6 border border-border bg-card/30 space-y-4">
          <h3 className="text-sm font-semibold text-muted-foreground uppercase tracking-widest">SHAP Token Explanations</h3>
          <div className="space-y-3">
            <div className="flex items-center justify-between text-xs font-mono">
              <span>sendTextMessage</span>
              <div className="flex-1 mx-4 bg-secondary h-2 flex items-center">
                <div className="bg-destructive h-full w-[80%] ml-auto"></div>
              </div>
              <span className="text-destructive w-12 text-right">+0.32</span>
            </div>
            <div className="flex items-center justify-between text-xs font-mono">
              <span>DexClassLoader</span>
              <div className="flex-1 mx-4 bg-secondary h-2 flex items-center">
                <div className="bg-destructive h-full w-[60%] ml-auto"></div>
              </div>
              <span className="text-destructive w-12 text-right">+0.24</span>
            </div>
            <div className="flex items-center justify-between text-xs font-mono">
              <span>onCreate</span>
              <div className="flex-1 mx-4 bg-secondary h-2 flex items-center">
                <div className="bg-emerald-500 h-full w-[20%] mr-auto"></div>
              </div>
              <span className="text-emerald-500 w-12 text-right">-0.05</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
