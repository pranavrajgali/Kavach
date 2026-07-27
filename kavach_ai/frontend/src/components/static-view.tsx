import React, { useState } from 'react';
import { useDetonation } from '@/context/DetonationContext';

export const StaticView: React.FC = () => {
  const { telemetry, simulationMode } = useDetonation();
  const [activeTab, setActiveTab] = useState<'code_analysis' | 'behavior_analysis' | 'application_permissions' | 'abused_permissions'>('code_analysis');

  const libs = telemetry?.native_libraries || [];

  return (
    <div className="space-y-6">
      {/* Title & Actions */}
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
        <div>
          <h2 className="text-xl font-bold text-foreground">Static & JNI Forensic Scan</h2>
          <p className="text-xs text-muted-foreground mt-1">Abstract syntax tree vulnerabilities, permissions abuse, and JNI native scans.</p>
        </div>
        {/* Compact Engine Status Badges */}
        <div className="flex flex-wrap gap-2 text-[9px] font-mono font-bold bg-[#141416] border border-border px-2.5 py-1.5 rounded-none items-center text-muted-foreground uppercase tracking-wider shrink-0">
          <div className="flex items-center gap-1.5">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse"></span>
            <span>Manifest Scanned</span>
          </div>
          <span className="text-border">|</span>
          <div className="flex items-center gap-1.5">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse"></span>
            <span>Bytecode Decompiled</span>
          </div>
          <span className="text-border">|</span>
          <div className="flex items-center gap-1.5">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse"></span>
            <span>Native Audited</span>
          </div>
        </div>
      </div>

      {/* Row 1: Static Summary Metrics */}
      <div className="border border-border rounded-none bg-card overflow-hidden grid grid-cols-1 md:grid-cols-4 divide-y md:divide-y-0 md:divide-x divide-border">
        {/* Metric 1 */}
        <div className="p-6 space-y-4">
          <span className="text-[10px] font-bold text-muted-foreground uppercase tracking-wider block">
            Static Verdict
          </span>
          <div className="space-y-1">
            <div className="text-2xl font-extrabold tracking-tight text-amber-500">
              WARNING
            </div>
            <div className="flex items-center gap-1 text-[11px] text-muted-foreground">
              <span>Potential policy violations</span>
            </div>
          </div>
        </div>

        {/* Metric 2 */}
        <div className="p-6 space-y-4">
          <span className="text-[10px] font-bold text-muted-foreground uppercase tracking-wider block">
            Vulnerabilities Flagged
          </span>
          <div className="space-y-1">
            <div className="text-2xl font-extrabold tracking-tight text-foreground">
              4 Issues
            </div>
            <div className="flex items-center gap-1 text-[11px] text-muted-foreground">
              <span className="text-amber-500 font-semibold">4 Warnings</span>
              <span>• 1 Info</span>
            </div>
          </div>
        </div>

        {/* Metric 3 */}
        <div className="p-6 space-y-4">
          <span className="text-[10px] font-bold text-muted-foreground uppercase tracking-wider block">
            Malware Permissions
          </span>
          <div className="space-y-1">
            <div className="text-2xl font-extrabold tracking-tight text-foreground">
              4 / 25
            </div>
            <div className="flex items-center gap-1 text-[11px] text-muted-foreground">
              <span className="text-red-500 font-semibold">High risk</span>
              <span>system access</span>
            </div>
          </div>
        </div>

        {/* Metric 4 */}
        <div className="p-6 space-y-4">
          <span className="text-[10px] font-bold text-muted-foreground uppercase tracking-wider block">
            Native Shared Libraries
          </span>
          <div className="space-y-1">
            <div className="text-2xl font-extrabold tracking-tight text-foreground">
              {simulationMode ? 2 : libs.length} libs
            </div>
            <div className="flex items-center gap-1 text-[11px] text-muted-foreground">
              <span className="text-red-500 font-semibold">Unverified binary hooks</span>
            </div>
          </div>
        </div>
      </div>

      {/* Interactive Tabs Menu for Static Data */}
      <div className="border-x border-b border-border bg-[#09090b] flex divide-x divide-border text-[10px] font-bold uppercase tracking-widest overflow-hidden rounded-none shrink-0">
        <button
          onClick={() => setActiveTab('application_permissions')}
          className={`flex-1 py-3 px-4 transition-all text-center cursor-pointer ${
            activeTab === 'application_permissions' ? 'bg-[#18181c] text-primary border-b-2 border-primary' : 'text-muted-foreground hover:bg-[#121215] hover:text-foreground'
          }`}
        >
          Application Permissions
        </button>
        <button
          onClick={() => setActiveTab('code_analysis')}
          className={`flex-1 py-3 px-4 transition-all text-center cursor-pointer ${
            activeTab === 'code_analysis' ? 'bg-[#18181c] text-primary border-b-2 border-primary' : 'text-muted-foreground hover:bg-[#121215] hover:text-foreground'
          }`}
        >
          Code Analysis
        </button>
        <button
          onClick={() => setActiveTab('behavior_analysis')}
          className={`flex-1 py-3 px-4 transition-all text-center cursor-pointer ${
            activeTab === 'behavior_analysis' ? 'bg-[#18181c] text-primary border-b-2 border-primary' : 'text-muted-foreground hover:bg-[#121215] hover:text-foreground'
          }`}
        >
          Behavior Analysis
        </button>
        <button
          onClick={() => setActiveTab('abused_permissions')}
          className={`flex-1 py-3 px-4 transition-all text-center cursor-pointer ${
            activeTab === 'abused_permissions' ? 'bg-[#18181c] text-primary border-b-2 border-primary' : 'text-muted-foreground hover:bg-[#121215] hover:text-foreground'
          }`}
        >
          Abused Permissions
        </button>
      </div>

      {/* Main View Area */}
      <div className="border-x border-b border-border rounded-none bg-card overflow-hidden">
        
        {/* Main Column */}
        <div className="p-6 space-y-4">
          {activeTab === 'code_analysis' && (
            <>
              <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-2">
                <div>
                  <span className="text-sm font-bold text-foreground">Code Analysis</span>
                  <p className="text-[11px] text-muted-foreground mt-0.5">
                    Synthesized static threat vulnerabilities detected in Dalvik bytecode.
                  </p>
                </div>
                {/* Search Bar */}
                <div className="flex items-center gap-1">
                  <span className="text-[10px] text-muted-foreground font-semibold">Search:</span>
                  <input 
                    type="text" 
                    disabled
                    placeholder="Search issues..."
                    className="border border-border bg-[#0e0e11] text-foreground text-xs px-2 py-0.5 rounded-none outline-none w-32 cursor-not-allowed"
                  />
                </div>
              </div>

              {/* Status Stats Summary */}
              <div className="flex items-center gap-4 text-[10px] font-mono py-1.5 bg-muted/40 border border-border px-3 rounded-none">
                <span className="text-muted-foreground font-bold">HIGH: <span className="text-zinc-500">0</span></span>
                <span className="text-amber-500 font-bold">WARNING: 4</span>
                <span className="text-blue-400 font-bold">INFO: 1</span>
                <span className="text-emerald-500 font-bold">SECURE: 1</span>
                <span className="text-muted-foreground font-bold">SUPPRESSED: <span className="text-zinc-500">0</span></span>
              </div>

              {/* Code Analysis Table Mockup */}
              <div className="overflow-x-auto pt-2">
                <table className="w-full text-left text-xs leading-normal">
                  <thead>
                    <tr className="text-muted-foreground border-b border-border">
                      <th className="pb-3 font-medium w-8">No</th>
                      <th className="pb-3 font-medium">Issue</th>
                      <th className="pb-3 font-medium">Severity</th>
                      <th className="pb-3 font-medium">Standards</th>
                      <th className="pb-3 font-medium">Files</th>
                      <th className="pb-3 font-medium text-right">Options</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border/60">
                    <tr className="hover:bg-accent/10 transition-colors">
                      <td className="py-3 font-mono">1</td>
                      <td className="py-3 text-foreground font-semibold text-[11px]">IP Address disclosure</td>
                      <td className="py-3">
                        <span className="bg-amber-500/10 text-amber-500 border border-amber-500/20 px-2 py-0.5 text-[9px] font-bold uppercase tracking-wider rounded-none">
                          warning
                        </span>
                      </td>
                      <td className="py-3 text-muted-foreground text-[10px] space-y-1">
                        <div className="font-semibold text-foreground">CWE: <span className="font-mono text-muted-foreground">CWE-200: Information Exposure</span></div>
                        <div className="font-semibold text-foreground">OWASP MASVS: <span className="font-mono text-muted-foreground">MSTG-CODE-2</span></div>
                      </td>
                      <td className="py-3">
                        <button className="px-2 py-0.5 bg-blue-500/15 border border-blue-500/30 text-blue-400 text-[9px] font-semibold tracking-wider hover:bg-blue-500/25 transition-all rounded-none cursor-pointer">
                          Show Files
                        </button>
                      </td>
                      <td className="py-3 text-right">
                        <button className="px-1.5 py-0.5 border border-border bg-[#0e0e11] text-muted-foreground hover:text-foreground text-[10px] rounded-none cursor-pointer">
                          👁️‍🗨️
                        </button>
                      </td>
                    </tr>
                    <tr className="hover:bg-accent/10 transition-colors">
                      <td className="py-3 font-mono">2</td>
                      <td className="py-3 text-foreground font-semibold text-[11px] max-w-[200px] leading-relaxed">
                        Files may contain hardcoded sensitive information like usernames, passwords, keys etc.
                      </td>
                      <td className="py-3">
                        <span className="bg-amber-500/10 text-amber-500 border border-amber-500/20 px-2 py-0.5 text-[9px] font-bold uppercase tracking-wider rounded-none">
                          warning
                        </span>
                      </td>
                      <td className="py-3 text-muted-foreground text-[10px] space-y-1">
                        <div className="font-semibold text-foreground">CWE: <span className="font-mono text-muted-foreground">CWE-312: Cleartext Storage of Sensitive Information</span></div>
                        <div className="font-semibold text-foreground">OWASP Top 10: <span className="font-mono text-muted-foreground">M9: Reverse Engineering</span></div>
                        <div className="font-semibold text-foreground">OWASP MASVS: <span className="font-mono text-muted-foreground">MSTG-STORAGE-14</span></div>
                      </td>
                      <td className="py-3">
                        <button className="px-2 py-0.5 bg-blue-500/15 border border-blue-500/30 text-blue-400 text-[9px] font-semibold tracking-wider hover:bg-blue-500/25 transition-all rounded-none cursor-pointer">
                          Show Files
                        </button>
                      </td>
                      <td className="py-3 text-right">
                        <button className="px-1.5 py-0.5 border border-border bg-[#0e0e11] text-muted-foreground hover:text-foreground text-[10px] rounded-none cursor-pointer">
                          👁️‍🗨️
                        </button>
                      </td>
                    </tr>
                    <tr className="hover:bg-accent/10 transition-colors">
                      <td className="py-3 font-mono">3</td>
                      <td className="py-3 text-foreground font-semibold text-[11px] leading-relaxed">
                        The App logs information. Sensitive information should never be logged.
                      </td>
                      <td className="py-3">
                        <span className="bg-blue-500/15 text-blue-400 border border-blue-500/30 px-2 py-0.5 text-[9px] font-bold uppercase tracking-wider rounded-none">
                          info
                        </span>
                      </td>
                      <td className="py-3 text-muted-foreground text-[10px] space-y-1">
                        <div className="font-semibold text-foreground">CWE: <span className="font-mono text-muted-foreground">CWE-532: Insertion of Sensitive Information into Log File</span></div>
                        <div className="font-semibold text-foreground">OWASP MASVS: <span className="font-mono text-muted-foreground">MSTG-STORAGE-3</span></div>
                      </td>
                      <td className="py-3">
                        <button className="px-2 py-0.5 bg-blue-500/15 border border-blue-500/30 text-blue-400 text-[9px] font-semibold tracking-wider hover:bg-blue-500/25 transition-all rounded-none cursor-pointer">
                          Show Files
                        </button>
                      </td>
                      <td className="py-3 text-right">
                        <button className="px-1.5 py-0.5 border border-border bg-[#0e0e11] text-muted-foreground hover:text-foreground text-[10px] rounded-none cursor-pointer">
                          👁️‍🗨️
                        </button>
                      </td>
                    </tr>
                    <tr className="hover:bg-accent/10 transition-colors">
                      <td className="py-3 font-mono">4</td>
                      <td className="py-3 text-foreground font-semibold text-[11px]">
                        The App uses an insecure Random Number Generator.
                      </td>
                      <td className="py-3">
                        <span className="bg-amber-500/10 text-amber-500 border border-amber-500/20 px-2 py-0.5 text-[9px] font-bold uppercase tracking-wider rounded-none">
                          warning
                        </span>
                      </td>
                      <td className="py-3 text-muted-foreground text-[10px] space-y-1">
                        <div className="font-semibold text-foreground">CWE: <span className="font-mono text-muted-foreground">CWE-330: Use of Insufficiently Random Values</span></div>
                        <div className="font-semibold text-foreground">OWASP Top 10: <span className="font-mono text-muted-foreground">M5: Insufficient Cryptography</span></div>
                      </td>
                      <td className="py-3">
                        <button className="px-2 py-0.5 bg-blue-500/15 border border-blue-500/30 text-blue-400 text-[9px] font-semibold tracking-wider hover:bg-blue-500/25 transition-all rounded-none cursor-pointer">
                          Show Files
                        </button>
                      </td>
                      <td className="py-3 text-right">
                        <button className="px-1.5 py-0.5 border border-border bg-[#0e0e11] text-muted-foreground hover:text-foreground text-[10px] rounded-none cursor-pointer">
                          👁️‍🗨️
                        </button>
                      </td>
                    </tr>
                  </tbody>
                </table>
              </div>

              {/* Pagination footer */}
              <div className="flex justify-between items-center text-[10px] text-muted-foreground pt-4 border-t border-border">
                <span>Showing 1 to 4 of 4 entries</span>
                <div className="flex gap-1">
                  <button className="px-2 py-1 bg-secondary text-foreground rounded-none border border-border cursor-pointer">Previous</button>
                  <button className="px-3 py-1 bg-primary text-primary-foreground rounded-none border border-primary font-bold">1</button>
                  <button className="px-2 py-1 bg-secondary text-foreground rounded-none border border-border cursor-pointer">Next</button>
                </div>
              </div>
            </>
          )}

          {activeTab === 'behavior_analysis' && (
            <>
              <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-2">
                <div>
                  <span className="text-sm font-bold text-foreground">Behavior Analysis</span>
                  <p className="text-[11px] text-muted-foreground mt-0.5">
                    Heuristic execution rules mapped statically from structural Smali logic checks.
                  </p>
                </div>
                {/* Search Bar */}
                <div className="flex items-center gap-1">
                  <span className="text-[10px] text-muted-foreground font-semibold">Search:</span>
                  <input 
                    type="text" 
                    disabled
                    placeholder="Search behaviors..."
                    className="border border-border bg-[#0e0e11] text-foreground text-xs px-2 py-0.5 rounded-none outline-none w-32 cursor-not-allowed"
                  />
                </div>
              </div>

              {/* Behavior Rules Table */}
              <div className="overflow-x-auto pt-2">
                <table className="w-full text-left text-xs leading-normal">
                  <thead>
                    <tr className="text-muted-foreground border-b border-border">
                      <th className="pb-3 font-medium w-16">Rule ID</th>
                      <th className="pb-3 font-medium">Behaviour</th>
                      <th className="pb-3 font-medium w-24">Label</th>
                      <th className="pb-3 font-medium">Files</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border/60">
                    <tr className="hover:bg-accent/10 transition-colors">
                      <td className="py-3 font-mono">00012</td>
                      <td className="py-3 text-foreground font-medium">Read data and put it into a buffer stream</td>
                      <td className="py-3">
                        <span className="bg-amber-500/10 text-amber-500 border border-amber-500/20 px-1.5 py-0.5 text-[8px] font-bold uppercase rounded-none">
                          file
                        </span>
                      </td>
                      <td className="py-3 font-mono text-[9px] text-blue-400 hover:underline">
                        org/teleal/common/io/IO.java
                      </td>
                    </tr>
                    <tr className="hover:bg-accent/10 transition-colors">
                      <td className="py-3 font-mono">00013</td>
                      <td className="py-3 text-foreground font-medium">Read file and put it into a stream</td>
                      <td className="py-3">
                        <span className="bg-amber-500/10 text-amber-500 border border-amber-500/20 px-1.5 py-0.5 text-[8px] font-bold uppercase rounded-none">
                          file
                        </span>
                      </td>
                      <td className="py-3 font-mono text-[9px] text-blue-400 leading-normal space-y-0.5">
                        <div className="hover:underline">okio/Okio.java</div>
                        <div className="hover:underline">org/teleal/common/io/IO.java</div>
                        <div className="hover:underline">org/teleal/common/xml/DOMParser.java</div>
                      </td>
                    </tr>
                    <tr className="hover:bg-accent/10 transition-colors">
                      <td className="py-3 font-mono">00022</td>
                      <td className="py-3 text-foreground font-medium">Open a file from given absolute path of the file</td>
                      <td className="py-3">
                        <span className="bg-amber-500/10 text-amber-500 border border-amber-500/20 px-1.5 py-0.5 text-[8px] font-bold uppercase rounded-none">
                          file
                        </span>
                      </td>
                      <td className="py-3 font-mono text-[9px] text-blue-400 leading-normal space-y-0.5">
                        <div className="hover:underline">org/teleal/common/jdoc/EasyDoclet.java</div>
                        <div className="hover:underline">org/teleal/common/mock/http/MockServletContext.java</div>
                      </td>
                    </tr>
                    <tr className="hover:bg-accent/10 transition-colors">
                      <td className="py-3 font-mono">00036</td>
                      <td className="py-3 text-foreground font-medium">Get resource file from res/raw directory</td>
                      <td className="py-3">
                        <span className="bg-[#a21caf]/10 text-[#e879f9] border border-[#a21caf]/20 px-1.5 py-0.5 text-[8px] font-bold uppercase rounded-none">
                          reflection
                        </span>
                      </td>
                      <td className="py-3 font-mono text-[9px] text-blue-400 hover:underline">
                        com/pure/iris/domain/logging/FileLoggingTree.java
                      </td>
                    </tr>
                    <tr className="hover:bg-accent/10 transition-colors">
                      <td className="py-3 font-mono">00039</td>
                      <td className="py-3 text-foreground font-medium">Start a web server</td>
                      <td className="py-3 flex flex-wrap gap-1">
                        <span className="bg-amber-500/10 text-amber-500 border border-amber-500/20 px-1.5 py-0.5 text-[8px] font-bold uppercase rounded-none">
                          control
                        </span>
                        <span className="bg-blue-500/10 text-blue-400 border border-blue-500/20 px-1.5 py-0.5 text-[8px] font-bold uppercase rounded-none">
                          network
                        </span>
                      </td>
                      <td className="py-3 font-mono text-[9px] text-blue-400 hover:underline">
                        org/teleal/cling/transport/impl/apache/StreamServerImpl.java
                      </td>
                    </tr>
                  </tbody>
                </table>
              </div>

              {/* Pagination footer */}
              <div className="flex justify-between items-center text-[10px] text-muted-foreground pt-4 border-t border-border">
                <span>Showing 1 to 5 of 12 entries</span>
                <div className="flex gap-1">
                  <button className="px-2 py-1 bg-secondary text-foreground rounded-none border border-border cursor-pointer">Previous</button>
                  <button className="px-3 py-1 bg-primary text-primary-foreground rounded-none border border-primary font-bold">1</button>
                  <button className="px-3 py-1 bg-secondary text-foreground rounded-none border border-border cursor-pointer">2</button>
                  <button className="px-2 py-1 bg-secondary text-foreground rounded-none border border-border cursor-pointer">Next</button>
                </div>
              </div>
            </>
          )}

          {activeTab === 'application_permissions' && (
            <>
              <div>
                <span className="text-sm font-bold text-foreground">Application Permissions</span>
                <p className="text-[11px] text-muted-foreground mt-0.5">
                  Static manifest permissions extracted from AndroidManifest.xml.
                </p>
              </div>

              {/* Permissions table */}
              <div className="overflow-x-auto pt-2">
                <table className="w-full text-left text-xs leading-normal">
                  <thead>
                    <tr className="text-muted-foreground border-b border-border">
                      <th className="pb-3 font-medium">Permission</th>
                      <th className="pb-3 font-medium w-16">Status</th>
                      <th className="pb-3 font-medium">Info</th>
                      <th className="pb-3 font-medium">Description</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border/60">
                    <tr className="hover:bg-accent/10 transition-colors">
                      <td className="py-3 font-mono text-foreground font-semibold text-[10px]">android.permission.ACCESS_NETWORK_STATE</td>
                      <td className="py-3">
                        <span className="bg-emerald-500/10 text-emerald-500 border border-emerald-500/20 px-1.5 py-0.5 text-[8px] font-bold uppercase rounded-none">
                          normal
                        </span>
                      </td>
                      <td className="py-3 text-foreground font-medium">view network status</td>
                      <td className="py-3 text-muted-foreground text-[10px]">Allows an application to view the status of all networks.</td>
                    </tr>
                    <tr className="hover:bg-accent/10 transition-colors">
                      <td className="py-3 font-mono text-foreground font-semibold text-[10px]">android.permission.ACCESS_WIFI_STATE</td>
                      <td className="py-3">
                        <span className="bg-emerald-500/10 text-emerald-500 border border-emerald-500/20 px-1.5 py-0.5 text-[8px] font-bold uppercase rounded-none">
                          normal
                        </span>
                      </td>
                      <td className="py-3 text-foreground font-medium">view Wi-Fi status</td>
                      <td className="py-3 text-muted-foreground text-[10px]">Allows an application to view the information about the status of Wi-Fi.</td>
                    </tr>
                    <tr className="hover:bg-accent/10 transition-colors">
                      <td className="py-3 font-mono text-foreground font-semibold text-[10px]">android.permission.CHANGE_WIFI_MULTICAST_STATE</td>
                      <td className="py-3">
                        <span className="bg-emerald-500/10 text-emerald-500 border border-emerald-500/20 px-1.5 py-0.5 text-[8px] font-bold uppercase rounded-none">
                          normal
                        </span>
                      </td>
                      <td className="py-3 text-foreground font-medium">allow Wi-Fi Multicast reception</td>
                      <td className="py-3 text-muted-foreground text-[10px]">Allows an application to receive packets not directly addressed to your device.</td>
                    </tr>
                    <tr className="hover:bg-accent/10 transition-colors">
                      <td className="py-3 font-mono text-foreground font-semibold text-[10px]">android.permission.INTERNET</td>
                      <td className="py-3">
                        <span className="bg-emerald-500/10 text-emerald-500 border border-emerald-500/20 px-1.5 py-0.5 text-[8px] font-bold uppercase rounded-none">
                          normal
                        </span>
                      </td>
                      <td className="py-3 text-foreground font-medium">full Internet access</td>
                      <td className="py-3 text-muted-foreground text-[10px]">Allows an application to create network sockets.</td>
                    </tr>
                    <tr className="hover:bg-accent/10 transition-colors">
                      <td className="py-3 font-mono text-foreground font-semibold text-[10px]">android.permission.POST_NOTIFICATIONS</td>
                      <td className="py-3">
                        <span className="bg-red-500/10 text-red-500 border border-red-500/20 px-1.5 py-0.5 text-[8px] font-bold uppercase rounded-none">
                          dangerous
                        </span>
                      </td>
                      <td className="py-3 text-foreground font-medium">allows an app to post notifications</td>
                      <td className="py-3 text-muted-foreground text-[10px]">Allows an app to post notifications.</td>
                    </tr>
                  </tbody>
                </table>
              </div>
            </>
          )}

          {activeTab === 'abused_permissions' && (
            <>
              <div>
                <span className="text-sm font-bold text-foreground">Abused Permissions</span>
                <p className="text-[11px] text-muted-foreground mt-0.5">
                  Static manifest permissions extracted and cross-referenced with standard malware signatures.
                </p>
              </div>

              {/* Row: Abused Permissions (Progress bars) */}
              <div className="grid grid-cols-1 gap-4 p-4 bg-muted/20 border border-border rounded-none text-xs">
                <div className="space-y-2">
                  <div className="flex justify-between font-bold text-foreground">
                    <span>Top Malware Permissions</span>
                    <span className="text-red-500">4/25</span>
                  </div>
                  {/* Progress Bar Red */}
                  <div className="w-full bg-[#18181c] h-2">
                    <div className="bg-red-500 h-2" style={{ width: '16%' }}></div>
                  </div>
                  <p className="text-[10px] text-muted-foreground leading-relaxed font-mono">
                    android.permission.ACCESS_NETWORK_STATE, android.permission.INTERNET, android.permission.ACCESS_WIFI_STATE, android.permission.WAKE_LOCK
                  </p>
                </div>

                <div className="space-y-2">
                  <div className="flex justify-between font-bold text-foreground">
                    <span>Other Common Permissions</span>
                    <span className="text-amber-500">1/44</span>
                  </div>
                  {/* Progress Bar Yellow */}
                  <div className="w-full bg-[#18181c] h-2">
                    <div className="bg-amber-500 h-2" style={{ width: '2.2%' }}></div>
                  </div>
                  <p className="text-[10px] text-muted-foreground leading-relaxed font-mono">
                    com.google.android.finsky.permission.BIND_GET_INSTALL_REFERRER_SERVICE
                  </p>
                </div>
              </div>

              {/* JNI & Native Library Scan */}
              <div className="pt-4 border-t border-border mt-4 space-y-2">
                <div>
                  <span className="text-xs font-bold text-foreground block">JNI Bridge Shared Objects</span>
                  <p className="text-[10px] text-muted-foreground mt-0.5">Scanned shared object libraries (.so) and native hooks.</p>
                </div>
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-xs leading-normal">
                    <thead>
                      <tr className="text-muted-foreground border-b border-border">
                        <th className="pb-3 font-medium">Shared Object (.so)</th>
                        <th className="pb-3 font-medium">Architecture</th>
                        <th className="pb-3 font-medium text-right">Verification Status</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-border/60">
                      {simulationMode ? (
                        <>
                          <tr className="hover:bg-accent/10 transition-colors">
                            <td className="py-3 font-mono text-[11px]">/lib/arm64-v8a/libobjection.so</td>
                            <td className="py-3 text-muted-foreground">ARM64</td>
                            <td className="py-3 text-right text-red-500 font-semibold">Frida Bypass Agent</td>
                          </tr>
                          <tr className="hover:bg-accent/10 transition-colors">
                            <td className="py-3 font-mono text-[11px]">/lib/arm64-v8a/libnative-helper.so</td>
                            <td className="py-3 text-muted-foreground">ARM64</td>
                            <td className="py-3 text-right text-amber-500 font-semibold">Reflection Linker</td>
                          </tr>
                          <tr className="hover:bg-accent/10 transition-colors">
                            <td className="py-3 font-mono text-[11px]">/lib/arm64-v8a/libcrypto-secure.so</td>
                            <td className="py-3 text-muted-foreground">ARM64</td>
                            <td className="py-3 text-right text-muted-foreground">Encryption Bridge</td>
                          </tr>
                        </>
                      ) : (telemetry?.native_libraries || []).length === 0 ? (
                        <tr>
                          <td colSpan={3} className="py-4 text-muted-foreground/60 italic text-center">
                            No custom native libraries (.so) loaded during detonation.
                          </td>
                        </tr>
                      ) : (
                        (telemetry?.native_libraries || []).map((lib, idx) => (
                          <tr key={idx} className="hover:bg-accent/10 transition-colors">
                            <td className="py-3 font-mono text-[11px]">{lib}</td>
                            <td className="py-3 text-muted-foreground">ARM64/Dynamic</td>
                            <td className="py-3 text-right text-muted-foreground">Loaded at Runtime</td>
                          </tr>
                        ))
                      )}
                    </tbody>
                  </table>
                </div>
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
};

export default StaticView;
