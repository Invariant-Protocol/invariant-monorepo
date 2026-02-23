"use client";

import { useState } from "react";
import { Lock, Server, Activity, Key, ShieldCheck, Download, ExternalLink } from "lucide-react";
import { Header } from "@/components/Header";
import { Footer } from "@/components/Footer";

export default function DashboardStub() {
  const [activeTab, setActiveTab] = useState("overview");

  // Mock Data for the B2B Dashboard
  const mockKeys = [
    { id: "pilot_flutter_sdk_key_01", status: "ACTIVE", created: "2026-02-21", type: "Production" },
    { id: "dev_testing_key_temp", status: "REVOKED", created: "2026-02-15", type: "Sandbox" }
  ];

  return (
    <div className="min-h-screen bg-[#050505] text-white font-sans selection:bg-[#00FFC2] selection:text-black flex flex-col">
      <Header />

      <main className="grow pt-32 pb-24 px-6 max-w-7xl mx-auto w-full flex gap-8">
        
        {/* SIDEBAR */}
        <aside className="hidden md:flex flex-col w-64 shrink-0 border-r border-white/10 pr-6 h-[calc(100vh-12rem)] sticky top-32">
          <div className="mb-8">
            <h2 className="font-serif text-2xl text-white mb-1">Partner Portal</h2>
            <p className="text-xs font-mono text-white/40 uppercase tracking-widest">Workspace: ACME Corp</p>
          </div>
          
          <nav className="space-y-2 grow">
            <TabButton id="overview" label="Overview" icon={<Activity size={16}/>} active={activeTab === "overview"} onClick={() => setActiveTab("overview")} />
            <TabButton id="api_keys" label="API & Security" icon={<Key size={16}/>} active={activeTab === "api_keys"} onClick={() => setActiveTab("api_keys")} />
            <TabButton id="mtls" label="mTLS Certificates" icon={<Lock size={16}/>} active={activeTab === "mtls"} onClick={() => setActiveTab("mtls")} />
          </nav>

          <div className="pt-6 border-t border-white/10">
             <div className="flex items-center gap-2 text-xs font-mono text-[#00FFC2]">
               <div className="w-2 h-2 rounded-full bg-[#00FFC2] animate-pulse"></div>
               NODE: ONLINE (PORT 8443)
             </div>
          </div>
        </aside>

        {/* MAIN CONTENT AREA */}
        <div className="flex-1 min-w-0">
          
          {/* TAB: OVERVIEW */}
          {activeTab === "overview" && (
            <div className="space-y-8 animate-in fade-in duration-500">
              <h1 className="text-3xl font-serif mb-6">System Overview</h1>
              
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <StatCard title="Total Attestations (24h)" value="1,248" trend="+12%" />
                <StatCard title="Threats Blocked" value="43" trend="-2%" alert />
                <StatCard title="Avg Latency" value="124ms" />
              </div>

              <div className="border border-white/10 bg-white/5 rounded-lg p-6 mt-8">
                <div className="flex justify-between items-center mb-6">
                  <h3 className="font-mono text-sm text-[#00FFC2] uppercase tracking-widest">Recent Shadow Logs</h3>
                  <button className="text-xs text-white/40 hover:text-white flex items-center gap-1"><ExternalLink size={12}/> View All</button>
                </div>
                <div className="space-y-3 font-mono text-xs">
                  <LogEntry time="10:21:44Z" event="ATTESTATION_FAILED" detail="Emulator Detected (sdk_gphone_x86)" type="error" />
                  <LogEntry time="10:18:12Z" event="ATTESTATION_OK" detail="Titan M2 Strongbox Verified" type="success" />
                  <LogEntry time="10:14:05Z" event="HMAC_MISMATCH" detail="Invalid Payload Signature" type="error" />
                  <LogEntry time="10:11:59Z" event="ATTESTATION_SHADOW" detail="Software-backed Key Used" type="warning" />
                </div>
              </div>
            </div>
          )}

          {/* TAB: API KEYS */}
          {activeTab === "api_keys" && (
            <div className="space-y-8 animate-in fade-in duration-500">
              <div className="flex justify-between items-end mb-6 border-b border-white/10 pb-6">
                <div>
                  <h1 className="text-3xl font-serif mb-2">API Credentials</h1>
                  <p className="text-white/50 text-sm font-light">Manage your HMAC secrets for payload signing.</p>
                </div>
                <button className="bg-white text-black px-4 py-2 text-sm font-bold rounded hover:bg-[#00FFC2] transition-colors">
                  Generate New Key
                </button>
              </div>

              <div className="border border-white/10 rounded-lg overflow-hidden">
                <table className="w-full text-left text-sm">
                  <thead className="bg-white/5 font-mono text-white/40 uppercase text-xs">
                    <tr>
                      <th className="p-4 border-b border-white/10">Key Identifier</th>
                      <th className="p-4 border-b border-white/10">Environment</th>
                      <th className="p-4 border-b border-white/10">Created</th>
                      <th className="p-4 border-b border-white/10">Status</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-white/5 text-white/80 font-mono">
                    {mockKeys.map((key, i) => (
                      <tr key={i} className="hover:bg-white/5 transition-colors">
                        <td className="p-4 text-white">{key.id}</td>
                        <td className="p-4 text-white/50">{key.type}</td>
                        <td className="p-4 text-white/50">{key.created}</td>
                        <td className="p-4">
                          <span className={`px-2 py-1 text-[10px] rounded ${key.status === 'ACTIVE' ? 'bg-[#00FFC2]/10 text-[#00FFC2]' : 'bg-red-500/10 text-red-500'}`}>
                            {key.status}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* TAB: mTLS */}
          {activeTab === "mtls" && (
            <div className="space-y-8 animate-in fade-in duration-500">
              <h1 className="text-3xl font-serif mb-2">Transport Security</h1>
              <p className="text-white/50 text-sm font-light mb-8 max-w-xl">
                The Invariant node enforces strict Mutual TLS (mTLS). You must attach a valid client certificate bundle to all API requests.
              </p>

              <div className="bg-white/5 border border-white/10 p-6 rounded-lg flex items-start gap-4">
                <ShieldCheck className="text-[#00FFC2] shrink-0 mt-1" size={24} />
                <div>
                  <h3 className="font-bold text-white mb-2">Active Client Certificate</h3>
                  <p className="text-sm text-white/60 mb-4 font-mono">Fingerprint: 8A2B...99F4</p>
                  <p className="text-xs text-white/40 mb-6">Expires: Dec 31, 2026</p>
                  
                  <button className="flex items-center gap-2 border border-white/20 text-white/80 px-4 py-2 rounded text-sm hover:bg-white/10 transition-colors">
                    <Download size={14} />
                    Download PKCS#12 Bundle (.p12)
                  </button>
                </div>
              </div>
            </div>
          )}

        </div>
      </main>
      <Footer />
    </div>
  );
}

// Sub-components
function TabButton({ id, label, icon, active, onClick }: any) {
  return (
    <button 
      onClick={onClick}
      className={`w-full flex items-center gap-3 px-4 py-3 rounded text-sm transition-colors ${
        active 
          ? "bg-[#00FFC2]/10 text-[#00FFC2] font-medium" 
          : "text-white/60 hover:bg-white/5 hover:text-white"
      }`}
    >
      {icon}
      {label}
    </button>
  );
}

function StatCard({ title, value, trend, alert = false }: any) {
  return (
    <div className="bg-white/5 border border-white/10 p-5 rounded-lg">
      <div className="text-white/40 text-xs font-mono mb-2 uppercase tracking-wide">{title}</div>
      <div className="flex items-end justify-between">
        <div className="text-3xl font-serif text-white">{value}</div>
        {trend && (
          <div className={`text-xs font-bold font-mono mb-1 ${alert ? 'text-red-400' : 'text-[#00FFC2]'}`}>
            {trend}
          </div>
        )}
      </div>
    </div>
  );
}

function LogEntry({ time, event, detail, type }: any) {
  const color = type === 'error' ? 'text-red-400' : type === 'success' ? 'text-[#00FFC2]' : 'text-amber-400';
  return (
    <div className="flex gap-4 border-b border-white/5 pb-2 last:border-0 last:pb-0">
      <span className="text-white/30 shrink-0 w-20">{time}</span>
      <span className={`${color} shrink-0 w-40 font-bold`}>{event}</span>
      <span className="text-white/60 truncate">{detail}</span>
    </div>
  );
}