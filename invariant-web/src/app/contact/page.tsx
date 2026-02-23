"use client";

import { Mail, Terminal, ShieldAlert, Archive } from "lucide-react";
import { Header } from "@/components/Header";
import { Footer } from "@/components/Footer";

export default function Contact() {
  return (
    <div className="min-h-screen bg-[#050505] text-white font-sans selection:bg-[#00FFC2] selection:text-black flex flex-col">
      
      <Header />

      <main className="grow pt-32 pb-24 px-6 max-w-5xl mx-auto w-full">
        
        {/* HEADER */}
        <div className="mb-16 border-b border-white/10 pb-12">
          <h1 className="text-4xl md:text-5xl font-serif mb-6">Contact the Maintainers.</h1>
          <p className="text-white/60 font-light text-lg max-w-2xl leading-relaxed">
            Invariant is an infrastructure protocol. We prioritize inquiries related to B2B SDK integration, security disclosures, and open-source contributions.
          </p>
        </div>

        {/* DEPARTMENT GRID */}
        <div className="grid md:grid-cols-2 gap-6 mb-24">
          
          {/* 1. TECHNICAL INTEGRATION */}
          <a href="mailto:partners@invariantprotocol.com" className="group p-8 border border-white/10 bg-white/5 rounded hover:border-[#00FFC2]/50 transition-all">
            <div className="flex justify-between items-start mb-6">
              <Terminal className="text-[#00FFC2]" size={28} />
              <span className="text-xs font-mono text-white/30 uppercase tracking-widest group-hover:text-[#00FFC2] transition-colors">Builders</span>
            </div>
            <h3 className="text-xl font-bold text-white mb-2">Technical Integration</h3>
            <p className="text-sm text-white/50 font-light mb-6">
              For enterprise platforms and developers seeking to implement the Invariant SDK or access the Partner Dashboard.
            </p>
            <span className="text-[#00FFC2] text-sm font-mono border-b border-[#00FFC2]/30 pb-1">partners@invariantprotocol.com</span>
          </a>

          {/* 2. SECURITY DISCLOSURE */}
          <a href="mailto:security@invariantprotocol.com" className="group p-8 border border-white/10 bg-white/5 rounded hover:border-white/30 transition-all">
            <div className="flex justify-between items-start mb-6">
              <ShieldAlert className="text-amber-500" size={28} />
              <span className="text-xs font-mono text-white/30 uppercase tracking-widest">Security</span>
            </div>
            <h3 className="text-xl font-bold text-white mb-2">Responsible Disclosure</h3>
            <p className="text-sm text-white/50 font-light mb-6">
              Report vulnerabilities regarding the Rust Attestation Engine, HMAC middleware, or Android Keystore bindings.
            </p>
            <span className="text-white/80 text-sm font-mono border-b border-white/30 pb-1">security@invariantprotocol.com</span>
          </a>

          {/* 3. LEGACY PILOT SUPPORT */}
          <div className="group p-8 border border-white/5 bg-black/40 rounded opacity-60 cursor-not-allowed">
            <div className="flex justify-between items-start mb-6">
              <Archive className="text-white/40" size={28} />
              <span className="text-xs font-mono text-white/20 uppercase tracking-widest">Legacy</span>
            </div>
            <h3 className="text-xl font-bold text-white/60 mb-2">Pilot Support (Closed)</h3>
            <p className="text-sm text-white/40 font-light mb-6">
              Phase 1 consumer pilot is concluded. Active support for the legacy mobile application has ended.
            </p>
          </div>

          {/* 4. GENERAL */}
          <a href="mailto:hello@invariantprotocol.com" className="group p-8 border border-white/10 bg-white/5 rounded hover:border-white/30 transition-all">
            <div className="flex justify-between items-start mb-6">
              <Mail className="text-white/60" size={28} />
              <span className="text-xs font-mono text-white/30 uppercase tracking-widest">General</span>
            </div>
            <h3 className="text-xl font-bold text-white mb-2">General Inquiries</h3>
            <p className="text-sm text-white/50 font-light mb-6">
              General information about the protocol, press, and research goals.
            </p>
            <span className="text-white/80 text-sm font-mono border-b border-white/30 pb-1">hello@invariantprotocol.com</span>
          </a>

        </div>

        {/* FOOTER DETAILS */}
        <div className="border-t border-white/10 pt-12 flex flex-col md:flex-row justify-between gap-8 text-sm text-white/40 font-mono">
          <div>
            <p className="mb-2 text-white/20 uppercase tracking-widest text-xs">Location</p>
            <p>East Sussex, United Kingdom</p>
          </div>
          <div>
            <p className="mb-2 text-white/20 uppercase tracking-widest text-xs">Project Status</p>
            <p>SDK V0.1 (Production)</p>
          </div>
        </div>

      </main>
      <Footer />
    </div>
  );
}