"use client";

import { AlertTriangle, Download, Server } from "lucide-react";
import { Header } from "@/components/Header";
import { Footer } from "@/components/Footer";
import Link from "next/link";

export default function Pilot() {
  return (
    <div className="min-h-screen bg-[#050505] text-white font-sans selection:bg-[#00FFC2] selection:text-black">
      <Header />

      <main className="pt-40 pb-24 px-6 max-w-3xl mx-auto text-center">
        
        <div className="inline-flex items-center gap-2 bg-amber-500/10 border border-amber-500/20 px-4 py-1.5 rounded-full mb-8">
          <AlertTriangle size={14} className="text-amber-500" />
          <span className="text-amber-500 text-xs font-bold tracking-widest uppercase">Phase 1 Complete</span>
        </div>

        <h1 className="text-5xl md:text-6xl font-serif mb-6 leading-tight text-white/80">
          Public Pilot Concluded.
        </h1>
        
        <p className="text-lg text-white/50 font-light leading-relaxed mb-12 max-w-xl mx-auto">
          The initial consumer testing phase for the Invariant Network is now officially closed. We have transitioned our infrastructure entirely toward B2B Enterprise SDK integrations and network hardening.
        </p>

        {/* REDIRECT CTA */}
        <div className="flex flex-col sm:flex-row gap-4 justify-center mb-20">
          <Link 
            href="/docs" 
            className="bg-[#00FFC2] text-black px-8 py-3 rounded-sm font-bold tracking-wide hover:bg-[#00FFC2]/90 transition-transform flex justify-center items-center gap-2"
          >
            View SDK Docs
          </Link>
          <Link 
            href="/dashboard" 
            className="border border-white/20 text-white px-8 py-3 rounded-sm font-medium hover:bg-white/5 transition-all flex justify-center items-center gap-2"
          >
            <Server size={18} />
            Partner Dashboard
          </Link>
        </div>

        {/* LEGACY DOWNLOAD (TOMBSTONE) */}
        <div className="border-t border-white/10 pt-16">
          <h4 className="text-sm font-mono text-white/30 uppercase tracking-widest mb-6">Archive / Legacy Client</h4>
          
          <div className="bg-black/50 border border-white/5 p-8 rounded-2xl max-w-md mx-auto relative overflow-hidden group opacity-60 hover:opacity-100 transition-opacity">
            <div className="flex flex-col items-center grayscale group-hover:grayscale-0 transition-all">
              <div className="w-12 h-12 bg-white/5 rounded-full flex items-center justify-center mb-4 text-white/40">
                <Download size={20} />
              </div>
              
              <h3 className="text-lg font-serif text-white/80 mb-1">Android Pilot Client (Inactive)</h3>
              <p className="text-white/40 text-xs mb-6 font-mono">v1.4.0 • Legacy Connect</p>
              
              <a 
                href="/invariant.apk" 
                download 
                className="w-full sm:w-auto border border-white/20 text-white/60 px-8 py-2 rounded text-sm hover:bg-white/5 transition-colors"
              >
                DOWNLOAD ARCHIVE APK
              </a>
            </div>
          </div>
        </div>

      </main>
      <Footer />
    </div>
  );
}