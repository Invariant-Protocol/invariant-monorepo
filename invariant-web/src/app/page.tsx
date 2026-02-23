"use client";

import { motion } from "framer-motion";
import { Shield, Fingerprint, Lock, ChevronRight, CheckCircle2, Terminal, Server } from "lucide-react";
import { Header } from "@/components/Header";
import { Footer } from "@/components/Footer";
import Link from "next/link";

export default function Landing() {
  return (
    <div className="min-h-screen bg-[#050505] text-white selection:bg-[#00FFC2] selection:text-black font-sans overflow-hidden flex flex-col">
      <Header />
      
      <main className="grow">
        
        {/* --- HERO SECTION: The Proposition --- */}
        <section className="relative pt-40 pb-32 px-6 max-w-7xl mx-auto">
          {/* Background Glow */}
          <div className="absolute top-0 right-0 w-125 h-125 bg-[#00FFC2] opacity-[0.03] blur-[120px] rounded-full pointer-events-none" />

          <motion.div 
            initial={{ opacity: 0, y: 30 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.8 }}
          >
            <div className="inline-flex items-center gap-2 border border-white/10 bg-white/5 px-4 py-1.5 rounded-full mb-8">
              <span className="w-2 h-2 bg-amber-500 rounded-full" />
              <span className="text-xs font-mono tracking-wide text-white/80 uppercase">Phase 1 Pilot Concluded • SDK v0.1 Live</span>
            </div>

            <h1 className="text-5xl md:text-8xl font-serif tracking-tight mb-8 leading-[1.1] text-white">
              Hardware-Rooted <br />
              <span className="text-transparent bg-clip-text bg-linear-to-r from-[#00FFC2] to-white/50">Sybil Resistance.</span>
            </h1>
            
            <p className="text-xl md:text-2xl text-white/50 max-w-2xl font-light leading-relaxed mb-12">
              Software identity is broken. Integrate the Invariant SDK to bind digital accounts to <span className="text-white">physical silicon</span>, making automated fraud mathematically impossible.
            </p>
            
            <div className="flex flex-col sm:flex-row gap-6">
              <Link 
                href="/docs" 
                className="bg-[#00FFC2] text-black px-8 py-4 rounded-sm font-semibold text-lg hover:bg-[#00FFC2]/90 transition-all flex items-center justify-center gap-3"
              >
                <Terminal size={20} />
                Explore Documentation
              </Link>
              <Link 
                href="/dashboard" 
                className="border border-white/20 text-white px-8 py-4 rounded-sm font-medium text-lg hover:bg-white/5 transition-all flex items-center justify-center gap-3"
              >
                <Server size={20} className="opacity-60" />
                Partner Dashboard
              </Link>
            </div>
          </motion.div>
        </section>

        {/* --- TRUST SIGNALS: The "Why" --- */}
        <section className="border-y border-white/5 bg-white/2">
          <div className="max-w-7xl mx-auto px-6 py-16 grid md:grid-cols-3 gap-12">
            <Feature 
              icon={<Shield size={24} className="text-[#00FFC2]" />}
              title="Hardware Attested"
              desc="We cryptographically verify the device's Secure Enclave (TEE/StrongBox) directly against OEM Root CAs."
            />
            <Feature 
              icon={<Fingerprint size={24} className="text-[#00FFC2]" />}
              title="Zero PII Surface"
              desc="No names, biometrics, or behavioral surveillance. We verify the silicon, preserving total end-user privacy."
            />
            <Feature 
              icon={<Lock size={24} className="text-[#00FFC2]" />}
              title="Fail-Closed mTLS"
              desc="Our backend enforces strictly mutual TLS and payload HMAC signing to prevent API abuse and token exfiltration."
            />
          </div>
        </section>

        {/* --- PROBLEM/SOLUTION: The Story --- */}
        <section className="py-32 px-6 max-w-7xl mx-auto">
          <div className="grid md:grid-cols-2 gap-20 items-center">
            <div>
              <h2 className="text-4xl md:text-5xl font-serif mb-8 leading-tight">
                The internet was built <br/> without a <span className="text-[#00FFC2]">Body.</span>
              </h2>
              <div className="space-y-6 text-lg text-white/60 font-light">
                <p>
                  Today, an attacker can spin up 10,000 automated sessions via emulators and device farms for fractions of a cent. Legacy defenses like CAPTCHAs and behavioral heuristics are collapsing under generative AI.
                </p>
                <p className="text-white border-l-2 border-[#00FFC2] pl-6 py-2">
                  Invariant shifts the battlefield from software to hardware. By requiring cryptographic proof of a physical Trusted Execution Environment, <strong>we raise the marginal cost of fraud from $0.00 to the cost of physical device acquisition.</strong>
                </p>
              </div>
            </div>
            
            {/* Visual Abstract: The Shield */}
            <div className="relative h-125 w-full bg-white/5 rounded-2xl border border-white/10 overflow-hidden flex items-center justify-center">
              <div className="absolute inset-0 bg-linear-to-tr from-[#00FFC2]/10 to-transparent opacity-50" />
              <div className="text-center space-y-6 relative z-10">
                <div className="w-24 h-24 bg-[#00FFC2]/10 rounded-full flex items-center justify-center mx-auto border border-[#00FFC2]/30 backdrop-blur-md">
                  <Shield size={48} className="text-[#00FFC2]" />
                </div>
                <div>
                  <div className="text-2xl font-serif text-white">Verification: STRONGBOX</div>
                  <div className="text-white/40 font-mono text-sm mt-2">OS STATE: LOCKED & VERIFIED</div>
                </div>
                <div className="flex gap-2 justify-center mt-4">
                  <Badge text="TITANIUM TIER" />
                  <Badge text="HARDWARE BOUND" />
                </div>
              </div>
            </div>
          </div>
        </section>

        {/* --- SDK INTEGRATION SECTION --- */}
        <section className="py-32 px-6 border-t border-white/10 bg-[#0A0A0A]">
          <div className="max-w-7xl mx-auto grid md:grid-cols-2 gap-16 items-center">
            <div>
              <div className="flex items-center gap-2 mb-6">
                <Terminal size={20} className="text-[#00FFC2]" />
                <span className="font-mono text-xs text-[#00FFC2] tracking-widest uppercase">Developer First</span>
              </div>
              <h2 className="text-4xl font-serif mb-6 text-white">
                Integration takes <br/> less than 15 minutes.
              </h2>
              <p className="text-white/50 text-lg font-light leading-relaxed mb-8">
                Drop the SDK into your mobile client. The Invariant Node handles the X.509 chain validation, nonce tracking, and root-of-trust verification, returning a deterministic hardware risk score.
              </p>
              
              <ul className="space-y-4 mb-10">
                <DevFeature text="Flutter & Native Android SDKs Available" />
                <DevFeature text="Shadow Mode (Audit traffic without blocking)" />
                <DevFeature text="Fail-Open Architecture ensures uptime" />
              </ul>

              <Link 
                href="/docs" 
                className="group inline-flex items-center text-white border-b border-white/30 pb-1 hover:border-[#00FFC2] hover:text-[#00FFC2] transition-colors"
              >
                <span className="font-mono text-sm mr-2">READ DOCUMENTATION</span>
                <ChevronRight size={16} className="group-hover:translate-x-1 transition-transform" />
              </Link>
            </div>

            {/* Right: Code Snippet Visual */}
            <div className="bg-[#050505] border border-white/10 rounded-lg p-6 font-mono text-sm relative group hover:border-white/20 transition-colors shadow-2xl">
              <div className="absolute top-4 right-4 flex gap-2">
                <div className="w-3 h-3 rounded-full bg-red-500/20" />
                <div className="w-3 h-3 rounded-full bg-yellow-500/20" />
                <div className="w-3 h-3 rounded-full bg-green-500/20" />
              </div>
              <div className="text-white/30 mb-4 select-none">// backend_auth.rs</div>
              <div className="space-y-2">
                <div className="text-purple-400">let<span className="text-white"> result = invariant_sdk::</span><span className="text-blue-400">verify_device</span><span className="text-white">(&payload).</span><span className="text-blue-400">await</span><span className="text-white">?;</span></div>
                <div className="text-white">&nbsp;</div>
                <div className="text-purple-400">match<span className="text-white"> result.tier {'{'}</span></div>
                <div className="text-white pl-4"><span className="text-green-400">TrustTier::StrongBox</span> {'=>'} {'{'}</div>
                <div className="text-white pl-8"><span className="text-white/50">// Hardware validated. High assurance.</span></div>
                <div className="text-white pl-8">authorize_session();</div>
                <div className="text-white pl-4">{'}'}</div>
                <div className="text-white pl-4"><span className="text-red-400">TrustTier::Emulator</span> {'=>'} {'{'}</div>
                <div className="text-white pl-8"><span className="text-white/50">// VM detected. Reject payload.</span></div>
                <div className="text-white pl-8">return <span className="text-yellow-400">Err</span>(AuthError::BotDetected);</div>
                <div className="text-white pl-4">{'}'}</div>
                <div className="text-white">{'}'}</div>
              </div>
            </div>
          </div>
        </section>

        {/* --- CTA: B2B Onboarding --- */}
        <section className="py-24 px-6 text-center border-t border-white/10">
          <h2 className="text-4xl font-serif mb-6">Deploy hardware-grade security.</h2>
          <p className="text-white/50 max-w-lg mx-auto mb-10 text-lg">
            Provision your API keys and configure mTLS certificates in the Partner Dashboard to begin your integration.
          </p>
          <Link 
            href="/dashboard" 
            className="inline-block border-b border-[#00FFC2] text-[#00FFC2] pb-1 text-xl hover:text-white hover:border-white transition-colors"
          >
            Access Partner Dashboard →
          </Link>
        </section>

      </main>
      <Footer />
    </div>
  );
}

function Feature({ icon, title, desc }: any) {
  return (
    <div className="group">
      <div className="mb-6 p-4 bg-white/5 w-fit rounded-lg border border-white/10 group-hover:border-[#00FFC2]/50 transition-colors">
        {icon}
      </div>
      <h3 className="text-xl font-serif text-white mb-3">{title}</h3>
      <p className="text-white/50 leading-relaxed font-light">
        {desc}
      </p>
    </div>
  );
}

function Badge({ text }: { text: string }) {
  return (
    <span className="px-3 py-1 rounded bg-[#00FFC2]/10 border border-[#00FFC2]/20 text-[#00FFC2] text-[10px] font-bold tracking-wider">
      {text}
    </span>
  );
}

function DevFeature({ text }: { text: string }) {
  return (
    <li className="flex items-center gap-3 text-white/70 font-light text-sm">
      <CheckCircle2 size={16} className="text-[#00FFC2] shrink-0" />
      {text}
    </li>
  );
}