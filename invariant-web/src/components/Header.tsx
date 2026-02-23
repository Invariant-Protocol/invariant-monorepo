"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

export function Header() {
  const pathname = usePathname();

  return (
    <nav className="fixed top-0 w-full bg-[#050505]/90 backdrop-blur-md border-b border-white/5 z-50 h-20 transition-all">
      <div className="max-w-7xl mx-auto px-6 h-full flex items-center justify-between">
        
        {/* LOGO */}
        <Link href="/" className="flex items-center space-x-3 group">
          <div className="h-3 w-3 bg-[#00FFC2] rounded-full group-hover:scale-110 transition-transform" />
          <span className="font-serif text-xl tracking-tight text-white">Invariant</span>
        </Link>

        {/* NAV */}
        <div className="hidden md:flex items-center space-x-10">
          <NavLink href="/impact" current={pathname}>Mission</NavLink>
          <NavLink href="/docs" current={pathname}>SDK Docs</NavLink>
          <NavLink href="/about" current={pathname}>Team</NavLink>
          
          {/* SEPARATOR */}
          <div className="h-4 w-px bg-white/10" />
          
          <Link 
            href="/pilot"
            className="text-sm font-mono text-white/40 hover:text-white transition-colors tracking-wide"
          >
            PILOT (CLOSED)
          </Link>

          {/* B2B ADMIN CTA */}
          <Link 
            href="/dashboard"
            className="bg-white text-black px-5 py-2.5 rounded-sm text-sm font-bold hover:bg-[#00FFC2] transition-colors"
          >
            Partner Dashboard
          </Link>
        </div>
      </div>
    </nav>
  );
}

function NavLink({ href, current, children }: any) {
  const isActive = current === href;
  return (
    <Link 
      href={href}
      className={`text-sm font-medium transition-colors ${
        isActive ? "text-[#00FFC2]" : "text-white/60 hover:text-white"
      }`}
    >
      {children}
    </Link>
  );
}