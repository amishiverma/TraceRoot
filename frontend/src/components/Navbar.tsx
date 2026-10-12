import React from 'react';
import { Terminal, Eye, BookOpen, Layers, Coins, ExternalLink, Cpu } from 'lucide-react';
import logoImg from '../assets/logo.png';

interface NavbarProps {
  onLaunchConsole: () => void;
  onOpenVR: () => void;
  onOpenDocs: () => void;
  onOpenPricing: () => void;
  onOpenEcosystem: () => void;
  isDashboard?: boolean;
}

export const Navbar: React.FC<NavbarProps> = ({
  onLaunchConsole,
  onOpenVR,
  onOpenDocs,
  onOpenPricing,
  onOpenEcosystem,
  isDashboard = false,
}) => {
  return (
    <header className="sticky top-0 z-40 w-full backdrop-blur-xl bg-obsidian-950/80 border-b border-white/10 transition-all">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-20 flex items-center justify-between">
        
        {/* Brand / Logo */}
        <div className="flex items-center space-x-3 cursor-pointer group" onClick={() => window.scrollTo({ top: 0, behavior: 'smooth' })}>
          <div className="relative flex items-center justify-center w-11 h-11 rounded-xl bg-[#121412] border border-stone-800 transition-transform group-hover:scale-105">
            <img 
              src={logoImg} 
              alt="TraceRoot Logo" 
              className="w-7 h-7 object-contain relative z-10" 
            />
            <div className="absolute -bottom-1 -right-1 w-2 h-2 rounded-full bg-lime-500 border-2 border-[#0b0d0c]" />
          </div>

          <div className="flex flex-col">
            <div className="flex items-center space-x-2">
              <span className="font-display font-bold text-xl tracking-wide text-white">
                TraceRoot
              </span>
            </div>
            <span className="text-[10px] text-stone-400 font-medium tracking-wider flex items-center gap-1 uppercase">
              <Cpu className="w-2.5 h-2.5 text-lime-500" /> DevSecOps Trust Layer
            </span>
          </div>
        </div>

        {/* Navigation Links */}
        <nav className="hidden md:flex items-center space-x-8">
          <button
            onClick={onOpenVR}
            className="group flex items-center space-x-1.5 text-sm font-medium text-stone-300 hover:text-lime-400 transition-colors"
          >
            <Eye className="w-4 h-4 text-stone-400 group-hover:text-lime-400 transition-colors" />
            <span>VR/AR View</span>
            <span className="text-[10px] font-mono px-1.5 py-0.5 rounded-md bg-[#161a15] text-lime-400 border border-lime-800/40">3D</span>
          </button>

          <button
            onClick={onOpenEcosystem}
            className="flex items-center space-x-1.5 text-sm font-medium text-stone-300 hover:text-lime-400 transition-colors"
          >
            <Layers className="w-4 h-4 text-stone-400 group-hover:text-lime-400 transition-colors" />
            <span>Ecosystem</span>
          </button>

          <button
            onClick={onOpenPricing}
            className="flex items-center space-x-1.5 text-sm font-medium text-stone-300 hover:text-lime-400 transition-colors"
          >
            <Coins className="w-4 h-4 text-stone-400 group-hover:text-lime-400 transition-colors" />
            <span>Pricing</span>
          </button>

          <button
            onClick={onOpenDocs}
            className="flex items-center space-x-1.5 text-sm font-medium text-stone-300 hover:text-lime-400 transition-colors"
          >
            <BookOpen className="w-4 h-4 text-stone-400 group-hover:text-lime-400 transition-colors" />
            <span>Docs</span>
          </button>
        </nav>

        {/* Right CTA */}
        <div className="flex items-center space-x-3">
          <div className="hidden lg:flex items-center space-x-2 px-3 py-1.5 rounded-full bg-[#121412] border border-stone-800 text-xs text-stone-300">
            <span className="w-2 h-2 rounded-full bg-lime-500" />
            <span className="font-mono text-[11px] text-stone-300">Polygon Anchor: Active</span>
          </div>

          <button
            onClick={onLaunchConsole}
            id="launch-console-btn"
            className="relative group overflow-hidden px-5 py-2.5 rounded-xl text-xs tracking-wide text-stone-950 font-bold transition-all duration-200 hover:opacity-95 active:scale-[0.98] bg-gradient-to-r from-lime-600 via-emerald-600 to-stone-700 border border-lime-500/20"
          >
            <span className="relative z-10 flex items-center space-x-2 font-bold text-stone-950">
              <Terminal className="w-4 h-4 text-stone-950" />
              <span>{isDashboard ? 'Control Center' : 'Launch Console'}</span>
            </span>
          </button>
        </div>

      </div>
    </header>
  );
};
