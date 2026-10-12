import React from 'react';
import { ArrowRight, ShieldCheck, Sparkles } from 'lucide-react';

interface PromoCardProps {
  onCtaClick: () => void;
}

export const PromoCard: React.FC<PromoCardProps> = ({ onCtaClick }) => {
  return (
    <div className="rounded-3xl p-6 sm:p-7 bg-gradient-to-br from-lime-800 via-emerald-900 to-stone-900 text-white border border-lime-700/30 relative overflow-hidden flex flex-col justify-between h-full shadow-lg">
      
      {/* Decorative background subtle circle */}
      <div className="absolute top-0 right-0 w-44 h-44 bg-white/5 rounded-full pointer-events-none" />

      <div>
        {/* Top Tag */}
        <div className="inline-flex items-center space-x-1.5 px-3 py-1 rounded-full bg-black/30 border border-white/10 text-[11px] font-sans font-semibold mb-4 text-lime-300">
          <Sparkles className="w-3.5 h-3.5 text-lime-400" />
          <span>PARAM'S AI SHIELD</span>
        </div>

        {/* Heading */}
        <h3 className="text-xl sm:text-2xl font-sans font-extrabold leading-snug tracking-tight mb-2">
          Trusted by Thousands. <br />
          Secure Your Code Today!
        </h3>

        {/* Subtext */}
        <p className="text-xs sm:text-sm text-stone-300 font-sans leading-relaxed mb-6">
          Autonomous zero-day heuristic protection and instant Polygon blockchain anchoring.
        </p>
      </div>

      <div>
        {/* Avatars Stack matching reference */}
        <div className="flex items-center space-x-3 mb-5">
          <div className="flex -space-x-2 overflow-hidden">
            <div className="inline-block h-8 w-8 rounded-full ring-2 ring-lime-800 bg-stone-900 text-stone-200 flex items-center justify-center font-bold text-[10px]">
              ER
            </div>
            <div className="inline-block h-8 w-8 rounded-full ring-2 ring-lime-800 bg-stone-850 text-lime-300 flex items-center justify-center font-bold text-[10px]">
              PV
            </div>
            <div className="inline-block h-8 w-8 rounded-full ring-2 ring-lime-800 bg-stone-800 text-stone-300 flex items-center justify-center font-bold text-[10px]">
              SL
            </div>
            <div className="inline-block h-8 w-8 rounded-full ring-2 ring-lime-800 bg-[#161a15] text-lime-400 flex items-center justify-center font-bold text-[10px]">
              +12k
            </div>
          </div>
          <span className="text-xs font-sans text-stone-300 font-medium">
            Active Maintainers
          </span>
        </div>

        {/* Crisp White CTA Button matching reference */}
        <button
          onClick={onCtaClick}
          className="w-full py-3.5 px-5 rounded-2xl bg-stone-100 hover:bg-white text-stone-950 font-sans font-bold text-xs tracking-wider flex items-center justify-center space-x-2 transition-transform duration-150 active:scale-95"
        >
          <span>Get Started</span>
          <ArrowRight className="w-4 h-4 text-stone-950 stroke-[2.5]" />
        </button>
      </div>

    </div>
  );
};
