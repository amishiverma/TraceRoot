import React from 'react';
import { Network, Bot, ShieldCheck, GitPullRequest, ArrowUpRight, Cpu, Check, Terminal, Zap } from 'lucide-react';

interface FeaturesSectionProps {
  onExploreFeature: (featureName: string) => void;
}

export const FeaturesSection: React.FC<FeaturesSectionProps> = ({ onExploreFeature }) => {
  return (
    <section className="relative py-24 bg-[#0b0d0c] border-t border-stone-800/80 overflow-hidden">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 relative z-10">
        
        {/* Section Header */}
        <div className="text-center max-w-3xl mx-auto mb-16">
          <div className="inline-flex items-center space-x-2 px-3.5 py-1.5 rounded-full bg-[#121412] border border-stone-800 text-xs font-sans text-lime-400 mb-4 font-medium">
            <Cpu className="w-3.5 h-3.5" />
            <span>ARCHITECTURAL CAPABILITIES</span>
          </div>
          <h2 className="text-3xl sm:text-5xl font-sans font-bold text-white tracking-tight mb-4">
            Next-Gen DevSecOps{' '}
            <span className="bg-gradient-to-r from-emerald-500 via-lime-400 to-stone-300 bg-clip-text text-transparent">
              Defense Matrix
            </span>
          </h2>
          <p className="text-stone-400 font-sans text-base sm:text-lg leading-relaxed">
            Built from first principles to defeat software supply chain infiltration, maintainer account hijacking, and zero-day dependency attacks.
          </p>
        </div>

        {/* Feature Grid: 4 Core Sections */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-7">
          
          {/* Section 1: Unleashing the Power of Dependency Graphs */}
          <div className="rounded-3xl bg-[#121412] border border-stone-800 hover:border-lime-700/40 p-7 sm:p-8 transition-all duration-200 group flex flex-col justify-between">
            <div>
              <div className="flex items-center justify-between mb-6">
                <div className="w-12 h-12 rounded-2xl bg-[#161a15] border border-lime-800/40 flex items-center justify-center text-lime-400">
                  <Network className="w-6 h-6" />
                </div>
                <span className="text-xs font-sans px-3 py-1 rounded-full bg-[#161a15] text-lime-400 border border-lime-800/40 font-medium">
                  DAG Topology Engine
                </span>
              </div>

              <h3 className="text-2xl font-sans font-bold text-white mb-3 flex items-center gap-2">
                Unleashing the Power of Dependency Graphs
                <ArrowUpRight className="w-5 h-5 text-lime-400 opacity-60 group-hover:translate-x-1 group-hover:-translate-y-1 transition-transform" />
              </h3>

              <p className="text-stone-400 text-sm sm:text-base leading-relaxed mb-6 font-sans">
                Traverse multi-tier recursive dependency trees in milliseconds. Trace deeply nested transitive dependencies, peer conflicts, and hidden runtime payloads across NPM, PyPI, and Go ecosystems.
              </p>
            </div>

            {/* Interactive Visual Preview Box */}
            <div className="rounded-2xl bg-[#0e100f] border border-stone-850 p-5">
              <div className="flex items-center justify-between text-xs font-sans text-stone-400 pb-3 border-b border-stone-800">
                <span className="flex items-center gap-2 text-stone-300 font-medium">
                  <span className="w-2 h-2 rounded-full bg-lime-500" />
                  DAG Visualizer Preview
                </span>
                <span className="font-mono text-stone-500">Depth: 7 Tiers</span>
              </div>

              {/* Node connection mock */}
              <div className="py-6 flex items-center justify-around relative">
                <div className="px-3.5 py-2.5 rounded-xl bg-[#161a15] border border-lime-700/50 text-xs font-sans text-lime-400 text-center">
                  @traceroot/core
                  <div className="text-[10px] text-stone-400 font-mono mt-0.5">Risk: 12 (Safe)</div>
                </div>

                <div className="h-0.5 w-12 bg-gradient-to-r from-lime-600 to-stone-600" />

                <div className="px-3.5 py-2.5 rounded-xl bg-[#181a17] border border-stone-700 text-xs font-sans text-stone-300 text-center">
                  ansi-colors-turbo
                  <div className="text-[10px] text-stone-400 font-mono mt-0.5">Risk: 58 (Review)</div>
                </div>

                <div className="h-0.5 w-12 bg-gradient-to-r from-stone-600 to-rose-500" />

                <div className="px-3.5 py-2.5 rounded-xl bg-[#181614] border border-rose-500/50 text-xs font-sans text-rose-400 text-center">
                  event-stream-patch
                  <div className="text-[10px] text-rose-400 font-bold font-mono mt-0.5">Risk: 94 (Zero-Day)</div>
                </div>
              </div>

              <div className="flex items-center justify-between pt-2 text-xs font-sans text-stone-500 border-t border-stone-800">
                <span>Cycles Detected: 0</span>
                <span className="text-lime-400 font-medium">Blast Radius Analysis Active</span>
              </div>
            </div>
          </div>

          {/* Section 2: AI Threat Explainer */}
          <div className="rounded-3xl bg-[#121412] border border-stone-800 hover:border-lime-700/40 p-7 sm:p-8 transition-all duration-200 group flex flex-col justify-between">
            <div>
              <div className="flex items-center justify-between mb-6">
                <div className="w-12 h-12 rounded-2xl bg-[#161a15] border border-lime-800/40 flex items-center justify-center text-lime-400">
                  <Bot className="w-6 h-6" />
                </div>
                <span className="text-xs font-sans px-3 py-1 rounded-full bg-[#161a15] text-lime-400 border border-lime-800/40 font-medium">
                  Param's Heuristic AI
                </span>
              </div>

              <h3 className="text-2xl font-sans font-bold text-white mb-3 flex items-center gap-2">
                Param's AI Threat Explainer
                <ArrowUpRight className="w-5 h-5 text-lime-400 opacity-60 group-hover:translate-x-1 group-hover:-translate-y-1 transition-transform" />
              </h3>

              <p className="text-stone-400 text-sm sm:text-base leading-relaxed mb-6 font-sans">
                Instant natural language intelligence on anomalous maintainer changes, sudden commit spikes, dormancy releases, and obfuscated entropy payloads. No cryptic CVE codes without context.
              </p>
            </div>

            {/* AI Explanation Terminal Mock */}
            <div className="rounded-2xl bg-[#0e100f] border border-stone-850 p-5 font-mono text-xs text-stone-300">
              <div className="flex items-center space-x-2 text-lime-400 pb-2.5 border-b border-stone-800">
                <Terminal className="w-4 h-4" />
                <span className="font-bold">PARAM AI SYNTHESIS #ZX-882</span>
              </div>
              <div className="mt-3 space-y-2 text-stone-300">
                <p className="text-lime-300">
                  &gt; Maintainer account email changed to disposable address 18h prior to publication.
                </p>
                <p className="text-stone-400">
                  &gt; Injected 24KB Base64 blob inside test fixture with runtime <span className="text-lime-400 font-semibold">eval()</span> execution pattern.
                </p>
                <p className="text-rose-400 font-semibold">
                  &gt; Verdict: High-confidence supply chain backdoor targeting cloud credential stores.
                </p>
              </div>
            </div>
          </div>

          {/* Section 3: Blockchain Trust Anchor */}
          <div className="rounded-3xl bg-[#121412] border border-stone-800 hover:border-lime-700/40 p-7 sm:p-8 transition-all duration-200 group flex flex-col justify-between">
            <div>
              <div className="flex items-center justify-between mb-6">
                <div className="w-12 h-12 rounded-2xl bg-[#161a15] border border-lime-800/40 flex items-center justify-center text-lime-400">
                  <ShieldCheck className="w-6 h-6" />
                </div>
                <span className="text-xs font-sans px-3 py-1 rounded-full bg-[#161a15] text-lime-400 border border-lime-800/40 font-medium">
                  Polygon PoS Proof
                </span>
              </div>

              <h3 className="text-2xl font-sans font-bold text-white mb-3 flex items-center gap-2">
                Blockchain Trust Anchor
                <ArrowUpRight className="w-5 h-5 text-lime-400 opacity-60 group-hover:translate-x-1 group-hover:-translate-y-1 transition-transform" />
              </h3>

              <p className="text-stone-400 text-sm sm:text-base leading-relaxed mb-6 font-sans">
                Every clean repository scan creates a cryptographic Merkle root anchored immutably to Polygon Mainnet. Prevent malicious repo tampering, build-system poisoning, and historical revisionism.
              </p>
            </div>

            {/* Blockchain Receipt Mock */}
            <div className="rounded-2xl bg-[#0e100f] border border-stone-850 p-5 font-mono text-xs">
              <div className="flex items-center justify-between pb-2.5 border-b border-stone-800">
                <span className="text-stone-400">NETWORK:</span>
                <span className="text-lime-400 flex items-center gap-1 font-semibold">
                  <Check className="w-3.5 h-3.5" /> Polygon PoS Validated
                </span>
              </div>
              <div className="mt-2.5 space-y-1.5 text-stone-400">
                <div className="flex justify-between">
                  <span>BLOCK HEIGHT:</span>
                  <span className="text-white font-bold">#5,928,174</span>
                </div>
                <div className="flex justify-between">
                  <span>MERKLE ROOT:</span>
                  <span className="text-lime-400 truncate max-w-[200px]">0x184fa9e283109a12cce49104fae9021481903be9</span>
                </div>
                <div className="flex justify-between">
                  <span>TX RECEIPT:</span>
                  <span className="text-stone-300 truncate max-w-[200px]">0x8f4d92a39b4012948123acbbef01293e8f49e79b</span>
                </div>
              </div>
            </div>
          </div>

          {/* Section 4: Automated GitHub Action Bot */}
          <div className="rounded-3xl bg-[#121412] border border-stone-800 hover:border-stone-700 p-7 sm:p-8 transition-all duration-200 group flex flex-col justify-between">
            <div>
              <div className="flex items-center justify-between mb-6">
                <div className="w-12 h-12 rounded-2xl bg-rose-500/10 border border-rose-500/20 flex items-center justify-center text-rose-400">
                  <GitPullRequest className="w-6 h-6" />
                </div>
                <span className="text-xs font-sans px-3 py-1 rounded-full bg-rose-500/10 text-rose-400 border border-rose-500/20 font-medium">
                  CI/CD Security Gate
                </span>
              </div>

              <h3 className="text-2xl font-sans font-bold text-white mb-3 flex items-center gap-2">
                Automated GitHub Action Bot
                <ArrowUpRight className="w-5 h-5 text-rose-400 opacity-60 group-hover:translate-x-1 group-hover:-translate-y-1 transition-transform" />
              </h3>

              <p className="text-stone-400 text-sm sm:text-base leading-relaxed mb-6 font-sans">
                Stops poisoned pull requests dead in their tracks. Our automated bot intercepts PRs before merge, generates cryptographic audits, and blocks untrusted dependencies with zero human latency.
              </p>
            </div>

            {/* PR Simulation Mock */}
            <div className="rounded-2xl bg-[#0e100f] border border-rose-500/30 p-5 font-mono text-xs">
              <div className="flex items-center justify-between pb-2.5 border-b border-stone-800">
                <span className="text-rose-400 font-bold flex items-center gap-1.5">
                  <Zap className="w-3.5 h-3.5 fill-rose-400" />
                  GATEWAY STATUS: BLOCKED PR #412
                </span>
                <span className="text-stone-500">Exit Code: 1</span>
              </div>
              <div className="mt-2.5 text-stone-300 space-y-1">
                <p className="text-stone-500">&gt; trace-root-bot [action] evaluate-dependencies --strict</p>
                <p className="text-rose-400 font-semibold">&gt; CRITICAL: High-risk package event-stream-patch blocked from production bundle.</p>
                <p className="text-stone-400">&gt; Cryptographic proof recorded. PR author notified with remediation diff.</p>
              </div>
            </div>
          </div>

        </div>

      </div>
    </section>
  );
};
