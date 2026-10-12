import React from 'react';
import { X, Check, ExternalLink, Terminal, Shield, Cpu, Layers, BookOpen, Copy } from 'lucide-react';

interface InfoModalProps {
  type: 'pricing' | 'ecosystem' | 'docs' | null;
  onClose: () => void;
}

export const InfoModals: React.FC<InfoModalProps> = ({ type, onClose }) => {
  if (!type) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-stone-950/85 backdrop-blur-md animate-in fade-in duration-200">
      <div className="relative w-full max-w-4xl max-h-[85vh] overflow-y-auto rounded-3xl bg-[#121412] border border-stone-800 p-6 sm:p-8 shadow-2xl">
        
        {/* Close Button */}
        <button
          onClick={onClose}
          className="absolute top-6 right-6 p-2 rounded-xl bg-[#0b0d0c] border border-stone-800 hover:border-stone-700 text-stone-400 hover:text-white transition-colors"
        >
          <X className="w-5 h-5" />
        </button>

        {/* PRICING MODAL - REFINED DEVSECOPS TIERS */}
        {type === 'pricing' && (
          <div className="space-y-6">
            <div className="text-center max-w-xl mx-auto">
              <span className="text-xs font-mono text-lime-400 uppercase tracking-wider">
                DEVSECOPS SECURITY SUITE
              </span>
              <h2 className="text-3xl font-sans font-bold text-stone-100 mt-1">
                Zero-Day Protection at Scale
              </h2>
              <p className="text-sm text-stone-400 mt-2">
                Autonomous supply chain monitoring, AST graph heuristics, and on-chain cryptographic provenance.
              </p>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-6 pt-4">
              {/* Tier 1 */}
              <div className="rounded-2xl p-6 bg-[#0b0d0c] border border-stone-800 flex flex-col justify-between">
                <div>
                  <h3 className="font-sans font-bold text-lg text-stone-100">Open-Source</h3>
                  <div className="text-2xl font-bold font-sans text-lime-400 my-2">Free <span className="text-xs font-normal text-stone-400">/ Community</span></div>
                  <p className="text-xs text-stone-400">For open-source maintainers and public package developers.</p>
                  <ul className="mt-4 space-y-2.5 text-xs font-sans text-stone-300">
                    <li className="flex items-center gap-2"><Check className="w-3.5 h-3.5 text-lime-400" /> Unlimited public repositories</li>
                    <li className="flex items-center gap-2"><Check className="w-3.5 h-3.5 text-lime-400" /> Dependency DAG tree generator</li>
                    <li className="flex items-center gap-2"><Check className="w-3.5 h-3.5 text-lime-400" /> Public blockchain proofs</li>
                  </ul>
                </div>
                <button onClick={onClose} className="w-full mt-6 py-2.5 rounded-xl bg-stone-900 border border-stone-800 text-xs font-sans text-stone-200 hover:border-lime-700/50">
                  CURRENT PLAN
                </button>
              </div>

              {/* Tier 2: Popular */}
              <div className="rounded-2xl p-6 bg-gradient-to-br from-[#162014] to-[#101710] border border-lime-600/50 relative flex flex-col justify-between">
                <span className="absolute -top-3 left-1/2 -translate-x-1/2 px-3 py-0.5 rounded-full bg-gradient-to-r from-lime-600 to-emerald-700 text-stone-100 text-[10px] font-sans font-bold border border-lime-500/30">
                  RECOMMENDED
                </span>
                <div>
                  <h3 className="font-sans font-bold text-lg text-white">Enterprise Core</h3>
                  <div className="text-2xl font-bold font-sans text-white my-2">Advanced <span className="text-xs font-normal text-stone-300">/ Team Suite</span></div>
                  <p className="text-xs text-stone-300">Autonomous protection for high-velocity software engineering organizations.</p>
                  <ul className="mt-4 space-y-2.5 text-xs font-sans text-stone-200">
                    <li className="flex items-center gap-2"><Check className="w-3.5 h-3.5 text-lime-400" /> Param's Real-time AI Threat Explainer</li>
                    <li className="flex items-center gap-2"><Check className="w-3.5 h-3.5 text-lime-400" /> Automated GitHub CI/CD Action Bot</li>
                    <li className="flex items-center gap-2"><Check className="w-3.5 h-3.5 text-lime-400" /> Polygon Mainnet Merkle Anchors</li>
                    <li className="flex items-center gap-2"><Check className="w-3.5 h-3.5 text-lime-400" /> Continuous private repo scanning</li>
                  </ul>
                </div>
                <button onClick={onClose} className="w-full mt-6 py-2.5 rounded-xl bg-gradient-to-r from-lime-600 via-emerald-700 to-stone-800 hover:from-lime-500 hover:to-emerald-600 text-stone-100 font-sans text-xs font-semibold border border-lime-500/30">
                  UPGRADE SHIELD
                </button>
              </div>

              {/* Tier 3 */}
              <div className="rounded-2xl p-6 bg-[#0b0d0c] border border-stone-800 flex flex-col justify-between">
                <div>
                  <h3 className="font-sans font-bold text-lg text-stone-100">Sovereign State</h3>
                  <div className="text-2xl font-bold font-sans text-stone-200 my-2">Custom <span className="text-xs font-normal text-stone-400">/ Air-Gapped</span></div>
                  <p className="text-xs text-stone-400">For defense contractors, aerospace systems, and critical national infrastructure.</p>
                  <ul className="mt-4 space-y-2.5 text-xs font-sans text-stone-300">
                    <li className="flex items-center gap-2"><Check className="w-3.5 h-3.5 text-lime-400" /> On-premise air-gapped runners</li>
                    <li className="flex items-center gap-2"><Check className="w-3.5 h-3.5 text-lime-400" /> Dedicated cryptographic subnets</li>
                    <li className="flex items-center gap-2"><Check className="w-3.5 h-3.5 text-lime-400" /> Custom heuristic ML model weights</li>
                  </ul>
                </div>
                <button onClick={onClose} className="w-full mt-6 py-2.5 rounded-xl bg-stone-900 border border-stone-800 text-xs font-sans text-stone-200 hover:border-lime-700/50">
                  CONTACT SECURITY TEAM
                </button>
              </div>
            </div>
          </div>
        )}

        {/* ECOSYSTEM MODAL */}
        {type === 'ecosystem' && (
          <div className="space-y-6">
            <div>
              <span className="text-xs font-mono text-lime-400 uppercase tracking-wider">
                INTEROPERABILITY &amp; INTEGRATIONS
              </span>
              <h2 className="text-3xl font-sans font-bold text-stone-100 mt-1">
                The TraceRoot Ecosystem
              </h2>
              <p className="text-sm text-stone-400 mt-2">
                Plugs into your existing software repositories, CI/CD pipelines, package registries, and trust verifiers.
              </p>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-4 pt-2 font-sans text-xs">
              {[
                { name: 'GitHub Actions', desc: 'Auto-blocks pull requests containing malicious dependencies', badge: 'Active' },
                { name: 'Polygon PoS', desc: 'Immutable public consensus anchoring for repository AST Merkle trees', badge: 'Live' },
                { name: 'OSV.dev Network', desc: 'Automated global vulnerability and zero-day advisory ingestion', badge: 'Synced' },
                { name: 'GitLab CI/CD', desc: 'Automated pipeline gates, quarantine jobs, and policy checks', badge: 'Verified' },
                { name: 'Kubernetes Admission', desc: 'Enforces pod deployment policy from verified cryptographic digest', badge: 'Beta' },
                { name: 'Sepolia Rollups', desc: 'Zero-gas testnet prototyping environment for local dev clusters', badge: 'Live' },
              ].map((eco) => (
                <div key={eco.name} className="p-4 rounded-2xl bg-[#0b0d0c] border border-stone-800 hover:border-lime-700/50 transition-all">
                  <div className="flex items-center justify-between mb-2">
                    <span className="font-bold text-stone-200">{eco.name}</span>
                    <span className="text-[10px] px-2 py-0.5 rounded-full bg-lime-950/60 text-lime-400 border border-lime-800/40">{eco.badge}</span>
                  </div>
                  <p className="text-[11px] text-stone-400 leading-snug">{eco.desc}</p>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* DOCS MODAL */}
        {type === 'docs' && (
          <div className="space-y-6 font-sans text-xs">
            <div>
              <span className="text-xs font-mono text-lime-400 uppercase tracking-wider">
                DEVELOPER DOCUMENTATION
              </span>
              <h2 className="text-3xl font-sans font-bold text-stone-100 mt-1">
                Getting Started with TraceRoot
              </h2>
              <p className="text-sm text-stone-400 mt-1">
                Integrate our CLI and GitHub Action bot into your repositories in under 60 seconds.
              </p>
            </div>

            <div className="space-y-4">
              <div>
                <div className="text-stone-300 font-bold mb-1.5 font-sans">1. Install TraceRoot CLI</div>
                <div className="p-3.5 rounded-xl bg-[#0b0d0c] border border-stone-800 text-lime-400 font-mono flex items-center justify-between">
                  <code>npm install -g @traceroot/cli</code>
                </div>
              </div>

              <div>
                <div className="text-stone-300 font-bold mb-1.5 font-sans">2. Run Local Repository Scan</div>
                <div className="p-3.5 rounded-xl bg-[#0b0d0c] border border-stone-800 text-stone-200 font-mono">
                  <code>traceroot scan --repo . --strict --blockchain polygon</code>
                </div>
              </div>

              <div>
                <div className="text-stone-300 font-bold mb-1.5 font-sans">3. Add GitHub Actions Workflow (.github/workflows/traceroot.yml)</div>
                <pre className="p-3.5 rounded-xl bg-[#0b0d0c] border border-stone-800 text-stone-300 font-mono overflow-x-auto text-[11px]">
{`name: TraceRoot Security Gate
on: [pull_request]
jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: traceroot/audit-action@v3
        with:
          polygon_api_key: \${{ secrets.TRACEROOT_POLYGON_KEY }}
          fail_on_zero_day: true`}
                </pre>
              </div>
            </div>
          </div>
        )}

      </div>
    </div>
  );
};
