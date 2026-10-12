import React, { useState } from 'react';
import { 
  X, 
  ShieldAlert, 
  Bot, 
  ExternalLink, 
  Lock, 
  AlertTriangle, 
  CheckCircle2, 
  ShieldX, 
  Copy,
  Check
} from 'lucide-react';
import { DependencyNode } from '../types';

interface ThreatDrawerProps {
  node: DependencyNode | null;
  onClose: () => void;
  onIsolate: (nodeId: string) => void;
  onOverride: (nodeId: string) => void;
}

export const ThreatDrawer: React.FC<ThreatDrawerProps> = ({
  node,
  onClose,
  onIsolate,
  onOverride,
}) => {
  const [isolated, setIsolated] = useState(false);
  const [overridden, setOverridden] = useState(false);
  const [copiedHash, setCopiedHash] = useState(false);

  if (!node) return null;

  const isCritical = node.status === 'critical';
  const isWarning = node.status === 'warning';

  const handleIsolateClick = () => {
    setIsolated(true);
    onIsolate(node.id);
  };

  const handleOverrideClick = () => {
    setOverridden(true);
    onOverride(node.id);
  };

  const handleCopyHash = () => {
    if (node.polygonHash) {
      navigator.clipboard.writeText(node.polygonHash);
      setCopiedHash(true);
      setTimeout(() => setCopiedHash(false), 2000);
    }
  };

  return (
    <div className="fixed inset-0 z-50 overflow-hidden bg-black/75 backdrop-blur-md flex justify-end animate-in fade-in duration-200">
      {/* Click outside backdrop */}
      <div className="absolute inset-0" onClick={onClose} />

      {/* Right-hand Slide-out Panel */}
      <div className="relative w-full max-w-xl bg-[#121412] border-l border-stone-800 h-full overflow-y-auto p-6 sm:p-8 flex flex-col justify-between shadow-2xl z-10 animate-in slide-in-from-right duration-300">
        
        <div>
          {/* Drawer Header */}
          <div className="flex items-center justify-between pb-4 border-b border-stone-800">
            <div className="flex items-center space-x-2">
              <span className={`w-2.5 h-2.5 rounded-full ${
                isCritical ? 'bg-rose-500' : isWarning ? 'bg-amber-500' : 'bg-lime-500'
              }`} />
              <span className="text-xs font-mono uppercase tracking-wider text-stone-400">
                THREAT AUDIT DRAWER // {node.category}
              </span>
            </div>

            <button
              onClick={onClose}
              className="p-2 rounded-xl bg-[#0b0d0c] border border-stone-800 hover:border-stone-700 text-stone-400 hover:text-white transition-colors"
            >
              <X className="w-4 h-4" />
            </button>
          </div>

          {/* Package Title & Risk Score Gauge */}
          <div className="py-6 border-b border-stone-800">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
              <div>
                <h2 className="text-2xl font-sans font-bold text-stone-100 tracking-tight">
                  {node.name}
                </h2>
                <div className="text-xs font-mono text-lime-400 mt-1">
                  Version: v{node.version} • License: {node.license}
                </div>
              </div>

              {/* Risk Badge Gauge */}
              <div className={`px-4 py-2 rounded-2xl text-center border shrink-0 ${
                isCritical
                  ? 'bg-rose-500/15 border-rose-500/40 text-rose-400'
                  : isWarning
                  ? 'bg-amber-500/15 border-amber-500/40 text-amber-400'
                  : 'bg-lime-950/40 border-lime-800/40 text-lime-400'
              }`}>
                <div className="text-[10px] font-sans font-semibold tracking-wider">RISK SCORE</div>
                <div className="text-2xl font-sans font-extrabold">{node.riskScore} / 100</div>
              </div>
            </div>

            {/* Quick Metadata Pill Row */}
            <div className="grid grid-cols-2 sm:grid-cols-3 gap-2.5 mt-4 font-sans text-xs">
              <div className="p-3 rounded-2xl bg-[#0b0d0c] border border-stone-800">
                <span className="text-stone-500 block text-[10px]">MAINTAINER</span>
                <span className="text-stone-200 truncate block font-medium">{node.maintainer}</span>
              </div>
              <div className="p-3 rounded-2xl bg-[#0b0d0c] border border-stone-800">
                <span className="text-stone-500 block text-[10px]">DOWNLOADS</span>
                <span className="text-stone-200 font-medium">{node.downloads}</span>
              </div>
              <div className="p-3 rounded-2xl bg-[#0b0d0c] border border-stone-800">
                <span className="text-stone-500 block text-[10px]">VELOCITY RISK</span>
                <span className={`capitalize font-bold ${
                  node.maintainerRisk === 'critical' ? 'text-rose-400' :
                  node.maintainerRisk === 'medium' ? 'text-amber-400' : 'text-lime-400'
                }`}>
                  {node.maintainerRisk}
                </span>
              </div>
            </div>
          </div>

          {/* PARAM'S AI THREAT EXPLANATION */}
          <div className="my-6">
            <div className="rounded-2xl bg-gradient-to-br from-[#121812] to-[#0e120f] border border-lime-800/40 p-5 relative overflow-hidden">
              <div className="flex items-center space-x-2 text-lime-400 text-xs font-sans font-bold mb-2.5 pb-2 border-b border-stone-800">
                <Bot className="w-4 h-4" />
                <span>PARAM'S AI THREAT EXPLAINER</span>
                <span className="text-[10px] px-2 py-0.5 rounded-full bg-lime-950/60 text-lime-400 font-mono border border-lime-800/40">
                  v3.8-HEURISTICS
                </span>
              </div>

              <div className="text-sm font-sans text-stone-200 leading-relaxed space-y-2">
                <p className="font-medium text-white">
                  {node.aiExplanation || "Param's AI Analysis: Continuous heuristic evaluation active. No active zero-day anomalies detected in release artifacts."}
                </p>
                <div className="text-xs font-mono text-stone-400 pt-2 border-t border-stone-800">
                  <span className="text-lime-300">Anomaly Fingerprint:</span> Sudden maintainer email modification combined with high-entropy binary payload inside test fixtures.
                </div>
              </div>
            </div>
          </div>

          {/* OSV.dev & CVE Vulnerability Matches */}
          <div className="mb-6">
            <div className="flex items-center justify-between text-xs font-sans text-stone-400 mb-2.5">
              <span className="flex items-center gap-1.5 text-stone-200 font-semibold">
                <ShieldAlert className="w-3.5 h-3.5 text-rose-400" />
                OSV.dev &amp; CVE Vulnerability Matches
              </span>
              <span>{node.cves.length} Detected</span>
            </div>

            {node.cves.length > 0 ? (
              <div className="space-y-2 text-xs font-mono">
                {node.cves.map((cve) => (
                  <div
                    key={cve}
                    className="p-3 rounded-2xl bg-[#0b0d0c] border border-rose-500/30 flex items-center justify-between"
                  >
                    <div>
                      <span className="text-rose-400 font-bold">{cve}</span>
                      <span className="text-stone-400 text-[11px] font-sans block mt-0.5">
                        Supply chain remote code execution &amp; credential leakage vector
                      </span>
                    </div>
                    <a
                      href={`https://osv.dev/vulnerability/${cve}`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-lime-400 hover:underline text-[11px] flex items-center gap-1"
                    >
                      <span>OSV Record</span>
                      <ExternalLink className="w-3 h-3" />
                    </a>
                  </div>
                ))}
              </div>
            ) : (
              <div className="p-3.5 rounded-2xl bg-[#0b0d0c] border border-stone-800 text-xs font-sans text-lime-400 flex items-center gap-2">
                <CheckCircle2 className="w-4 h-4" />
                <span>Zero published CVE advisories currently linked to this package.</span>
              </div>
            )}
          </div>

          {/* Blockchain Trust Proof for this package */}
          {node.polygonHash && (
            <div className="mb-6 p-3.5 rounded-2xl bg-[#0b0d0c] border border-stone-800 font-mono text-xs">
              <div className="flex items-center justify-between text-[11px] text-stone-400 pb-2 border-b border-stone-800">
                <span className="flex items-center gap-1 text-lime-400">
                  <Lock className="w-3.5 h-3.5" />
                  POLYGON AUDIT RECEIPT
                </span>
                <span className="text-stone-500">Block #5,928,174</span>
              </div>
              <div className="flex items-center justify-between mt-2.5">
                <span className="text-lime-300 truncate max-w-[240px]">
                  {node.polygonHash}
                </span>
                <button
                  onClick={handleCopyHash}
                  className="text-[11px] text-stone-300 hover:text-white px-2.5 py-1 rounded-xl bg-stone-900 border border-stone-800 flex items-center gap-1.5"
                >
                  {copiedHash ? <Check className="w-3 h-3 text-lime-400" /> : <Copy className="w-3.5 h-3.5" />}
                  <span>{copiedHash ? 'Copied' : 'Copy'}</span>
                </button>
              </div>
            </div>
          )}

          {/* Isolation State Feedback Toast */}
          {isolated && (
            <div className="mb-4 p-3.5 rounded-2xl bg-rose-500/15 border border-rose-500/30 text-xs font-sans text-rose-300 flex items-center gap-2.5">
              <ShieldX className="w-4 h-4 shrink-0 text-rose-400" />
              <span>PACKAGE QUARANTINED: Build scripts stripped &amp; lockfile pinned to clean fallback.</span>
            </div>
          )}

          {overridden && (
            <div className="mb-4 p-3.5 rounded-2xl bg-amber-500/15 border border-amber-500/30 text-xs font-sans text-amber-300 flex items-center gap-2.5">
              <AlertTriangle className="w-4 h-4 shrink-0 text-amber-400" />
              <span>OVERRIDE SIGNED: Whitelisted by Ethan Reynolds with cryptographic signature.</span>
            </div>
          )}
        </div>

        {/* Action Buttons: Isolate Package, Override, View Code on GitHub */}
        <div className="pt-6 border-t border-stone-800 space-y-3">
          <button
            onClick={handleIsolateClick}
            disabled={isolated}
            className={`w-full py-3.5 rounded-2xl font-sans text-xs font-bold tracking-wider flex items-center justify-center space-x-2 transition-all ${
              isolated
                ? 'bg-[#0b0d0c] text-stone-500 border border-stone-800 cursor-not-allowed'
                : 'bg-gradient-to-r from-rose-600 to-rose-700 hover:from-rose-500 hover:to-rose-600 text-white shadow-lg active:scale-95'
            }`}
          >
            <ShieldAlert className="w-4 h-4" />
            <span>{isolated ? 'PACKAGE ISOLATED' : 'ISOLATE PACKAGE'}</span>
          </button>

          <div className="grid grid-cols-2 gap-3">
            <button
              onClick={handleOverrideClick}
              disabled={overridden}
              className={`py-3 rounded-2xl font-sans text-xs font-semibold tracking-wider flex items-center justify-center space-x-1.5 transition-all ${
                overridden
                  ? 'bg-[#0b0d0c] text-stone-500 border border-stone-800 cursor-not-allowed'
                  : 'bg-[#0b0d0c] hover:bg-stone-900 text-stone-200 border border-stone-800 hover:border-lime-700/50'
              }`}
            >
              <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
              <span>{overridden ? 'OVERRIDDEN' : 'OVERRIDE'}</span>
            </button>

            <a
              href={`https://github.com/search?q=${encodeURIComponent(node.name)}&type=repositories`}
              target="_blank"
              rel="noopener noreferrer"
              className="py-3 rounded-2xl font-sans text-xs font-semibold tracking-wider flex items-center justify-center space-x-1.5 bg-[#0b0d0c] hover:bg-stone-900 text-stone-200 border border-stone-800 hover:border-lime-700/50 transition-all"
            >
              <span>GITHUB</span>
              <ExternalLink className="w-3.5 h-3.5 text-lime-400" />
            </a>
          </div>
        </div>

      </div>
    </div>
  );
};
