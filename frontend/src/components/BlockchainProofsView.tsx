import React, { useState } from 'react';
import { Coins, CheckCircle2, Copy, Check, ExternalLink, ShieldCheck, Lock, Search } from 'lucide-react';
import { mockBlockchainProofs } from '../data/mockData';

export const BlockchainProofsView: React.FC = () => {
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [searchTerm, setSearchTerm] = useState('');

  const handleCopy = (id: string, text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const filteredProofs = mockBlockchainProofs.filter(
    (p) =>
      p.txHash.toLowerCase().includes(searchTerm.toLowerCase()) ||
      p.network.toLowerCase().includes(searchTerm.toLowerCase()) ||
      p.merkleRoot.toLowerCase().includes(searchTerm.toLowerCase())
  );

  return (
    <div className="space-y-6">
      {/* Top Banner */}
      <div className="rounded-3xl bg-[#121412] p-7 relative overflow-hidden border border-stone-800 shadow-lg">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="space-y-1">
            <span className="text-xs font-sans text-lime-400 font-medium block">
              Cryptographic Immutability Layer
            </span>
            <h2 className="text-2xl font-sans font-bold text-white">
              Polygon &amp; Sepolia Trust Anchor Receipts
            </h2>
            <p className="text-sm text-stone-400 font-sans">
              Every repository AST hash is anchored as a Merkle tree root to public blockchain networks, ensuring zero-knowledge provenance verification.
            </p>
          </div>

          <div className="flex items-center space-x-3 shrink-0">
            <div className="p-3.5 rounded-2xl bg-[#161816] border border-stone-800 text-center font-sans">
              <span className="text-[10px] text-stone-400 block font-medium">TOTAL PROOFS ANCHORED</span>
              <span className="text-xl font-bold text-lime-400 font-mono">14,290</span>
            </div>
            <div className="p-3.5 rounded-2xl bg-[#161816] border border-stone-800 text-center font-sans">
              <span className="text-[10px] text-stone-400 block font-medium">POLYGON FINALITY</span>
              <span className="text-xl font-bold text-lime-400 font-mono">2.1s</span>
            </div>
          </div>
        </div>
      </div>

      {/* Search Bar */}
      <div className="relative max-w-md">
        <Search className="w-4 h-4 text-stone-500 absolute left-3 top-1/2 -translate-y-1/2" />
        <input
          type="text"
          placeholder="Filter by Tx Hash, Merkle Root, or Network..."
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
          className="w-full bg-[#0e100f] border border-stone-800 rounded-full pl-9 pr-4 py-2.5 text-xs font-sans text-white placeholder-stone-500 focus:outline-none focus:border-lime-700/50"
        />
      </div>

      {/* Proofs List */}
      <div className="grid grid-cols-1 gap-4">
        {filteredProofs.map((proof) => (
          <div
            key={proof.id}
            className="rounded-2xl bg-[#121412] p-6 border border-stone-800 hover:border-lime-700/40 transition-all font-sans text-xs space-y-4 shadow-lg"
          >
            <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-3 border-b border-stone-800 gap-2">
              <div className="flex items-center space-x-2.5">
                <span className="w-2 h-2 rounded-full bg-lime-500" />
                <span className="font-bold text-stone-100 text-sm">{proof.network}</span>
                <span className="text-[10px] px-2 py-0.5 rounded-full bg-[#161a15] text-lime-400 border border-lime-800/40 font-medium">
                  {proof.status.toUpperCase()}
                </span>
              </div>
              <span className="text-stone-400 text-[11px] font-mono">{proof.timestamp}</span>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-stone-300">
              <div className="space-y-1 bg-[#0e100f] p-3.5 rounded-xl border border-stone-850 font-mono">
                <span className="text-stone-500 text-[10px] block font-sans">TRANSACTION HASH</span>
                <div className="flex items-center justify-between">
                  <span className="text-lime-400 truncate max-w-[280px]">
                    {proof.txHash}
                  </span>
                  <button
                    onClick={() => handleCopy(proof.id + '-tx', proof.txHash)}
                    className="p-1 rounded text-stone-400 hover:text-white"
                  >
                    {copiedId === proof.id + '-tx' ? <Check className="w-3.5 h-3.5 text-lime-400" /> : <Copy className="w-3.5 h-3.5" />}
                  </button>
                </div>
              </div>

              <div className="space-y-1 bg-[#0e100f] p-3.5 rounded-xl border border-stone-850 font-mono">
                <span className="text-stone-500 text-[10px] block font-sans">MERKLE ROOT HASH</span>
                <div className="flex items-center justify-between">
                  <span className="text-stone-300 truncate max-w-[280px]">
                    {proof.merkleRoot}
                  </span>
                  <button
                    onClick={() => handleCopy(proof.id + '-merkle', proof.merkleRoot)}
                    className="p-1 rounded text-stone-400 hover:text-white"
                  >
                    {copiedId === proof.id + '-merkle' ? <Check className="w-3.5 h-3.5 text-lime-400" /> : <Copy className="w-3.5 h-3.5" />}
                  </button>
                </div>
              </div>
            </div>

            <div className="flex flex-wrap items-center justify-between pt-2 border-t border-stone-800 text-[11px] text-stone-400 gap-2 font-mono">
              <div className="flex items-center space-x-4">
                <span>Block #{proof.blockNumber}</span>
                <span>Gas: {proof.gasUsed}</span>
                <span>Validator: {proof.validator}</span>
              </div>

              <a
                href={`https://polygonscan.com/tx/${proof.txHash}`}
                target="_blank"
                rel="noopener noreferrer"
                className="text-lime-400 hover:underline flex items-center gap-1 font-sans"
              >
                <span>View on PolygonScan</span>
                <ExternalLink className="w-3 h-3" />
              </a>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};
