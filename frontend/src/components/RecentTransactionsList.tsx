import React from 'react';
import { ShieldAlert, ShieldCheck, GitPullRequest, Coins, ArrowUpRight, ArrowDownRight, Layers } from 'lucide-react';

interface RecentTransactionsListProps {
  onSelectItem?: (name: string) => void;
}

export const RecentTransactionsList: React.FC<RecentTransactionsListProps> = ({ onSelectItem }) => {
  const auditEvents = [
    {
      id: 'tx-1',
      title: 'event-stream-patch',
      subtitle: 'PR #29482 Quarantined',
      timestamp: 'Today, 14:32',
      metric: 'CVSS 9.8',
      status: 'BLOCKED',
      isCritical: true,
      icon: ShieldAlert,
      iconBg: 'bg-rose-500/15 text-rose-400',
    },
    {
      id: 'tx-2',
      title: 'Polygon Block #5928174',
      subtitle: 'Merkle Root Finality',
      timestamp: 'Today, 12:15',
      metric: 'Block #5.9M',
      status: 'ANCHORED',
      isCritical: false,
      icon: Coins,
      iconBg: 'bg-[#161a15] text-lime-400',
    },
    {
      id: 'tx-3',
      title: 'expressjs/express',
      subtitle: 'AST Graph Verified',
      timestamp: 'Yesterday, 19:40',
      metric: '2,847 Pkgs',
      status: 'VERIFIED',
      isCritical: false,
      icon: ShieldCheck,
      iconBg: 'bg-[#161a15] text-lime-400',
    },
    {
      id: 'tx-4',
      title: 'ansi-colors-turbo',
      subtitle: 'Maintainer Velocity Spike',
      timestamp: 'Oct 10, 11:04',
      metric: 'CVSS 5.8',
      status: 'FLAGGED',
      isCritical: true,
      icon: GitPullRequest,
      iconBg: 'bg-amber-500/15 text-amber-400',
    },
    {
      id: 'tx-5',
      title: 'web3/web3.js',
      subtitle: 'Cryptographic Audit Done',
      timestamp: 'Oct 09, 16:22',
      metric: 'Zero CVE',
      status: 'AUDITED',
      isCritical: false,
      icon: Layers,
      iconBg: 'bg-[#161a15] text-lime-400',
    },
  ];

  return (
    <div className="rounded-3xl bg-[#121412] border border-stone-800 p-6 sm:p-7 flex flex-col justify-between shadow-lg relative overflow-hidden h-full">
      
      {/* Header */}
      <div className="flex items-center justify-between pb-3">
        <div>
          <span className="text-xs font-sans text-stone-400 block">Audit Activity Stream</span>
          <span className="text-sm font-sans font-bold text-stone-200">Recent Scans &amp; Audit Events</span>
        </div>
        <span className="text-xs font-sans text-lime-400 hover:underline cursor-pointer">
          See all
        </span>
      </div>

      {/* List Items matching reference style */}
      <div className="space-y-3.5 my-2 max-h-56 overflow-y-auto pr-1">
        {auditEvents.map((item) => {
          const Icon = item.icon;

          return (
            <div
              key={item.id}
              onClick={() => onSelectItem && onSelectItem(item.title)}
              className="flex items-center justify-between p-2 rounded-2xl hover:bg-[#161816] transition-all duration-150 cursor-pointer group"
            >
              {/* Left: Icon Badge & Title */}
              <div className="flex items-center space-x-3.5">
                <div className={`w-10 h-10 rounded-2xl ${item.iconBg} flex items-center justify-center shrink-0 transition-transform group-hover:scale-105`}>
                  <Icon className="w-5 h-5 stroke-[2.2]" />
                </div>
                <div>
                  <h4 className="text-xs sm:text-sm font-sans font-bold text-stone-100 group-hover:text-lime-400 transition-colors leading-tight">
                    {item.title}
                  </h4>
                  <span className="text-[11px] text-stone-500 font-sans block mt-0.5">
                    {item.timestamp}
                  </span>
                </div>
              </div>

              {/* Right: Security Metric & Status */}
              <div className="text-right">
                <span
                  className={`text-xs sm:text-sm font-sans font-extrabold block leading-tight ${
                    item.isCritical ? 'text-rose-400' : 'text-lime-400'
                  }`}
                >
                  {item.metric}
                </span>
                <span className="text-[10px] font-mono text-stone-500 block uppercase tracking-wider">
                  {item.status}
                </span>
              </div>
            </div>
          );
        })}
      </div>

      {/* Bottom Footer */}
      <div className="pt-2.5 border-t border-white/5 flex items-center justify-between text-xs font-sans text-stone-500">
        <span>Auto-Audit Bot: Running</span>
        <span className="text-emerald-400/90 font-medium">100% Policy Pass Rate</span>
      </div>

    </div>
  );
};
