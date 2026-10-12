import React from 'react';
import { MainBalanceChart } from './MainBalanceChart';
import { StackedCardContainer } from './StackedCardContainer';
import { PromoCard } from './PromoCard';
import { MonthlyBarChart } from './MonthlyBarChart';
import { RecentTransactionsList } from './RecentTransactionsList';
import { DependencyNode } from '../types';

interface DashboardOverviewProps {
  onScanRepo: () => void;
  onVerifyHash: () => void;
  onCtaClick: () => void;
  onSelectItem: (name: string) => void;
}

export const DashboardOverview: React.FC<DashboardOverviewProps> = ({
  onScanRepo,
  onVerifyHash,
  onCtaClick,
  onSelectItem,
}) => {
  return (
    <div className="space-y-6 sm:space-y-7 max-w-[1600px] mx-auto">
      
      {/* Top Row: Wide Main Chart (Top Left) & Overlapping Stacked Cards (Top Right) */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 sm:gap-7 items-stretch">
        {/* Top Left: 7 cols */}
        <div className="lg:col-span-7 xl:col-span-8 min-h-[380px]">
          <MainBalanceChart />
        </div>

        {/* Top Right: 5 cols */}
        <div className="lg:col-span-5 xl:col-span-4 min-h-[380px]">
          <StackedCardContainer
            onScanRepo={onScanRepo}
            onVerifyHash={onVerifyHash}
          />
        </div>
      </div>

      {/* Bottom Row: 3-Column Bento Box (Promo Card, Monthly Bar Chart, Activity Feed) */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6 sm:gap-7 items-stretch">
        {/* Bottom Left: Promo / CTA Card */}
        <div className="min-h-[340px]">
          <PromoCard onCtaClick={onCtaClick} />
        </div>

        {/* Bottom Center: Monthly Bar Chart */}
        <div className="min-h-[340px]">
          <MonthlyBarChart />
        </div>

        {/* Bottom Right: Recent Scans & Transactions List */}
        <div className="min-h-[340px]">
          <RecentTransactionsList onSelectItem={onSelectItem} />
        </div>
      </div>

    </div>
  );
};
