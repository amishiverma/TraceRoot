import React, { useState } from 'react';
import { BarChart3, TrendingUp, ShieldAlert } from 'lucide-react';

export const MonthlyBarChart: React.FC = () => {
  const [selectedMonth, setSelectedMonth] = useState<number>(5); // Default October

  const data = [
    { month: 'May', value: 200, label: '200', count: 18 },
    { month: 'Jun', value: 340, label: '340', count: 24 },
    { month: 'Jul', value: 280, label: '280', count: 19 },
    { month: 'Aug', value: 420, label: '420', count: 31 },
    { month: 'Sep', value: 390, label: '390', count: 28 },
    { month: 'Oct', value: 500, label: '500', count: 42 },
  ];

  const maxVal = 550;

  return (
    <div className="rounded-3xl bg-[#121412] border border-stone-800 p-6 sm:p-7 flex flex-col justify-between shadow-lg relative overflow-hidden h-full">
      
      {/* Header */}
      <div className="flex items-center justify-between pb-4">
        <div>
          <span className="text-xs font-sans text-stone-400 block">Monthly Threat Mitigations</span>
          <span className="text-sm font-sans font-bold text-stone-200">Package Risk Sweeps</span>
        </div>
        <span className="inline-flex items-center space-x-1 text-xs font-sans text-lime-400 font-semibold">
          <TrendingUp className="w-3.5 h-3.5" />
          <span>+24.8% Swept</span>
        </span>
      </div>

      {/* Bar Chart Area */}
      <div className="flex-1 flex items-end justify-between gap-2.5 sm:gap-3 py-4 min-h-[160px]">
        {data.map((item, idx) => {
          const isSelected = selectedMonth === idx;
          const heightPercent = (item.value / maxVal) * 100;

          return (
            <div
              key={item.month}
              onClick={() => setSelectedMonth(idx)}
              className="flex-1 flex flex-col items-center justify-end h-full cursor-pointer group"
            >
              {/* Value on top of the bar */}
              <span
                className={`text-[11px] font-sans font-bold transition-all mb-2 ${
                  isSelected ? 'text-lime-400 scale-110' : 'text-stone-500 group-hover:text-stone-300'
                }`}
              >
                {item.label}
              </span>

              {/* Vertical Bar */}
              <div className="w-full max-w-[42px] h-36 bg-[#161816] rounded-2xl p-1 flex items-end overflow-hidden border border-stone-800 group-hover:border-stone-700 transition-colors">
                <div
                  className={`w-full rounded-xl transition-all duration-300 ${
                    isSelected
                      ? 'bg-gradient-to-t from-lime-700 to-lime-500'
                      : 'bg-[#222621] group-hover:bg-[#2b302a]'
                  }`}
                  style={{ height: `${heightPercent}%` }}
                />
              </div>

              {/* Month Label below */}
              <span
                className={`text-xs font-sans mt-3 transition-colors ${
                  isSelected ? 'text-stone-100 font-bold' : 'text-stone-500 group-hover:text-stone-300'
                }`}
              >
                {item.month}
              </span>
            </div>
          );
        })}
      </div>

      {/* Footer Info */}
      <div className="pt-3 border-t border-stone-800 flex items-center justify-between text-xs font-sans text-stone-500">
        <span>Peak Volume: October (500 Analyzed)</span>
        <span className="text-lime-400/90 font-medium font-mono">42 zero-days deflected</span>
      </div>

    </div>
  );
};
