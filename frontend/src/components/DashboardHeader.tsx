import React, { useState } from 'react';
import { Search, Bell, RefreshCw, Moon, Sun, ChevronDown, Check, Shield } from 'lucide-react';
import { NotificationItem } from '../types';

interface DashboardHeaderProps {
  onOpenSearch: () => void;
  onBackToLanding: () => void;
  notifications: NotificationItem[];
  currentRepo: string;
}

export const DashboardHeader: React.FC<DashboardHeaderProps> = ({
  onOpenSearch,
  onBackToLanding,
  notifications,
  currentRepo,
}) => {
  const [showNotifications, setShowNotifications] = useState(false);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [unreadNotifications, setUnreadNotifications] = useState(notifications);

  const unreadCount = unreadNotifications.filter((n) => !n.read).length;

  const handleRefresh = () => {
    setIsRefreshing(true);
    setTimeout(() => setIsRefreshing(false), 800);
  };

  const markAllAsRead = () => {
    setUnreadNotifications((prev) => prev.map((n) => ({ ...n, read: true })));
  };

  return (
    <header className="h-20 w-full bg-[#0b0d0c]/95 backdrop-blur-xl border-b border-stone-800/80 px-6 sm:px-8 flex items-center justify-between z-20 sticky top-0">
      
      {/* Left: Search Bar with shortcut */}
      <div className="flex-1 max-w-md">
        <div
          onClick={onOpenSearch}
          className="flex items-center justify-between px-4 py-2.5 rounded-full bg-[#121412] border border-stone-800 hover:border-lime-700/50 text-stone-400 text-sm transition-all duration-200 cursor-pointer group"
        >
          <div className="flex items-center space-x-3">
            <Search className="w-4 h-4 text-stone-400 group-hover:text-lime-400 transition-colors" />
            <span className="text-xs sm:text-sm text-stone-400 group-hover:text-stone-300 font-sans">
              Search packages, hash, CVEs...
            </span>
          </div>
          <kbd className="hidden sm:inline-flex items-center px-2 py-0.5 rounded-md bg-[#0e100f] border border-stone-800 text-[11px] font-mono text-stone-400">
            ⌘ + Space
          </kbd>
        </div>
      </div>

      {/* Center: Repository Context Pill */}
      <div className="hidden lg:flex items-center space-x-2 px-3.5 py-1.5 rounded-full bg-[#121412] border border-stone-800 text-xs font-sans">
        <span className="w-2 h-2 rounded-full bg-lime-500" />
        <span className="text-stone-400">Target Repo:</span>
        <span className="text-stone-200 font-semibold">{currentRepo}</span>
      </div>

      {/* Right: System Utility Icons & Profile Dropdown */}
      <div className="flex items-center space-x-3 sm:space-x-4">
        
        {/* Refresh Utility Icon */}
        <button
          onClick={handleRefresh}
          className="p-2.5 rounded-full bg-[#121412] border border-stone-800 hover:border-stone-700 text-stone-400 hover:text-stone-200 transition-colors"
          title="Refresh Data Feed"
        >
          <RefreshCw className={`w-4 h-4 ${isRefreshing ? 'animate-spin text-lime-400' : ''}`} />
        </button>

        {/* Notifications Icon with Unread Dot */}
        <div className="relative">
          <button
            onClick={() => setShowNotifications(!showNotifications)}
            className="relative p-2.5 rounded-full bg-[#121412] border border-stone-800 hover:border-stone-700 text-stone-400 hover:text-stone-200 transition-colors"
            title="Threat Notifications"
          >
            <Bell className="w-4 h-4" />
            {unreadCount > 0 && (
              <span className="absolute top-2 right-2 w-2 h-2 rounded-full bg-lime-500" />
            )}
          </button>

          {/* Notifications Dropdown */}
          {showNotifications && (
            <div className="absolute right-0 mt-3 w-80 sm:w-96 rounded-2xl bg-[#121412] border border-stone-800 shadow-xl p-4 z-50 animate-in fade-in slide-in-from-top-2 duration-150">
              <div className="flex items-center justify-between pb-3 border-b border-stone-800">
                <span className="font-sans font-semibold text-sm text-stone-100">Recent Alerts</span>
                <button
                  onClick={markAllAsRead}
                  className="text-xs text-lime-400 hover:underline font-sans"
                >
                  Mark read
                </button>
              </div>
              <div className="divide-y divide-stone-800 max-h-72 overflow-y-auto mt-2">
                {unreadNotifications.map((notif) => (
                  <div key={notif.id} className="py-2.5">
                    <div className="flex items-center justify-between text-xs">
                      <span className={`font-medium ${notif.severity === 'critical' ? 'text-rose-400' : 'text-lime-400'}`}>
                        {notif.title}
                      </span>
                      <span className="text-[10px] text-stone-500 font-mono">{notif.timestamp}</span>
                    </div>
                    <p className="text-xs text-stone-400 font-sans mt-0.5">{notif.message}</p>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* User Profile Pill ("Ethan Reynolds / @ethan_reynolds") */}
        <div className="flex items-center space-x-3 pl-2 sm:pl-3 py-1 pr-3 rounded-full bg-[#121412] border border-stone-800 hover:border-stone-700 transition-colors cursor-pointer select-none">
          <div className="relative">
            <div className="w-9 h-9 rounded-full bg-gradient-to-tr from-lime-600 via-emerald-700 to-stone-700 p-0.5">
              <div className="w-full h-full rounded-full bg-[#0e100f] flex items-center justify-center text-xs font-bold text-lime-300">
                ER
              </div>
            </div>
            <div className="absolute bottom-0 right-0 w-2.5 h-2.5 rounded-full bg-lime-500 border-2 border-[#121412]" />
          </div>

          <div className="hidden sm:flex flex-col text-left">
            <span className="text-xs font-semibold text-stone-100 font-sans leading-snug">
              Ethan Reynolds
            </span>
            <span className="text-[10px] text-stone-400 font-mono leading-none">
              @ethan_reynolds
            </span>
          </div>

          <ChevronDown className="w-3.5 h-3.5 text-stone-400" />
        </div>

      </div>

    </header>
  );
};
