import React, { useState, useEffect } from 'react';
import { Navbar } from './components/Navbar';
import { LandingHero } from './components/LandingHero';
import { FeaturesSection } from './components/FeaturesSection';
import { DashboardHeader } from './components/DashboardHeader';
import { Sidebar } from './components/Sidebar';
import { DashboardOverview } from './components/DashboardOverview';
import { DependencyGraph } from './components/DependencyGraph';
import { AnalyticsChart } from './components/AnalyticsChart';
import { VulnerabilityLogsView } from './components/VulnerabilityLogsView';
import { BlockchainProofsView } from './components/BlockchainProofsView';
import { SettingsModal } from './components/SettingsModal';
import { ThreatDrawer } from './components/ThreatDrawer';
import { ScanningModal } from './components/ScanningModal';
import { VRARViewModal } from './components/VRARViewModal';
import { CommandPalette } from './components/CommandPalette';
import { InfoModals } from './components/InfoModals';
import { 
  initialNodes, 
  initialEdges, 
  mockActivityLogs, 
  mockNotifications 
} from './data/mockData';
import { DependencyNode, ActiveTab } from './types';
import { Shield } from 'lucide-react';
import logoImg from './assets/logo.png';

export const App: React.FC = () => {
  // Page mode: 'landing' or 'dashboard'
  const [currentView, setCurrentView] = useState<'landing' | 'dashboard'>('landing');

  // Dashboard active tab
  const [activeTab, setActiveTab] = useState<ActiveTab>('overview');

  // Data states
  const [nodes, setNodes] = useState<DependencyNode[]>(initialNodes);
  const [edges] = useState(initialEdges);
  const [currentRepo, setCurrentRepo] = useState('facebook/react');
  const [selectedNode, setSelectedNode] = useState<DependencyNode | null>(null);

  // Modals
  const [scanningRepo, setScanningRepo] = useState<string | null>(null);
  const [showVRModal, setShowVRModal] = useState(false);
  const [showCommandPalette, setShowCommandPalette] = useState(false);
  const [infoModalType, setInfoModalType] = useState<'pricing' | 'ecosystem' | 'docs' | null>(null);

  // Keyboard shortcut listener for Command + Space
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.code === 'Space') {
        e.preventDefault();
        setShowCommandPalette((prev) => !prev);
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, []);

  // Initiate scan from input or chips
  const handleStartScan = (repoUrl: string) => {
    setScanningRepo(repoUrl);
  };

  // When scan completes, update repo and jump to Dashboard
  const handleScanComplete = () => {
    if (scanningRepo) {
      const cleanName = scanningRepo.replace('https://github.com/', '').replace('.git', '');
      setCurrentRepo(cleanName || 'facebook/react');
    }
    setScanningRepo(null);
    setCurrentView('dashboard');
    setActiveTab('overview');
  };

  // Node isolation action
  const handleIsolateNode = (nodeId: string) => {
    setNodes((prev) =>
      prev.map((n) => (n.id === nodeId ? { ...n, status: 'warning', riskScore: 35 } : n))
    );
  };

  // Node override action
  const handleOverrideNode = (nodeId: string) => {
    setNodes((prev) =>
      prev.map((n) => (n.id === nodeId ? { ...n, status: 'safe', riskScore: 15 } : n))
    );
  };

  // Trigger package detail from activity or card
  const handleSelectPackageByName = (name: string) => {
    const found = nodes.find((n) => n.name.toLowerCase().includes(name.toLowerCase()) || name.toLowerCase().includes(n.name.toLowerCase()));
    if (found) {
      setSelectedNode(found);
    } else {
      setSelectedNode(nodes[1]); // Default to high-risk package (event-stream-patch)
    }
    setCurrentView('dashboard');
  };

  return (
    <div className="min-h-screen bg-[#0b0d0c] text-stone-100 flex flex-col font-sans selection:bg-lime-600/30 selection:text-lime-200 antialiased">
      
      {/* LANDING PAGE VIEW */}
      {currentView === 'landing' ? (
        <div className="flex-1 flex flex-col">
          {/* Top Navbar */}
          <Navbar
            onLaunchConsole={() => setCurrentView('dashboard')}
            onOpenVR={() => setShowVRModal(true)}
            onOpenDocs={() => setInfoModalType('docs')}
            onOpenPricing={() => setInfoModalType('pricing')}
            onOpenEcosystem={() => setInfoModalType('ecosystem')}
            isDashboard={false}
          />

          {/* Hero Section */}
          <main className="flex-1">
            <LandingHero onStartScan={handleStartScan} />
            <FeaturesSection onExploreFeature={(feat) => {
              setCurrentView('dashboard');
              if (feat.includes('Graph')) setActiveTab('graph');
              else if (feat.includes('Blockchain')) setActiveTab('blockchain');
              else setActiveTab('overview');
            }} />
          </main>

          {/* Landing Footer */}
          <footer className="border-t border-stone-800/80 py-12 bg-[#0b0d0c]">
            <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex flex-col sm:flex-row items-center justify-between gap-6 text-xs font-sans text-stone-400">
              <div className="flex items-center space-x-3">
                <div className="w-8 h-8 rounded-xl bg-[#121412] border border-stone-800 flex items-center justify-center">
                  <img src={logoImg} alt="TraceRoot Logo" className="w-5 h-5 object-contain" />
                </div>
                <div>
                  <span className="font-bold text-white tracking-wider">TraceRoot</span>
                  <span className="text-stone-500 block text-[10px]">
                    Autonomous DevSecOps &amp; Blockchain Trust Layer
                  </span>
                </div>
              </div>

              <div className="flex items-center space-x-6">
                <button onClick={() => setInfoModalType('docs')} className="hover:text-lime-400 transition-colors">
                  Documentation
                </button>
                <button onClick={() => setInfoModalType('pricing')} className="hover:text-lime-400 transition-colors">
                  Pricing
                </button>
                <button onClick={() => setInfoModalType('ecosystem')} className="hover:text-lime-400 transition-colors">
                  Ecosystem
                </button>
                <button onClick={() => setShowVRModal(true)} className="hover:text-emerald-300 transition-colors text-emerald-400">
                  Attack Surface Map
                </button>
              </div>

              <div className="text-[11px] text-stone-400 font-sans">
                Polygon PoS Consensus • Protected by Sentinel AI
              </div>
            </div>
          </footer>
        </div>
      ) : (
        /* MAIN SECURITY CONTROL CENTER (DASHBOARD - REDESIGNED PER REFERENCE IMAGE) */
        <div className="flex-1 flex min-h-screen">
          {/* Left Slim Vertical Sidebar with Glowing Orange Active Pill */}
          <Sidebar
            activeTab={activeTab}
            onTabChange={(tab) => setActiveTab(tab)}
            onBackToLanding={() => setCurrentView('landing')}
          />

          {/* Main Dashboard Column */}
          <div className="flex-1 flex flex-col min-w-0">
            {/* Top Navigation Bar with Search Pill & Profile */}
            <DashboardHeader
              onOpenSearch={() => setShowCommandPalette(true)}
              onBackToLanding={() => setCurrentView('landing')}
              notifications={mockNotifications}
              currentRepo={currentRepo}
            />

            {/* Main Content Area */}
            <main className="flex-1 p-5 sm:p-7 lg:p-8 overflow-y-auto bg-[#0c0a09] min-h-[calc(100vh-5rem)]">
              {/* Overview Tab: 3-Row Bento Box matching Image 1 */}
              {activeTab === 'overview' && (
                <DashboardOverview
                  onScanRepo={() => setScanningRepo(`https://github.com/${currentRepo}`)}
                  onVerifyHash={() => setActiveTab('blockchain')}
                  onCtaClick={() => setInfoModalType('pricing')}
                  onSelectItem={handleSelectPackageByName}
                  onOpenVR={() => setShowVRModal(true)}
                  currentRepo={currentRepo}
                />
              )}

              {/* Dependency Map Tab */}
              {activeTab === 'graph' && (
                <div className="space-y-4 max-w-[1600px] mx-auto">
                  <div className="flex items-center justify-between pb-3 border-b border-white/5">
                    <div>
                      <h2 className="text-2xl font-sans font-bold text-stone-100">
                        Dependency Graph &amp; DAG Topology
                      </h2>
                      <p className="text-xs text-stone-400 font-sans mt-0.5">
                        Interactive supply chain visualization for <span className="text-stone-300 font-medium">{currentRepo}</span>
                      </p>
                    </div>
                  </div>
                  <DependencyGraph
                    nodes={nodes}
                    edges={edges}
                    onSelectNode={(node) => setSelectedNode(node)}
                    selectedNodeId={selectedNode?.id}
                    isFullScreen={true}
                  />
                </div>
              )}

              {/* Threat Analytics Tab */}
              {activeTab === 'analytics' && (
                <div className="space-y-6 max-w-[1600px] mx-auto">
                  <div className="flex items-center justify-between pb-3 border-b border-white/5">
                    <div>
                      <h2 className="text-2xl font-sans font-bold text-stone-100">
                        Threat Analytics &amp; Risk Metrics
                      </h2>
                      <p className="text-xs text-stone-400 font-sans mt-0.5">
                        Time-series anomaly progressions, dormant code spikes, and risk index
                      </p>
                    </div>
                  </div>
                  <AnalyticsChart />
                </div>
              )}

              {/* Vulnerability Logs Tab */}
              {activeTab === 'vulnerabilities' && (
                <div className="max-w-[1600px] mx-auto">
                  <VulnerabilityLogsView
                    nodes={nodes}
                    onSelectNode={(node) => setSelectedNode(node)}
                  />
                </div>
              )}

              {/* Blockchain Proofs Tab */}
              {activeTab === 'blockchain' && (
                <div className="max-w-[1600px] mx-auto">
                  <BlockchainProofsView />
                </div>
              )}

              {/* Settings Tab */}
              {activeTab === 'settings' && (
                <div className="max-w-[1600px] mx-auto">
                  <SettingsModal />
                </div>
              )}
            </main>
          </div>
        </div>
      )}

      {/* INTERACTIVE THREAT DRAWER (Triggered on Node / Transaction Click) */}
      <ThreatDrawer
        node={selectedNode}
        onClose={() => {
          setSelectedNode(null);
          setCurrentView('dashboard');
        }}
        onIsolate={handleIsolateNode}
        onOverride={handleOverrideNode}
      />

      {/* HUD SCANNING SIMULATION MODAL */}
      {scanningRepo && (
        <ScanningModal
          repoUrl={scanningRepo}
          onComplete={handleScanComplete}
          onCancel={() => setScanningRepo(null)}
        />
      )}

      {/* AUTONOMOUS SUPPLY CHAIN ATTACK SURFACE MODAL */}
      {showVRModal && (
        <VRARViewModal
          onClose={() => setShowVRModal(false)}
          onSelectNodeByName={(name) => {
            const found = nodes.find((n) => n.name === name);
            if (found) {
              setSelectedNode(found);
              setCurrentView('dashboard');
              setShowVRModal(false);
            }
          }}
        />
      )}

      {/* COMMAND PALETTE (⌘ + Space) */}
      <CommandPalette
        isOpen={showCommandPalette}
        onClose={() => setShowCommandPalette(false)}
        nodes={nodes}
        onSelectNode={(node) => {
          setSelectedNode(node);
          setCurrentView('dashboard');
        }}
        onNavigateTab={(tab) => {
          setCurrentView('dashboard');
          setActiveTab(tab);
        }}
      />

      {/* INFO MODALS (Pricing, Ecosystem, Docs) */}
      <InfoModals
        type={infoModalType}
        onClose={() => setInfoModalType(null)}
      />

    </div>
  );
};

export default App;
