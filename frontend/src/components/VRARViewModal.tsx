import React, { useState, useEffect } from 'react';
import { Eye, X, Compass, RotateCw, ZoomIn, ZoomOut, Layers, Radio, Shield } from 'lucide-react';

interface VRARViewModalProps {
  onClose: () => void;
  onSelectNodeByName?: (name: string) => void;
}

export const VRARViewModal: React.FC<VRARViewModalProps> = ({ onClose, onSelectNodeByName }) => {
  const [angle, setAngle] = useState(24);
  const [depth, setDepth] = useState(45);
  const [activeSpatialNode, setActiveSpatialNode] = useState<string | null>('event-stream-patch');

  // Auto rotate slightly for futuristic feel
  useEffect(() => {
    const interval = setInterval(() => {
      setAngle((prev) => (prev + 0.4) % 360);
    }, 50);
    return () => clearInterval(interval);
  }, []);

  const spatialNodes = [
    { name: '@traceroot/core', x: 0, y: 0, z: 0, risk: 12, color: '#84cc16', label: 'HUB' },
    { name: 'event-stream-patch', x: 120, y: -60, z: 80, risk: 94, color: '#f43f5e', label: 'ZERO-DAY' },
    { name: 'liblzma-native-async', x: -110, y: 80, z: -40, risk: 88, color: '#f43f5e', label: 'MALWARE' },
    { name: 'ansi-colors-turbo', x: 80, y: 70, z: -60, risk: 58, color: '#65a30d', label: 'DORMANT' },
    { name: 'react-dom-renderer', x: -90, y: -80, z: 50, risk: 18, color: '#3f6212', label: 'VENDOR' },
    { name: 'elliptic-curve-fast', x: 0, y: 130, z: 30, risk: 42, color: '#84cc16', label: 'LEAK' },
  ];

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-stone-950/85 backdrop-blur-md">
      <div className="relative w-full max-w-5xl h-[85vh] rounded-3xl bg-[#121412] border border-stone-800 flex flex-col justify-between overflow-hidden shadow-2xl">
        
        {/* Top VR HUD Bar */}
        <div className="p-6 flex items-center justify-between border-b border-stone-800 relative z-20 bg-[#0b0d0c]">
          <div className="flex items-center space-x-3">
            <div className="w-10 h-10 rounded-xl bg-[#121412] border border-stone-800 flex items-center justify-center text-lime-400">
              <Eye className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-display font-bold text-lg text-stone-100">
                  Spatial 3D Topology Matrix // VR/AR View
                </span>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded-md bg-lime-950/60 text-lime-400 border border-lime-800/40">
                  HMD PROTOCOL v2.1
                </span>
              </div>
              <p className="text-xs font-mono text-stone-400 mt-0.5">
                Spatial Coordinate Engine • Yaw: {Math.round(angle)}° • Pitch: 32° • Roll: 0°
              </p>
            </div>
          </div>

          <div className="flex items-center space-x-2">
            <button
              onClick={() => setAngle((a) => a + 30)}
              className="p-2 rounded-xl bg-[#121412] border border-stone-800 hover:border-lime-700/50 text-stone-300 hover:text-white transition-colors"
              title="Manual Rotate"
            >
              <RotateCw className="w-4 h-4" />
            </button>
            <button
              onClick={onClose}
              className="p-2 rounded-xl bg-[#121412] border border-stone-800 hover:border-stone-700 text-stone-300 hover:text-white transition-colors"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* 3D Spatial Canvas Area */}
        <div className="relative flex-1 w-full flex items-center justify-center overflow-hidden">
          
          {/* Orbital Depth Rings */}
          <div className="absolute w-[600px] h-[600px] rounded-full border border-stone-800 pointer-events-none animate-spin" style={{ animationDuration: '60s' }} />
          <div className="absolute w-[440px] h-[440px] rounded-full border border-stone-800/80 pointer-events-none" />
          <div className="absolute w-[280px] h-[280px] rounded-full border border-lime-900/30 pointer-events-none" />

          {/* Central Grid Plane */}
          <div
            className="relative w-96 h-96 transition-transform duration-100 flex items-center justify-center"
            style={{
              transform: `perspective(800px) rotateX(60deg) rotateZ(${angle}deg)`,
              transformStyle: 'preserve-3d',
            }}
          >
            {/* Grid Floor */}
            <div className="absolute inset-0 border border-lime-800/30 sage-grid opacity-60 rounded-full" />

            {/* Center Hub */}
            <div className="w-12 h-12 rounded-full bg-lime-950/60 border-2 border-lime-600 flex items-center justify-center">
              <div className="w-4 h-4 rounded-full bg-lime-400" />
            </div>

            {/* Floating Spatial Nodes */}
            {spatialNodes.map((node, index) => {
              const rad = (angle + index * 60) * (Math.PI / 180);
              const dist = 140 + (index % 2) * 50;
              const px = Math.cos(rad) * dist;
              const py = Math.sin(rad) * dist;

              return (
                <div
                  key={node.name}
                  onClick={() => {
                    setActiveSpatialNode(node.name);
                    if (onSelectNodeByName) onSelectNodeByName(node.name);
                  }}
                  style={{
                    transform: `translate(${px}px, ${py}px) rotateZ(-${angle}deg) rotateX(-60deg)`,
                    transformStyle: 'preserve-3d',
                  }}
                  className="absolute cursor-pointer group"
                >
                  <div
                    className="p-3 rounded-xl border font-sans text-xs transition-all duration-200 hover:scale-105"
                    style={{
                      background: '#121412',
                      borderColor: node.color,
                    }}
                  >
                    <div className="flex items-center space-x-1.5 text-[9px] font-mono">
                      <span className="w-1.5 h-1.5 rounded-full" style={{ backgroundColor: node.color }} />
                      <span style={{ color: node.color }} className="font-bold">{node.label}</span>
                    </div>
                    <div className="text-white font-semibold truncate max-w-[120px] mt-0.5">
                      {node.name}
                    </div>
                    <div className="text-[10px] font-mono text-stone-400 mt-1">
                      Risk: {node.risk}/100
                    </div>
                  </div>
                </div>
              );
            })}
          </div>

          {/* HUD Target Lock on Selected Node */}
          {activeSpatialNode && (
            <div className="absolute bottom-6 left-6 p-4 rounded-xl bg-[#121412] border border-stone-800 max-w-xs text-xs">
              <div className="text-[10px] text-lime-400 uppercase tracking-wider mb-1 flex items-center gap-1 font-semibold">
                <Radio className="w-3 h-3" /> Spatial Target Lock
              </div>
              <div className="text-stone-100 font-bold text-sm font-mono">{activeSpatialNode}</div>
              <p className="text-stone-400 text-xs font-sans mt-1">
                Visualizing multi-dimensional dependency supply paths through 3D graph vectorization.
              </p>
            </div>
          )}

          {/* HUD Sensor Coordinates on Right */}
          <div className="absolute top-6 right-6 p-3 rounded-xl bg-[#121412] border border-stone-800 font-mono text-[10px] text-stone-400 space-y-1">
            <div>FOV: 110° STEREOSCOPIC</div>
            <div>RENDER PIPELINE: WEBGL-ACCELERATED</div>
            <div>LATENCY: 4.2ms M2P</div>
            <div className="text-lime-400">STATUS: TRACKING STABLE</div>
          </div>
        </div>

        {/* Bottom Bar */}
        <div className="p-4 bg-[#0b0d0c] border-t border-stone-800 flex items-center justify-between text-xs text-stone-400 relative z-20">
          <span className="font-sans">Spatial Orbit Controls: Mouse Drag to Reposition • Scroll to Zoom</span>
          <button
            onClick={onClose}
            className="px-5 py-2 rounded-xl bg-gradient-to-r from-lime-600 via-emerald-700 to-stone-800 hover:from-lime-500 hover:to-emerald-600 text-stone-100 font-semibold text-xs border border-lime-500/30 transition-all"
          >
            Exit VR View
          </button>
        </div>

      </div>
    </div>
  );
};
