import React, { useState, useEffect, useRef } from 'react';
import { motion, useScroll, useTransform, useSpring } from 'framer-motion';
import { 
  Search, 
  Shield, 
  Sparkles, 
  Activity, 
  Lock, 
  Zap, 
  GitBranch, 
  Cpu, 
  ChevronDown, 
  CheckCircle2, 
  ArrowRight,
  ShieldAlert,
  Terminal,
  Compass,
  ArrowDown
} from 'lucide-react';

const GithubIcon = ({ className = 'w-5 h-5' }: { className?: string }) => (
  <svg className={className} fill="currentColor" viewBox="0 0 24 24">
    <path fillRule="evenodd" clipRule="evenodd" d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.53 1.032 1.53 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0022 12.017C22 6.484 17.522 2 12 2z" />
  </svg>
);

const TOTAL_FRAMES = 300;

interface LandingHeroProps {
  onStartScan: (repoUrl: string) => void;
}

// ============================================================================
// STAGE 1: LOGO VIDEO 300-FRAME SCROLLYTELLING SEQUENCE (PURE VISUAL CANVAS)
// ============================================================================
const LogoScrollySection: React.FC = () => {
  const containerRef = useRef<HTMLDivElement>(null);
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const imagesRef = useRef<HTMLImageElement[]>([]);
  const [isLoaded, setIsLoaded] = useState(false);

  const { scrollYProgress } = useScroll({
    target: containerRef,
    offset: ['start start', 'end end'],
  });

  const smoothProgress = useSpring(scrollYProgress, {
    damping: 24,
    stiffness: 120,
    mass: 0.18,
  });

  // Cinematic Text Transitions: Strictly non-overlapping ranges (Frame 24 to Frame 205)
  // Phase 1: Frame 24 to 75 (progress 0.08 -> 0.24)
  const phase1Opacity = useTransform(smoothProgress, [0.07, 0.09, 0.22, 0.24], [0, 1, 1, 0]);
  const phase1Y = useTransform(smoothProgress, [0.07, 0.09, 0.22, 0.24], [16, 0, 0, -12]);
  const phase1Display = useTransform(smoothProgress, (v) => (v >= 0.06 && v <= 0.245 ? 'block' : 'none'));

  // Phase 2: Frame 88 to 140 (progress 0.29 -> 0.46)
  const phase2Opacity = useTransform(smoothProgress, [0.28, 0.30, 0.44, 0.46], [0, 1, 1, 0]);
  const phase2Y = useTransform(smoothProgress, [0.28, 0.30, 0.44, 0.46], [16, 0, 0, -12]);
  const phase2Display = useTransform(smoothProgress, (v) => (v >= 0.275 && v <= 0.465 ? 'block' : 'none'));

  // Phase 3: Frame 152 to 205 (progress 0.50 -> 0.6833)
  const phase3Opacity = useTransform(smoothProgress, [0.49, 0.51, 0.65, 0.6833], [0, 1, 1, 0]);
  const phase3Y = useTransform(smoothProgress, [0.49, 0.51, 0.65, 0.6833], [16, 0, 0, -12]);
  const phase3Display = useTransform(smoothProgress, (v) => (v >= 0.485 && v <= 0.6833 ? 'block' : 'none'));

  // Overall overlay container visibility
  const overlayOpacity = useTransform(smoothProgress, [0.06, 0.08, 0.67, 0.6833], [0, 1, 1, 0]);

  // Preload logo frames
  useEffect(() => {
    let count = 0;
    const images: HTMLImageElement[] = [];

    for (let i = 1; i <= TOTAL_FRAMES; i++) {
      const img = new Image();
      const num = String(i).padStart(4, '0');
      img.src = `/frames/logo/frame_${num}.jpg`;

      img.onload = () => {
        count++;
        if (count >= 5 && !isLoaded) {
          setIsLoaded(true);
          drawFrame(0);
        }
      };
      images.push(img);
    }
    imagesRef.current = images;
  }, []);

  const drawFrame = (frameIndex: number) => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    const img = imagesRef.current[frameIndex];
    if (!img || !img.complete) return;

    const canvasWidth = canvas.width;
    const canvasHeight = canvas.height;
    const imgWidth = img.width || 1234;
    const imgHeight = img.height || 674;

    const hRatio = canvasWidth / imgWidth;
    const vRatio = canvasHeight / imgHeight;
    const ratio = Math.max(hRatio, vRatio);

    const centerShift_x = (canvasWidth - imgWidth * ratio) / 2;
    const centerShift_y = (canvasHeight - imgHeight * ratio) / 2;

    ctx.clearRect(0, 0, canvasWidth, canvasHeight);
    ctx.drawImage(
      img,
      0,
      0,
      imgWidth,
      imgHeight,
      centerShift_x,
      centerShift_y,
      imgWidth * ratio,
      imgHeight * ratio
    );
  };

  useEffect(() => {
    const handleResize = () => {
      const canvas = canvasRef.current;
      if (!canvas) return;
      const dpr = window.devicePixelRatio || 1;
      canvas.width = window.innerWidth * dpr;
      canvas.height = window.innerHeight * dpr;
      const progress = smoothProgress.get();
      const frameIdx = Math.min(TOTAL_FRAMES - 1, Math.max(0, Math.floor(progress * (TOTAL_FRAMES - 1))));
      drawFrame(frameIdx);
    };

    handleResize();
    window.addEventListener('resize', handleResize);

    const unsubscribe = smoothProgress.on('change', (latest) => {
      const frameIdx = Math.min(TOTAL_FRAMES - 1, Math.max(0, Math.floor(latest * (TOTAL_FRAMES - 1))));
      drawFrame(frameIdx);
    });

    return () => {
      window.removeEventListener('resize', handleResize);
      unsubscribe();
    };
  }, [isLoaded]);

  return (
    <div ref={containerRef} className="relative h-[250vh] bg-[#0b0d0c]">
      <div className="sticky top-0 h-screen w-full overflow-hidden bg-[#0b0d0c] flex flex-col justify-center items-center select-none">
        
        {/* Fullscreen Logo 300-Frame Canvas */}
        <canvas
          ref={canvasRef}
          className="absolute inset-0 w-full h-full object-cover z-0 pointer-events-none"
        />

        {/* Subtle Obsidian Dark Edge Vignettes */}
        <div className="absolute inset-0 bg-gradient-to-t from-[#0b0d0c] via-transparent to-[#0b0d0c]/80 z-1 pointer-events-none" />
        <div className="absolute inset-0 bg-gradient-to-r from-[#0b0d0c]/60 via-transparent to-[#0b0d0c]/60 z-1 pointer-events-none" />

        {/* Centered Glowing Pure Text Transition (Frame 0024 to Frame 0205) */}
        <motion.div
          style={{ opacity: overlayOpacity }}
          className="absolute inset-0 z-10 pointer-events-none flex items-center justify-center px-6"
        >
          <div className="relative w-full max-w-4xl flex items-center justify-center">
            
            {/* Act 1: Frames 24 to 75 */}
            <motion.h2
              style={{
                opacity: phase1Opacity,
                y: phase1Y,
                display: phase1Display,
                textShadow: '0 0 15px rgba(255,255,255,0.9), 0 0 30px rgba(132,204,22,0.95), 0 0 60px rgba(132,204,22,0.7), 0 0 90px rgba(45,212,191,0.45)',
              }}
              className="text-3xl sm:text-5xl md:text-6xl font-display font-extrabold text-white tracking-tight text-center leading-tight"
            >
              Mapping Every Hidden Dependency
            </motion.h2>

            {/* Act 2: Frames 88 to 140 */}
            <motion.h2
              style={{
                opacity: phase2Opacity,
                y: phase2Y,
                display: phase2Display,
                textShadow: '0 0 15px rgba(255,255,255,0.9), 0 0 30px rgba(132,204,22,0.95), 0 0 60px rgba(132,204,22,0.7), 0 0 90px rgba(45,212,191,0.45)',
              }}
              className="absolute text-3xl sm:text-5xl md:text-6xl font-display font-extrabold text-white tracking-tight text-center leading-tight"
            >
              Isolating Threats at the Core
            </motion.h2>

            {/* Act 3: Frames 152 to 205 */}
            <motion.h2
              style={{
                opacity: phase3Opacity,
                y: phase3Y,
                display: phase3Display,
                textShadow: '0 0 15px rgba(255,255,255,0.9), 0 0 30px rgba(132,204,22,0.95), 0 0 60px rgba(132,204,22,0.7), 0 0 90px rgba(45,212,191,0.45)',
              }}
              className="absolute text-3xl sm:text-5xl md:text-6xl font-display font-extrabold text-white tracking-tight text-center leading-tight"
            >
              Anchored to the Root of Trust
            </motion.h2>

          </div>
        </motion.div>

      </div>
    </div>
  );
};

// ============================================================================
// STAGE 2: HERO VIDEO 300-FRAME SCROLLYTELLING & REPOSITORY GATEWAY
// ============================================================================
const HeroScrollySection: React.FC<LandingHeroProps> = ({ onStartScan }) => {
  const [repoInput, setRepoInput] = useState('https://github.com/facebook/react');
  const [isFocused, setIsFocused] = useState(false);
  const [isLoaded, setIsLoaded] = useState(false);

  const containerRef = useRef<HTMLDivElement>(null);
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const imagesRef = useRef<HTMLImageElement[]>([]);

  const { scrollYProgress } = useScroll({
    target: containerRef,
    offset: ['start start', 'end end'],
  });

  const smoothProgress = useSpring(scrollYProgress, {
    damping: 24,
    stiffness: 120,
    mass: 0.18,
  });

  // Preload hero frames
  useEffect(() => {
    let count = 0;
    const images: HTMLImageElement[] = [];

    for (let i = 1; i <= TOTAL_FRAMES; i++) {
      const img = new Image();
      const num = String(i).padStart(4, '0');
      img.src = `/frames/hero/frame_${num}.jpg`;

      img.onload = () => {
        count++;
        if (count >= 5 && !isLoaded) {
          setIsLoaded(true);
          drawFrame(0);
        }
      };
      images.push(img);
    }
    imagesRef.current = images;
  }, []);

  const drawFrame = (frameIndex: number) => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    const img = imagesRef.current[frameIndex];
    if (!img || !img.complete) return;

    const canvasWidth = canvas.width;
    const canvasHeight = canvas.height;
    const imgWidth = img.width || 1234;
    const imgHeight = img.height || 674;

    const hRatio = canvasWidth / imgWidth;
    const vRatio = canvasHeight / imgHeight;
    const ratio = Math.max(hRatio, vRatio);

    const centerShift_x = (canvasWidth - imgWidth * ratio) / 2;
    const centerShift_y = (canvasHeight - imgHeight * ratio) / 2;

    ctx.clearRect(0, 0, canvasWidth, canvasHeight);
    ctx.drawImage(
      img,
      0,
      0,
      imgWidth,
      imgHeight,
      centerShift_x,
      centerShift_y,
      imgWidth * ratio,
      imgHeight * ratio
    );
  };

  useEffect(() => {
    const handleResize = () => {
      const canvas = canvasRef.current;
      if (!canvas) return;
      const dpr = window.devicePixelRatio || 1;
      canvas.width = window.innerWidth * dpr;
      canvas.height = window.innerHeight * dpr;
      const progress = smoothProgress.get();
      const frameIdx = Math.min(TOTAL_FRAMES - 1, Math.max(0, Math.floor(progress * (TOTAL_FRAMES - 1))));
      drawFrame(frameIdx);
    };

    handleResize();
    window.addEventListener('resize', handleResize);

    const unsubscribe = smoothProgress.on('change', (latest) => {
      const frameIdx = Math.min(TOTAL_FRAMES - 1, Math.max(0, Math.floor(latest * (TOTAL_FRAMES - 1))));
      drawFrame(frameIdx);
    });

    return () => {
      window.removeEventListener('resize', handleResize);
      unsubscribe();
    };
  }, [isLoaded]);

  // Stage 2 Text Timeline Animations
  // Act 1: Search Gateway & Title - extended scroll duration so screen text stays much longer
  const act1Opacity = useTransform(smoothProgress, [0, 0.32, 0.44], [1, 1, 0]);
  const act1Scale = useTransform(smoothProgress, [0, 0.32, 0.44], [1, 1, 0.90]);
  const act1Y = useTransform(smoothProgress, [0, 0.32, 0.44], [0, 0, -40]);
  const act1Pointer = useTransform(smoothProgress, (val) => (val < 0.40 ? 'auto' : 'none'));

  // Carousel of target tags: One centered tag at a time, vanishing upwards as next enters from below
  // Tag 0 (facebook/react)
  const tag0Opacity = useTransform(smoothProgress, [0, 0.06, 0.095], [1, 1, 0]);
  const tag0Y = useTransform(smoothProgress, [0, 0.06, 0.095], [0, 0, -28]);
  const tag0Display = useTransform(smoothProgress, (v) => (v <= 0.098 ? 'flex' : 'none'));

  // Tag 1 (expressjs/express)
  const tag1Opacity = useTransform(smoothProgress, [0.06, 0.095, 0.155, 0.19], [0, 1, 1, 0]);
  const tag1Y = useTransform(smoothProgress, [0.06, 0.095, 0.155, 0.19], [28, 0, 0, -28]);
  const tag1Display = useTransform(smoothProgress, (v) => (v >= 0.058 && v <= 0.192 ? 'flex' : 'none'));

  // Tag 2 (web3/web3.js)
  const tag2Opacity = useTransform(smoothProgress, [0.155, 0.19, 0.25, 0.285], [0, 1, 1, 0]);
  const tag2Y = useTransform(smoothProgress, [0.155, 0.19, 0.25, 0.285], [28, 0, 0, -28]);
  const tag2Display = useTransform(smoothProgress, (v) => (v >= 0.152 && v <= 0.288 ? 'flex' : 'none'));

  // Tag 3 (tailwindlabs/tailwindcss)
  const tag3Opacity = useTransform(smoothProgress, [0.25, 0.285, 0.35], [0, 1, 1]);
  const tag3Y = useTransform(smoothProgress, [0.25, 0.285, 0.35], [28, 0, 0]);
  const tag3Display = useTransform(smoothProgress, (v) => (v >= 0.248 ? 'flex' : 'none'));

  const targetTagTransforms = [
    { opacity: tag0Opacity, y: tag0Y, display: tag0Display },
    { opacity: tag1Opacity, y: tag1Y, display: tag1Display },
    { opacity: tag2Opacity, y: tag2Y, display: tag2Display },
    { opacity: tag3Opacity, y: tag3Y, display: tag3Display },
  ];

  // Act 2: Left-side Heuristic Zero-Day Alert (Scroll 42% - 68%)
  const act2Opacity = useTransform(smoothProgress, [0.42, 0.50, 0.62, 0.70], [0, 1, 1, 0]);
  const act2X = useTransform(smoothProgress, [0.42, 0.50, 0.62, 0.70], [-350, 0, 0, -350]);

  // Act 3: Right-side Polygon PoS Consensus Callout (Scroll 66% - 88%)
  const act3Opacity = useTransform(smoothProgress, [0.66, 0.74, 0.84, 0.89], [0, 1, 1, 0]);
  const act3X = useTransform(smoothProgress, [0.66, 0.74, 0.84, 0.89], [350, 0, 0, 350]);

  // Act 4: Live Repository Gateway & 4-Column Metrics Grid (Scroll 86% - 100%)
  const act4Opacity = useTransform(smoothProgress, [0.86, 0.93, 1], [0, 1, 1]);
  const act4Y = useTransform(smoothProgress, [0.86, 0.93, 1], [50, 0, 0]);
  const act4Pointer = useTransform(smoothProgress, (val) => (val >= 0.86 ? 'auto' : 'none'));

  const canvasOverlayOpacity = useTransform(smoothProgress, [0, 0.35, 0.75, 1], [0.40, 0.55, 0.65, 0.75]);

  const presets = [
    { label: 'facebook/react', url: 'https://github.com/facebook/react', risk: 'High Anomaly' },
    { label: 'expressjs/express', url: 'https://github.com/expressjs/express', risk: 'Verified' },
    { label: 'web3/web3.js', url: 'https://github.com/web3/web3.js', risk: 'Zero-Day Alert' },
    { label: 'tailwindlabs/tailwindcss', url: 'https://github.com/tailwindlabs/tailwindcss', risk: 'Review' },
  ];

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (repoInput.trim()) {
      onStartScan(repoInput.trim());
    }
  };

  return (
    <div ref={containerRef} className="relative h-[380vh] bg-[#0b0d0c]">
      <div className="sticky top-0 h-screen w-full overflow-hidden bg-[#0b0d0c] flex flex-col justify-between select-none">
        
        {/* Hero 300-Frame Canvas */}
        <canvas
          ref={canvasRef}
          className="absolute inset-0 w-full h-full object-cover z-0 pointer-events-none"
        />

        {/* Dynamic Darkening Vignette Overlays */}
        <motion.div
          style={{ opacity: canvasOverlayOpacity }}
          className="absolute inset-0 bg-[#0b0d0c] z-1 pointer-events-none"
        />
        <div className="absolute inset-0 bg-gradient-to-t from-[#0b0d0c] via-transparent to-[#0b0d0c]/80 z-2 pointer-events-none" />
        <div className="absolute inset-0 bg-gradient-to-r from-[#0b0d0c]/70 via-transparent to-[#0b0d0c]/70 z-2 pointer-events-none" />

        {/* Top Spacer for Fixed Navbar */}
        <div className="h-20 shrink-0 pointer-events-none" />

        {/* Act 1: Search Gateway */}
        <motion.div
          style={{
            opacity: act1Opacity,
            scale: act1Scale,
            y: act1Y,
            pointerEvents: act1Pointer as any,
          }}
          className="relative z-10 max-w-4xl mx-auto px-4 w-full text-center my-auto flex flex-col items-center justify-center"
        >
          <h1 className="text-4xl sm:text-6xl lg:text-7xl font-sans font-extrabold tracking-tight text-white max-w-4xl mx-auto leading-[1.1] mb-5">
            Step Into the Future of <br className="hidden sm:inline" />
            <span className="bg-clip-text text-transparent bg-gradient-to-r from-emerald-500 via-lime-400 to-stone-300">
              Code Security
            </span>
          </h1>

          <p className="max-w-2xl mx-auto text-base sm:text-lg text-stone-300 font-sans font-normal leading-relaxed mb-8">
            300-frame deep application telemetry. Intercept zero-days, analyze dependency trees, and anchor cryptographic proofs.
          </p>

          <div className="w-full max-w-2xl mx-auto mb-4">
            <form
              onSubmit={handleSubmit}
              className={`relative rounded-2xl p-1 transition-all duration-200 ${
                isFocused
                  ? 'bg-[#181a17] border border-lime-600/40'
                  : 'bg-[#141614] border border-stone-800'
              }`}
            >
              <div className="flex flex-col sm:flex-row items-center gap-2 bg-[#0e100f] rounded-xl p-2">
                <div className="flex items-center pl-3 text-stone-400">
                  <GithubIcon className="w-5 h-5 text-stone-400" />
                </div>
                <input
                  type="text"
                  value={repoInput}
                  onChange={(e) => setRepoInput(e.target.value)}
                  onFocus={() => setIsFocused(true)}
                  onBlur={() => setIsFocused(false)}
                  placeholder="Enter GitHub Repository URL (e.g., https://github.com/facebook/react)..."
                  className="w-full bg-transparent px-3 py-3 text-sm md:text-base font-sans text-white placeholder-stone-500 focus:outline-none"
                />
                <button
                  type="submit"
                  id="scan-repo-btn"
                  className="w-full sm:w-auto shrink-0 flex items-center justify-center space-x-2 px-6 py-3.5 rounded-xl bg-gradient-to-r from-lime-600 via-emerald-600 to-stone-700 hover:from-lime-500 hover:to-emerald-500 text-stone-950 font-sans font-bold text-xs tracking-wider border border-lime-500/20 transition-all duration-200 active:scale-95"
                >
                  <Search className="w-4 h-4 stroke-[2.5]" />
                  <span>SCAN REPOSITORY</span>
                </button>
              </div>
            </form>

            {/* Target Carousel: centered, vanishes upwards, next enters from below */}
            <div className="flex items-center justify-center gap-2.5 mt-4 text-xs font-sans text-stone-400">
              <span className="text-stone-500 flex items-center gap-1 font-medium shrink-0">
                <Zap className="w-3.5 h-3.5 text-lime-400" /> TARGET:
              </span>

              <div className="relative h-9 min-w-[290px] sm:min-w-[340px] flex items-center justify-center overflow-hidden">
                {presets.map((preset, idx) => (
                  <motion.button
                    key={preset.label}
                    type="button"
                    style={{
                      opacity: targetTagTransforms[idx].opacity,
                      y: targetTagTransforms[idx].y,
                      display: targetTagTransforms[idx].display,
                    }}
                    onClick={() => {
                      setRepoInput(preset.url);
                      onStartScan(preset.url);
                    }}
                    className="absolute px-3.5 py-1.5 rounded-full bg-[#121412] border border-stone-800 hover:border-lime-700/50 hover:text-lime-300 text-stone-300 transition-colors flex items-center gap-2 cursor-pointer shadow-sm"
                  >
                    <span className="font-medium text-xs text-stone-200">{preset.label}</span>
                    <span className={`text-[10px] px-2 py-0.5 rounded-full font-medium ${
                      preset.risk.includes('Zero') ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30' :
                      preset.risk.includes('High') ? 'bg-amber-500/20 text-amber-300 border border-amber-500/30' : 'bg-lime-500/20 text-lime-400 border border-lime-500/30'
                    }`}>
                      {preset.risk}
                    </span>
                  </motion.button>
                ))}
              </div>
            </div>
          </div>

          {/* Clean arrow without tail (no text, pure chevron) */}
          <motion.div
            animate={{ y: [0, 8, 0] }}
            transition={{ repeat: Infinity, duration: 1.8, ease: 'easeInOut' }}
            className="flex justify-center items-center mt-6 text-stone-400 hover:text-lime-400 transition-colors"
          >
            <ChevronDown className="w-6 h-6 stroke-[2]" />
          </motion.div>
        </motion.div>

        {/* Act 2: Left-side Heuristic Zero-Day */}
        <motion.div
          style={{ x: act2X, opacity: act2Opacity }}
          className="absolute left-6 md:left-16 top-1/2 -translate-y-1/2 z-20 max-w-md w-full pointer-events-none"
        >
          <div className="rounded-2xl p-6 bg-[#121412] border border-stone-800 pointer-events-auto shadow-lg">
            <div className="flex items-center justify-between mb-3">
              <span className="text-[10px] font-mono font-semibold px-2.5 py-0.5 rounded-md bg-[#161a15] text-lime-400 border border-lime-800/40 uppercase tracking-wider flex items-center gap-1.5">
                <Shield className="w-3.5 h-3.5 text-lime-400" /> 01 // HEURISTIC INTERCEPTOR
              </span>
              <span className="text-xs font-mono text-lime-400 flex items-center gap-1">
                <CheckCircle2 className="w-3.5 h-3.5" /> ACTIVE GATE
              </span>
            </div>

            <h3 className="font-sans font-bold text-xl text-white mb-2">
              Catch Zero-Days Before Merge
            </h3>
            <p className="text-xs sm:text-sm text-stone-300 font-sans leading-relaxed mb-4">
              Our autonomous classifier monitors maintainer velocity shifts, high-entropy bytecode injection, and hidden socket calls before packages reach your production fleet.
            </p>

            <div className="p-3 rounded-xl bg-[#0e100f] border border-stone-850 space-y-2 text-xs font-mono">
              <div className="flex justify-between text-stone-400">
                <span>Zero-Days Neutralized:</span>
                <span className="text-rose-400 font-bold">14,290</span>
              </div>
              <div className="flex justify-between text-stone-400">
                <span>False-Positive Ratio:</span>
                <span className="text-lime-400 font-bold">0.00%</span>
              </div>
              <div className="flex justify-between text-stone-400">
                <span>Classification Latency:</span>
                <span className="text-lime-400 font-bold">&lt; 420 ms</span>
              </div>
            </div>
          </div>
        </motion.div>

        {/* Act 3: Right-side Polygon Trust Anchor */}
        <motion.div
          style={{ x: act3X, opacity: act3Opacity }}
          className="absolute right-6 md:right-16 top-1/2 -translate-y-1/2 z-20 max-w-md w-full pointer-events-none"
        >
          <div className="rounded-2xl p-6 bg-[#121412] border border-stone-800 pointer-events-auto shadow-lg">
            <div className="flex items-center justify-between mb-3">
              <span className="text-[10px] font-mono font-semibold px-2.5 py-0.5 rounded-md bg-[#161a15] text-lime-400 border border-lime-800/40 uppercase tracking-wider flex items-center gap-1.5">
                <Lock className="w-3.5 h-3.5 text-lime-400" /> 02 // ON-CHAIN CONSENSUS
              </span>
              <span className="text-xs font-mono text-lime-400">
                100% IMMUTABLE
              </span>
            </div>

            <h3 className="font-sans font-bold text-xl text-white mb-2">
              Polygon PoS Trust Anchor
            </h3>
            <p className="text-xs sm:text-sm text-stone-300 font-sans leading-relaxed mb-4">
              Audit results and package state hashes are cryptographically anchored to Polygon mainnet, providing mathematical proof of zero tampering.
            </p>

            <div className="p-3 rounded-xl bg-[#0e100f] border border-stone-850 space-y-2 text-xs font-mono">
              <div className="flex justify-between text-stone-400">
                <span>Mainnet Anchor Block:</span>
                <span className="text-stone-200 font-bold">#5,928,174</span>
              </div>
              <div className="flex justify-between text-stone-400">
                <span>Ledger Integrity:</span>
                <span className="text-lime-400 font-bold">Verified</span>
              </div>
              <div className="flex justify-between text-stone-400">
                <span>Merkle Roots Anchored:</span>
                <span className="text-stone-200 font-bold">2,847 Anchors</span>
              </div>
            </div>
          </div>
        </motion.div>

        {/* Act 4: Live Repository Gateway & Stats */}
        <motion.div
          style={{
            opacity: act4Opacity,
            y: act4Y,
            pointerEvents: act4Pointer as any,
          }}
          className="absolute inset-x-0 bottom-16 z-30 max-w-5xl mx-auto px-4 w-full"
        >
          <div className="text-center mb-5">
            <span className="text-xs font-mono uppercase tracking-widest text-lime-400 font-semibold flex items-center justify-center gap-1.5 mb-1">
              <Zap className="w-3.5 h-3.5 text-lime-400" /> 03 // LIVE REPOSITORY GATEWAY
            </span>
            <h2 className="text-2xl sm:text-4xl font-sans font-bold text-white tracking-tight">
              Audit Any Repository in Real-Time
            </h2>
          </div>

          <form
            onSubmit={handleSubmit}
            className={`relative rounded-2xl p-1 transition-all duration-200 mb-4 ${
              isFocused
                ? 'bg-[#181a17] border border-lime-600/40'
                : 'bg-[#141614] border border-stone-800'
            }`}
          >
            <div className="flex flex-col sm:flex-row items-center gap-2 bg-[#0e100f] rounded-xl p-2">
              <div className="flex items-center pl-3 text-stone-400">
                <GithubIcon className="w-5 h-5 text-stone-400" />
              </div>
              <input
                type="text"
                value={repoInput}
                onChange={(e) => setRepoInput(e.target.value)}
                onFocus={() => setIsFocused(true)}
                onBlur={() => setIsFocused(false)}
                placeholder="Enter GitHub Repository URL (e.g., https://github.com/facebook/react)..."
                className="w-full bg-transparent px-3 py-3 text-sm md:text-base font-sans text-white placeholder-stone-500 focus:outline-none"
              />
              <button
                type="submit"
                id="scan-repo-btn-stage2"
                className="w-full sm:w-auto shrink-0 flex items-center justify-center space-x-2 px-6 py-3.5 rounded-xl bg-gradient-to-r from-lime-600 via-emerald-600 to-stone-700 hover:from-lime-500 hover:to-emerald-500 text-stone-950 font-sans font-bold text-xs tracking-wider border border-lime-500/20 transition-all duration-200 active:scale-95"
              >
                <Search className="w-4 h-4 stroke-[2.5]" />
                <span>SCAN REPOSITORY</span>
              </button>
            </div>
          </form>

          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            <div className="rounded-xl bg-[#121412] p-3.5 text-left border border-stone-800">
              <div className="flex items-center space-x-1.5 text-stone-400 text-xs font-sans mb-1">
                <Activity className="w-3.5 h-3.5 text-lime-400" />
                <span>PACKAGES AUDITED</span>
              </div>
              <div className="text-2xl font-sans font-bold text-white">482,910</div>
              <div className="text-[11px] text-lime-400 mt-1">+18.4% weekly</div>
            </div>

            <div className="rounded-xl bg-[#121412] p-3.5 text-left border border-stone-800">
              <div className="flex items-center space-x-1.5 text-stone-400 text-xs font-sans mb-1">
                <Shield className="w-3.5 h-3.5 text-rose-400" />
                <span>ZERO-DAYS BLOCKED</span>
              </div>
              <div className="text-2xl font-sans font-bold text-rose-400">14,290</div>
              <div className="text-[11px] text-stone-400 mt-1">0% false-positives</div>
            </div>

            <div className="rounded-xl bg-[#121412] p-3.5 text-left border border-stone-800">
              <div className="flex items-center space-x-1.5 text-stone-400 text-xs font-sans mb-1">
                <Lock className="w-3.5 h-3.5 text-stone-300" />
                <span>POLYGON ANCHOR</span>
              </div>
              <div className="text-2xl font-sans font-bold text-white">100% PROVEN</div>
              <div className="text-[11px] font-mono text-lime-400 mt-1">Block #5.9M</div>
            </div>

            <div className="rounded-xl bg-[#121412] p-3.5 text-left border border-stone-800">
              <div className="flex items-center space-x-1.5 text-stone-400 text-xs font-sans mb-1">
                <Sparkles className="w-3.5 h-3.5 text-lime-400" />
                <span>HEURISTIC SPEED</span>
              </div>
              <div className="text-2xl font-sans font-bold text-white">&lt; 420 ms</div>
              <div className="text-[11px] text-lime-400 mt-1">Real-time scan</div>
            </div>
          </div>
        </motion.div>
      </div>
    </div>
  );
};

// ============================================================================
// MAIN COMPONENT: SEQUENTIAL MULTI-STAGE SCROLLING (LOGO -> HERO)
// ============================================================================
export const LandingHero: React.FC<LandingHeroProps> = ({ onStartScan }) => {
  return (
    <div className="w-full bg-[#0b0d0c]">
      {/* 1. First Page: Logo Video 300-Frame Scrollytelling Sequence */}
      <LogoScrollySection />

      {/* 2. Second Page: Hero Video 300-Frame Scrollytelling & Gateway */}
      <HeroScrollySection onStartScan={onStartScan} />
    </div>
  );
};
