/**
 * TraceRoot DevSecOps Sentinel - GitHub Content Script (Manifest V3)
 * Detects GitHub repository roots, injects a cyber-themed "🛡️ Scan Dependencies" button,
 * and renders an in-page cyber HUD modal with vulnerability and Web3 anchor data.
 */

(function () {
  const BUTTON_ID = "traceroot-scan-btn";
  const MODAL_ID = "traceroot-hud-modal";
  let isScanning = false;

  /**
   * Reserved GitHub top-level path segments that are NOT user/org repositories
   */
  const RESERVED_ROUTES = new Set([
    "settings", "notifications", "explore", "trending", "topics", "collections",
    "events", "sponsors", "features", "enterprise", "pricing", "marketplace",
    "login", "join", "security", "customer-stories", "readme", "pulls", "issues",
    "discussions", "dashboard", "orgs", "organizations"
  ]);

  /**
   * Validates if current page is a GitHub repository root
   * Returns clean repo URL (e.g., https://github.com/owner/repo) or null
   */
  function getRepoUrlIfRoot() {
    if (window.location.hostname !== "github.com") return null;

    const pathSegments = window.location.pathname.replace(/^\/+|\/+$/g, "").split("/");
    if (pathSegments.length < 2) return null;

    const [owner, repo, section] = pathSegments;

    // Check if the first segment is a reserved route
    if (RESERVED_ROUTES.has(owner.toLowerCase())) return null;

    // Root is either /owner/repo or /owner/repo/tree/main (branch root)
    if (pathSegments.length === 2) {
      return `https://github.com/${owner}/${repo}`;
    }

    if (pathSegments.length >= 3 && section === "tree") {
      return `https://github.com/${owner}/${repo}`;
    }

    return null;
  }

  /**
   * Injects the cyber-themed scan button into GitHub's UI
   */
  function injectScanButton() {
    const repoUrl = getRepoUrlIfRoot();
    if (!repoUrl) {
      removeExistingButton();
      return;
    }

    // Already injected?
    if (document.getElementById(BUTTON_ID)) return;

    // Search for high-visibility injection targets next to GitHub's "Code" button
    const injectionTarget = findButtonInsertionTarget();
    if (!injectionTarget) return;

    const button = document.createElement("button");
    button.id = BUTTON_ID;
    button.type = "button";
    button.className = "traceroot-cyber-btn";
    button.innerHTML = `
      <span class="traceroot-shield-icon">🛡️</span>
      <span class="traceroot-btn-label">Scan Dependencies</span>
      <span class="traceroot-pulse-dot"></span>
    `;

    button.addEventListener("click", () => handleTriggerScan(repoUrl, button));

    // Insert next to target
    if (injectionTarget.parentElement) {
      injectionTarget.parentElement.insertBefore(button, injectionTarget);
    }
  }

  /**
   * Finds suitable anchor elements in GitHub's DOM
   */
  function findButtonInsertionTarget() {
    // 1. Classic & modern File Navigation container (next to Code button)
    const codeBtn = document.querySelector("get-repo") ||
                    document.querySelector("[data-component='PH_ActionMenu']") ||
                    document.querySelector(".file-navigation get-repo") ||
                    document.querySelector(".file-navigation .btn-primary") ||
                    document.querySelector(".file-navigation summary");

    if (codeBtn) return codeBtn;

    // 2. File navigation bar fallback
    const fileNav = document.querySelector(".file-navigation");
    if (fileNav) return fileNav.firstElementChild;

    // 3. Top pagehead actions (near Star/Fork buttons)
    const pageActions = document.querySelector("#repository-container-header ul.pagehead-actions") ||
                        document.querySelector(".pagehead-actions");
    if (pageActions) return pageActions.firstElementChild;

    return null;
  }

  function removeExistingButton() {
    const btn = document.getElementById(BUTTON_ID);
    if (btn) btn.remove();
  }

  /**
   * Dispatches scan request to background service worker and renders results
   */
  async function handleTriggerScan(repoUrl, buttonElement) {
    if (isScanning) return;
    isScanning = true;

    // Update button UI to scanning state
    buttonElement.classList.add("traceroot-btn-scanning");
    buttonElement.innerHTML = `
      <span class="traceroot-spinner"></span>
      <span class="traceroot-btn-label">Auditing via FastAPI...</span>
    `;

    try {
      // Send message to background service worker to bypass CORS
      chrome.runtime.sendMessage(
        { action: "SCAN_REPO", github_url: repoUrl },
        (response) => {
          isScanning = false;
          buttonElement.classList.remove("traceroot-btn-scanning");
          buttonElement.innerHTML = `
            <span class="traceroot-shield-icon">🛡️</span>
            <span class="traceroot-btn-label">Scan Dependencies</span>
            <span class="traceroot-pulse-dot"></span>
          `;

          if (chrome.runtime.lastError) {
            showHudModal({
              success: false,
              error: chrome.runtime.lastError.message || "Failed to contact background service worker.",
              repoUrl,
            });
            return;
          }

          if (!response || !response.success) {
            showHudModal({
              success: false,
              error: response?.error || "DevSecOps scanner returned an error.",
              repoUrl,
            });
            return;
          }

          showHudModal({
            success: true,
            data: response.data,
            repoUrl,
          });
        }
      );
    } catch (err) {
      isScanning = false;
      buttonElement.classList.remove("traceroot-btn-scanning");
      buttonElement.innerHTML = `
        <span class="traceroot-shield-icon">🛡️</span>
        <span class="traceroot-btn-label">Scan Dependencies</span>
        <span class="traceroot-pulse-dot"></span>
      `;
      showHudModal({
        success: false,
        error: err.message || "Unexpected client error.",
        repoUrl,
      });
    }
  }

  /**
   * Renders the Cyber HUD Modal on the GitHub page
   */
  function showHudModal(result) {
    const existing = document.getElementById(MODAL_ID);
    if (existing) existing.remove();

    const overlay = document.createElement("div");
    overlay.id = MODAL_ID;
    overlay.className = "traceroot-overlay";

    if (!result.success) {
      overlay.innerHTML = `
        <div class="traceroot-modal-card traceroot-modal-error">
          <div class="traceroot-modal-header">
            <div class="traceroot-modal-title">
              <span class="traceroot-icon-neon">⚠️</span>
              <h3>TraceRoot DevSecOps Sentinel</h3>
            </div>
            <button class="traceroot-close-btn" id="traceroot-close-modal">✕</button>
          </div>
          <div class="traceroot-modal-body">
            <div class="traceroot-alert-box">
              <span class="traceroot-alert-badge">SCAN FAILED</span>
              <p class="traceroot-error-text">${escapeHtml(result.error)}</p>
              <div class="traceroot-tip">
                Ensure your FastAPI backend is running at <code>https://traceroot-br3o.onrender.com/api/scan</code>.
              </div>
            </div>
          </div>
        </div>
      `;
    } else {
      const data = result.data || {};
      const dependencies = Array.isArray(data.dependencies) ? data.dependencies : [];
      const txHash = data.transaction_hash || "0x0000000000000000000000000000000000000000";

      // Calculate highest risk score and identify the top threat package
      let maxRisk = 0;
      let topThreatPkg = null;

      dependencies.forEach((dep) => {
        const score = typeof dep.final_risk_score === "number" ? dep.final_risk_score : 0;
        if (score >= maxRisk) {
          maxRisk = score;
          topThreatPkg = dep;
        }
      });

      // Fallback if no dependencies returned
      if (!topThreatPkg && dependencies.length > 0) {
        topThreatPkg = dependencies[0];
      }

      // Risk level classification
      let riskClass = "traceroot-risk-low";
      let riskBadge = "LOW RISK // SAFE";
      let riskColor = "#00ff88";

      if (maxRisk >= 70) {
        riskClass = "traceroot-risk-critical";
        riskBadge = "CRITICAL RISK // IMMEDIATE ACTION";
        riskColor = "#ff0055";
      } else if (maxRisk >= 30) {
        riskClass = "traceroot-risk-medium";
        riskBadge = "ELEVATED RISK // REVIEW REQUIRED";
        riskColor = "#ffaa00";
      }

      const explanation = topThreatPkg?.ai_threat_explanation || "No critical vulnerability explanations flagged by Gemini AI engine.";

      // Truncate transaction hash for display
      const shortTx = txHash.length > 18 ? `${txHash.slice(0, 10)}...${txHash.slice(-8)}` : txHash;

      overlay.innerHTML = `
        <div class="traceroot-modal-card ${riskClass}">
          <div class="traceroot-modal-header">
            <div class="traceroot-modal-title">
              <span class="traceroot-cyber-logo">🛡️</span>
              <div>
                <h3>TraceRoot DevSecOps Sentinel</h3>
                <span class="traceroot-repo-tag">${escapeHtml(result.repoUrl)}</span>
              </div>
            </div>
            <button class="traceroot-close-btn" id="traceroot-close-modal">✕</button>
          </div>

          <div class="traceroot-modal-body">
            <!-- Overall Risk Gauge -->
            <div class="traceroot-metric-grid">
              <div class="traceroot-risk-card ${riskClass}">
                <div class="traceroot-risk-header">
                  <span class="traceroot-label">MAX RISK RATING</span>
                  <span class="traceroot-risk-pill" style="color: ${riskColor}; border-color: ${riskColor};">
                    ${riskBadge}
                  </span>
                </div>
                <div class="traceroot-score-display">
                  <span class="traceroot-score-num" style="color: ${riskColor}; text-shadow: 0 0 15px ${riskColor};">
                    ${maxRisk}
                  </span>
                  <span class="traceroot-score-total">/ 100</span>
                </div>
                <div class="traceroot-meter-bar">
                  <div class="traceroot-meter-fill" style="width: ${Math.min(maxRisk, 100)}%; background: ${riskColor}; box-shadow: 0 0 10px ${riskColor};"></div>
                </div>
              </div>

              <!-- Web3 Blockchain Anchor -->
              <div class="traceroot-web3-card">
                <div class="traceroot-web3-header">
                  <span class="traceroot-web3-badge">✅ Anchored to Web3</span>
                  <span class="traceroot-chain-tag">POLYGON / ETHEREUM</span>
                </div>
                <div class="traceroot-tx-display">
                  <span class="traceroot-tx-label">TX HASH:</span>
                  <code class="traceroot-tx-code" title="${escapeHtml(txHash)}">${escapeHtml(shortTx)}</code>
                  <button class="traceroot-copy-btn" id="traceroot-copy-tx" data-tx="${escapeHtml(txHash)}" title="Copy Hash">📋</button>
                </div>
              </div>
            </div>

            <!-- Gemini AI Threat Vector Explanation -->
            <div class="traceroot-ai-card">
              <div class="traceroot-ai-header">
                <span class="traceroot-ai-icon">🤖</span>
                <span class="traceroot-ai-title">GEMINI AI THREAT SYNTHESIS</span>
                ${topThreatPkg ? `<span class="traceroot-pkg-target">TARGET: ${escapeHtml(topThreatPkg.package || topThreatPkg.name || "Top Package")}</span>` : ""}
              </div>
              <div class="traceroot-ai-content">
                <p>${escapeHtml(explanation)}</p>
              </div>
            </div>

            <!-- Dependencies List -->
            <div class="traceroot-deps-container">
              <div class="traceroot-deps-header">
                <span>AUDITED PACKAGES (${dependencies.length})</span>
              </div>
              <div class="traceroot-deps-list">
                ${
                  dependencies.length === 0
                    ? `<div class="traceroot-dep-empty">No dependency manifests detected in scan payload.</div>`
                    : dependencies
                        .map((dep) => {
                          const depScore = dep.final_risk_score ?? 0;
                          const depFlags = Array.isArray(dep.risk_flags) ? dep.risk_flags : [];
                          const depColor = depScore >= 70 ? "#ff0055" : depScore >= 30 ? "#ffaa00" : "#00ff88";

                          return `
                            <div class="traceroot-dep-item">
                              <div class="traceroot-dep-left">
                                <span class="traceroot-dep-name">${escapeHtml(dep.package || dep.name || "dependency")}</span>
                                <div class="traceroot-flags">
                                  ${
                                    depFlags.length > 0
                                      ? depFlags.map((f) => `<span class="traceroot-flag-tag">${escapeHtml(f)}</span>`).join("")
                                      : `<span class="traceroot-flag-clean">PASSED CHECKS</span>`
                                  }
                                </div>
                              </div>
                              <div class="traceroot-dep-right">
                                <span class="traceroot-dep-score" style="color: ${depColor}; border-color: ${depColor};">
                                  SCORE ${depScore}
                                </span>
                              </div>
                            </div>
                          `;
                        })
                        .join("")
                }
              </div>
            </div>
          </div>
        </div>
      `;
    }

    document.body.appendChild(overlay);

    // Event Listeners for modal
    const closeBtn = document.getElementById("traceroot-close-modal");
    if (closeBtn) {
      closeBtn.addEventListener("click", () => overlay.remove());
    }

    overlay.addEventListener("click", (e) => {
      if (e.target === overlay) overlay.remove();
    });

    const copyBtn = document.getElementById("traceroot-copy-tx");
    if (copyBtn) {
      copyBtn.addEventListener("click", () => {
        const hash = copyBtn.getAttribute("data-tx");
        if (hash) {
          navigator.clipboard.writeText(hash).then(() => {
            copyBtn.textContent = "✔";
            setTimeout(() => (copyBtn.textContent = "📋"), 1500);
          });
        }
      });
    }
  }

  function escapeHtml(str) {
    if (!str) return "";
    return String(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }

  /**
   * Inject Cyber styling rules for the button and modal
   */
  function injectStyles() {
    if (document.getElementById("traceroot-styles")) return;

    const style = document.createElement("style");
    style.id = "traceroot-styles";
    style.textContent = `
      /* Injected Cyberpunk Scan Button */
      .traceroot-cyber-btn {
        display: inline-flex;
        align-items: center;
        gap: 6px;
        background: linear-gradient(135deg, #090d16 0%, #0d1527 100%);
        color: #00f3ff;
        border: 1px solid rgba(0, 243, 255, 0.6);
        border-radius: 6px;
        padding: 5px 12px;
        font-size: 13px;
        font-weight: 600;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, monospace;
        cursor: pointer;
        position: relative;
        margin-right: 8px;
        transition: all 0.25s cubic-bezier(0.4, 0, 0.2, 1);
        box-shadow: 0 0 10px rgba(0, 243, 255, 0.2);
        vertical-align: middle;
        text-shadow: 0 0 6px rgba(0, 243, 255, 0.6);
      }

      .traceroot-cyber-btn:hover {
        background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
        border-color: #00ff88;
        color: #00ff88;
        box-shadow: 0 0 16px rgba(0, 255, 136, 0.4);
        transform: translateY(-1px);
      }

      .traceroot-shield-icon {
        font-size: 14px;
        filter: drop-shadow(0 0 4px #00f3ff);
      }

      .traceroot-pulse-dot {
        width: 6px;
        height: 6px;
        background-color: #00ff88;
        border-radius: 50%;
        display: inline-block;
        box-shadow: 0 0 8px #00ff88;
        animation: traceroot-pulse 1.8s infinite;
      }

      @keyframes traceroot-pulse {
        0% { transform: scale(0.9); opacity: 0.7; }
        50% { transform: scale(1.3); opacity: 1; box-shadow: 0 0 12px #00ff88; }
        100% { transform: scale(0.9); opacity: 0.7; }
      }

      .traceroot-btn-scanning {
        border-color: #ffaa00 !important;
        color: #ffaa00 !important;
        box-shadow: 0 0 12px rgba(255, 170, 0, 0.4) !important;
        cursor: wait !important;
      }

      .traceroot-spinner {
        width: 12px;
        height: 12px;
        border: 2px solid rgba(255, 170, 0, 0.3);
        border-top-color: #ffaa00;
        border-radius: 50%;
        animation: traceroot-spin 0.8s linear infinite;
        display: inline-block;
      }

      @keyframes traceroot-spin {
        to { transform: rotate(360deg); }
      }

      /* Modal Overlay & HUD */
      .traceroot-overlay {
        position: fixed;
        inset: 0;
        z-index: 9999999;
        background: rgba(4, 6, 12, 0.78);
        backdrop-filter: blur(8px);
        display: flex;
        align-items: center;
        justify-content: center;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, monospace;
        animation: traceroot-fade-in 0.25s ease-out;
      }

      @keyframes traceroot-fade-in {
        from { opacity: 0; }
        to { opacity: 1; }
      }

      .traceroot-modal-card {
        background: #090c15;
        width: 90%;
        max-width: 620px;
        max-height: 85vh;
        overflow-y: auto;
        border-radius: 12px;
        border: 1px solid rgba(0, 243, 255, 0.4);
        box-shadow: 0 0 35px rgba(0, 243, 255, 0.2), inset 0 0 20px rgba(0, 0, 0, 0.8);
        color: #e2e8f0;
        display: flex;
        flex-direction: column;
      }

      .traceroot-modal-card.traceroot-risk-critical {
        border-color: #ff0055;
        box-shadow: 0 0 40px rgba(255, 0, 85, 0.35);
        animation: traceroot-glow-red 2s infinite alternate;
      }

      @keyframes traceroot-glow-red {
        from { box-shadow: 0 0 25px rgba(255, 0, 85, 0.3); }
        to { box-shadow: 0 0 45px rgba(255, 0, 85, 0.6); }
      }

      .traceroot-modal-card.traceroot-risk-low {
        border-color: #00ff88;
        box-shadow: 0 0 30px rgba(0, 255, 136, 0.3);
      }

      .traceroot-modal-header {
        display: flex;
        justify-content: space-between;
        align-items: center;
        padding: 16px 20px;
        border-bottom: 1px solid rgba(255, 255, 255, 0.08);
        background: rgba(15, 23, 42, 0.6);
      }

      .traceroot-modal-title {
        display: flex;
        align-items: center;
        gap: 12px;
      }

      .traceroot-modal-title h3 {
        margin: 0;
        font-size: 16px;
        font-weight: 700;
        color: #f8fafc;
        letter-spacing: 0.5px;
      }

      .traceroot-repo-tag {
        font-size: 11px;
        color: #94a3b8;
        font-family: monospace;
      }

      .traceroot-close-btn {
        background: none;
        border: none;
        color: #94a3b8;
        font-size: 18px;
        cursor: pointer;
        padding: 4px 8px;
        transition: color 0.2s;
      }

      .traceroot-close-btn:hover {
        color: #ff0055;
      }

      .traceroot-modal-body {
        padding: 20px;
        display: flex;
        flex-direction: column;
        gap: 16px;
      }

      .traceroot-metric-grid {
        display: grid;
        grid-template-columns: 1fr 1fr;
        gap: 12px;
      }

      .traceroot-risk-card, .traceroot-web3-card {
        background: rgba(15, 23, 42, 0.5);
        border: 1px solid rgba(255, 255, 255, 0.08);
        border-radius: 8px;
        padding: 14px;
        display: flex;
        flex-direction: column;
        justify-content: space-between;
      }

      .traceroot-risk-header, .traceroot-web3-header {
        display: flex;
        justify-content: space-between;
        align-items: center;
        margin-bottom: 8px;
      }

      .traceroot-label {
        font-size: 10px;
        font-weight: 700;
        color: #64748b;
        letter-spacing: 0.8px;
      }

      .traceroot-risk-pill {
        font-size: 10px;
        font-weight: 700;
        padding: 2px 6px;
        border: 1px solid;
        border-radius: 4px;
      }

      .traceroot-score-display {
        display: flex;
        align-items: baseline;
        gap: 4px;
        margin-bottom: 8px;
      }

      .traceroot-score-num {
        font-size: 36px;
        font-weight: 900;
        font-family: monospace;
      }

      .traceroot-score-total {
        font-size: 14px;
        color: #64748b;
      }

      .traceroot-meter-bar {
        height: 6px;
        background: rgba(255, 255, 255, 0.08);
        border-radius: 3px;
        overflow: hidden;
      }

      .traceroot-meter-fill {
        height: 100%;
        transition: width 0.5s ease;
      }

      .traceroot-web3-badge {
        font-size: 11px;
        font-weight: 700;
        color: #00ff88;
        display: flex;
        align-items: center;
        gap: 4px;
      }

      .traceroot-chain-tag {
        font-size: 9px;
        color: #64748b;
        font-family: monospace;
      }

      .traceroot-tx-display {
        display: flex;
        align-items: center;
        gap: 6px;
        background: #05070d;
        padding: 6px 8px;
        border-radius: 6px;
        border: 1px solid rgba(0, 243, 255, 0.2);
        margin-top: 8px;
      }

      .traceroot-tx-label {
        font-size: 10px;
        color: #00f3ff;
        font-weight: 700;
      }

      .traceroot-tx-code {
        font-size: 11px;
        font-family: monospace;
        color: #e2e8f0;
        flex: 1;
        overflow: hidden;
        text-overflow: ellipsis;
        white-space: nowrap;
      }

      .traceroot-copy-btn {
        background: none;
        border: none;
        cursor: pointer;
        color: #94a3b8;
        font-size: 12px;
      }

      .traceroot-copy-btn:hover {
        color: #00f3ff;
      }

      /* AI Threat Vector Box */
      .traceroot-ai-card {
        background: rgba(13, 21, 38, 0.7);
        border: 1px solid rgba(0, 243, 255, 0.3);
        border-radius: 8px;
        padding: 14px;
      }

      .traceroot-ai-header {
        display: flex;
        align-items: center;
        gap: 8px;
        margin-bottom: 8px;
        border-bottom: 1px solid rgba(0, 243, 255, 0.15);
        padding-bottom: 6px;
      }

      .traceroot-ai-title {
        font-size: 11px;
        font-weight: 700;
        color: #00f3ff;
        letter-spacing: 0.8px;
      }

      .traceroot-pkg-target {
        font-size: 10px;
        color: #ffaa00;
        margin-left: auto;
        font-family: monospace;
      }

      .traceroot-ai-content p {
        margin: 0;
        font-size: 12px;
        line-height: 1.5;
        color: #cbd5e1;
      }

      /* Dependencies List */
      .traceroot-deps-container {
        border: 1px solid rgba(255, 255, 255, 0.08);
        border-radius: 8px;
        background: rgba(10, 15, 26, 0.4);
        padding: 12px;
      }

      .traceroot-deps-header {
        font-size: 11px;
        font-weight: 700;
        color: #94a3b8;
        letter-spacing: 0.8px;
        margin-bottom: 10px;
      }

      .traceroot-deps-list {
        display: flex;
        flex-direction: column;
        gap: 8px;
        max-height: 180px;
        overflow-y: auto;
      }

      .traceroot-dep-item {
        display: flex;
        justify-content: space-between;
        align-items: center;
        background: #0b1120;
        border: 1px solid rgba(255, 255, 255, 0.05);
        border-radius: 6px;
        padding: 8px 10px;
      }

      .traceroot-dep-name {
        font-size: 12px;
        font-weight: 600;
        color: #f1f5f9;
        font-family: monospace;
      }

      .traceroot-flags {
        display: flex;
        gap: 4px;
        margin-top: 4px;
        flex-wrap: wrap;
      }

      .traceroot-flag-tag {
        font-size: 9px;
        background: rgba(255, 0, 85, 0.15);
        color: #ff0055;
        border: 1px solid rgba(255, 0, 85, 0.3);
        padding: 1px 4px;
        border-radius: 3px;
        font-family: monospace;
      }

      .traceroot-flag-clean {
        font-size: 9px;
        background: rgba(0, 255, 136, 0.1);
        color: #00ff88;
        border: 1px solid rgba(0, 255, 136, 0.2);
        padding: 1px 4px;
        border-radius: 3px;
      }

      .traceroot-dep-score {
        font-size: 11px;
        font-weight: 700;
        font-family: monospace;
        border: 1px solid;
        padding: 2px 6px;
        border-radius: 4px;
      }

      .traceroot-dep-empty {
        font-size: 12px;
        color: #64748b;
        text-align: center;
        padding: 12px;
      }

      /* Alert & Error Box */
      .traceroot-alert-box {
        background: rgba(255, 0, 85, 0.08);
        border: 1px solid rgba(255, 0, 85, 0.4);
        border-radius: 8px;
        padding: 16px;
      }

      .traceroot-alert-badge {
        font-size: 10px;
        font-weight: 800;
        background: #ff0055;
        color: #fff;
        padding: 2px 6px;
        border-radius: 4px;
      }

      .traceroot-error-text {
        font-size: 13px;
        color: #fecdd3;
        margin: 10px 0;
        line-height: 1.4;
      }

      .traceroot-tip {
        font-size: 11px;
        color: #94a3b8;
      }

      .traceroot-tip code {
        color: #00f3ff;
        background: rgba(0, 243, 255, 0.1);
        padding: 2px 4px;
        border-radius: 3px;
      }
    `;
    document.head.appendChild(style);
  }

  /**
   * Observer and Lifecycle Handlers for dynamic GitHub SPA/Turbo navigation
   */
  function init() {
    injectStyles();
    injectScanButton();

    // GitHub uses Turbo (Drive) for client-side navigation
    document.addEventListener("turbo:load", () => {
      injectStyles();
      injectScanButton();
    });

    document.addEventListener("turbo:render", () => {
      injectScanButton();
    });

    // Fallback for PJAX or custom DOM re-renders
    const observer = new MutationObserver((mutations) => {
      if (!document.getElementById(BUTTON_ID)) {
        injectScanButton();
      }
    });

    observer.observe(document.body, { childList: true, subtree: true });
  }

  // Run when document is ready
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
