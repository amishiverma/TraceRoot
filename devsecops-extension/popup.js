/**
 * TraceRoot DevSecOps Sentinel - Popup Script (Manifest V3)
 * Orchestrates repo detection, communicates with background service worker,
 * and renders cybersecurity risk scorecards, Gemini threat vectors, and Web3 anchors.
 */

document.addEventListener("DOMContentLoaded", () => {
  // UI Element References
  const detectedRepoName = document.getElementById("detected-repo-name");
  const customRepoInput = document.getElementById("custom-repo-input");
  const toggleCustomUrlBtn = document.getElementById("toggle-custom-url-btn");
  const scanTriggerBtn = document.getElementById("scan-trigger-btn");
  const scanBtnLabel = document.getElementById("scan-btn-label");

  const systemStatus = document.getElementById("system-status");
  const statusText = document.getElementById("status-text");

  const loadingContainer = document.getElementById("loading-container");
  const loadingStageText = document.getElementById("loading-stage-text");
  const telemetryLog1 = document.getElementById("telemetry-log-1");
  const telemetryLog2 = document.getElementById("telemetry-log-2");
  const telemetryLog3 = document.getElementById("telemetry-log-3");

  const errorCard = document.getElementById("error-card");
  const errorCardMsg = document.getElementById("error-card-msg");
  const dismissErrorBtn = document.getElementById("dismiss-error-btn");

  const resultsContainer = document.getElementById("results-container");
  const riskBannerCard = document.getElementById("risk-banner-card");
  const riskBadgeText = document.getElementById("risk-badge-text");
  const maxRiskScoreVal = document.getElementById("max-risk-score-val");
  const riskBarFill = document.getElementById("risk-bar-fill");

  const web3AnchorBadge = document.getElementById("web3-anchor-badge");
  const web3NetworkSubtext = document.getElementById("web3-network-subtext");
  const web3TxHashDisplay = document.getElementById("web3-tx-hash-display");
  const copyTxBtn = document.getElementById("copy-tx-btn");

  const aiTargetPkg = document.getElementById("ai-target-pkg");
  const aiThreatExplanationText = document.getElementById("ai-threat-explanation-text");

  const depsCountTag = document.getElementById("deps-count-tag");
  const depsListContainer = document.getElementById("deps-list-container");

  let activeRepoUrl = "";
  let isEditingCustomUrl = false;
  let loadingInterval = null;

  // 1. Live Backend Health Check
  checkBackendHealth();

  // 2. Detect current tab and extract GitHub repository
  detectActiveTabRepo();

  // 3. Check for cached previous scan
  loadCachedScan();

  // 4. Event Listeners
  if (dismissErrorBtn) {
    dismissErrorBtn.addEventListener("click", () => {
      errorCard.style.display = "none";
    });
  }

  scanTriggerBtn.addEventListener("click", () => {
    const targetUrl = isEditingCustomUrl ? customRepoInput.value.trim() : activeRepoUrl;
    if (!targetUrl) {
      showError("Please specify a valid GitHub repository URL (e.g., https://github.com/owner/repo).");
      return;
    }
    executeScan(targetUrl);
  });

  toggleCustomUrlBtn.addEventListener("click", () => {
    isEditingCustomUrl = !isEditingCustomUrl;
    if (isEditingCustomUrl) {
      customRepoInput.style.display = "block";
      customRepoInput.value = activeRepoUrl || "https://github.com/";
      customRepoInput.focus();
      toggleCustomUrlBtn.textContent = "✕";
    } else {
      customRepoInput.style.display = "none";
      toggleCustomUrlBtn.textContent = "✏️";
    }
  });

  customRepoInput.addEventListener("input", () => {
    const val = customRepoInput.value.trim();
    if (val) {
      detectedRepoName.textContent = formatRepoLabel(val);
    }
  });

  copyTxBtn.addEventListener("click", () => {
    const hash = copyTxBtn.getAttribute("data-full-hash") || web3TxHashDisplay.textContent;
    if (hash) {
      navigator.clipboard.writeText(hash).then(() => {
        copyTxBtn.textContent = "✔";
        setTimeout(() => {
          copyTxBtn.textContent = "📋";
        }, 1500);
      });
    }
  });

  /**
   * Pings the backend service health endpoint
   */
  function checkBackendHealth() {
    chrome.runtime.sendMessage({ action: "CHECK_HEALTH" }, (response) => {
      if (chrome.runtime.lastError || !response || !response.success) {
        if (statusText) statusText.textContent = "OFFLINE";
        if (systemStatus) {
          systemStatus.style.background = "rgba(255, 0, 85, 0.1)";
          systemStatus.style.borderColor = "rgba(255, 0, 85, 0.3)";
          systemStatus.style.color = "var(--neon-red)";
        }
      } else {
        if (statusText) statusText.textContent = "ONLINE";
        if (systemStatus) {
          systemStatus.style.background = "rgba(0, 255, 136, 0.1)";
          systemStatus.style.borderColor = "rgba(0, 255, 136, 0.3)";
          systemStatus.style.color = "var(--neon-green)";
        }
      }
    });
  }

  /**
   * Identifies if active browser tab is on a GitHub repository
   */
  function detectActiveTabRepo() {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (!tabs || tabs.length === 0 || !tabs[0].url) {
        detectedRepoName.textContent = "No active tab detected";
        return;
      }

      const currentUrl = tabs[0].url;
      const match = currentUrl.match(/^https?:\/\/github\.com\/([^\/]+)\/([^\/]+)/);

      if (match) {
        const owner = match[1];
        const repo = match[2].split("?")[0].split("#")[0].replace(/\.git$/, "");
        activeRepoUrl = `https://github.com/${owner}/${repo}`;
        detectedRepoName.textContent = `${owner}/${repo}`;
        customRepoInput.value = activeRepoUrl;
      } else {
        detectedRepoName.textContent = "Not a GitHub repository";
        activeRepoUrl = "";
        // Prompt for custom URL
        isEditingCustomUrl = true;
        customRepoInput.style.display = "block";
        customRepoInput.placeholder = "Enter https://github.com/owner/repo";
        toggleCustomUrlBtn.textContent = "✕";
      }
    });
  }

  /**
   * Retrieves last completed scan from storage for fast startup rendering
   */
  function loadCachedScan() {
    chrome.storage.local.get(["lastScan", "lastRepoUrl"], (res) => {
      if (res && res.lastScan) {
        renderScanResults(res.lastScan, res.lastRepoUrl);
      }
    });
  }

  /**
   * Coordinates request with background service worker and manages loading telemetry
   */
  function executeScan(repoUrl) {
    // Reset views
    errorCard.style.display = "none";
    resultsContainer.style.display = "none";
    scanTriggerBtn.disabled = true;
    startLoadingTelemetry();

    chrome.runtime.sendMessage(
      { action: "SCAN_REPO", github_url: repoUrl },
      (response) => {
        stopLoadingTelemetry();
        scanTriggerBtn.disabled = false;

        if (chrome.runtime.lastError) {
          showError(chrome.runtime.lastError.message || "Failed to reach background service worker.");
          return;
        }

        if (!response || !response.success) {
          showError(response?.error || "DevSecOps audit service encountered an error.");
          return;
        }

        // Persist scan cache to storage so loadCachedScan() works reliably
        chrome.storage.local.set({ lastScan: response.data, lastRepoUrl: repoUrl });

        renderScanResults(response.data, repoUrl);
      }
    );
  }

  /**
   * Animates telemetry console messages across the 3-5 second scan duration
   */
  function startLoadingTelemetry() {
    loadingContainer.style.display = "flex";
    let step = 0;
    const stages = [
      {
        title: "Initializing Dependency Graph...",
        t1: "POST /api/scan initiated",
        t2: "Resolving package manifests (package.json / requirements.txt)",
        t3: "Cloning AST dependency structures...",
      },
      {
        title: "Executing DevSecOps Vulnerability Analysis...",
        t1: "Querying OSV & CVE intelligence feeds",
        t2: "Calculating static risk weights and heuristics",
        t3: "Streaming package metadata to Gemini AI model...",
      },
      {
        title: "Generating AI Threat Vectors & Web3 Anchor...",
        t1: "Gemini AI Threat Synthesis completed",
        t2: "Anchoring cryptographic state to Blockchain",
        t3: "Verifying smart contract transaction hash...",
      },
    ];

    const updateStage = () => {
      const current = stages[step % stages.length];
      loadingStageText.textContent = current.title;
      telemetryLog1.textContent = current.t1;
      telemetryLog2.textContent = current.t2;
      telemetryLog3.textContent = current.t3;
      step++;
    };

    updateStage();
    loadingInterval = setInterval(updateStage, 1400);
  }

  function stopLoadingTelemetry() {
    if (loadingInterval) {
      clearInterval(loadingInterval);
      loadingInterval = null;
    }
    loadingContainer.style.display = "none";
  }

  /**
   * Calculates overall risk and updates DOM with cyber aesthetics
   */
  function renderScanResults(data, repoUrl) {
    if (!data) return;

    const dependencies = Array.isArray(data.dependencies) ? data.dependencies : [];
    const txHash = data.transaction_hash || "0x0000000000000000000000000000000000000000";

    // 1. Calculate the 'Overall Risk' by finding the highest final_risk_score
    let maxRisk = 0;
    let highestRiskPackage = null;

    dependencies.forEach((dep) => {
      const score = typeof dep.final_risk_score === "number" ? dep.final_risk_score : 0;
      if (score >= maxRisk) {
        maxRisk = score;
        highestRiskPackage = dep;
      }
    });

    if (!highestRiskPackage && dependencies.length > 0) {
      highestRiskPackage = dependencies[0];
    }

    // 2. Risk Styling:
    // If Max Risk < 30: Glowing Neon Green.
    // If Max Risk >= 70: Pulsing Neon Red.
    // Else (30 - 69): Warning Amber.
    riskBannerCard.classList.remove("risk-low", "risk-medium", "risk-critical");

    let badgeLabel = "SAFE // LOW RISK";
    let themeColor = "var(--neon-green)";

    if (maxRisk >= 70) {
      riskBannerCard.classList.add("risk-critical");
      badgeLabel = "CRITICAL RISK DETECTED";
      themeColor = "var(--neon-red)";
    } else if (maxRisk >= 30) {
      riskBannerCard.classList.add("risk-medium");
      badgeLabel = "ELEVATED RISK";
      themeColor = "var(--neon-amber)";
    } else {
      riskBannerCard.classList.add("risk-low");
      badgeLabel = "SAFE // LOW RISK";
      themeColor = "var(--neon-green)";
    }

    // Apply values to overall risk card
    riskBadgeText.textContent = badgeLabel;
    riskBadgeText.style.color = themeColor;
    riskBadgeText.style.borderColor = themeColor;

    maxRiskScoreVal.textContent = maxRisk;
    maxRiskScoreVal.style.color = themeColor;
    maxRiskScoreVal.style.textShadow = `0 0 20px ${themeColor}`;

    riskBarFill.style.width = `${Math.min(Math.max(maxRisk, 5), 100)}%`;
    riskBarFill.style.backgroundColor = themeColor;
    riskBarFill.style.boxShadow = `0 0 12px ${themeColor}`;

    // 3. Display Web3 Transaction Hash & Mode
    const isMockTx = !txHash || txHash === "0x0000000000000000000000000000000000000000" || txHash.startsWith("mock_tx_");
    const shortTx = txHash && txHash.length > 20 ? `${txHash.slice(0, 10)}...${txHash.slice(-8)}` : (txHash || "—");

    web3TxHashDisplay.textContent = shortTx;
    web3TxHashDisplay.title = txHash || "";
    if (txHash) {
      copyTxBtn.setAttribute("data-full-hash", txHash);
      copyTxBtn.style.display = "inline-block";
    } else {
      copyTxBtn.style.display = "none";
    }

    if (web3AnchorBadge) {
      web3AnchorBadge.textContent = isMockTx ? "⚠️ Simulated Anchor (Dev Mode)" : "✅ Anchored to Polygon";
    }
    if (web3NetworkSubtext) {
      web3NetworkSubtext.textContent = isMockTx ? "LOCAL MOCK HASH" : "AMOY TESTNET";
    }

    // Click to view on Explorer if not mock
    if (!isMockTx && web3TxHashDisplay) {
      web3TxHashDisplay.style.cursor = "pointer";
      web3TxHashDisplay.style.textDecoration = "underline";
      web3TxHashDisplay.title = `Click to view on Polygon Amoy Explorer:\n${txHash}`;
      web3TxHashDisplay.onclick = () => {
        chrome.tabs.create({ url: `https://amoy.polygonscan.com/tx/${txHash}` });
      };
    } else if (web3TxHashDisplay) {
      web3TxHashDisplay.style.cursor = "default";
      web3TxHashDisplay.style.textDecoration = "none";
      web3TxHashDisplay.onclick = null;
    }

    // 4. Display Gemini AI Threat Explanation from highest-risk package
    const threatExplanation = highestRiskPackage?.ai_threat_explanation ||
      "Gemini AI threat synthesis passed: No high-risk vulnerability vectors or anomalous patterns detected in dependency tree.";

    aiThreatExplanationText.textContent = threatExplanation;

    const targetPkgName = highestRiskPackage?.package;
    if (highestRiskPackage && targetPkgName) {
      aiTargetPkg.textContent = `TARGET: ${targetPkgName}`;
      aiTargetPkg.style.display = "inline-block";
    } else {
      aiTargetPkg.style.display = "none";
    }

    // 4b. Display ML Anomaly info in risk banner
    const mlScore = highestRiskPackage?.ml_anomaly_score;
    const mlStatus = highestRiskPackage?.ml_anomaly_status;
    const mlNote = highestRiskPackage?.ml_anomaly_note;

    // Remove any existing ML badge
    const existingMlBadge = riskBannerCard.querySelector(".ml-badge");
    if (existingMlBadge) existingMlBadge.remove();

    if (mlScore !== null && mlScore !== undefined) {
      const mlBadge = document.createElement("span");
      mlBadge.className = "ml-badge";
      mlBadge.style.cssText = "font-size: 11px; padding: 2px 6px; border-radius: 4px; background: #8b5cf6; color: white; margin-left: 8px;";
      mlBadge.textContent = `ML: ${mlScore.toFixed(1)} (${mlStatus})`;
      if (mlNote) mlBadge.title = mlNote;
      riskBannerCard.appendChild(mlBadge);
    }

    // 5. Render Dependencies List with Interactive Accordions
    depsCountTag.textContent = `${dependencies.length}`;
    depsListContainer.innerHTML = "";

    if (dependencies.length === 0) {
      depsListContainer.innerHTML = `
        <div style="font-size: 11px; color: var(--text-muted); text-align: center; padding: 10px;">
          No dependencies found in repository manifest.
        </div>
      `;
    } else {
      dependencies.forEach((dep) => {
        const depScore = dep.final_risk_score ?? 0;
        const depFlags = Array.isArray(dep.risk_flags) ? dep.risk_flags : [];
        const depColor = depScore >= 70 ? "var(--neon-red)" : depScore >= 30 ? "var(--neon-amber)" : "var(--neon-green)";

        const rowWrapper = document.createElement("div");
        rowWrapper.className = "dep-item-wrapper";

        const row = document.createElement("div");
        row.className = "dep-row";

        const flagsHtml = depFlags.length > 0
          ? depFlags.map((flag) => `<span class="flag-pill">${escapeHtml(flag)}</span>`).join("")
          : `<span class="flag-clean">PASSED</span>`;

        // Display version info: requested (range) and resolved if available
        const requestedVer = dep.requested_version || dep.version || "";
        const resolvedVer = dep.resolved_version;
        const versionHtml = resolvedVer && resolvedVer !== requestedVer
          ? `<span style="opacity: 0.5; font-size: 11px; margin-left: 4px;">(${escapeHtml(requestedVer)} → ${escapeHtml(resolvedVer)})</span>`
          : `<span style="opacity: 0.5; font-size: 12px;">v${escapeHtml(requestedVer || "")}</span>`;

        // ML anomaly badge for each dep
        const mlBadge = dep.ml_anomaly_score !== null && dep.ml_anomaly_score !== undefined
          ? `<span class="ml-badge" style="font-size: 10px; padding: 1px 4px; border-radius: 3px; background: #8b5cf6; color: white; margin-left: 4px;" title="${dep.ml_anomaly_note || ''}">ML: ${dep.ml_anomaly_score.toFixed(1)}</span>`
          : "";

        row.innerHTML = `
          <div class="dep-info">
            <span class="dep-name">${escapeHtml(dep.package)} ${versionHtml}</span>
            <div class="dep-flags">${flagsHtml}</div>
          </div>
          <div style="display: flex; align-items: center; gap: 6px;">
            ${mlBadge}
            <span class="dep-score-badge" style="color: ${depColor}; border-color: ${depColor};">
              ${depScore}
            </span>
            <span class="accordion-arrow" style="font-size: 10px; color: var(--text-dim); transition: transform 0.2s;">▼</span>
          </div>
        `;

        // Expandable Detail Panel
        const detailPanel = document.createElement("div");
        detailPanel.className = "dep-detail-panel";

        const vulns = Array.isArray(dep.vulnerabilities) ? dep.vulnerabilities : [];
        let vulnsHtml = "";
        if (vulns.length > 0) {
          vulnsHtml = `
            <div style="margin-bottom: 4px; color: var(--neon-red); font-weight: 700;">
              Detected OSV Advisories (${vulns.length}):
            </div>
            ${vulns.slice(0, 3).map((v) => `
              <div style="margin-bottom: 4px; padding-left: 6px; border-left: 2px solid var(--neon-red);">
                <span style="color: #fff; font-weight: 600;">${escapeHtml(v.id || 'CVE')}</span>:
                <span>${escapeHtml(v.summary || 'Known Security Vulnerability')}</span>
              </div>
            `).join("")}
            ${vulns.length > 3 ? `<div style="font-size: 10px; opacity: 0.6;">+ ${vulns.length - 3} more vulnerabilities</div>` : ""}
          `;
        } else {
          vulnsHtml = `<div style="color: var(--neon-green);">• Clean: No known CVEs reported in OSV database.</div>`;
        }

        detailPanel.innerHTML = `
          <div style="margin-bottom: 6px; font-size: 10px; color: var(--text-dim);">
            Dependency Tree: <strong>${escapeHtml(dep.parent || 'root')}</strong> → <strong>${escapeHtml(dep.package)}</strong>
          </div>
          ${vulnsHtml}
          ${dep.ml_anomaly_note ? `<div style="margin-top: 4px; font-size: 10px; color: #a78bfa;">ML Note: ${escapeHtml(dep.ml_anomaly_note)}</div>` : ''}
        `;

        // Toggle Accordion Click
        row.addEventListener("click", () => {
          const isExpanded = detailPanel.style.display === "block";
          detailPanel.style.display = isExpanded ? "none" : "block";
          const arrow = row.querySelector(".accordion-arrow");
          if (arrow) {
            arrow.style.transform = isExpanded ? "rotate(0deg)" : "rotate(180deg)";
            arrow.style.color = isExpanded ? "var(--text-dim)" : "var(--neon-cyan)";
          }
        });

        rowWrapper.appendChild(row);
        rowWrapper.appendChild(detailPanel);
        depsListContainer.appendChild(rowWrapper);
      });
    }

    // Reveal results
    resultsContainer.style.display = "flex";
  }

  function showError(message) {
    errorCardMsg.textContent = message;
    errorCard.style.display = "flex";
  }

  function formatRepoLabel(url) {
    const match = url.match(/github\.com\/([^\/]+)\/([^\/]+)/);
    return match ? `${match[1]}/${match[2].replace(/\.git$/, "")}` : url;
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
});
