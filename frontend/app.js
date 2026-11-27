/**
 * PhishGuard AI - Frontend Controller
 * Handles real-time scans, Chart.js visualizations, batch analysis, and PWA registration.
 */

// Tab Management
function switchTab(tabId) {
  document.querySelectorAll(".tab-content").forEach((el) => el.classList.add("hidden"));
  document.querySelectorAll(".nav-tab").forEach((btn) => btn.classList.remove("active"));
  document.querySelectorAll(".nav-tab-mobile").forEach((btn) => btn.classList.replace("bg-cyan-500", "bg-slate-800"));

  const targetTab = document.getElementById(`tab-${tabId}`);
  if (targetTab) targetTab.classList.remove("hidden");

  const activeBtn = document.getElementById(`tab-btn-${tabId}`);
  if (activeBtn) activeBtn.classList.add("active");

  if (tabId === "metrics") {
    loadModelMetrics();
  } else if (tabId === "history") {
    loadScanHistory();
  }
}

// Sample preset handler
function setSample(url) {
  document.getElementById("url-input").value = url;
  document.getElementById("url-input").focus();
}

// Single URL Scan
async function handleScan(event) {
  event.preventDefault();
  const input = document.getElementById("url-input");
  const url = input.value.trim();
  if (!url) return;

  const loadingEl = document.getElementById("scan-loading");
  const resultEl = document.getElementById("scan-result");
  const scanBtn = document.getElementById("scan-button");

  loadingEl.classList.remove("hidden");
  resultEl.classList.add("hidden");
  scanBtn.disabled = true;

  const deepToggle = document.getElementById("deep-scan-toggle");
  const deepScan = deepToggle ? deepToggle.checked : true;

  try {
    const res = await fetch("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url, deep_scan: deepScan })
    });

    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.detail || "Scanning failed");
    }

    const data = await res.json();
    renderScanResult(data);
  } catch (error) {
    alert("Error scanning URL: " + error.message);
  } finally {
    loadingEl.classList.add("hidden");
    scanBtn.disabled = false;
  }
}

function renderScanResult(data) {
  const resultEl = document.getElementById("scan-result");
  const banner = document.getElementById("verdict-banner");
  const badge = document.getElementById("verdict-badge");
  const levelText = document.getElementById("risk-level-text");
  const title = document.getElementById("verdict-title");
  const urlDisplay = document.getElementById("target-url-display");
  const scoreNum = document.getElementById("threat-score-number");
  const categoryBadge = document.getElementById("risk-category-badge");

  urlDisplay.textContent = data.url;
  scoreNum.textContent = `${data.risk_percentage}%`;
  levelText.textContent = data.risk_level;

  // Verdict Theme Styles
  banner.className = "glass-card p-6 sm:p-8 rounded-2xl border-l-8 transition-all";
  if (data.verdict === "PHISHING") {
    banner.classList.add("border-l-rose-500", "shadow-rose-950/20");
    badge.className = "px-3.5 py-1 rounded-full text-xs font-bold uppercase tracking-wider bg-rose-500/20 text-rose-400 border border-rose-500/40";
    badge.textContent = "PHISHING DETECTED";
    title.textContent = "Potentially Malicious / Phishing URL";
    title.className = "text-2xl sm:text-3xl font-extrabold text-rose-400";
    categoryBadge.className = "mt-1 text-xs font-semibold px-2.5 py-0.5 rounded-full bg-rose-500/20 text-rose-400";
    categoryBadge.textContent = "High Risk";
  } else if (data.verdict === "SUSPICIOUS") {
    banner.classList.add("border-l-amber-500", "shadow-amber-950/20");
    badge.className = "px-3.5 py-1 rounded-full text-xs font-bold uppercase tracking-wider bg-amber-500/20 text-amber-400 border border-amber-500/40";
    badge.textContent = "SUSPICIOUS PATTERNS";
    title.textContent = "Caution Advised - Suspicious URL";
    title.className = "text-2xl sm:text-3xl font-extrabold text-amber-400";
    categoryBadge.className = "mt-1 text-xs font-semibold px-2.5 py-0.5 rounded-full bg-amber-500/20 text-amber-400";
    categoryBadge.textContent = "Moderate Risk";
  } else {
    banner.classList.add("border-l-emerald-500", "shadow-emerald-950/20");
    badge.className = "px-3.5 py-1 rounded-full text-xs font-bold uppercase tracking-wider bg-emerald-500/20 text-emerald-400 border border-emerald-500/40";
    badge.textContent = "LEGITIMATE / SAFE";
    title.textContent = "Legitimate Website Verified";
    title.className = "text-2xl sm:text-3xl font-extrabold text-emerald-400";
    categoryBadge.className = "mt-1 text-xs font-semibold px-2.5 py-0.5 rounded-full bg-emerald-500/20 text-emerald-400";
    categoryBadge.textContent = "Safe";
  }

  // HTTPS Advisory Alert Box
  const httpsBox = document.getElementById("https-advisory-box");
  const httpsIcon = document.getElementById("https-icon");
  const httpsTitle = document.getElementById("https-status-title");
  const httpsBadge = document.getElementById("https-status-badge");
  const httpsNote = document.getElementById("https-status-note");

  const httpsData = data.https_analysis;
  httpsTitle.textContent = httpsData.status;
  httpsNote.textContent = httpsData.note;

  if (httpsData.badge === "safe") {
    httpsBox.className = "mt-6 p-4 rounded-xl border border-emerald-500/30 bg-emerald-950/20 text-emerald-300 flex items-start gap-3.5";
    httpsIcon.className = "fa-solid fa-lock text-emerald-400 text-lg mt-0.5";
    httpsBadge.className = "px-2 py-0.5 rounded text-[10px] uppercase font-bold bg-emerald-500/20 text-emerald-300";
    httpsBadge.textContent = "Encrypted Safe";
  } else if (httpsData.badge === "warning") {
    httpsBox.className = "mt-6 p-4 rounded-xl border border-amber-500/30 bg-amber-950/30 text-amber-200 flex items-start gap-3.5";
    httpsIcon.className = "fa-solid fa-triangle-exclamation text-amber-400 text-lg mt-0.5";
    httpsBadge.className = "px-2 py-0.5 rounded text-[10px] uppercase font-bold bg-amber-500/20 text-amber-300";
    httpsBadge.textContent = "Deceptive SSL Warning";
  } else {
    httpsBox.className = "mt-6 p-4 rounded-xl border border-rose-500/30 bg-rose-950/30 text-rose-200 flex items-start gap-3.5";
    httpsIcon.className = "fa-solid fa-unlock text-rose-400 text-lg mt-0.5";
    httpsBadge.className = "px-2 py-0.5 rounded text-[10px] uppercase font-bold bg-rose-500/20 text-rose-300";
    httpsBadge.textContent = "Unencrypted Insecure";
  }

  // XAI Findings List
  const findingsList = document.getElementById("findings-list");
  findingsList.innerHTML = "";
  if (data.findings && data.findings.length > 0) {
    data.findings.forEach((f) => {
      const item = document.createElement("div");
      let borderColor = "border-slate-700";
      let iconColor = "text-slate-400";
      let icon = "fa-circle-info";

      if (f.severity === "CRITICAL") {
        borderColor = "border-rose-500/40 bg-rose-950/10";
        iconColor = "text-rose-400";
        icon = "fa-skull-crossbones";
      } else if (f.severity === "HIGH") {
        borderColor = "border-amber-500/40 bg-amber-950/10";
        iconColor = "text-amber-400";
        icon = "fa-triangle-exclamation";
      } else if (f.severity === "SAFE") {
        borderColor = "border-emerald-500/40 bg-emerald-950/10";
        iconColor = "text-emerald-400";
        icon = "fa-shield-check";
      }

      item.className = `p-3 rounded-xl border ${borderColor} flex items-start gap-3 text-xs`;
      item.innerHTML = `
        <i class="fa-solid ${icon} ${iconColor} text-sm mt-0.5"></i>
        <div class="space-y-0.5">
          <div class="font-bold text-white">${f.title}</div>
          <p class="text-slate-400 leading-relaxed">${f.description}</p>
        </div>
      `;
      findingsList.appendChild(item);
    });
  }

  // Recommendations
  const recList = document.getElementById("recommendations-list");
  recList.innerHTML = "";
  if (data.recommendations) {
    data.recommendations.forEach((rec) => {
      const li = document.createElement("li");
      li.className = "flex items-start gap-2";
      li.innerHTML = `<i class="fa-solid fa-arrow-right text-cyan-400 text-xs mt-1"></i> <span>${rec}</span>`;
      recList.appendChild(li);
    });
  }

  // Feature Snapshot Grid
  const featSnapshot = document.getElementById("feature-snapshot");
  featSnapshot.innerHTML = "";
  const f = data.features || {};
  const sampleFeatures = [
    { label: "URL Length", val: f.url_length },
    { label: "Subdomains", val: f.count_subdomains },
    { label: "Shannon Entropy", val: f.domain_shannon_entropy },
    { label: "Typosquatting Risk", val: f.typosquatting_risk ? "Yes" : "No" },
    { label: "IP in Hostname", val: f.has_ip_address ? "Yes" : "No" },
    { label: "HTTPS Abused", val: f.https_with_suspicious_features ? "Yes" : "No" }
  ];

  sampleFeatures.forEach((sf) => {
    const card = document.createElement("div");
    card.className = "p-2.5 rounded-lg bg-slate-900/60 border border-slate-800 flex justify-between items-center";
    card.innerHTML = `
      <span class="text-slate-400">${sf.label}</span>
      <span class="font-mono font-bold text-cyan-400">${sf.val}</span>
    `;
    featSnapshot.appendChild(card);
  });

  // Deep Inspection: Redirect Chain & Website Content
  const deepRow = document.getElementById("deep-inspection-row");
  if (deepRow) {
    if (data.deep_scan && data.deep_scan.enabled && data.redirect_analysis) {
      deepRow.classList.remove("hidden");
      const ra = data.redirect_analysis;
      const rBadge = document.getElementById("redirect-safety-badge");
      const rScore = document.getElementById("redirect-safety-score");
      const rSummary = document.getElementById("redirect-summary-text");
      const rHops = document.getElementById("redirect-hops-list");

      rBadge.textContent = ra.safety_verdict;
      rScore.textContent = `${ra.safety_score}%`;
      rSummary.textContent = ra.summary;

      if (ra.safety_verdict === "DANGEROUS REDIRECT") {
        rBadge.className = "px-2.5 py-0.5 rounded-full text-[11px] font-bold uppercase bg-rose-500/20 text-rose-400 border border-rose-500/30";
        rScore.className = "text-2xl font-extrabold text-rose-400 ml-4";
      } else if (ra.safety_verdict === "SUSPICIOUS REDIRECT") {
        rBadge.className = "px-2.5 py-0.5 rounded-full text-[11px] font-bold uppercase bg-amber-500/20 text-amber-400 border border-amber-500/30";
        rScore.className = "text-2xl font-extrabold text-amber-400 ml-4";
      } else {
        rBadge.className = "px-2.5 py-0.5 rounded-full text-[11px] font-bold uppercase bg-emerald-500/20 text-emerald-400 border border-emerald-500/30";
        rScore.className = "text-2xl font-extrabold text-emerald-400 ml-4";
      }

      rHops.innerHTML = "";
      if (ra.hops && ra.hops.length > 0) {
        ra.hops.forEach((hop) => {
          const hopEl = document.createElement("div");
          hopEl.className = "p-2.5 rounded-lg bg-slate-900/60 border border-slate-800 space-y-1";
          const tags = [];
          if (hop.cross_domain) tags.push('<span class="px-1.5 py-0.5 rounded bg-amber-500/20 text-amber-300 text-[10px]">Cross-Domain</span>');
          if (hop.https_downgrade) tags.push('<span class="px-1.5 py-0.5 rounded bg-rose-500/20 text-rose-300 text-[10px]">HTTPS Downgrade</span>');
          hopEl.innerHTML = `
            <div class="flex items-center justify-between">
              <span class="text-cyan-400 font-bold">Hop #${hop.step} (HTTP ${hop.status_code})</span>
              <div class="flex gap-1">${tags.join("")}</div>
            </div>
            <div class="text-slate-300 break-all">→ ${hop.to_url}</div>
          `;
          rHops.appendChild(hopEl);
        });
      } else {
        rHops.innerHTML = `<div class="p-2.5 rounded-lg bg-slate-900/60 border border-slate-800 text-slate-400">Final Destination: <span class="text-cyan-400 break-all">${ra.final_url}</span></div>`;
      }

      // Website Content & DOM Analysis
      const ca = data.content_analysis || {};
      const cBadge = document.getElementById("content-status-badge");
      const cBox = document.getElementById("content-details-box");
      cBox.innerHTML = "";

      if (ca.available) {
        cBadge.textContent = `HTTP ${ca.http_status || 200} • HTML Inspected`;
        const sslText = ca.ssl_certificate && ca.ssl_certificate.available
          ? `${ca.ssl_certificate.issuer} (${ca.ssl_certificate.valid ? "Valid" : "Invalid"})`
          : "No HTTPS / N/A";

        const rows = [
          { label: "Page Title", val: ca.page_title, warn: ca.title_brand_mismatch },
          { label: "SSL Certificate", val: sslText, warn: ca.ssl_certificate && ca.ssl_certificate.available && !ca.ssl_certificate.valid },
          { label: "Forms / Password Inputs", val: `${ca.form_count} form(s) • Password field: ${ca.has_password_field ? "Yes" : "No"}`, warn: ca.has_password_field && data.risk_percentage >= 35 },
          { label: "External Form Actions", val: ca.external_form_actions && ca.external_form_actions.length > 0 ? `${ca.external_form_actions.length} external target(s)` : "None", warn: ca.external_form_actions && ca.external_form_actions.length > 0 },
          { label: "Iframes (Hidden)", val: `${ca.iframe_count} total (${ca.hidden_iframe_count} hidden)`, warn: ca.hidden_iframe_count > 0 },
          { label: "External Link Ratio", val: `${Math.round((ca.external_link_ratio || 0) * 100)}% (${ca.external_links}/${ca.total_links})`, warn: false },
          { label: "External Favicon / No Right-Click", val: `Favicon: ${ca.favicon_external ? "External" : "Same-origin"} • Right-Click: ${ca.right_click_disabled ? "Blocked" : "Normal"}`, warn: ca.favicon_external || ca.right_click_disabled }
        ];

        rows.forEach((r) => {
          const rowEl = document.createElement("div");
          rowEl.className = "p-2.5 rounded-lg bg-slate-900/60 border border-slate-800 flex flex-col sm:flex-row sm:justify-between sm:items-center gap-1";
          rowEl.innerHTML = `
            <span class="text-slate-400">${r.label}</span>
            <span class="font-mono font-semibold ${r.warn ? "text-rose-400" : "text-slate-200"} break-all">${r.val}</span>
          `;
          cBox.appendChild(rowEl);
        });
      } else {
        cBadge.textContent = "Live Fetch Skipped / Offline";
        cBox.innerHTML = `<div class="p-3 rounded-lg bg-slate-900/60 border border-slate-800 text-slate-400">${ca.reason || data.deep_scan.fetch_message || "Could not retrieve live HTML content."}</div>`;
      }
    } else {
      deepRow.classList.add("hidden");
    }
  }

  resultEl.classList.remove("hidden");
  resultEl.scrollIntoView({ behavior: "smooth" });
}

// Batch Scanner Handler
async function handleBatchScan() {
  const text = document.getElementById("batch-input").value.trim();
  if (!text) {
    alert("Please enter URLs or email text to scan.");
    return;
  }

  const btn = document.getElementById("batch-scan-btn");
  btn.disabled = true;
  btn.innerHTML = `<i class="fa-solid fa-spinner fa-spin mr-1"></i> Scanning...`;

  try {
    const res = await fetch("/api/batch", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ raw_text: text })
    });

    if (!res.ok) throw new Error("Batch scan request failed");

    const data = await res.json();
    renderBatchResults(data);
  } catch (err) {
    alert("Batch Scan Error: " + err.message);
  } finally {
    btn.disabled = false;
    btn.innerHTML = `<i class="fa-solid fa-magnifying-glass-chart mr-1"></i> Scan All Links`;
  }
}

function renderBatchResults(data) {
  const container = document.getElementById("batch-results-container");
  document.getElementById("batch-total").textContent = data.total_scanned;
  document.getElementById("batch-phishing").textContent = data.phishing_count;
  document.getElementById("batch-suspicious").textContent = data.suspicious_count;
  document.getElementById("batch-legitimate").textContent = data.legitimate_count;

  const tbody = document.getElementById("batch-table-body");
  tbody.innerHTML = "";

  data.results.forEach((r) => {
    const tr = document.createElement("tr");
    let badgeClass = "bg-emerald-500/20 text-emerald-400 border border-emerald-500/30";
    if (r.verdict === "PHISHING") badgeClass = "bg-rose-500/20 text-rose-400 border border-rose-500/30";
    if (r.verdict === "SUSPICIOUS") badgeClass = "bg-amber-500/20 text-amber-400 border border-amber-500/30";

    tr.className = "hover:bg-slate-800/40 transition";
    tr.innerHTML = `
      <td class="py-3 px-4 font-mono text-slate-300 break-all max-w-xs">${r.url}</td>
      <td class="py-3 px-4">
        <span class="px-2.5 py-0.5 rounded text-[11px] font-bold uppercase ${badgeClass}">${r.verdict}</span>
      </td>
      <td class="py-3 px-4 font-bold text-white">${r.risk_percentage}%</td>
      <td class="py-3 px-4 text-slate-400 text-xs">${r.https_analysis.status}</td>
    `;
    tbody.appendChild(tr);
  });

  container.classList.remove("hidden");
  container.scrollIntoView({ behavior: "smooth" });
}

// Charts Instances
let featuresChartInstance = null;
let rocChartInstance = null;

// Academic Metrics Loading
async function loadModelMetrics() {
  try {
    const res = await fetch("/api/metrics");
    if (!res.ok) return;
    const data = await res.json();

    // Render 3 Model Comparison Cards
    const grid = document.getElementById("model-comparison-grid");
    grid.innerHTML = "";

    const models = data.model_comparison || {};
    for (const [name, m] of Object.entries(models)) {
      const card = document.createElement("div");
      const isRf = name === "Random Forest";
      card.className = `glass-card p-6 rounded-2xl relative ${isRf ? 'border-cyan-500/50 glow-active' : ''}`;
      card.innerHTML = `
        ${isRf ? '<span class="absolute top-3 right-3 text-[10px] uppercase font-bold tracking-wider px-2 py-0.5 rounded bg-cyan-500 text-slate-950">Recommended</span>' : ''}
        <h4 class="text-lg font-bold text-white mb-4">${name}</h4>
        <div class="grid grid-cols-2 gap-3 text-xs mb-4">
          <div class="p-2.5 rounded-lg bg-slate-900/60 border border-slate-800">
            <span class="text-slate-400 block">Accuracy</span>
            <span class="text-lg font-bold text-white">${(m.accuracy * 100).toFixed(1)}%</span>
          </div>
          <div class="p-2.5 rounded-lg bg-slate-900/60 border border-slate-800">
            <span class="text-slate-400 block">Precision</span>
            <span class="text-lg font-bold text-white">${(m.precision * 100).toFixed(1)}%</span>
          </div>
          <div class="p-2.5 rounded-lg bg-slate-900/60 border border-slate-800">
            <span class="text-slate-400 block">Recall</span>
            <span class="text-lg font-bold text-white">${(m.recall * 100).toFixed(1)}%</span>
          </div>
          <div class="p-2.5 rounded-lg bg-slate-900/60 border border-slate-800">
            <span class="text-slate-400 block">F1-Score</span>
            <span class="text-lg font-bold text-cyan-400">${(m.f1_score * 100).toFixed(1)}%</span>
          </div>
        </div>
        <div class="text-[11px] text-slate-400 pt-3 border-t border-slate-800 flex justify-between">
          <span>ROC-AUC Score:</span>
          <span class="font-mono font-bold text-white">${m.roc_auc.toFixed(4)}</span>
        </div>
      `;
      grid.appendChild(card);
    }

    // Render Feature Importances Chart
    renderFeaturesChart(data.feature_importances || []);
    // Render ROC Curves Chart
    renderRocChart(models);
  } catch (err) {
    console.error("Failed to load metrics:", err);
  }
}

function renderFeaturesChart(importances) {
  const top10 = importances.slice(0, 8);
  const labels = top10.map((f) => f.feature.replace(/_/g, " "));
  const values = top10.map((f) => f.importance);

  const ctx = document.getElementById("features-chart").getContext("2d");
  if (featuresChartInstance) featuresChartInstance.destroy();

  featuresChartInstance = new Chart(ctx, {
    type: "bar",
    data: {
      labels: labels,
      datasets: [{
        label: "Feature Importance Weight",
        data: values,
        backgroundColor: "rgba(6, 182, 212, 0.7)",
        borderColor: "rgba(6, 182, 212, 1)",
        borderWidth: 1,
        borderRadius: 6
      }]
    },
    options: {
      indexAxis: "y",
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { display: false }
      },
      scales: {
        x: {
          grid: { color: "rgba(255, 255, 255, 0.05)" },
          ticks: { color: "#94a3b8" }
        },
        y: {
          grid: { display: false },
          ticks: { color: "#f1f5f9", font: { size: 11 } }
        }
      }
    }
  });
}

function renderRocChart(models) {
  const ctx = document.getElementById("roc-chart").getContext("2d");
  if (rocChartInstance) rocChartInstance.destroy();

  const datasets = [];
  const colors = {
    "Random Forest": "#06b6d4",
    "Decision Tree": "#f59e0b",
    "Logistic Regression": "#8b5cf6"
  };

  for (const [name, m] of Object.entries(models)) {
    if (m.roc_curve) {
      datasets.push({
        label: `${name} (AUC: ${m.roc_auc.toFixed(2)})`,
        data: m.roc_curve.map((p) => ({ x: p.fpr, y: p.tpr })),
        borderColor: colors[name] || "#3b82f6",
        borderWidth: 2,
        tension: 0.1,
        showLine: true,
        pointRadius: 2
      });
    }
  }

  // Diagonal reference line (Random guessing baseline)
  datasets.push({
    label: "Random Chance (AUC = 0.5)",
    data: [{ x: 0, y: 0 }, { x: 1, y: 1 }],
    borderColor: "#475569",
    borderDash: [5, 5],
    borderWidth: 1.5,
    pointRadius: 0
  });

  rocChartInstance = new Chart(ctx, {
    type: "scatter",
    data: { datasets },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      scales: {
        x: {
          title: { display: true, text: "False Positive Rate (1 - Specificity)", color: "#94a3b8" },
          grid: { color: "rgba(255, 255, 255, 0.05)" },
          ticks: { color: "#94a3b8" },
          min: 0,
          max: 1
        },
        y: {
          title: { display: true, text: "True Positive Rate (Recall)", color: "#94a3b8" },
          grid: { color: "rgba(255, 255, 255, 0.05)" },
          ticks: { color: "#94a3b8" },
          min: 0,
          max: 1
        }
      },
      plugins: {
        legend: {
          labels: { color: "#f1f5f9", boxWidth: 12 }
        }
      }
    }
  });
}

// History Handling
async function loadScanHistory() {
  try {
    const res = await fetch("/api/history?limit=30");
    if (!res.ok) return;
    const items = await res.json();

    const tbody = document.getElementById("history-table-body");
    tbody.innerHTML = "";

    if (!items || items.length === 0) {
      tbody.innerHTML = `<tr><td colspan="5" class="py-8 text-center text-slate-500">No scans recorded yet.</td></tr>`;
      return;
    }

    items.forEach((item) => {
      const tr = document.createElement("tr");
      let badgeClass = "bg-emerald-500/20 text-emerald-400";
      if (item.verdict === "PHISHING") badgeClass = "bg-rose-500/20 text-rose-400";
      if (item.verdict === "SUSPICIOUS") badgeClass = "bg-amber-500/20 text-amber-400";

      tr.className = "hover:bg-slate-800/40 transition";
      tr.innerHTML = `
        <td class="py-3 px-4 text-slate-500 text-xs">${item.scanned_at}</td>
        <td class="py-3 px-4 font-mono text-slate-300 break-all max-w-xs">${item.url}</td>
        <td class="py-3 px-4">
          <span class="px-2.5 py-0.5 rounded text-[11px] font-bold uppercase ${badgeClass}">${item.verdict}</span>
        </td>
        <td class="py-3 px-4 font-bold text-white">${item.risk_percentage}%</td>
        <td class="py-3 px-4 text-slate-400 text-xs">${item.https_status || "N/A"}</td>
      `;
      tbody.appendChild(tr);
    });
  } catch (err) {
    console.error("Failed to load history:", err);
  }
}

async function handleClearHistory() {
  if (!confirm("Are you sure you want to clear all scan history?")) return;
  try {
    await fetch("/api/clear-history", { method: "POST" });
    loadScanHistory();
  } catch (err) {
    alert("Failed to clear history");
  }
}

// Progressive Web App (PWA) Registration
let deferredPrompt;
window.addEventListener("beforeinstallprompt", (e) => {
  e.preventDefault();
  deferredPrompt = e;
  const btn = document.getElementById("pwa-install-btn");
  if (btn) {
    btn.classList.remove("hidden");
    btn.addEventListener("click", async () => {
      if (deferredPrompt) {
        deferredPrompt.prompt();
        const { outcome } = await deferredPrompt.userChoice;
        if (outcome === "accepted") {
          btn.classList.add("hidden");
        }
        deferredPrompt = null;
      }
    });
  }
});

if ("serviceWorker" in navigator) {
  window.addEventListener("load", () => {
    navigator.serviceWorker.register("/service-worker.js").catch((err) => {
      console.log("Service Worker Registration:", err);
    });
  });
}
