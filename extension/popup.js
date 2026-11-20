/**
 * Extension popup script
 * Queries active browser tab, calls local API at http://127.0.0.1:8000/api/scan,
 * and displays instant threat verdict with XAI reasons.
 */

const API_BASE = "http://127.0.0.1:8000";

document.addEventListener("DOMContentLoaded", async () => {
  const input = document.getElementById("target-url");
  const scanBtn = document.getElementById("scan-btn");

  // Attempt to auto-detect active tab URL in Chrome/Edge
  if (typeof chrome !== "undefined" && chrome.tabs && chrome.tabs.query) {
    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (tab && tab.url && tab.url.startsWith("http")) {
        input.value = tab.url;
        performScan(tab.url);
      }
    } catch (e) {
      console.log("Could not get tab URL:", e);
    }
  }

  scanBtn.addEventListener("click", () => {
    const url = input.value.trim();
    if (url) performScan(url);
  });
});

async function performScan(url) {
  const loader = document.getElementById("loader");
  const resultBox = document.getElementById("result-box");
  const verdictTag = document.getElementById("verdict-tag");
  const threatScore = document.getElementById("threat-score");
  const httpsNote = document.getElementById("https-note");
  const reasonsList = document.getElementById("reasons-list");

  loader.style.display = "block";
  resultBox.style.display = "none";

  try {
    const res = await fetch(`${API_BASE}/api/scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url })
    });

    if (!res.ok) throw new Error("API call failed");
    const data = await res.json();

    verdictTag.textContent = data.verdict;
    if (data.verdict === "PHISHING") {
      verdictTag.className = "badge badge-phishing";
      threatScore.style.color = "#f87171";
    } else if (data.verdict === "SUSPICIOUS") {
      verdictTag.className = "badge badge-suspicious";
      threatScore.style.color = "#fbbf24";
    } else {
      verdictTag.className = "badge badge-legitimate";
      threatScore.style.color = "#34d399";
    }

    threatScore.textContent = `Threat Risk: ${data.risk_percentage}%`;
    httpsNote.textContent = `HTTPS: ${data.https_analysis.status}`;

    reasonsList.innerHTML = "";
    if (data.findings && data.findings.length > 0) {
      data.findings.forEach((f) => {
        const li = document.createElement("li");
        li.textContent = `${f.title}: ${f.description}`;
        reasonsList.appendChild(li);
      });
    }

    resultBox.style.display = "block";
  } catch (err) {
    alert("Could not connect to PhishGuard API. Make sure backend is running on http://127.0.0.1:8000");
  } finally {
    loader.style.display = "none";
  }
}
