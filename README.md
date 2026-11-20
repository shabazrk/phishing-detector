# 🛡️ PhishGuard AI: AI-Based Phishing URL and Malicious Website Detection System

> **5th-Semester Computer Science & Engineering (CSE) Mini Project**  
> *Combining Networking, Network Security, and Machine Learning with Explainable AI (XAI).*

---

## 📌 Project Overview
PhishGuard AI analyzes website URLs and predicts whether they are **Legitimate (Safe)** or **Phishing (Malicious)** using a trained **Random Forest** ensemble classifier and an **Explainable AI (XAI)** reasoning layer.

### 🌟 Key Innovations & Enhancements
1. **Addressing the Modern HTTPS Phishing Dilemma:**
   * Traditional detectors assumed `HTTPS = Safe`. Modern phishing campaigns heavily leverage free automated SSL certificates (Let's Encrypt, Cloudflare).
   * PhishGuard AI features **HTTPS token spoofing detection**, **protocol-scheme mismatches**, **HTTPS abuse on free PaaS clouds** (Firebase, Vercel, Glitch), and **domain-TLD interaction analysis**.
2. **Explainable AI (XAI):**
   * Eliminates the black-box dilemma. The system outputs exact, human-readable risk factors (e.g. *IP address in URL*, *Typosquatting against PayPal*, *High Shannon entropy indicates DGA*).
3. **Multi-Platform Access (Website + App):**
   * **Responsive Web Dashboard** (Cybersecurity dark glassmorphism).
   * **Installable Progressive Web App (PWA)** for mobile & desktop.
   * **Chrome/Brave Extension** (Manifest V3) for active tab link scanning.
4. **Academic Viva Dashboard:**
   * Live interactive **Confusion Matrix**, **ROC-AUC curves**, **Precision/Recall/F1-score**, and **Feature Importance charts** comparing Random Forest, Decision Trees, and Logistic Regression.

---

## 🗂️ Project Directory Structure

```
AI Phishing Detector/
├── run.py                 # Master application launcher (FastAPI + Web UI)
├── requirements.txt       # Python dependencies
├── phishing_scans.db      # SQLite database for scan logs & statistics
├── ml/
│   ├── features.py        # 25+ lexical, structural, entropy & HTTPS features
│   ├── dataset.py         # Curated balanced dataset of modern phishing & benign URLs
│   ├── explainer.py       # Explainable AI (XAI) security findings engine
│   ├── train.py           # ML training pipeline, cross-validation & metrics generator
│   ├── phishing_model.joblib # Serialized Random Forest model
│   └── model_metrics.json # Stored benchmark metrics for academic viva
├── server/
│   ├── app.py             # FastAPI REST endpoints (/api/scan, /api/batch, etc.)
│   └── database.py        # SQLite database operations
├── frontend/
│   ├── index.html         # Responsive web dashboard with PWA meta tags
│   ├── app.js             # Client controller, Chart.js graphs, live risk gauge
│   ├── styles.css         # Custom futuristic glassmorphism styles
│   ├── manifest.json      # PWA App Manifest (installable on mobile/desktop)
│   ├── service-worker.js  # PWA offline cache & service worker
│   └── icon-192.png       # App icons
└── extension/
    ├── manifest.json      # Chrome / Brave Manifest V3 extension configuration
    ├── popup.html         # Extension popup UI
    ├── popup.js           # One-click scan of current active browser tab
    └── icon.png
```

---

## 🚀 Quickstart Guide

### 1. Activate Environment & Run
```bash
# Run the application
.venv/bin/python3 run.py
```

Open your browser and visit:
👉 **[http://127.0.0.1:8000](http://127.0.0.1:8000)**

### 2. How to Install as an App (PWA)
1. Open `http://127.0.0.1:8000` in Chrome, Edge, or Safari (iOS/Android).
2. Click the **"Install App"** button in the header (or browser menu -> *Install PhishGuard AI* / *Add to Home Screen*).
3. The application will launch in its own standalone native window!

### 3. How to Load the Browser Extension
1. Open Google Chrome or Brave and navigate to `chrome://extensions`.
2. Enable **Developer mode** (top-right toggle).
3. Click **"Load unpacked"** and select the `extension/` folder inside this project.
4. Click the PhishGuard icon in your extension bar to scan any active website tab!

---

## 📊 Extracted Features Summary (25 Parameters)

| Category | Features |
| :--- | :--- |
| **Lexical Lengths** | URL length, domain length, path length, query length |
| **Character Counts** | Dots, hyphens, underscores, slashes, `@` symbols, question marks, equal signs |
| **Security & Obfuscation** | IP address as hostname, non-standard port, double-slash redirect trick, digit ratio |
| **HTTPS Specific** | `is_https`, HTTPS token in hostname, scheme mismatch, HTTPS on free cloud PaaS |
| **Advanced Heuristics** | Shannon character entropy (DGA detection), Typosquatting Levenshtein distance, High-risk TLD list |

---

## 🎓 Viva & Presentation Talking Points

1. **Why not visit the suspicious website to inspect HTML/DOM?**
   * *Answer:* Active scraping exposes the user/server to drive-by malware, malicious JavaScript execution, and zero-day browser vulnerabilities. Lexical and URL-based feature analysis is **100% safe, fast, and works before the user ever loads the connection.**

2. **Why Random Forest over Deep Learning (e.g. LSTM)?**
   * *Answer:* Tabular URL features perform exceptionally well with tree-based ensembles. Random Forest resists overfitting via bootstrap aggregating (bagging), provides natural Gini feature importances for Explainable AI, and executes in milliseconds on standard CPU hardware.

3. **How does this system defeat modern HTTPS phishing?**
   * *Answer:* Instead of treating HTTPS as a binary "safe" indicator, the system evaluates context: whether `https` is spoofed in the domain string, whether SSL is used over disposable TLDs or free cloud platforms, and whether the domain displays brand imitation.
