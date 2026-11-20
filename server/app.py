"""
FastAPI Server for AI Phishing URL & Malicious Website Detection System.
Provides REST API endpoints for single/batch scans, model evaluation metrics,
and scan history, while serving the responsive web frontend and PWA assets.
"""

import os
import json
import re
from typing import List, Optional
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel

from ml.train import predict_url, METRICS_PATH
from server.database import save_scan, get_recent_scans, get_scan_stats, clear_history

app = FastAPI(
    title="AI Phishing URL & Malicious Website Detection API",
    description="Intelligent URL threat analysis with Random Forest and Explainable AI (XAI)",
    version="1.0.0"
)

# Enable CORS for Chrome Extension and external access
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

FRONTEND_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "frontend")


class ScanRequest(BaseModel):
    url: str


class BatchScanRequest(BaseModel):
    urls: Optional[List[str]] = None
    raw_text: Optional[str] = None


@app.post("/api/scan")
def scan_single_url(req: ScanRequest):
    """Analyzes a single URL using Random Forest and Explainable AI."""
    url = req.url.strip()
    if not url:
        raise HTTPException(status_code=400, detail="URL cannot be empty")

    result = predict_url(url)
    # Save to SQLite history
    save_scan(result)
    return result


@app.post("/api/batch")
def scan_batch_urls(req: BatchScanRequest):
    """
    Extracts URLs from list or raw text block (e.g. an email) and analyzes each.
    """
    target_urls = []
    if req.urls:
        target_urls.extend([u.strip() for u in req.urls if u.strip()])

    if req.raw_text:
        # Extract URLs using regular expression
        extracted = re.findall(
            r"https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[^\s]*",
            req.raw_text
        )
        target_urls.extend(extracted)

    # Deduplicate while preserving order
    seen = set()
    unique_urls = []
    for u in target_urls:
        if u not in seen:
            seen.add(u)
            unique_urls.append(u)

    if not unique_urls:
        raise HTTPException(status_code=400, detail="No valid URLs found to scan")

    results = []
    for u in unique_urls[:50]:  # Limit to 50 for safety
        res = predict_url(u)
        save_scan(res)
        results.append(res)

    summary = {
        "total_scanned": len(results),
        "phishing_count": sum(1 for r in results if r["verdict"] == "PHISHING"),
        "suspicious_count": sum(1 for r in results if r["verdict"] == "SUSPICIOUS"),
        "legitimate_count": sum(1 for r in results if r["verdict"] == "LEGITIMATE"),
        "results": results
    }
    return summary


@app.get("/api/metrics")
def get_evaluation_metrics():
    """Returns academic model comparison metrics (Accuracy, ROC-AUC, Confusion Matrix, XAI weights)."""
    if not os.path.exists(METRICS_PATH):
        raise HTTPException(status_code=404, detail="Model metrics not generated yet")
    with open(METRICS_PATH, "r") as f:
        data = json.load(f)
    return data


@app.get("/api/history")
def get_history(limit: int = 50):
    """Returns recent scan history from SQLite."""
    return get_recent_scans(limit=limit)


@app.get("/api/stats")
def get_stats():
    """Returns aggregated scanning statistics."""
    return get_scan_stats()


@app.post("/api/clear-history")
def clear_scan_history():
    """Clears SQLite scan history."""
    clear_history()
    return {"message": "History cleared successfully"}


# Mount static frontend directory
if os.path.exists(FRONTEND_DIR):
    app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")

    @app.get("/")
    def serve_frontend_index():
        return FileResponse(os.path.join(FRONTEND_DIR, "index.html"))

    @app.get("/manifest.json")
    def serve_manifest():
        return FileResponse(os.path.join(FRONTEND_DIR, "manifest.json"))

    @app.get("/service-worker.js")
    def serve_sw():
        return FileResponse(
            os.path.join(FRONTEND_DIR, "service-worker.js"),
            media_type="application/javascript"
        )
