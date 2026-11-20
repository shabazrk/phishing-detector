"""
PhishGuard AI - Application Runner
Starts the FastAPI backend server and serves the responsive web interface & PWA.
"""

import os
import uvicorn
from ml.train import get_model
from server.database import init_db

if __name__ == "__main__":
    print("\n" + "=" * 65)
    print(" 🛡️  PhishGuard AI - Phishing URL & Malicious Website Detection")
    print("    CSE 5th Semester Mini Project System")
    print("=" * 65)

    # Ensure database and model are initialized
    print("[*] Initializing SQLite database...")
    init_db()

    print("[*] Verifying Random Forest ML Model...")
    get_model()

    print("\n[+] Local Access: http://127.0.0.1:8000")
    print("[+] Mobile / LAN Access: http://<YOUR-MAC-IP>:8000")
    print("    (Find your Mac IP in System Settings -> Wi-Fi -> Details)")
    print("[+] Progressive Web App (PWA) installable on Android / iOS")
    print("[+] Browser Extension ready in folder: ./extension")
    print("=" * 65 + "\n")

    uvicorn.run("server.app:app", host="0.0.0.0", port=8000, reload=True)
