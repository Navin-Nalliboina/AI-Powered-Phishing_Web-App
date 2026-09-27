import os
import sys
import webbrowser
import threading
import time
import uvicorn

# Add project root to sys.path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from backend.database import init_db, SessionLocal, Submission, AnomalyLog, ChatMessage
from backend.train_model import train_and_save, MODEL_FILE
from backend.ml_engine import ml_engine


def seed_initial_demo_data():
    """Populates realistic initial entries so the dashboard and tables look rich on first launch."""
    db = SessionLocal()
    try:
        # Check if already seeded
        if db.query(Submission).count() > 0:
            return

        print("[*] Seeding demo threat scans and telemetry data...")

        demo_items = [
            ("URGENT: Your PayPal account has been restricted! Click here to verify your identity within 24 hours at http://paypal-account-center.top/restricted/login.php", "email"),
            ("http://wellsfargo-verify-security.top/login.php?cmd=reauth_token_8392", "url"),
            ("FedEx Delivery Notice: Parcel delivery failed due to incorrect shipping address. Click to pay $1.99 redelivery fee: http://fedx-package-tracking.tk/track", "text"),
            ("Hey team, here are the meeting notes and roadmap slides from today's product sync. Let me know if you have feedback.", "email"),
            ("https://github.com/torvalds/linux", "url")
        ]

        for content, c_type in demo_items:
            res = ml_engine.analyze(content)
            sub = Submission(
                input_type=res["input_type"] if c_type == "auto" else c_type,
                raw_content=content,
                risk_score=res["risk_score"],
                risk_level=res["risk_level"],
                confidence=res["confidence"],
                explanation=str(res["explanation"]).replace("'", '"'),
                indicators=str(res["indicators"]).replace("'", '"'),
                client_ip="127.0.0.1"
            )
            db.add(sub)

        # Add a demo anomaly
        anomaly = AnomalyLog(
            anomaly_type="LOW_CONFIDENCE_PREDICTION",
            severity="Low",
            details="Borderline linguistic indicators detected in invoice attachment query. Flagged for review.",
            payload_preview="Please check attached wire instruction invoice #82910...",
            client_ip="127.0.0.1",
            is_resolved=False
        )
        db.add(anomaly)
        db.commit()
        print("[+] Demo telemetry and audit records initialized successfully.")

    except Exception as e:
        print(f"[!] Seeding warning: {e}")
    finally:
        db.close()


import socket
import urllib.request


def is_port_in_use(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(('127.0.0.1', port)) == 0


def open_browser(port: int = 8000):
    """Waits 1.5 seconds for server to start, then opens the web application."""
    time.sleep(1.5)
    url = f"http://127.0.0.1:{port}"
    print(f"\n[*] Opening CyberShield AI in your browser: {url}\n")
    try:
        webbrowser.open(url)
    except Exception:
        pass


def main():
    print("=" * 65)
    print("   CYBERSHIELD AI - PHISHING & CYBER THREAT DETECTION PLATFORM   ")
    print("=" * 65)

    target_port = 8000

    # Check if an instance is already running
    if is_port_in_use(target_port):
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{target_port}/api/stats", timeout=1.5) as resp:
                if resp.status == 200:
                    print(f"\n[+] CyberShield AI is already running on http://127.0.0.1:{target_port}!")
                    print("[*] Opening application in your browser...")
                    webbrowser.open(f"http://127.0.0.1:{target_port}")
                    print("[*] Ready. Press Ctrl+C if you wish to exit.")
                    try:
                        while True:
                            time.sleep(1)
                    except KeyboardInterrupt:
                        return
        except Exception:
            # Port is used by something else, switch to 8001
            target_port = 8001
            print(f"[!] Port 8000 is occupied. Switching to port {target_port}...")

    # 1. Initialize SQLite Database
    print("[*] Initializing SQLite database...")
    init_db()

    # 2. Check & Train AI Threat Detection Model
    if not os.path.exists(MODEL_FILE):
        print("[*] Training AI NLP Phishing Model...")
        train_and_save()
    else:
        print(f"[+] AI Model ready: {MODEL_FILE}")

    # 3. Seed demo data
    seed_initial_demo_data()

    # 4. Open browser thread
    threading.Thread(target=open_browser, args=(target_port,), daemon=True).start()

    # 5. Start Uvicorn Server
    print(f"[*] Starting FastAPI server on http://127.0.0.1:{target_port}...")
    uvicorn.run("backend.app:app", host="127.0.0.1", port=target_port, reload=False)


if __name__ == "__main__":
    main()
