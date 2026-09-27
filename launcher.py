import os
import sys
import time
import socket
import threading
import webbrowser
import urllib.request
import tkinter as tk
from tkinter import ttk

# Add project root to sys.path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

ICO_PATH = os.path.join(BASE_DIR, "logo.ico")
SERVER_URL = "http://127.0.0.1:8000"


def is_server_running(port=8000):
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/stats", timeout=1.2) as resp:
            return resp.status == 200
    except Exception:
        return False


def start_server_in_background():
    """Starts the FastAPI backend if not already active."""
    if not is_server_running(8000):
        def _run():
            try:
                import uvicorn
                from backend.app import app
                from backend.database import init_db
                init_db()
                uvicorn.run("backend.app:app", host="127.0.0.1", port=8000, reload=False, log_level="warning")
            except Exception as e:
                print(f"[!] Server error: {e}")

        t = threading.Thread(target=_run, daemon=True)
        t.start()
        time.sleep(1.8)


class CyberAppLauncher:
    def __init__(self, root):
        self.root = root
        self.root.title("AI-Powered Phishing & Threat Detection Web App")
        self.root.geometry("580x460")
        self.root.resizable(False, False)
        self.root.configure(bg="#0b1120")

        # Set Window Icon
        if os.path.exists(ICO_PATH):
            try:
                self.root.iconbitmap(ICO_PATH)
            except Exception:
                pass

        self._center_window()
        self._build_ui()

        # Check initial server status in background
        threading.Thread(target=self._check_status_loop, daemon=True).start()

    def _center_window(self):
        self.root.update_idletasks()
        w = 580
        h = 460
        x = (self.root.winfo_screenwidth() // 2) - (w // 2)
        y = (self.root.winfo_screenheight() // 2) - (h // 2)
        self.root.geometry(f"{w}x{h}+{x}+{y}")

    def _build_ui(self):
        # Header Badge
        badge_frame = tk.Frame(self.root, bg="#0b1120")
        badge_frame.pack(pady=(28, 6))

        badge_lbl = tk.Label(
            badge_frame,
            text="🛡️ CYBERSHIELD AI DEFENSE PLATFORM",
            font=("Segoe UI", 9, "bold"),
            fg="#38bdf8",
            bg="#162238",
            padx=12,
            pady=4
        )
        badge_lbl.pack()

        # Primary App Title (Exact as requested)
        title_lbl = tk.Label(
            self.root,
            text="AI-Powered Phishing &\nThreat Detection Web App",
            font=("Segoe UI", 18, "bold"),
            fg="#ffffff",
            bg="#0b1120",
            justify="center"
        )
        title_lbl.pack(pady=(4, 6))

        # Subtitle
        sub_lbl = tk.Label(
            self.root,
            text="Real-Time NLP Classifier • Voice Assistant • Security Intelligence",
            font=("Segoe UI", 9),
            fg="#94a3b8",
            bg="#0b1120"
        )
        sub_lbl.pack(pady=(0, 20))

        # Status Box
        self.status_box = tk.Frame(self.root, bg="#131c31", highlightbackground="#1e293b", highlightthickness=1)
        self.status_box.pack(fill="x", padx=45, pady=(0, 22))

        self.status_dot = tk.Label(
            self.status_box,
            text="●",
            font=("Segoe UI", 12),
            fg="#22c55e",
            bg="#131c31"
        )
        self.status_dot.pack(side="left", padx=(16, 6), pady=10)

        self.status_text = tk.Label(
            self.status_box,
            text="Checking system and backend status...",
            font=("Segoe UI", 9, "bold"),
            fg="#e2e8f0",
            bg="#131c31"
        )
        self.status_text.pack(side="left", pady=10)

        # START APPLICATION Button (Middle Down Side)
        btn_frame = tk.Frame(self.root, bg="#0b1120")
        btn_frame.pack(pady=(0, 16))

        self.start_btn = tk.Button(
            btn_frame,
            text="🚀  START APPLICATION",
            font=("Segoe UI", 13, "bold"),
            fg="#ffffff",
            bg="#0284c7",
            activebackground="#0369a1",
            activeforeground="#ffffff",
            relief="flat",
            padx=28,
            pady=11,
            cursor="hand2",
            command=self.launch_application
        )
        self.start_btn.pack()

        # Hover effects
        self.start_btn.bind("<Enter>", lambda e: self.start_btn.configure(bg="#0ea5e9"))
        self.start_btn.bind("<Leave>", lambda e: self.start_btn.configure(bg="#0284c7"))

        # Direct Navigation Buttons
        quick_frame = tk.Frame(self.root, bg="#0b1120")
        quick_frame.pack(pady=(0, 15))

        quick_links = [
            ("🔍 Threat Scanner", "/"),
            ("📊 Dashboard", "/dashboard"),
            ("🕒 Recent History", "/history"),
            ("💬 AI Chatbot", "/chatbot")
        ]

        for label, path in quick_links:
            btn = tk.Button(
                quick_frame,
                text=label,
                font=("Segoe UI", 8),
                fg="#94a3b8",
                bg="#1e293b",
                activebackground="#334155",
                activeforeground="#ffffff",
                relief="flat",
                padx=8,
                pady=4,
                cursor="hand2",
                command=lambda p=path: self.open_url(p)
            )
            btn.pack(side="left", padx=4)

        # Footer note
        footer_lbl = tk.Label(
            self.root,
            text="Localhost Web Server: http://127.0.0.1:8000 • Verified Owner: LAPTOP-OUSMHCVJ",
            font=("Segoe UI", 8),
            fg="#64748b",
            bg="#0b1120"
        )
        footer_lbl.pack(side="bottom", pady=12)

    def _check_status_loop(self):
        while True:
            running = is_server_running(8000)
            if running:
                self.status_dot.configure(fg="#22c55e")
                self.status_text.configure(text="System Ready: AI Threat Engine Online on Port 8000", fg="#4ade80")
            else:
                self.status_dot.configure(fg="#f59e0b")
                self.status_text.configure(text="System Standby: Click 'Start Application' to Launch", fg="#fde047")
            time.sleep(3)

    def launch_application(self):
        self.status_text.configure(text="⚡ Initializing AI Engine & Starting Server...", fg="#38bdf8")
        self.root.update()

        def _do_launch():
            start_server_in_background()
            webbrowser.open(SERVER_URL)
            self.status_dot.configure(fg="#22c55e")
            self.status_text.configure(text=f"✅ Application Opened in Browser ({SERVER_URL})", fg="#4ade80")

        threading.Thread(target=_do_launch, daemon=True).start()

    def open_url(self, path):
        def _do():
            start_server_in_background()
            webbrowser.open(f"{SERVER_URL}{path}")
        threading.Thread(target=_do, daemon=True).start()


def main():
    root = tk.Tk()
    app = CyberAppLauncher(root)
    root.mainloop()


if __name__ == "__main__":
    main()
