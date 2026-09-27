# 🛡️ CyberShield AI: AI-Powered Phishing & Threat Detection Web App with Chatbot Assistant

An advanced, real-time cybersecurity platform featuring a hybrid AI threat detection engine, an intelligent voice-enabled chatbot assistant, anomaly detection and rate limiting, an SQLite database, and an interactive cybersecurity analytics dashboard.

---

## 🌟 Key Features

### 1. 🤖 Threat Detection Engine (AI & Heuristic Engine)
- **NLP Machine Learning Classifier:** Scikit-Learn TF-IDF pipeline trained on authentic phishing datasets (credential harvesters, fake invoices, banking scams, brand impersonations).
- **Deep Lexical Threat Analyzer:**
  - Evaluates direct IP hostnames (`http://192.168.1.1/login`).
  - Detects high-risk Top-Level Domains (`.top`, `.xyz`, `.tk`, `.fit`, `.work`, etc.).
  - Catches typosquatting and brand spoofing (e.g. `paypal.com.verify.xyz`).
  - Detects URL obfuscation (`@` symbol tricks) and link-shortener redirects (`bit.ly`, `tinyurl`).
  - Identifies psychological coercion cues, urgency traps (*"action required within 24 hours"*), and financial fraud indicators.
- **Outputs:**
  - Composite Risk Score ($0.0\% - 100.0\%$).
  - Threat Categorization: **Safe**, **Suspicious**, or **Malicious**.
  - Model Confidence Percentage.
  - Transparent human-readable explanations (*"Why was this flagged?"*).

---

### 2. 💬 Interactive Chatbot Assistant with Voice Narration
- **"Tell Me Yourself" / Developer Profile Feature:**
  - Triggered by asking *"tell me yourself"*, *"who are you"*, or *"show profile"*.
  - Displays a rich developer profile card with your name, title, bio, core technical skills, GitHub, LinkedIn, and email.
  - **Voice Narration (Text-to-Speech):** Speaks aloud the developer introduction using the browser's native Web Speech API.
- **Scan Result Explanations:**
  - Ask *"Why was this flagged?"* or *"Explain my scan"* to receive an instant, spoken breakdown of the latest evaluated content.
- **Comprehensive Knowledge Base & Broad Q&A:**
  - Answers any questions on phishing, smishing, 2FA, ransomware, incident response, SQL Injection, XSS, firewalls, VPNs, and cybersecurity best practices.
  - Accessible on all pages via a floating widget and on the dedicated `/chatbot` page.

---

### 3. 🛡️ Error & Anomaly Detection System
- **IP Rate Limiting & Abuse Prevention:** Monitors and blocks rapid-fire flood attacks from the same IP, logging `RATE_LIMIT_EXCEEDED` anomalies.
- **Malformed Input & Payload Size Inspection:** Rejects binary garbage, null bytes, and payloads exceeding safety thresholds, logging `MALFORMED_INPUT` or `EXCESSIVE_PAYLOAD`.
- **Low-Confidence Triage:** Automatically flags borderline model predictions ($46\% - 54\%$ or low confidence) as `LOW_CONFIDENCE_PREDICTION` for admin security review.
- **Admin Center (`/admin`):** Review, audit, and resolve flagged anomalies.

---

### 4. 📊 Real-Time Security Operations Dashboard
- Live metric cards: Total Submissions, Malicious Threats Blocked, Suspicious Flagged, Anomalies Monitored, Average Risk Index, and Assistant Queries.
- Interactive Chart.js visualizations:
  - Threat Risk Distribution (Doughnut Chart)
  - Submissions by Channel (Bar Chart: URLs vs Emails vs SMS)
- Live real-time threat activity stream feed.

---

### 5. 🗄️ SQLite Database (SQLAlchemy)
- `submissions`: Stores raw content, category, risk score, threat level, confidence, indicators, client IP, and timestamps.
- `chat_messages`: Stores conversational logs and session history.
- `anomaly_logs`: Stores security anomalies, payloads, origin IP, severity, and resolution status.
- `user_profile`: Stores creator/developer profile information for the *"tell me yourself"* showcase.

---

## 🚀 How to Run Anytime in the Future

### Option 1: Double-Click the Desktop Shortcut (Easiest)
- A shortcut named **`CyberShield AI`** has been placed right on your **Windows Desktop**!
- Simply double-click **`CyberShield AI`** on your Desktop anytime to launch the app and open your browser automatically.

### Option 2: Double-Click `start_app.bat`
- Open the project folder and double-click:
  ```
  start_app.bat
  ```

### Option 3: Terminal Command
- Open PowerShell or Command Prompt in the project folder and run:
  ```powershell
  python run.py
  ```

### Option 4: Auto-Start on Windows Boot (Run Automatically Every Time)
- If you want CyberShield AI to start silently in the background whenever you turn on your computer:
  - Double-click **`setup_auto_start.bat`** (registers the app in Windows Startup).
  - To turn it off anytime, double-click **`remove_auto_start.bat`**.

---

## 🌐 Application Routes & Navigation

| Route | Label in Navbar | Description |
|---|---|---|
| `http://127.0.0.1:8000/` | **Threat Scanner** | Clean input scanner for text, emails, and URLs with live AI risk score and explanation. |
| `http://127.0.0.1:8000/dashboard` | **Analytics Dashboard** | Visual charts (threat ratios, channels, telemetry). |
| `http://127.0.0.1:8000/operations` | **Security & Operations** | Anomaly audit logs, rate-limit triggers, and system controls. |
| `http://127.0.0.1:8000/history` | **Recent History** | Dedicated full database table of all analyzed scans with search and filters. |
| `http://127.0.0.1:8000/chatbot` | **AI Assistant** | Voice-enabled assistant with "tell me yourself" profile and scan explanations. |
| **Top-Right Icon** | **Admin Profile** | Quick profile modal and owner laptop status. |

---

## 🖥️ Desktop App Launcher (Double-Click)

When you double-click the **CyberShield AI** icon on your Desktop:
1. It opens a native Desktop Launcher window titled:
   **"AI-Powered Phishing & Threat Detection Web App"**
2. In the middle down side, click the **"🚀 START APPLICATION"** button.
3. It launches the AI engine and opens the website in your browser!
