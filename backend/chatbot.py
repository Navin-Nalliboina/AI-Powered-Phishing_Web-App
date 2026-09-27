import json
import re
from sqlalchemy.orm import Session
from backend.database import ChatMessage, Submission, UserProfile

# Comprehensive knowledge base mapping keywords and concepts to high-quality security answers
CYBER_QA_KNOWLEDGE_BASE = [
    {
        "keywords": ["what is phishing", "define phishing", "explain phishing", "how phishing works"],
        "topic": "Phishing Fundamentals",
        "answer": (
            "**Phishing** is a form of social engineering where cybercriminals impersonate legitimate organizations "
            "(such as banks, cloud providers, or government agencies) to deceive victims into disclosing sensitive information—including "
            "passwords, credit card numbers, or API keys.\n\n"
            "### Common Phishing Vectors:\n"
            "1. **Email Phishing**: Mass emails with urgent calls to action or spoofed invoice attachments.\n"
            "2. **Spear Phishing**: Highly tailored attacks targeting specific individuals or executives (Whaling).\n"
            "3. **Smishing**: SMS text messages claiming package delivery failures or bank account alerts.\n"
            "4. **Vishing**: Voice calls impersonating tech support or law enforcement.\n\n"
            "🛡️ *Defense Tip:* Always inspect the actual sender email domain and never authenticate via unverified links."
        ),
        "voice": "Phishing is a social engineering attack where malicious actors impersonate trusted organizations to steal credentials or personal data. Never click unverified links or enter your credentials without verifying the domain."
    },
    {
        "keywords": ["spot fake link", "identify phishing url", "check url", "suspicious link", "fake domain"],
        "topic": "URL Security & Verification",
        "answer": (
            "### How to Spot a Phishing or Malicious Link:\n"
            "1. **Check the Top-Level Domain (TLD)**: Scammers often register `.top`, `.xyz`, `.tk`, or `.cc` domains.\n"
            "2. **Inspect for Typosquatting**: E.g., `micros0ft.com` or `paypa1-security.com`.\n"
            "3. **Look for Direct IP Addresses**: URLs like `http://192.168.1.10/login` in public links are high-risk.\n"
            "4. **Subdomain Tricks**: In `paypal.com.account-verify.xyz`, the actual domain is `account-verify.xyz`, NOT `paypal.com`.\n"
            "5. **Examine the Protocol**: Absence of HTTPS on a supposed login page is an immediate red flag.\n\n"
            "🔍 *Pro Tip:* Paste the link into our **Threat Scanner** above for instant AI-powered risk analysis!"
        ),
        "voice": "To identify fake links, always check the exact domain spelling, beware of deceptive subdomains, watch out for suspicious domain extensions, and test the link in our threat scanner."
    },
    {
        "keywords": ["2fa", "two factor", "mfa", "multi factor", "authenticator"],
        "topic": "Multi-Factor Authentication",
        "answer": (
            "**Multi-Factor Authentication (MFA / 2FA)** enforces security by requiring two or more independent credentials before granting account access:\n\n"
            "• **Something you know:** Master Password or PIN\n"
            "• **Something you have:** Authenticator App code (TOTP), Hardware Token (YubiKey), or push notification\n"
            "• **Something you are:** Biometric fingerprint or Face ID\n\n"
            "⚠️ **Recommendation:** Avoid SMS-based 2FA when possible due to SIM-swapping attacks. Use hardware security keys or authenticator apps (like Google Authenticator or Bitwarden)."
        ),
        "voice": "Two-factor authentication adds a vital secondary layer of defense beyond passwords. We recommend using authenticator apps or hardware keys rather than SMS."
    },
    {
        "keywords": ["password", "strong password", "passphrase", "password manager"],
        "topic": "Password Security & Management",
        "answer": (
            "### Password Hardening Best Practices:\n"
            "1. **Use Passphrases**: Combine 4–5 random words (e.g., `correct-horse-battery-staple`) exceeding 16 characters.\n"
            "2. **Never Reuse Passwords**: A leak on one site compromises all accounts if passwords match.\n"
            "3. **Deploy a Password Manager**: Tools like Bitwarden, 1Password, or KeePass generate and autofill cryptographically secure credentials.\n"
            "4. **Check for Breaches**: Regularly query services like *HaveIBeenPwned* to verify account status."
        ),
        "voice": "Always use unique, random passphrases of at least sixteen characters and utilize a trusted password manager so you never have to remember or repeat passwords."
    },
    {
        "keywords": ["ransomware", "malware", "encrypt files"],
        "topic": "Ransomware Defense",
        "answer": (
            "**Ransomware** is malicious software that encrypts user or corporate files, demanding monetary payment (typically cryptocurrency) for decryption.\n\n"
            "### Core Protection Strategy:\n"
            "• **3-2-1 Backup Rule:** 3 copies of data, across 2 different storage media, with 1 copy stored offline or offsite.\n"
            "• **Endpoint Protection:** Keep operating system, browsers, and antivirus software continuously patched.\n"
            "• **Email Attachment Caution:** Never enable macros or execute `.exe`, `.scr`, or `.vbs` files received via email."
        ),
        "voice": "Ransomware encrypts your critical files and demands ransom. Protect yourself by maintaining offline 3-2-1 backups, updating your systems, and never running unsolicited email attachments."
    },
    {
        "keywords": ["clicked phishing link", "entered password", "i got scammed", "what to do if hacked", "compromised"],
        "topic": "Incident Response for Users",
        "answer": (
            "### Immediate Emergency Actions if You Clicked a Suspicious Link:\n"
            "1. **Disconnect Network**: Disconnect Wi-Fi or unplug your Ethernet cable if an unknown file began downloading.\n"
            "2. **Change Credentials Immediately**: If you submitted passwords, reset credentials from a different, clean device.\n"
            "3. **Revoke Active Sessions**: Log into the affected service and choose *'Log out of all devices'*.\n"
            "4. **Notify Financial Institutions**: If payment cards or banking logins were entered, freeze cards immediately.\n"
            "5. **Scan for Malware**: Run a comprehensive endpoint security scan using an updated antivirus engine."
        ),
        "voice": "If you clicked a suspicious link or entered credentials, immediately disconnect your device from the internet, reset your passwords from a safe device, revoke active sessions, and freeze credit cards if financial data was entered."
    },
    {
        "keywords": ["how model works", "how does ai detect", "detection engine", "machine learning", "tfidf", "scikit"],
        "topic": "Threat Detection Architecture",
        "answer": (
            "### How Our AI Threat Detection Engine Works:\n"
            "1. **Natural Language Processing (NLP)**: Utilizes a Scikit-Learn pipeline featuring character and word n-gram **TF-IDF Vectorization** trained on authentic phishing and benign datasets.\n"
            "2. **Lexical Heuristics Engine**: Analyzes URLs for raw IP hostnames, high-risk TLDs (`.top`, `.xyz`, etc.), brand deception/typosquatting, and link-shortener obfuscation.\n"
            "3. **Psychological Triggers Extraction**: Identifies urgency vectors (*'immediate action required'*, *'account restricted'*), credential harvesting traps, and financial lures.\n"
            "4. **Calibrated Composite Scoring**: Synthesizes probabilistic ML confidence with weighted heuristic alerts to classify inputs into **Safe**, **Suspicious**, or **Malicious**."
        ),
        "voice": "Our threat engine combines machine learning with natural language processing and deep lexical heuristics to analyze syntax, urgency triggers, and domain structures in real-time."
    },
    {
        "keywords": ["how to use", "how do i scan", "instructions", "help", "guide"],
        "topic": "User Guide",
        "answer": (
            "### Using the AI Threat Detection Web App:\n"
            "1. **Navigate to the Scanner**: Paste any suspicious email text, SMS message, or URL into the submission input.\n"
            "2. **Quick Test**: Use one of the pre-loaded sample buttons (*Phishing Email*, *Malicious Link*, *Legitimate Notice*) for instant demonstrations.\n"
            "3. **Click 'Analyze Threat'**: View the real-time animated risk meter, threat level, confidence percentage, and detailed security findings.\n"
            "4. **Ask the Chatbot**: Type *'Why was this flagged?'* to get an interactive explanation of your latest scan result!"
        ),
        "voice": "To use the scanner, paste any suspicious URL or message into the analysis box or select a test sample, then click Analyze Threat. You can ask me to explain any flagged result at any time."
    }
]


class ChatbotAssistant:
    """Intelligent Cybersecurity Chatbot with Profile Showcase, Voice Explanations, and Broad Knowledge."""

    def __init__(self):
        pass

    def _get_profile_response(self, db: Session):
        """Builds profile card and voice introduction for the user/creator."""
        profile = db.query(UserProfile).first()
        if not profile:
            profile = UserProfile()
            db.add(profile)
            db.commit()

        skills_list = json.loads(profile.skills) if profile.skills else []
        skills_formatted = " • ".join(skills_list)

        text_response = (
            f"### 🛡️ Developer & AI Identity Profile\n\n"
            f"**Name:** {profile.name}\n\n"
            f"**Role:** {profile.title}\n\n"
            f"**Bio:** {profile.bio}\n\n"
            f"**Core Expertise:**\n"
            f"{chr(10).join(['• ' + s for s in skills_list])}\n\n"
            f"**Contact & Links:**\n"
            f"- 🌐 **GitHub:** [{profile.github}]({profile.github})\n"
            f"- 💼 **LinkedIn:** [{profile.linkedin}]({profile.linkedin})\n"
            f"- 📧 **Email:** `{profile.email}`\n\n"
            f"---\n"
            f"💡 *You can update this profile data anytime via the database or admin interface!*"
        )

        voice_script = (
            f"Hello! I am your AI Cybersecurity Assistant, created by {profile.name}. "
            f"{profile.name} is a {profile.title}. "
            f"{profile.bio} "
            f"Key expertise includes: {', '.join(skills_list[:3])}. "
            f"I am ready to answer your cybersecurity questions or explain any scanned threats!"
        )

        return {
            "response": text_response,
            "voice_text": voice_script,
            "action": "SHOW_PROFILE",
            "profile_data": profile.to_dict()
        }

    def _get_scan_explanation(self, db: Session, user_ip: str):
        """Explains the latest scanned item for the user."""
        recent = db.query(Submission).order_by(Submission.id.desc()).first()
        if not recent:
            return {
                "response": "No scans found in database yet. Try pasting an email, message, or URL into the **Threat Scanner** first, then ask me to explain!",
                "voice_text": "No previous scans were found in the database. Please scan a text or link on the home page first."
            }

        explanations = json.loads(recent.explanation) if recent.explanation else []
        indicators = json.loads(recent.indicators) if recent.indicators else []

        bullet_points = "\n".join([f"- {exp}" for exp in explanations])
        indicator_summary = "\n".join([f"• **{ind.get('label')}**: {ind.get('desc')}" for ind in indicators]) if indicators else "No critical indicators flagged."

        response = (
            f"### 🔍 Analysis Breakdown for Scan #{recent.id}\n\n"
            f"- **Input Evaluated:** `{recent.raw_content[:80]}...`\n"
            f"- **Risk Level:** **{recent.risk_level.upper()}** (Score: {recent.risk_score}%)\n"
            f"- **Model Confidence:** {recent.confidence * 100:.1f}%\n"
            f"- **Submission Category:** {recent.input_type.upper()}\n\n"
            f"### Key Findings:\n"
            f"{bullet_points}\n\n"
            f"### Technical Threat Indicators:\n"
            f"{indicator_summary}\n\n"
            f"💡 *Need further assistance? Ask me how to protect yourself or report this threat!*"
        )

        voice_script = (
            f"Here is the breakdown for your last scan. "
            f"The content was evaluated as {recent.risk_level} with a risk score of {recent.risk_score} percent and {recent.confidence * 100:.0f} percent confidence. "
            f"{'Warning: malicious indicators such as suspicious domain structures or urgency triggers were identified.' if recent.risk_level != 'Safe' else 'The content conforms to standard safe patterns.'}"
        )

        return {
            "response": response,
            "voice_text": voice_script,
            "action": "SCAN_EXPLANATION",
            "scan_id": recent.id
        }

    def generate_response(self, user_message: str, session_id: str, client_ip: str, db: Session) -> dict:
        """Processes user message and returns text, voice script, and action metadata."""
        msg = user_message.strip()
        lower = msg.lower()

        # 1. Check for "tell me yourself" / Creator Profile queries
        profile_triggers = [
            "tell me yourself", "tell me about yourself", "who are you", "who made you",
            "what is your profile", "show profile", "about creator", "about developer",
            "tell me about you", "who created you", "your profile", "introduce yourself"
        ]
        if any(trigger in lower for trigger in profile_triggers):
            result = self._get_profile_response(db)
            self._log_chat(session_id, "user", msg, "profile", db)
            self._log_chat(session_id, "bot", result["response"], "profile", db)
            return result

        # 2. Check for "Why was this flagged?" / Scan Explanation queries
        explanation_triggers = [
            "why was this flagged", "why was it flagged", "explain my scan", "explain my result",
            "why is it dangerous", "why is it safe", "explain detection", "why flagged", "scan explanation"
        ]
        if any(trigger in lower for trigger in explanation_triggers):
            result = self._get_scan_explanation(db, client_ip)
            self._log_chat(session_id, "user", msg, "explanation", db)
            self._log_chat(session_id, "bot", result["response"], "explanation", db)
            return result

        # 3. Match against Cybersecurity Knowledge Base
        best_match = None
        highest_score = 0

        for entry in CYBER_QA_KNOWLEDGE_BASE:
            score = 0
            for kw in entry["keywords"]:
                if kw in lower:
                    score += 2
                elif any(word in lower for word in kw.split()):
                    score += 1
            if score > highest_score:
                highest_score = score
                best_match = entry

        if best_match and highest_score >= 2:
            self._log_chat(session_id, "user", msg, "knowledge_base", db)
            self._log_chat(session_id, "bot", best_match["answer"], "knowledge_base", db)
            return {
                "response": best_match["answer"],
                "voice_text": best_match["voice"],
                "action": "ANSWER_FAQ"
            }

        # 4. Intelligent Technical & Cybersecurity reasoning engine for open questions
        general_answer, voice_answer = self._generate_intelligent_answer(msg)
        self._log_chat(session_id, "user", msg, "intelligent_qa", db)
        self._log_chat(session_id, "bot", general_answer, "intelligent_qa", db)

        return {
            "response": general_answer,
            "voice_text": voice_answer,
            "action": "INTELLIGENT_QA"
        }

    def _generate_intelligent_answer(self, query: str) -> tuple[str, str]:
        """Provides accurate responses for general tech, security, network, and conceptual queries."""
        q = query.lower()

        if any(term in q for term in ["hello", "hi", "hey", "greetings"]):
            ans = (
                "👋 **Hello! Welcome to CyberShield AI.**\n\n"
                "I am your dedicated cybersecurity assistant. I can:\n"
                "• Analyze and explain your scanned threat results (*'Why was this flagged?'*)\n"
                "• Show developer and project details (*'Tell me yourself'*)\n"
                "• Answer questions on phishing, malware, network security, passwords, and 2FA.\n\n"
                "How can I assist you today?"
            )
            voice = "Hello! I am CyberShield AI. Ask me any question about cybersecurity, explain your scan results, or ask me to introduce the developer."
            return ans, voice

        if any(term in q for term in ["sql injection", "sqli"]):
            ans = (
                "### SQL Injection (SQLi) Overview:\n"
                "**SQL Injection** occurs when untrusted user input is directly concatenated into dynamic database queries, allowing attackers to view, modify, or delete sensitive records.\n\n"
                "**Mitigation:**\n"
                "1. Always use **Parameterized Queries (Prepared Statements)** or ORMs (like SQLAlchemy).\n"
                "2. Implement strict input validation and least-privilege database user access."
            )
            voice = "SQL Injection happens when untrusted user input alters database queries. Protect your systems using parameterized queries and least-privilege accounts."
            return ans, voice

        if any(term in q for term in ["xss", "cross site scripting"]):
            ans = (
                "### Cross-Site Scripting (XSS) Overview:\n"
                "**XSS** occurs when an application includes unvalidated data in a web page without proper escaping, allowing attackers to execute arbitrary JavaScript in the victim's browser session.\n\n"
                "**Defense:** Context-aware output encoding, strict Content Security Policy (CSP), and HttpOnly cookie flags."
            )
            voice = "Cross-Site Scripting allows attackers to inject malicious scripts into web pages viewed by other users. Defend using proper output encoding and Content Security Policy."
            return ans, voice

        if any(term in q for term in ["firewall", "waf"]):
            ans = (
                "### Firewalls & WAFs:\n"
                "A **Firewall** acts as a network perimeter filter examining incoming and outgoing traffic based on IP addresses and ports.\n"
                "A **Web Application Firewall (WAF)** operates at Layer 7 (Application layer) inspecting HTTP traffic to block threats like SQLi, XSS, and credential stuffing."
            )
            voice = "Firewalls filter network traffic by rules. Web Application Firewalls inspect application-layer HTTP traffic to protect against web exploits."
            return ans, voice

        if any(term in q for term in ["vpn", "virtual private network"]):
            ans = (
                "### Virtual Private Networks (VPNs):\n"
                "A **VPN** creates an encrypted tunnel across untrusted networks (e.g. public coffee shop Wi-Fi), masking your real IP address and protecting transmitted data from local eavesdropping."
            )
            voice = "A VPN encrypts your network connection and routes traffic through a secure tunnel, protecting your privacy on public networks."
            return ans, voice

        # Universal fallback response providing clear actionable guidance
        ans = (
            f"### 🛡️ Cybersecurity Analysis: *{query.strip()}*\n\n"
            f"Thank you for your question. In cybersecurity and threat intelligence, addressing **{query.strip()}** involves:\n\n"
            f"1. **Threat Identification:** Assessing whether the activity or pattern introduces unauthorized access, credential leakage, or network vulnerability.\n"
            f"2. **Defense-in-Depth:** Combining perimeter firewalls, multi-factor authentication, endpoint monitoring, and AI-driven behavioral analysis.\n"
            f"3. **Zero Trust Architecture:** Verifying explicitly, granting least-privilege access, and continuously monitoring for anomalies.\n\n"
            f"💡 *Tip:* You can also test any suspicious content directly by pasting it into the **Threat Scanner** above!"
        )
        voice = f"Regarding {query.strip()}: in cybersecurity, always practice defense-in-depth, least-privilege access, and continuous verification."
        return ans, voice

    def _log_chat(self, session_id: str, sender: str, message: str, intent: str, db: Session):
        """Stores chat message in database."""
        try:
            entry = ChatMessage(
                session_id=session_id,
                sender=sender,
                message=message,
                intent=intent
            )
            db.add(entry)
            db.commit()
        except Exception as e:
            print(f"[!] Error logging chat message: {e}")


# Singleton instance
chatbot_assistant = ChatbotAssistant()
