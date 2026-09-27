import os
import re
import urllib.parse
import pickle
from backend.train_model import train_and_save, MODEL_FILE, PureNLPPhishingModel

# High-risk phishing & threat keywords
URGENCY_KEYWORDS = [
    r"\bimmediate(ly)?\b", r"\burgent(ly)?\b", r"\baction required\b", r"\baccount (suspended|locked|restricted)\b",
    r"\bwithin 24 hours\b", r"\bfinal notice\b", r"\bsecurity (alert|warning|breach)\b", r"\bunauthorized access\b",
    r"\bterminate your account\b", r"\bdeactivate\b", r"\bexpires? in\b", r"\bre-authenticate\b"
]

CREDENTIAL_KEYWORDS = [
    r"\bverify your (identity|account|password|credentials|billing)\b",
    r"\bconfirm your (passcode|pin|ssn|social security)\b",
    r"\benter your (password|credentials|login details)\b",
    r"\bupdate your (billing|payment|credit card)\b",
    r"\bclick (here|the link below) to (verify|login|unlock|claim)\b"
]

FINANCIAL_SCAM_KEYWORDS = [
    r"\bwire transfer\b", r"\bbitcoin\b", r"\bcrypto(currency)?\b", r"\bwallet private key\b",
    r"\bunclaimed (funds|inheritance|refund|lottery)\b", r"\bwon \$?[\d,]+\b",
    r"\binvoice overdue\b", r"\btax refund\b", r"\bclaim your reward\b", r"\bwestern union\b"
]

SUSPICIOUS_TLDS = [
    ".top", ".xyz", ".tk", ".fit", ".work", ".click", ".ru", ".cc", ".club",
    ".info", ".live", ".gq", ".cf", ".ga", ".ml", ".buzz", ".monster"
]

SUSPICIOUS_BRANDS = [
    "paypal", "apple", "microsoft", "netflix", "amazon", "chase", "wellsfargo",
    "bankofamerica", "google", "facebook", "instagram", "dhl", "fedex", "telegram"
]

SHORTENERS = [
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "buff.ly", "ow.ly", "rb.gy"
]


class ThreatDetectionEngine:
    def __init__(self):
        self.model = self._load_or_train_model()

    def _load_or_train_model(self):
        if not os.path.exists(MODEL_FILE):
            print("[*] Model file not found. Auto-training now...")
            return train_and_save()
        try:
            with open(MODEL_FILE, "rb") as f:
                return pickle.load(f)
        except Exception as e:
            print(f"[!] Error loading model: {e}. Re-training...")
            return train_and_save()

    def _is_url(self, text: str) -> bool:
        clean = text.strip()
        return bool(re.match(r"^(https?://|www\.|[a-zA-Z0-9-]+\.[a-zA-Z]{2,})", clean))

    def _analyze_url(self, url: str):
        flags = []
        url_threat_score = 0
        parsed = urllib.parse.urlparse(url if "://" in url else f"http://{url}")
        host = (parsed.hostname or "").lower()
        path = parsed.path.lower()
        query = parsed.query.lower()

        # 1. IP address in hostname
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", host):
            flags.append({
                "type": "IP_HOST",
                "label": "Direct IP Host",
                "desc": f"Hostname '{host}' uses a direct numerical IP address instead of a recognized domain name. Phishers frequently use raw IP addresses to bypass domain reputation checks."
            })
            url_threat_score += 45

        # 2. Suspicious TLD
        for tld in SUSPICIOUS_TLDS:
            if host.endswith(tld):
                flags.append({
                    "type": "SUSPICIOUS_TLD",
                    "label": f"High-Risk TLD ({tld})",
                    "desc": f"Domain utilizes '{tld}', an atypical Top-Level Domain statistically associated with cheap, disposable phishing and malware campaigns."
                })
                url_threat_score += 35
                break

        # 3. URL Shortener detection
        for s in SHORTENERS:
            if s in host:
                flags.append({
                    "type": "URL_SHORTENER",
                    "label": "Shortened URL Redirect",
                    "desc": f"URL uses shortening service '{s}' which obscures the genuine final destination address from the user."
                })
                url_threat_score += 25
                break

        # 4. Brand spoofing / Subdomain deception (e.g. paypal.com.evil.xyz)
        for brand in SUSPICIOUS_BRANDS:
            if brand in host and not host.endswith(f".{brand}.com") and host != f"{brand}.com":
                flags.append({
                    "type": "BRAND_SPOOF",
                    "label": f"Brand Deception ({brand.title()})",
                    "desc": f"Domain incorporates the well-known brand '{brand.title()}' inside its subdomains or URL tokens, a classic typosquatting and phishing tactic."
                })
                url_threat_score += 40
                break

        # 5. Suspicious keywords in URL path or query
        path_matches = re.findall(r"(login|verify|secure|account|update|signin|banking|auth|recovery|password)", path + " " + query)
        if path_matches:
            found = list(set(path_matches))
            flags.append({
                "type": "SENSITIVE_URL_KEYWORDS",
                "label": "Sensitive Credential Terms in URL",
                "desc": f"URL path/parameters contain high-risk authentication keywords: {', '.join(found)}."
            })
            url_threat_score += 20

        # 6. Embedded '@' symbol in URL
        if "@" in url:
            flags.append({
                "type": "AT_SYMBOL_OBFUSCATION",
                "label": "URL Obfuscation ('@')",
                "desc": "The '@' character in URLs causes browsers to ignore all preceding characters for authentication, deceiving the user regarding the destination host."
            })
            url_threat_score += 35

        # 7. Excessive subdomains
        dots_count = host.count(".")
        if dots_count >= 3:
            flags.append({
                "type": "EXCESSIVE_SUBDOMAINS",
                "label": "Excessive Subdomains",
                "desc": f"Domain has {dots_count} levels of subdomains, commonly deployed by attackers to spoof institutional URLs."
            })
            url_threat_score += 15

        return url_threat_score, flags

    def _analyze_text_heuristics(self, text: str):
        flags = []
        text_threat_score = 0
        lower = text.lower()

        # 1. Urgency & Coercion
        urgency_found = []
        for pattern in URGENCY_KEYWORDS:
            matches = re.findall(pattern, lower)
            if matches:
                urgency_found.append(pattern.replace(r"\b", "").replace("(", "").replace(")", "").replace("?", ""))
        if urgency_found:
            flags.append({
                "type": "URGENCY_PRESSURE",
                "label": "Psychological Coercion / Urgency",
                "desc": "Contains high-urgency language designed to induce panic, rush decision-making, or threaten immediate account suspension."
            })
            text_threat_score += 30

        # 2. Credential harvesting cues
        cred_found = []
        for pattern in CREDENTIAL_KEYWORDS:
            if re.search(pattern, lower):
                cred_found.append(pattern)
        if cred_found:
            flags.append({
                "type": "CREDENTIAL_HARVESTING",
                "label": "Credential Harvesting Triggers",
                "desc": "Requests the recipient to verify passwords, confirm sensitive authentication credentials, or follow an external link to authenticate."
            })
            text_threat_score += 35

        # 3. Financial scams & rewards
        fin_found = []
        for pattern in FINANCIAL_SCAM_KEYWORDS:
            if re.search(pattern, lower):
                fin_found.append(pattern)
        if fin_found:
            flags.append({
                "type": "FINANCIAL_BAIT",
                "label": "Financial Fraud / Scam Indicator",
                "desc": "Mentions unexpected prize winnings, cryptocurrency deposits, wire transfers, or fake invoice attachments."
            })
            text_threat_score += 30

        return text_threat_score, flags

    def analyze(self, content: str):
        """
        Analyzes the submitted content using NLP ML classifier + Cybersecurity heuristics.
        Returns: {
            risk_score: float (0 - 100),
            risk_level: "Safe" | "Suspicious" | "Malicious",
            confidence: float (0.0 - 1.0),
            explanation: list[str],
            indicators: list[dict],
            input_type: str
        }
        """
        content_clean = content.strip()
        is_url_type = self._is_url(content_clean)
        input_type = "url" if is_url_type else ("email" if ("subject:" in content_clean.lower() or "dear " in content_clean.lower() or "from:" in content_clean.lower()) else "text")

        # 1. ML Model Prediction
        try:
            proba = self.model.predict_proba([content_clean])[0]
            ml_phish_prob = float(proba[1]) # probability of phishing (0.0 - 1.0)
        except Exception as e:
            print(f"[!] Inference exception: {e}")
            ml_phish_prob = 0.5

        # 2. Heuristics & Lexical Analysis
        heuristic_score = 0
        all_indicators = []

        if is_url_type:
            u_score, u_flags = self._analyze_url(content_clean)
            heuristic_score += u_score
            all_indicators.extend(u_flags)

        t_score, t_flags = self._analyze_text_heuristics(content_clean)
        heuristic_score += t_score
        all_indicators.extend(t_flags)

        # 3. Composite Risk Calculation (0 - 100 scale)
        # Combine ML probability (50% weight) and heuristic score (50% weight)
        ml_score = ml_phish_prob * 100
        composite_score = min(100.0, max(0.0, (ml_score * 0.55) + (min(100.0, heuristic_score) * 0.45)))

        # If strong technical indicators exist (e.g. brand spoof + suspicious TLD), ensure minimum score threshold
        if heuristic_score >= 60 and composite_score < 70:
            composite_score = max(composite_score, 75.0)

        # 4. Risk Level Categorization
        if composite_score < 35.0:
            risk_level = "Safe"
        elif composite_score < 70.0:
            risk_level = "Suspicious"
        else:
            risk_level = "Malicious"

        # 5. Confidence Score
        # High confidence when ML and heuristics align or when extreme scores are reached
        dist_from_boundary = abs(composite_score - 50.0) / 50.0  # 0 to 1
        confidence = min(0.99, max(0.60, 0.65 + (dist_from_boundary * 0.32)))

        # 6. Detailed Explanations
        explanations = []
        if risk_level == "Malicious":
            explanations.append(f"CRITICAL THREAT DETECTED: Content exhibits severe indicators of a malicious phishing attack or cyber threat with an overall risk score of {composite_score:.1f}%.")
        elif risk_level == "Suspicious":
            explanations.append(f"SUSPICIOUS ACTIVITY FLAGGED: Content presents warning signs consistent with social engineering or deceptive communications (Risk Score: {composite_score:.1f}%).")
        else:
            explanations.append(f"BENIGN / SAFE EVALUATION: No malicious threat signatures or phishing patterns were detected (Risk Score: {composite_score:.1f}%).")

        for ind in all_indicators:
            explanations.append(f"• [{ind['label']}]: {ind['desc']}")

        if not all_indicators and risk_level == "Safe":
            explanations.append("• Standard linguistic patterns observed without urgency cues, spoofed domains, or credential harvesting payloads.")

        return {
            "risk_score": round(composite_score, 1),
            "risk_level": risk_level,
            "confidence": round(confidence, 2),
            "explanation": explanations,
            "indicators": all_indicators,
            "input_type": input_type
        }


# Singleton engine instance
ml_engine = ThreatDetectionEngine()
