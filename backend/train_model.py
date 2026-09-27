import os
import re
import math
import json
import pickle
from collections import Counter

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODELS_DIR = os.path.join(BASE_DIR, "models")
os.makedirs(MODELS_DIR, exist_ok=True)
MODEL_FILE = os.path.join(MODELS_DIR, "phishing_detector.pkl")

# Diverse real-world dataset representing benign and phishing texts, URLs, and emails
TRAINING_DATA = [
    # --- PHISHING SAMPLES (1 = Phishing/Threat) ---
    ("URGENT: Your PayPal account has been restricted! Click here to verify your identity within 24 hours or your funds will be frozen.", 1),
    ("Dear customer, We detected unauthorized login attempt to your Wells Fargo bank account. Re-authenticate now at http://wellsfargo-verify-security.top/login", 1),
    ("Your Apple ID has been locked due to multiple invalid password attempts. Unlock immediately: http://192.168.1.10/apple-support/verify.html", 1),
    ("Final Notice: Outstanding invoice #849202 is overdue. Please download and execute the attached billing document or your service will be terminated.", 1),
    ("Microsoft 365 Security Alert: Suspicious email activity detected. Review and update your credentials immediately: http://login-microsoftonline.xyz/auth", 1),
    ("You have won $1,500,000 in the International Lottery Sweepstakes! Send your bank details and SSN to claim your reward today.", 1),
    ("Netflix Payment Declined: Update your billing payment method to continue watching. Go to http://netflix-billing-update.cc/secure", 1),
    ("Security Warning: Your crypto wallet private key was requested from IP 185.220.101.4. Click here to cancel transaction and secure funds.", 1),
    ("Amazon Order Confirmation: You bought iPhone 15 Pro Max for $1,299. If this was not you, call fraud helpline or click http://amzn-support-cancel.fit/order", 1),
    ("HR Dept: Please sign the mandatory updated employee policy document by 5 PM today at http://company-hr-portal.club/doc-sign", 1),
    ("IRS Tax Refund Alert: You have an unclaimed federal tax refund of $842.00. Submit your direct deposit info at http://irs-gov-taxrefund.info", 1),
    ("FedEx Delivery Notice: Parcel delivery failed due to incorrect shipping address. Click to pay $1.99 redelivery fee: http://fedx-package-tracking.tk/track", 1),
    ("DHL Express: Your shipment is pending customs fee verification. Pay immediately or parcel will be returned to sender.", 1),
    ("Warning: Password expiration notification. Your corporate email password will expire in 2 hours. Keep current password by validating credentials here.", 1),
    ("Bank of America: Unusual credit card transaction of $749.99 detected. Verify if you authorized this charge now.", 1),
    ("Exclusive Offer: Double your Bitcoin in 48 hours! Deposit BTC to this verified trading smart contract.", 1),
    ("Chase Online: Your account has been temporarily flagged for suspicious wire activity. Complete security audit here.", 1),
    ("Google Account: Critical security alert - someone knows your password! Verify your account immediately.", 1),
    ("http://login.chase.com.security-verify.xyz/signin", 1),
    ("http://paypal-account-center.top/restricted/login.php?cmd=verify", 1),
    ("http://194.26.29.112/secure-banking/index.html", 1),
    ("http://appleid.apple.com.verify-billing.tk/auth", 1),
    ("http://update-instagram-badges.cc/verify-account", 1),
    ("http://bit.ly/secure-banking-login-alert", 1),
    ("http://secure-login-att.com.temporary-access.work/webmail", 1),
    ("Urgent wire request from CEO: Transfer $45,000 to new vendor before 3 PM today. Keep this confidential.", 1),
    ("Notice of Subpoena: You are summoned to appear before Federal Court. Download court summons documents now.", 1),
    ("Your Telegram code is 84920. Never share this code. Enter code at http://telegram-web-login.top", 1),
    ("Steam Community Alert: Your Steam inventory will be banned due to scam reports. Contact Steam Admin immediately.", 1),
    ("Meta Business Manager: Your Facebook page violates copyright terms and will be deleted in 24 hours. Appeal here.", 1),

    # --- BENIGN / LEGITIMATE SAMPLES (0 = Safe) ---
    ("Hey Sarah, are we still meeting tomorrow at 10 AM for the quarterly roadmap review?", 0),
    ("Hi team, please find attached the minutes from yesterday's product design sync. Have a great weekend!", 0),
    ("Your weekly GitHub digest: 5 pull requests merged in your repository. Check code reviews online.", 0),
    ("Thanks for your order at REI! Your hiking boots have shipped and should arrive by Thursday.", 0),
    ("Hi everyone, the lunch order for today has been placed. Pizza should arrive around 12:30 PM in the break room.", 0),
    ("Can you review this pull request when you get a chance? I refactored the database connection pool.", 0),
    ("Reminder: Doctor's appointment scheduled for tomorrow at 3:00 PM at City Health Center.", 0),
    ("https://github.com/torvalds/linux", 0),
    ("https://en.wikipedia.org/wiki/Phishing", 0),
    ("https://www.google.com/search?q=cybersecurity+best+practices", 0),
    ("https://docs.python.org/3/library/sqlite3.html", 0),
    ("https://fastapi.tiangolo.com/tutorial/first-steps/", 0),
    ("https://stackoverflow.com/questions/11227809/why-is-processing-a-sorted-array-faster-than-processing-an-unsorted-array", 0),
    ("https://www.microsoft.com/en-us/security", 0),
    ("https://aws.amazon.com/free/", 0),
    ("https://www.coursera.org/learn/cyber-security-specialization", 0),
    ("Here are the lecture slides from today's computer networks class on TCP/IP protocol stack.", 0),
    ("Good morning, could you send me the latest sales figures for Q2? Thanks, Dave.", 0),
    ("Happy birthday John! Wishing you all the best and a fantastic year ahead!", 0),
    ("The library book you reserved is now ready for pickup at Central Library branch.", 0),
    ("Please note that our office will be closed on Monday in observance of Labor Day.", 0),
    ("Sprint retrospective starts at 4 PM in conference room B. Bring your sprint action items.", 0),
    ("Your monthly electricity bill of $42.50 is now available online at your standard utility portal.", 0),
    ("Receipt for your subscription renewal. Thank you for using Spotify Premium.", 0),
    ("New comment on your blog post: 'Great explanation of transformer attention mechanisms!'", 0),
    ("Flight confirmation: Your flight AA142 departing Chicago to Boston is confirmed on schedule.", 0),
    ("Weather alert: Rain expected this afternoon in Seattle with mild temperatures around 62 degrees.", 0),
    ("Git commit: Fixed memory leak in websocket event listener and updated unit tests.", 0),
    ("Hey, did you catch the match last night? What a fantastic comeback in the final minutes!", 0),
    ("Your grocery pickup order is packed and ready at Kroger Store #421.", 0)
]


class PureNLPPhishingModel:
    """
    Self-contained pure-Python NLP Phishing Detection Pipeline:
    - Tokenizer with word unigrams & bigrams
    - TF-IDF Vectorizer with Sublinear Term Frequency
    - Multinomial Naive Bayes Probabilistic Classifier with Laplace Smoothing
    """

    def __init__(self):
        self.vocab = {}
        self.idf = {}
        self.class_priors = {}
        self.feature_log_probs = {0: {}, 1: {}}
        self.classes = [0, 1]

    def _tokenize(self, text: str) -> list[str]:
        # Lowercase, extract alphanumeric tokens and common URL/email markers
        clean = re.sub(r"[^a-zA-Z0-9\.\-\:\/\@]", " ", text.lower())
        words = [w for w in clean.split() if len(w) > 1]
        tokens = list(words)
        # Add word bigrams
        for i in range(len(words) - 1):
            tokens.append(f"{words[i]}_{words[i+1]}")
        return tokens

    def fit(self, texts: list[str], labels: list[int]):
        num_docs = len(texts)
        doc_tokens = [self._tokenize(t) for t in texts]

        # 1. Document frequency for IDF
        df_counter = Counter()
        for tokens in doc_tokens:
            unique_tokens = set(tokens)
            df_counter.update(unique_tokens)

        # Build vocabulary (frequency >= 1)
        self.vocab = {token: idx for idx, (token, count) in enumerate(df_counter.items()) if count >= 1}
        vocab_size = len(self.vocab)

        # Compute smoothed IDF: log((1 + N) / (1 + df)) + 1
        for token, df in df_counter.items():
            if token in self.vocab:
                self.idf[token] = math.log((1.0 + num_docs) / (1.0 + df)) + 1.0

        # Class counts
        class_doc_counts = Counter(labels)
        for c in self.classes:
            self.class_priors[c] = math.log((class_doc_counts[c] + 1) / (num_docs + 2))

        # 2. Compute TF-IDF features per class
        class_token_weights = {0: Counter(), 1: Counter()}
        total_class_weights = {0: 0.0, 1: 0.0}

        for tokens, label in zip(doc_tokens, labels):
            tf_counter = Counter(tokens)
            for token, count in tf_counter.items():
                if token in self.vocab:
                    # sublinear TF: 1 + log(tf)
                    tf_val = 1.0 + math.log(count)
                    weight = tf_val * self.idf[token]
                    class_token_weights[label][token] += weight
                    total_class_weights[label] += weight

        # 3. Log-likelihood with Laplace additive smoothing
        for c in self.classes:
            denom = total_class_weights[c] + vocab_size
            for token in self.vocab:
                count_w = class_token_weights[c].get(token, 0.0)
                self.feature_log_probs[c][token] = math.log((count_w + 1.0) / denom)

    def predict_proba(self, texts: list[str]) -> list[list[float]]:
        results = []
        for text in texts:
            tokens = self._tokenize(text)
            tf_counter = Counter(tokens)

            # Compute log posterior for each class
            log_posteriors = {}
            for c in self.classes:
                log_prob = self.class_priors[c]
                for token, count in tf_counter.items():
                    if token in self.vocab:
                        weight = 1.0 + math.log(count)
                        log_prob += weight * self.feature_log_probs[c][token]
                log_posteriors[c] = log_prob

            # Convert log probabilities to calibrated probabilities using Softmax / log-sum-exp
            max_log = max(log_posteriors[0], log_posteriors[1])
            exp_0 = math.exp(min(50, max(-50, log_posteriors[0] - max_log)))
            exp_1 = math.exp(min(50, max(-50, log_posteriors[1] - max_log)))
            sum_exp = exp_0 + exp_1

            p0 = exp_0 / sum_exp
            p1 = exp_1 / sum_exp
            results.append([p0, p1])
        return results


def train_and_save():
    """Trains the pure-Python NLP threat model and serializes it."""
    texts = [item[0] for item in TRAINING_DATA]
    labels = [item[1] for item in TRAINING_DATA]

    model = PureNLPPhishingModel()
    model.fit(texts, labels)

    with open(MODEL_FILE, "wb") as f:
        pickle.dump(model, f)

    print(f"[+] Phishing detection model successfully trained and saved to: {MODEL_FILE}")
    return model


if __name__ == "__main__":
    train_and_save()
