import time
import collections
from datetime import datetime
from sqlalchemy.orm import Session
from backend.database import AnomalyLog

# In-memory sliding window for rate limiting: ip -> list of timestamps
_IP_REQUEST_HISTORY = collections.defaultdict(list)

# Limits
MAX_REQUESTS_PER_MINUTE = 15
MAX_CONTENT_LENGTH = 15000
MIN_CONFIDENCE_THRESHOLD = 0.68


class AnomalyDetector:
    """Monitors incoming submissions for potential abuse, malformed payloads, and low-confidence ML outputs."""

    @staticmethod
    def check_rate_limit(client_ip: str, db: Session) -> bool:
        """
        Detects repeated submissions from the same IP (potential DoS/abuse).
        Returns True if safe, False if rate-limited.
        """
        now = time.time()
        window = 60.0 # 60 seconds window

        # Filter out timestamps older than window
        timestamps = [t for t in _IP_REQUEST_HISTORY[client_ip] if now - t < window]
        timestamps.append(now)
        _IP_REQUEST_HISTORY[client_ip] = timestamps

        if len(timestamps) > MAX_REQUESTS_PER_MINUTE:
            # Log anomaly to database
            anomaly = AnomalyLog(
                anomaly_type="RATE_LIMIT_EXCEEDED",
                severity="High",
                details=f"IP {client_ip} exceeded maximum threshold of {MAX_REQUESTS_PER_MINUTE} submissions per minute ({len(timestamps)} requests received).",
                payload_preview="[Blocked due to rate limiting]",
                client_ip=client_ip,
                is_resolved=False
            )
            db.add(anomaly)
            db.commit()
            return False
        return True

    @staticmethod
    def validate_payload(raw_content: str, client_ip: str, db: Session) -> tuple[bool, str]:
        """
        Validates payload length and checks for malformed text or binary garbage.
        Returns: (is_valid: bool, error_message: str)
        """
        if not raw_content or not raw_content.strip():
            return False, "Submission cannot be empty."

        # Check payload length
        if len(raw_content) > MAX_CONTENT_LENGTH:
            anomaly = AnomalyLog(
                anomaly_type="EXCESSIVE_PAYLOAD",
                severity="Medium",
                details=f"Submitted text length ({len(raw_content)} chars) exceeds maximum safety limit of {MAX_CONTENT_LENGTH} chars.",
                payload_preview=raw_content[:200] + "...",
                client_ip=client_ip,
                is_resolved=False
            )
            db.add(anomaly)
            db.commit()
            return False, f"Input payload exceeds maximum allowed size of {MAX_CONTENT_LENGTH} characters."

        # Check for malformed characters (e.g., null bytes, excessive unprintable ascii)
        null_bytes = raw_content.count('\x00')
        control_chars = sum(1 for c in raw_content if ord(c) < 32 and c not in '\r\n\t')
        if null_bytes > 0 or control_chars > 20:
            anomaly = AnomalyLog(
                anomaly_type="MALFORMED_INPUT",
                severity="High",
                details=f"Input contains {null_bytes} null bytes and {control_chars} illegal control characters (possible exploit/fuzzing attempt).",
                payload_preview=repr(raw_content[:150]),
                client_ip=client_ip,
                is_resolved=False
            )
            db.add(anomaly)
            db.commit()
            return False, "Malformed content detected: input contains prohibited control characters or binary payload."

        return True, ""

    @staticmethod
    def check_prediction_confidence(risk_score: float, confidence: float, content_preview: str, client_ip: str, db: Session):
        """
        Flags predictions with borderline or low confidence for human review.
        """
        # Flag if confidence is below threshold or score is right in the ambiguous middle (45-55)
        if confidence < MIN_CONFIDENCE_THRESHOLD or (46.0 <= risk_score <= 54.0):
            anomaly = AnomalyLog(
                anomaly_type="LOW_CONFIDENCE_PREDICTION",
                severity="Low",
                details=f"AI model produced borderline evaluation: Risk Score {risk_score}%, Confidence {confidence * 100:.1f}%. Flagged for analyst verification.",
                payload_preview=content_preview[:250],
                client_ip=client_ip,
                is_resolved=False
            )
            db.add(anomaly)
            db.commit()
