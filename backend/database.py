import os
import json
from datetime import datetime
from sqlalchemy import create_engine, Column, Integer, String, Float, Text, Boolean, DateTime
from sqlalchemy.orm import declarative_base, sessionmaker

# Database path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "cyber_shield.db")
DATABASE_URL = f"sqlite:///{DB_PATH}"

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


class Submission(Base):
    """Stores user submitted texts, URLs, and emails along with AI risk evaluation."""
    __tablename__ = "submissions"

    id = Column(Integer, primary_key=True, index=True)
    input_type = Column(String(50), default="text")  # "url", "email", "text"
    raw_content = Column(Text, nullable=False)
    risk_score = Column(Float, default=0.0)          # 0 - 100%
    risk_level = Column(String(50), default="Safe")  # Safe, Suspicious, Malicious
    confidence = Column(Float, default=0.0)          # 0.0 - 1.0
    explanation = Column(Text, default="[]")         # JSON list of explanation reasons
    indicators = Column(Text, default="[]")          # JSON list of specific detected triggers
    client_ip = Column(String(100), default="127.0.0.1")
    created_at = Column(DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "input_type": self.input_type,
            "raw_content": self.raw_content,
            "risk_score": round(self.risk_score, 1),
            "risk_level": self.risk_level,
            "confidence": round(self.confidence * 100, 1),
            "explanation": json.loads(self.explanation) if self.explanation else [],
            "indicators": json.loads(self.indicators) if self.indicators else [],
            "client_ip": self.client_ip,
            "created_at": self.created_at.strftime("%Y-%m-%d %H:%M:%S") if self.created_at else None
        }


class ChatMessage(Base):
    """Stores conversational logs between users and the AI cybersecurity chatbot."""
    __tablename__ = "chat_messages"

    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(String(100), index=True)
    sender = Column(String(20), nullable=False)      # "user" or "bot"
    message = Column(Text, nullable=False)
    intent = Column(String(100), default="general")
    referenced_submission_id = Column(Integer, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "session_id": self.session_id,
            "sender": self.sender,
            "message": self.message,
            "intent": self.intent,
            "referenced_submission_id": self.referenced_submission_id,
            "created_at": self.created_at.strftime("%Y-%m-%d %H:%M:%S") if self.created_at else None
        }


class AnomalyLog(Base):
    """Stores security anomalies, input malformations, rate-limiting, and low-confidence flags."""
    __tablename__ = "anomaly_logs"

    id = Column(Integer, primary_key=True, index=True)
    anomaly_type = Column(String(100), nullable=False) # e.g. "LOW_CONFIDENCE", "RATE_LIMIT_EXCEEDED", "MALFORMED_INPUT"
    severity = Column(String(50), default="Medium")    # Low, Medium, High, Critical
    details = Column(Text, nullable=False)
    payload_preview = Column(Text, default="")
    client_ip = Column(String(100), default="127.0.0.1")
    is_resolved = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "anomaly_type": self.anomaly_type,
            "severity": self.severity,
            "details": self.details,
            "payload_preview": self.payload_preview,
            "client_ip": self.client_ip,
            "is_resolved": self.is_resolved,
            "created_at": self.created_at.strftime("%Y-%m-%d %H:%M:%S") if self.created_at else None
        }


class UserProfile(Base):
    """Stores developer/user profile information displayed when user asks 'tell me yourself'."""
    __tablename__ = "user_profile"

    id = Column(Integer, primary_key=True)
    name = Column(String(150), default="Cybersecurity & AI Developer")
    title = Column(String(200), default="Full-Stack AI Security Specialist & Machine Learning Researcher")
    bio = Column(Text, default="Passionate AI and Cybersecurity innovator dedicated to engineering real-time threat detection systems, intelligent defense agents, and resilient web applications.")
    skills = Column(Text, default=json.dumps([
        "Phishing & Threat Analysis",
        "NLP & Machine Learning",
        "Python / FastAPI / REST APIs",
        "Web Application Security & OWASP",
        "Anomaly Detection & Threat Intelligence",
        "Full-Stack Development (HTML/CSS/JS/Chart.js)"
    ]))
    email = Column(String(150), default="developer@aicyberdefense.local")
    github = Column(String(250), default="https://github.com/developer")
    linkedin = Column(String(250), default="https://linkedin.com/in/developer")
    owner_device = Column(String(100), default="LAPTOP-OUSMHCVJ")
    owner_key = Column(String(100), default="CYBER_OWNER_LAPTOP_SECURE_TOKEN_2026")

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "title": self.title,
            "bio": self.bio,
            "skills": json.loads(self.skills) if self.skills else [],
            "email": self.email,
            "github": self.github,
            "linkedin": self.linkedin,
            "owner_device": self.owner_device
        }


def init_db():
    """Initializes tables and populates default developer profile if absent."""
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        # Verify columns exist in user_profile table (for SQLite schema evolution)
        with engine.connect() as conn:
            from sqlalchemy import text
            try:
                conn.execute(text("ALTER TABLE user_profile ADD COLUMN owner_device VARCHAR(100) DEFAULT 'LAPTOP-OUSMHCVJ'"))
                conn.commit()
            except Exception:
                pass
            try:
                conn.execute(text("ALTER TABLE user_profile ADD COLUMN owner_key VARCHAR(100) DEFAULT 'CYBER_OWNER_LAPTOP_SECURE_TOKEN_2026'"))
                conn.commit()
            except Exception:
                pass

        profile = db.query(UserProfile).first()
        if not profile:
            profile = UserProfile()
            db.add(profile)
            db.commit()
    finally:
        db.close()


def get_db():
    """FastAPI database session dependency."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
