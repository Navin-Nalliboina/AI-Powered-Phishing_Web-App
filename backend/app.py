import os
import json
from datetime import datetime, timedelta
from fastapi import FastAPI, HTTPException, Request, Depends, status
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from sqlalchemy import func

from backend.database import init_db, get_db, Submission, ChatMessage, AnomalyLog, UserProfile
from backend.ml_engine import ml_engine
from backend.anomaly_detector import AnomalyDetector
from backend.chatbot import chatbot_assistant

# Initialize Database
init_db()

# Create FastAPI app
app = FastAPI(
    title="CyberShield AI - Threat Detection & Assistant Platform",
    description="Full-stack AI-Powered Phishing & Cyber Threat Detection Web Application with Chatbot Assistant",
    version="1.0.0"
)

# Enable CORS for flexibility
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Absolute paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(BASE_DIR)
FRONTEND_DIR = os.path.join(PROJECT_ROOT, "frontend")


# Pydantic Schemas
class ScanRequest(BaseModel):
    content: str = Field(..., min_length=1, description="URL, email body, or message text to analyze")
    input_type: str = Field(default="auto", description="Input type: auto, text, email, url")


class ChatRequest(BaseModel):
    message: str = Field(..., min_length=1)
    session_id: str = Field(default="default_session")


class ProfileUpdateRequest(BaseModel):
    name: str
    title: str
    bio: str
    skills: list[str]
    email: str
    github: str
    linkedin: str


# Helper to get client IP
def get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "127.0.0.1"


# ==================== API ENDPOINTS ====================

@app.post("/api/scan")
async def analyze_threat(payload: ScanRequest, request: Request, db: Session = Depends(get_db)):
    """Analyzes text or URL for phishing and cyber threats with anomaly inspection."""
    client_ip = get_client_ip(request)

    # 1. Anomaly check: Rate limiting
    if not AnomalyDetector.check_rate_limit(client_ip, db):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded: excessive submissions detected from this IP. Please wait before scanning again."
        )

    # 2. Anomaly check: Payload size & malformed character validation
    is_valid, err_msg = AnomalyDetector.validate_payload(payload.content, client_ip, db)
    if not is_valid:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=err_msg)

    # 3. Threat Engine Analysis
    result = ml_engine.analyze(payload.content)

    # 4. Anomaly check: Low-confidence prediction
    AnomalyDetector.check_prediction_confidence(
        risk_score=result["risk_score"],
        confidence=result["confidence"],
        content_preview=payload.content[:150],
        client_ip=client_ip,
        db=db
    )

    # 5. Persist to Database
    submission = Submission(
        input_type=result["input_type"] if payload.input_type == "auto" else payload.input_type,
        raw_content=payload.content,
        risk_score=result["risk_score"],
        risk_level=result["risk_level"],
        confidence=result["confidence"],
        explanation=json.dumps(result["explanation"]),
        indicators=json.dumps(result["indicators"]),
        client_ip=client_ip
    )
    db.add(submission)
    db.commit()
    db.refresh(submission)

    return submission.to_dict()


import platform
OWNER_COMPUTER_NAME = "LAPTOP-OUSMHCVJ"


@app.get("/api/scans/recent")
def get_recent_scans(limit: int = None, all_records: bool = True, db: Session = Depends(get_db)):
    """Retrieves all submissions history from database."""
    query = db.query(Submission).order_by(Submission.id.desc())
    if not all_records and limit:
        query = query.limit(limit)
    scans = query.all()
    return [s.to_dict() for s in scans]


@app.post("/api/chat")
async def chat_interaction(payload: ChatRequest, request: Request, db: Session = Depends(get_db)):
    """Interacts with the AI cybersecurity assistant with voice and profile support."""
    client_ip = get_client_ip(request)
    response_data = chatbot_assistant.generate_response(
        user_message=payload.message,
        session_id=payload.session_id,
        client_ip=client_ip,
        db=db
    )
    return response_data


@app.get("/api/chat/history/{session_id}")
def get_chat_history(session_id: str, db: Session = Depends(get_db)):
    """Retrieves conversation logs for a session."""
    messages = db.query(ChatMessage).filter(ChatMessage.session_id == session_id).order_by(ChatMessage.id.asc()).all()
    return [m.to_dict() for m in messages]


@app.get("/api/stats")
def get_dashboard_stats(db: Session = Depends(get_db)):
    """Aggregates metrics for the real-time cybersecurity dashboard."""
    total_scans = db.query(Submission).count()
    malicious_count = db.query(Submission).filter(Submission.risk_level == "Malicious").count()
    suspicious_count = db.query(Submission).filter(Submission.risk_level == "Suspicious").count()
    safe_count = db.query(Submission).filter(Submission.risk_level == "Safe").count()
    total_anomalies = db.query(AnomalyLog).count()
    unresolved_anomalies = db.query(AnomalyLog).filter(AnomalyLog.is_resolved == False).count()
    chat_count = db.query(ChatMessage).filter(ChatMessage.sender == "user").count()

    avg_score_res = db.query(func.avg(Submission.risk_score)).scalar()
    avg_risk_score = round(float(avg_score_res), 1) if avg_score_res else 0.0

    # Type breakdown
    url_count = db.query(Submission).filter(Submission.input_type == "url").count()
    email_count = db.query(Submission).filter(Submission.input_type == "email").count()
    text_count = db.query(Submission).filter(Submission.input_type == "text").count()

    # Recent scans summary
    recent_scans = db.query(Submission).order_by(Submission.id.desc()).limit(7).all()

    return {
        "total_scans": total_scans,
        "malicious_count": malicious_count,
        "suspicious_count": suspicious_count,
        "safe_count": safe_count,
        "total_anomalies": total_anomalies,
        "unresolved_anomalies": unresolved_anomalies,
        "chat_queries": chat_count,
        "avg_risk_score": avg_risk_score,
        "distribution": {
            "safe": safe_count,
            "suspicious": suspicious_count,
            "malicious": malicious_count
        },
        "by_type": {
            "url": url_count,
            "email": email_count,
            "text": text_count
        },
        "recent_scans": [s.to_dict() for s in recent_scans]
    }


@app.get("/api/anomalies")
def get_anomalies(limit: int = 50, db: Session = Depends(get_db)):
    """Lists flagged anomalies for security audit."""
    anomalies = db.query(AnomalyLog).order_by(AnomalyLog.id.desc()).limit(limit).all()
    return [a.to_dict() for a in anomalies]


@app.post("/api/anomalies/{anomaly_id}/resolve")
def resolve_anomaly(anomaly_id: int, db: Session = Depends(get_db)):
    """Marks an anomaly as reviewed and resolved by admin."""
    anomaly = db.query(AnomalyLog).filter(AnomalyLog.id == anomaly_id).first()
    if not anomaly:
        raise HTTPException(status_code=404, detail="Anomaly log not found.")
    anomaly.is_resolved = True
    db.commit()
    return {"status": "success", "message": f"Anomaly #{anomaly_id} marked as resolved."}


@app.get("/api/admin/status")
def get_admin_status(request: Request, db: Session = Depends(get_db)):
    """Checks if current request originates from the authorized owner laptop."""
    client_ip = get_client_ip(request)
    current_machine = platform.node()
    is_local = client_ip in ["127.0.0.1", "::1", "localhost", "testclient"]
    is_owner_laptop = is_local and (current_machine == OWNER_COMPUTER_NAME or os.environ.get("COMPUTERNAME") == OWNER_COMPUTER_NAME)
    return {
        "is_owner_laptop": is_owner_laptop,
        "laptop_name": current_machine,
        "owner_target": OWNER_COMPUTER_NAME,
        "can_edit": is_owner_laptop
    }


@app.get("/api/profile")
def get_profile(db: Session = Depends(get_db)):
    """Retrieves developer profile info."""
    profile = db.query(UserProfile).first()
    if not profile:
        profile = UserProfile()
        db.add(profile)
        db.commit()
    return profile.to_dict()


@app.put("/api/profile")
def update_profile(data: ProfileUpdateRequest, request: Request, db: Session = Depends(get_db)):
    """Updates developer profile info only if executed on the verified owner laptop."""
    client_ip = get_client_ip(request)
    current_machine = platform.node()
    is_local = client_ip in ["127.0.0.1", "::1", "localhost", "testclient"]
    is_owner_laptop = is_local and (current_machine == OWNER_COMPUTER_NAME or os.environ.get("COMPUTERNAME") == OWNER_COMPUTER_NAME)

    if not is_owner_laptop:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Access Denied: Only the verified owner on {OWNER_COMPUTER_NAME} is authorized to modify this admin profile."
        )

    profile = db.query(UserProfile).first()
    if not profile:
        profile = UserProfile()
        db.add(profile)

    profile.name = data.name
    profile.title = data.title
    profile.bio = data.bio
    profile.skills = json.dumps(data.skills)
    profile.email = data.email
    profile.github = data.github
    profile.linkedin = data.linkedin
    db.commit()
    return profile.to_dict()


# ==================== STATIC WEB PAGES ====================

# Serve Frontend static assets
if os.path.exists(FRONTEND_DIR):
    app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")

@app.get("/")
def serve_home():
    return FileResponse(os.path.join(FRONTEND_DIR, "index.html"))

@app.get("/dashboard")
def serve_dashboard():
    return FileResponse(os.path.join(FRONTEND_DIR, "dashboard.html"))

@app.get("/admin")
def serve_admin():
    return FileResponse(os.path.join(FRONTEND_DIR, "admin.html"))

@app.get("/operations")
def serve_operations():
    return FileResponse(os.path.join(FRONTEND_DIR, "admin.html"))

@app.get("/history")
def serve_history():
    return FileResponse(os.path.join(FRONTEND_DIR, "history.html"))

@app.get("/chatbot")
def serve_chatbot():
    return FileResponse(os.path.join(FRONTEND_DIR, "chatbot.html"))
