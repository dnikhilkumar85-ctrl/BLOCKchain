from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime
import os
import logging

logger = logging.getLogger(__name__)

# --- CONFIGURATION ---
# Tries PostgreSQL first; falls back to SQLite if Postgres is unavailable.
# Override by setting the DATABASE_URL environment variable.
_POSTGRES_URL = os.environ.get(
    "DATABASE_URL",
    "postgresql://postgres:saketh123@localhost:5432/idsdashboard"
)
_SQLITE_URL = "sqlite:///./soarops.db"

def _make_engine(url: str):
    if url.startswith("sqlite"):
        return create_engine(url, connect_args={"check_same_thread": False})
    return create_engine(url)

# Try PostgreSQL; fall back to SQLite automatically
try:
    engine = _make_engine(_POSTGRES_URL)
    # Quick connectivity test
    with engine.connect() as _conn:
        pass
    DATABASE_URL = _POSTGRES_URL
    logger.info(f"Connected to PostgreSQL: {_POSTGRES_URL}")
except Exception as _pg_err:
    logger.warning(
        f"PostgreSQL not available ({_pg_err}). "
        f"Falling back to SQLite at '{_SQLITE_URL}'. "
        "Set DATABASE_URL env var to use a different database."
    )
    engine = _make_engine(_SQLITE_URL)
    DATABASE_URL = _SQLITE_URL

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# --- MODELS ---

class TrafficLog(Base):
    """Stores all processed traffic logs (Monitor Mode)"""
    __tablename__ = "traffic_logs"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    src_ip = Column(String, index=True)
    country = Column(String)
    lat = Column(Float)
    lon = Column(Float)
    type = Column(String) # "DDoS", "SQL Injection", "Normal"
    confidence = Column(Float)
    destination_port = Column(Integer)
    action = Column(String) # "MONITOR"
    
    # Context Data Enhancements
    target_username = Column(String, nullable=True)
    burst_score = Column(Float, nullable=True)
    failed_attempts = Column(Integer, nullable=True)
    traffic_volume = Column(String, nullable=True)
    login_behavior = Column(String, nullable=True)

    # Unidirectional Telemetry
    flow_direction = Column(String, default="INGRESS_UNIDIRECTIONAL")
    fwd_packets = Column(Integer, default=1)
    fwd_bytes = Column(Float, default=0.0)
    fwd_iat_mean = Column(Float, default=0.0)
    detection_rationale = Column(String, nullable=True)

class AutoBlocked(Base):
    """Stores incidents automatically blocked by the system"""
    __tablename__ = "auto_blocked"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    src_ip = Column(String, index=True)
    country = Column(String)
    limit_reached = Column(String) # Reason, e.g., "Confidence > 95%"
    confidence = Column(Float)
    type = Column(String)
    action = Column(String, default="AUTO_BLOCKED")

class ManualReview(Base):
    """Stores incidents sent to Admin Portal for manual review"""
    __tablename__ = "manual_review"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    src_ip = Column(String, index=True)
    country = Column(String)
    type = Column(String)
    confidence = Column(Float)
    destination_port = Column(Integer)
    status = Column(String, default="PENDING") # PENDING, RESOLVED
    
    # Outcome
    action_taken = Column(String, nullable=True) # "MANUAL_BLOCK", "FALSE_POSITIVE"
    analyst_id = Column(String, nullable=True)
    resolved_at = Column(DateTime, nullable=True)

    # Context Data Enhancements
    target_username = Column(String, nullable=True)
    burst_score = Column(Float, nullable=True)
    failed_attempts = Column(Integer, nullable=True)
    traffic_volume = Column(String, nullable=True)
    login_behavior = Column(String, nullable=True)

    # Unidirectional Telemetry
    flow_direction = Column(String, default="INGRESS_UNIDIRECTIONAL")
    fwd_packets = Column(Integer, default=1)
    fwd_bytes = Column(Float, default=0.0)
    fwd_iat_mean = Column(Float, default=0.0)
    detection_rationale = Column(String, nullable=True)

class ChatSession(Base):
    """Stores a conversation session between user and AI"""
    __tablename__ = "chat_sessions"

    id = Column(Integer, primary_key=True, index=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    title = Column(String, default="New Conversation")

class ChatMessage(Base):
    """Stores individual messages within a session"""
    __tablename__ = "chat_messages"

    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(Integer, index=True) # Foreign Key relationship can be added if needed
    role = Column(String) # "user" or "ai"
    content = Column(Text)
    timestamp = Column(DateTime, default=datetime.utcnow)

# --- INITIALIZATION ---
def init_db():
    Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
