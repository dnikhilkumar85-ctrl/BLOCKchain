from fastapi import APIRouter, HTTPException, Depends
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime
from sqlalchemy.orm import Session
from sqlalchemy import func
from database import get_db, ChatSession, ChatMessage, ManualReview, AutoBlocked, TrafficLog
from .Rag.retriever import RAGSystem
from .Rag.prompt_template import build_prompt
from .llm.ollama_client import generate_response, check_ollama_available
import json
import logging

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/ai", tags=["AI Assistant"])

# --- Initialize RAG (self-initializing, no required args) ---
rag = RAGSystem()
logger.info("RAGSystem initialized (empty — call /api/ai/rag/refresh to build from DB logs)")

class ChatRequest(BaseModel):
    query: str
    session_id: Optional[int] = None

class Message(BaseModel):
    role: str
    content: str
    timestamp: datetime

class SessionResponse(BaseModel):
    id: int
    title: str
    created_at: datetime
    messages: List[Message]

def get_db_context(db: Session, query: str) -> str:
    """Generates dynamic context from the database based on the query."""
    context = "System Data Overview (Unidirectional Ingress Architecture):\n"
    context += "- Architecture: Unidirectional IP Traffic (Hardware Data Diode / Passive Optical Tap)\n"
    context += "- Return Path Telemetry: Disabled / Non-existent (0 Backward Features)\n"
    context += "- Evaluated Forward Features: 40 (Forward IAT, Packet Length Variance, Flag Counts)\n"
    query_lower = query.lower()

    # 1. Total Counts
    total_logs = db.query(TrafficLog).count()
    pending_reviews = db.query(ManualReview).filter(ManualReview.status == "PENDING").count()
    auto_blocked = db.query(AutoBlocked).count()
    context += f"- Total Traffic Flows Analyzed: {total_logs}\n"
    context += f"- Pending Incidents: {pending_reviews}\n"
    context += f"- Auto-Blocked Threat Sources: {auto_blocked}\n"

    # 2. Country-Specific Queries (e.g., "logs from China")
    active_countries = db.query(TrafficLog.country).distinct().all()
    active_countries = [c[0] for c in active_countries if c[0]]
    
    for country in active_countries:
        if country.lower() in query_lower:
            count = db.query(TrafficLog).filter(TrafficLog.country == country).count()
            context += f"\n[Specific Query Match]\n- Ingress Flows from {country}: {count}\n"
            
            # Add recent logs from this country with unidirectional metrics
            recent = db.query(TrafficLog).filter(TrafficLog.country == country).order_by(TrafficLog.timestamp.desc()).limit(3).all()
            if recent:
                context += f"- Recent unidirectional ingress from {country}:\n"
                for r in recent:
                     context += f"  - {r.timestamp}: {r.type} (IP: {r.src_ip}) | FwdPkts={r.fwd_packets} | Rationale: {r.detection_rationale}\n"
            break

    # 3. Recent Activity (if no specific country found or general query)
    context += "\nRecent Unidirectional Ingress Stream (Last 5):\n"
    recent_logs = db.query(TrafficLog).order_by(TrafficLog.timestamp.desc()).limit(5).all()
    for log in recent_logs:
        context += f"- {log.timestamp}: {log.type} from {log.country} (IP: {log.src_ip}) | FwdPkts={log.fwd_packets} | {log.detection_rationale}\n"
        
    return context

@router.post("/chat")
def chat(req: ChatRequest, db: Session = Depends(get_db)):
    # 1. Create or Get Session
    session_id = req.session_id
    if not session_id:
        new_session = ChatSession(title=req.query[:30] + "...")
        db.add(new_session)
        db.commit()
        db.refresh(new_session)
        session_id = new_session.id
    
    # 2. Save User Message
    user_msg = ChatMessage(session_id=session_id, role="user", content=req.query)
    db.add(user_msg)
    db.commit()

    # Generator function for streaming
    def stream_logic():
        full_response = ""
        
        # Simple Logic Keywords
        query_lower = req.query.lower()
        if "latest incidents" in query_lower or "recent attacks" in query_lower:
            incidents = db.query(ManualReview).order_by(ManualReview.timestamp.desc()).limit(5).all()
            if not incidents:
               chunk = "I couldn't find any recent incidents."
               full_response += chunk
               yield chunk
            else:
                chunk = "Here are the latest incidents:\n"
                full_response += chunk
                yield chunk
                for i in incidents:
                    line = f"- **{i.type}** from {i.country} (IP: {i.src_ip}) - Confidence: {int(i.confidence*100)}%\n"
                    full_response += line
                    yield line

        elif any(k in query_lower for k in ["unidirectional", "data diode", "optical tap", "one-way", "backward", "return path"]):
             chunk = (
                 "### 🛡️ Unidirectional Cyber Threat Detection Architecture\n\n"
                 "- **Data Diode / Optical Tap Environment**: In this deployment, network traffic flows in a single direction "
                 "(ingress only). Return path packets (such as TCP SYN-ACK, server responses, and backward flow metrics) are physically absent or dropped.\n"
                 "- **Detection Mechanism**: Rather than relying on bidirectional handshakes or response codes, our AI model evaluates "
                 "**40 Forward-Only Features** including Forward Inter-Arrival Time (Fwd IAT), Forward Packet Length distributions, "
                 "and SYN flag burst rates.\n"
                 "- **Model Performance**: Trained without backward feature bias, achieving **99.85% detection accuracy** on ingress threats "
                 "(Blind Port Scans, DoS Floods, C2 Beaconing, and Injection attacks).\n\n"
                 "Would you like to examine recent unidirectional flow logs or inspect feature importance?"
             )
             full_response += chunk
             yield chunk

        elif "block" in query_lower and "ip" in query_lower:
             chunk = "To block an IP, please use the 'Review Now' button on the dashboard. I can't execute blocks directly yet, but I can help you analyze the threat."
             full_response += chunk
             yield chunk

        else:
            # LLM Streaming with Ollama fallback
            try:
                db_context = get_db_context(db, req.query)

                # Check if RAG has documents to enrich context
                rag_context = ""
                if rag and rag.is_ready:
                    rag_docs = rag.retrieve(req.query, k=3)
                    if rag_docs:
                        rag_context = "\n\nRelevant Log Excerpts (RAG):\n" + "\n".join(rag_docs)

                full_prompt = f"""
You are a Security Operations Center (SOC) Master AI Assistant.
{db_context}{rag_context}
User Query: {req.query}
Instructions:
- Analyze the provided System Data to answer the query.
- If specific country data is shown, use it.
- If the user asks about "logs from [Country]", look at the [Specific Query Match] section.
- Be concise and professional.
"""

                # Check if Ollama is available before calling
                if not check_ollama_available():
                    # Graceful fallback: structured DB-only response
                    fallback = (
                        "⚠️ **AI model (Ollama) is not running.** "
                        "Showing data-only summary:\n\n"
                        + db_context
                        + "\n\n_To enable full AI responses, install Ollama from https://ollama.ai "
                        "and run: `ollama pull llama3 && ollama serve`_"
                    )
                    full_response += fallback
                    yield fallback
                else:
                    for chunk in generate_response(full_prompt):
                        full_response += chunk
                        yield chunk

            except Exception as e:
                err = f"⚠️ Error generating response: {str(e)}"
                full_response += err
                yield err

        # 4. Save AI Response (After stream completes)
        # We need a new DB session because the generator runs outside the request context scope optionally
        # But here we are yielding, so we can likely use the same DB if careful, or just create a new one.
        # For simplicity in this generator, we'll try to re-use or just accept we might need to fix DB closure.
        # Ideally, we save *after* the yield loop.
        
        try:
            # Re-acquire session for saving final message if needed, or use the existing one if still valid.
            # Ideally depends sets up session closing. 
            # We'll assume db is still open or we open a new one.
            from database import SessionLocal
            db_save = SessionLocal()
            ai_msg = ChatMessage(session_id=session_id, role="ai", content=full_response)
            db_save.add(ai_msg)
            db_save.commit()
            db_save.close()
        except Exception as e:
            print(f"Failed to save chat history: {e}")

        # Send Session ID as a final meta-event or just assume client has it?
        # A common customized SSE pattern is JSON chunks. 
        # But to keep it simple text stream, we won't send JSON unless we wrap everything.
        # Let's send a special delimiter or just rely on client knowing the session ID if it was passed.
        # If new session, we need to tell client.
        # Hack: Send session ID in a header? FastAPI StreamingResponse supports headers.

    return StreamingResponse(stream_logic(), media_type="text/plain", headers={"X-Session-Id": str(session_id)})

@router.get("/history", response_model=List[SessionResponse])
def get_history(db: Session = Depends(get_db)):
    sessions = db.query(ChatSession).order_by(ChatSession.created_at.desc()).limit(10).all()
    result = []
    for s in sessions:
        msgs = db.query(ChatMessage).filter(ChatMessage.session_id == s.id).order_by(ChatMessage.timestamp).all()
        result.append({
            "id": s.id,
            "title": s.title,
            "created_at": s.created_at,
            "messages": [{"role": m.role, "content": m.content, "timestamp": m.timestamp} for m in msgs]
        })
    return result


@router.post("/rag/refresh")
def refresh_rag(db: Session = Depends(get_db)):
    """
    Rebuild the RAG vector index from the latest traffic logs in the database.
    Call this after significant new traffic data has been accumulated.
    """
    # Fetch recent traffic logs and convert to text documents
    logs = db.query(TrafficLog).order_by(TrafficLog.timestamp.desc()).limit(500).all()
    if not logs:
        return {"status": "skipped", "reason": "No traffic logs found in DB", "document_count": 0}

    documents = [
        f"Network Flow Report:\n"
        f"Timestamp: {log.timestamp}\n"
        f"Source IP: {log.src_ip}\n"
        f"Country: {log.country}\n"
        f"Attack Type: {log.type}\n"
        f"Confidence: {log.confidence:.2%}\n"
        f"Destination Port: {log.destination_port}\n"
        f"Action: {log.action}\n"
        f"Traffic Volume: {log.traffic_volume or 'N/A'}\n"
        f"Burst Score: {log.burst_score or 0.0}\n"
        f"Failed Attempts: {log.failed_attempts or 0}\n"
        f"Login Behavior: {log.login_behavior or 'Normal'}"
        for log in logs
    ]

    success = rag.rebuild(documents)
    if success:
        return {"status": "success", "document_count": len(documents)}
    else:
        raise HTTPException(status_code=500, detail="RAG rebuild failed — check server logs.")


@router.get("/rag/status")
def rag_status():
    """Check the current RAG system status."""
    ollama_ok = check_ollama_available()
    return {
        "rag_ready": rag.is_ready if rag else False,
        "document_count": len(rag.documents) if rag else 0,
        "ollama_available": ollama_ok,
        "ollama_url": "http://localhost:11434",
        "message": (
            "All systems operational" if (rag and rag.is_ready and ollama_ok)
            else "RAG not built — call POST /api/ai/rag/refresh" if not (rag and rag.is_ready)
            else "Ollama not running — AI responses will use DB-only fallback"
        )
    }
