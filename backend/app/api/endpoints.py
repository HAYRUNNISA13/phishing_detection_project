from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from ..database import get_db
from ..schemas import PhishingRequest, DetectionResponse
from ..core.agents import PhishingAgent
from ..core.ollama_client import OllamaClient
from .. import models
import asyncio

router = APIRouter()
agent = PhishingAgent()
client = OllamaClient()

@router.post("/detect/direct", response_model=DetectionResponse)
async def detect_direct(request: PhishingRequest, db: Session = Depends(get_db)):
    """Doğrudan LLM'e sorar (Baseline)"""
    result = await client.analyze_text_simple(request.content, model=request.model)
    
    
    new_log = models.DetectionLog(
        message_content=request.content,
        detection_mode=f"direct-{request.model}",
        is_phishing=str(result['is_phishing']),
        explanation=result['explanation']
    )
    db.add(new_log)
    db.commit()
    return result

@router.post("/detect/agentic", response_model=DetectionResponse)
async def detect_agentic(request: PhishingRequest, db: Session = Depends(get_db)):
    """Senin özel ajan yapını çalıştırır (WHOIS + Mantıksal Analiz)"""
    result = await agent.run_full_analysis(
        request.content, 
        image_base64=request.image_base64, 
        document_base64=request.document_base64,
        model=request.model
    )
    
    # Kayıt işlemi
    new_log = models.DetectionLog(
        message_content=request.content,
        detection_mode=f"agentic-{request.model}",
        is_phishing=str(result['is_phishing']),
        explanation=result['explanation']
    )
    db.add(new_log)
    db.commit()
    return result

@router.post("/detect/compare")
async def compare_detection(request: PhishingRequest):
    """Side-by-side comparison of two LLMs (Qwen vs Gemma) using the Agentic mode."""
    qwen_res = await agent.run_full_analysis(
        request.content, 
        image_base64=request.image_base64, 
        document_base64=request.document_base64, 
        model="qwen2.5:7b"
    )
    # For Gemma, gemma:7b or gemma2:9b depending on what's installed on system
    gemma_model = request.model if "gemma" in request.model else "gemma:7b"
    gemma_res = await agent.run_full_analysis(
        request.content, 
        image_base64=request.image_base64, 
        document_base64=request.document_base64, 
        model=gemma_model
    )
    
    return {
        "qwen2.5:7b": {
            "verdict": "Phishing" if qwen_res["is_phishing"] else "Safe",
            "reasoning": qwen_res["explanation"],
            "tools_used": ["WHOIS Intelligence", "Multimodal Vision", "LLM Reasoning"]
        },
        gemma_model: {
            "verdict": "Phishing" if gemma_res["is_phishing"] else "Safe",
            "reasoning": gemma_res["explanation"],
            "tools_used": ["WHOIS Intelligence", "Multimodal Vision", "LLM Reasoning"]
        }
    }

@router.get("/stats")
def get_stats(db: Session = Depends(get_db)):
    """Provides analytical statistics for the SOC Dashboard."""
    total = db.query(models.DetectionLog).count()
    phishing = db.query(models.DetectionLog).filter(models.DetectionLog.is_phishing == 'True').count()
    safe = db.query(models.DetectionLog).filter(models.DetectionLog.is_phishing == 'False').count()
    
    recent = db.query(models.DetectionLog).order_by(models.DetectionLog.created_at.desc()).limit(10).all()
    
    recent_logs = []
    for r in recent:
        # Prevent huge explanations from clogging the JSON, keeping only 100 characters
        snippet = (r.explanation[:100] + '...') if r.explanation and len(r.explanation) > 100 else r.explanation
        recent_logs.append({
            "id": r.id, 
            "date": r.created_at.isoformat() if r.created_at else None, 
            "verdict": r.is_phishing, 
            "mode": r.detection_mode,
            "snippet": snippet
        })
        
    return {
        "status": "success",
        "total": total,
        "phishing": phishing,
        "safe": safe,
        "recent": recent_logs
    }