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
    
    # Veritabanına kaydet [cite: 30, 69]
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
    # Ajan önce metni okur, link varsa WHOIS çeker, sonra karar verir [cite: 27, 78]
    result = await agent.run_full_analysis(request.content, request.image_base64, model=request.model)
    
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
    qwen_req = agent.run_full_analysis(request.content, request.image_base64, model="qwen2.5:7b")
    # For Gemma, gemma:7b or gemma2:9b depending on what's installed on system
    gemma_model = request.model if "gemma" in request.model else "gemma:7b"
    gemma_req = agent.run_full_analysis(request.content, request.image_base64, model=gemma_model)
    
    # Run both simultaneously
    qwen_res, gemma_res = await asyncio.gather(qwen_req, gemma_req)
    
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