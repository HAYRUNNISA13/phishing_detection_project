from sqlalchemy import Column, Integer, String, Text, DateTime
from datetime import datetime
from .database import Base

class DetectionLog(Base):
    __tablename__ = "detection_logs"

    id = Column(Integer, primary_key=True, index=True)
    message_content = Column(Text)
    detection_mode = Column(String(50))  # 'direct' veya 'agent'
    is_phishing = Column(String(20))
    confidence_score = Column(Integer)
    explanation = Column(Text)           # XAI Raporu [cite: 29, 69]
    created_at = Column(DateTime, default=datetime.utcnow)