from pydantic import BaseModel
from typing import Optional

class PhishingRequest(BaseModel):
    content: str  # SMS metni veya analiz edilecek metin
    image_base64: Optional[str] = None  # Ekran görüntüsü varsa (Qwen2-VL için)
    model: str = "qwen2.5:7b"  # Hangi model ile analiz yapilacagi

class DetectionResponse(BaseModel):
    is_phishing: bool
    confidence: float
    explanation: str  # XAI Raporu [cite: 29, 53]
    mode: str