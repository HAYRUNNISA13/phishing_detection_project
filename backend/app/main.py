from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse # Bunu ekledik
import os

from .database import engine, Base
from .api import endpoints
from .core.websocket_manager import manager

# Veritabanı tablolarını otomatik oluştur [cite: 30, 69]
Base.metadata.create_all(bind=engine)

app = FastAPI(title="PhishGuard AI - SWE402", version="1.0.0")

# CORS ayarları
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- ARAYÜZÜ BURADAN SUNUYORUZ ---
@app.get("/")
async def get_index():
    # Bu dosyanın (main.py) olduğu yer: backend/app/
    # Bir üstü: backend/
    # Bir üstü: phishing_detection_project/ (root)
    current_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    file_path = os.path.join(current_dir, "test_ui", "index.html")
    
    if not os.path.exists(file_path):
        return {"error": f"Dosya bulunamadı: {file_path}. Lütfen test_ui klasöründe index.html olduğundan emin olun."}
        
    return FileResponse(file_path)

# WebSocket [cite: 61]
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)

app.include_router(endpoints.router, prefix="/api/v1")