import json
from fastapi import WebSocket
from typing import List

class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)

    async def send_log(self, message: str, model: str = "system"):
        payload = json.dumps({"model": model, "message": message})
        for connection in self.active_connections:
            try:
                await connection.send_text(payload)
            except:
                pass

manager = ConnectionManager()