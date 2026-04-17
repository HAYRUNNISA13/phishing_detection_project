import httpx
import json

class OllamaClient:
    def __init__(self):
        self.url = "http://localhost:11434/api/generate"

    async def analyze_with_vision(self, text, image_b64):
        """Analyze image and text using LLaVA model."""
        prompt = f"Analyze this text: '{text}' and the provided image. Detect any brand spoofing, malicious QR codes, or visual inconsistencies. Provide a detailed technical observation."
        payload = {
            "model": "llava",
            "prompt": prompt,
            "images": [image_b64],
            "stream": False
        }
        async with httpx.AsyncClient() as client:
            response = await client.post(self.url, json=payload, timeout=60.0)
            return response.json().get("response")

    async def analyze_text_simple(self, text, model="qwen2.5:7b"):
        """Simple baseline analysis without agent or vision."""
        prompt = f"Analyze this SMS/Email and determine if it is phishing or safe. Text: '{text}'"
        payload = {
            "model": model,
            "prompt": prompt,
            "stream": False
        }
        async with httpx.AsyncClient() as client:
            response = await client.post(self.url, json=payload, timeout=60.0)
            result_text = response.json().get("response", "")
            return {
                "is_phishing": "phishing" in result_text.lower(),
                "confidence": 0.85,
                "explanation": result_text,
                "mode": "direct"
            }

    async def generate_final_xai_report_stream(self, text, observations, manager, model="qwen2.5:7b"):
        """Generates a final XAI report with streaming to WebSocket logs."""
        obs_text = "\n".join(observations)
        prompt = f"""
        INPUT MESSAGE: {text}
        TECHNICAL OBSERVATIONS:
        {obs_text}
        
        TASK: Act as a Cybersecurity Analyst. Write a detailed XAI (Explainable AI) report.
        1. Determine if this is PHISHING or SAFE.
        2. Explain technical reasons (domain age, etc.) and psychological triggers.
        3. Provide a final verdict.
        LANGUAGE: English
        """
        payload = {"model": model, "prompt": prompt, "stream": True}
        
        full_response = ""
        async with httpx.AsyncClient() as client:
            async with client.stream("POST", self.url, json=payload, timeout=120.0) as response:
                async for line in response.aiter_lines():
                    if line:
                        chunk = json.loads(line)
                        text_chunk = chunk.get("response", "")
                        full_response += text_chunk
                        # Anlık olarak kelimeleri terminale gönderiyoruz
                        if text_chunk.strip():
                            await manager.send_log(f"🧠 Reasoning: {text_chunk}", model=model)
        
        return {
            "is_phishing": "phishing" in full_response.lower(),
            "confidence": 0.95,
            "explanation": full_response,
            "mode": f"agentic-{model}"
        }