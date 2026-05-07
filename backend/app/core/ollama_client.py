import httpx
import json
import base64
from io import BytesIO
from PIL import Image

def _resize_base64_image(base64_str: str, max_size=(800, 800)) -> str:
    """Resizes a base64 image to prevent Ollama memory overload/timeout."""
    if "base64," in base64_str:
        base64_str = base64_str.split("base64,")[1]
    
    img_data = base64.b64decode(base64_str)
    img = Image.open(BytesIO(img_data))
    
    # Maintain aspect ratio while sizing down
    img.thumbnail(max_size, Image.Resampling.LANCZOS)
    
    # Convert RGBA to RGB for JPEG format
    if img.mode in ("RGBA", "P"):
        img = img.convert("RGB")
        
    buffered = BytesIO()
    img.save(buffered, format="JPEG", quality=85)
    return base64.b64encode(buffered.getvalue()).decode('utf-8')

class OllamaClient:
    def __init__(self):
        self.url = "http://localhost:11434/api/generate"

    async def analyze_with_vision(self, text, image_b64):
        """Analyze image and text using LLaVA model."""
        # Shrink the image to prevent CPU/RAM crashes and timeouts
        optimized_image_b64 = _resize_base64_image(image_b64, max_size=(800, 800))
        
        prompt = f"Analyze this text: '{text}' and the provided image. Detect any brand spoofing, malicious QR codes, or visual inconsistencies. Provide a detailed technical observation."
        payload = {
            "model": "llava",
            "prompt": prompt,
            "images": [optimized_image_b64],
            "stream": False,
            "keep_alive": 0,
            "options": {
                "num_ctx": 1024,
                "num_predict": 128
            }
        }
        async with httpx.AsyncClient() as client:
            # Increased timeout to 180s for visual models
            response = await client.post(self.url, json=payload, timeout=180.0)
            return response.json().get("response")

    async def analyze_text_simple(self, text, model="qwen2.5:7b"):
        """Simple baseline analysis without agent or vision."""
        prompt = f"Analyze this SMS/Email and determine if it is phishing or safe. Text: '{text}'"
        payload = {
            "model": model,
            "prompt": prompt,
            "stream": False,
            "keep_alive": 0,
            "options": {
                "num_ctx": 2048,
                "num_predict": 512
            }
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
        obs_text = "\n".join(observations)
        prompt = f"""
        You are a highly capable AI Assistant specializing in Threat Intelligence.
        Analyze the following user input and the technical observations provided.
        
        INPUT MESSAGE: {text}
        OBSERVATIONS: {obs_text}
        
        INSTRUCTIONS:
        Evaluate the true intent of the message.
        - Does it attempt to deceive the user, steal credentials, or redirect to a malicious domain? If so, the verdict is PHISHING.
        - Is it a benign notification, a genuine alert, a standard advertisement, or simply a safe message without malicious intent? If so, the verdict is SAFE.
        
        OUTPUT FORMAT:
        You MUST begin your response strictly with either the phrase "VERDICT: PHISHING" or "VERDICT: SAFE". 
        After stating the verdict, write a detailed, comprehensive, and professional analysis report explaining your reasoning. Focus on the domain reputation, psychological tactics, and structural evidence.
        """
        payload = {
            "model": model, 
            "prompt": prompt, 
            "stream": True, 
            "keep_alive": 0,
            "options": {
                "num_ctx": 3072,
                "num_predict": 1024
            }
        }
        
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
        
        # Extremely lenient parsing since 7B models often ignore strict formatting
        is_phishing = True
        upper_resp = full_response.upper()
        prefix = upper_resp[:150] # Check the beginning area of the response
        
        safe_keywords = ["VERDICT: SAFE", "VERDICT: SECURE", "IS SECURE", "IS SAFE", "NOT PHISHING", "LEGITIMATE", "GENUINE", "NO MALICIOUS"]
        for kw in safe_keywords:
            if kw in prefix:
                is_phishing = False
                break
                
        # Fallback if it literally just starts with "safe" or "secure"
        if upper_resp.strip().startswith("SAFE") or upper_resp.strip().startswith("SECURE"):
            is_phishing = False
            
        # Hard override if it explicitly states Fishing
        if "VERDICT: PHISHING" in prefix and "VERDICT: SAFE" not in prefix:
            is_phishing = True
            
        return {
            "is_phishing": is_phishing,
            "confidence": 0.95,
            "explanation": full_response,
            "mode": f"agentic-{model}"
        }