import re
from .tools import check_domain_age
from .ollama_client import OllamaClient
from .websocket_manager import manager

class PhishingAgent:
    def __init__(self):
        self.client = OllamaClient()

    def _extract_urls(self, text):
        return re.findall(r'(https?://[^\s]+)', text)

    async def run_full_analysis(self, text: str, image_base64: str = None, model: str = "qwen2.5:7b"):
        await manager.send_log("🔍 Initializing Analysis: Scanning message content...", model=model)
        
        urls = self._extract_urls(text)
        observations = []
        
        if urls:
            await manager.send_log(f"🔗 URL Detected: {urls[0]}", model=model)
            await manager.send_log("📡 Querying WHOIS database for domain intelligence...", model=model)
            try:
                domain_data = check_domain_age(urls[0])
            except Exception as e:
                domain_data = f"WHOIS error: {str(e)}"
            observations.append(f"Domain Intelligence: {domain_data}")
            await manager.send_log(f"✅ Technical Evidence Gathered: {domain_data}", model=model)
        
        if image_base64:
            await manager.send_log("🖼️ Activating Multimodal Analysis (LLaVA)...", model=model)
            vision_insight = await self.client.analyze_with_vision(text, image_base64)
            observations.append(f"Visual Analysis: {vision_insight}")
            await manager.send_log(f"👁️ Visual Insight: {str(vision_insight)[:100]}...", model=model)

        await manager.send_log("🧠 Synthesizing evidence for final XAI Report...", model=model)
        
        # Streaming report generation
        return await self.client.generate_final_xai_report_stream(text, observations, manager, model=model)