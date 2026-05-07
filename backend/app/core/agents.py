import re
from .tools import check_domain_age, check_virustotal_reputation
from .ollama_client import OllamaClient
from .websocket_manager import manager
from .rag_manager import rag_manager

class PhishingAgent:
    def __init__(self):
        self.client = OllamaClient()

    def _extract_urls(self, text):
        return re.findall(r'(https?://[^\s]+)', text)

    async def run_full_analysis(self, text: str, image_base64: str = None, document_base64: str = None, model: str = "qwen2.5:7b"):
        await manager.send_log("🔍 Initializing Analysis: Scanning message content...", model=model)
        
        # 0. Document Parsing
        if document_base64:
            from .tools import extract_text_from_pdf
            await manager.send_log("📄 Extracting text from uploaded PDF document...", model=model)
            pdf_text = extract_text_from_pdf(document_base64)
            text = f"DOCUMENT CONTENT:\n{pdf_text}\n\nUSER PROMPT/META:\n{text}"
            await manager.send_log("✅ PDF Text Extracted and injected into context.", model=model)
        
        urls = self._extract_urls(text)
        observations = []
        
        # 1. RAG Memory Search
        await manager.send_log("🗄️ Querying Vector Database for historical attack patterns...", model=model)
        rag_insight = rag_manager.find_similar_attacks(text)
        observations.append(rag_insight)
        await manager.send_log(f"✅ RAG Result: {rag_insight}", model=model)
        
        # 2. URL Threat Intelligence
        if urls:
            from .tools import unshorten_url
            raw_url = urls[0]
            target_url = unshorten_url(raw_url)
            
            if target_url != raw_url:
                await manager.send_log(f"🔗 Masked URL unshortened: {target_url}", model=model)
            else:
                await manager.send_log(f"🔗 URL Detected: {target_url}", model=model)
            
            # WHOIS Check
            await manager.send_log("📡 Querying WHOIS database for domain intelligence...", model=model)
            try:
                domain_data = check_domain_age(target_url)
            except Exception as e:
                domain_data = f"WHOIS error: {str(e)}"
            observations.append(f"Domain Intelligence: {domain_data}")
            await manager.send_log(f"✅ WHOIS Evidence: {domain_data}", model=model)
            
            # VirusTotal API Check
            await manager.send_log("🛡️ Reaching out to VirusTotal Threat Intelligence API...", model=model)
            vt_data = check_virustotal_reputation(target_url)
            observations.append(vt_data)
            await manager.send_log(f"✅ {vt_data}", model=model)
        
        # 3. Multimodal Analysis
        if image_base64:
            await manager.send_log("🖼️ Activating Multimodal Analysis (LLaVA)...", model=model)
            vision_insight = await self.client.analyze_with_vision(text, image_base64)
            observations.append(f"Visual Analysis: {vision_insight}")
            await manager.send_log(f"[VISION_REPORT] {vision_insight}", model=model)

        await manager.send_log("🧠 Synthesizing evidence for final XAI Report...", model=model)
        
        # Streaming report generation
        final_report = await self.client.generate_final_xai_report_stream(text, observations, manager, model=model)
        
        # Save to RAG memory after completion
        if final_report and final_report.get("explanation"):
            verdict_str = "PHISHING" if final_report.get("is_phishing") else "SAFE"
            rag_manager.add_attack_to_memory(text, verdict_str, final_report.get("explanation"))
            await manager.send_log(f"💾 Analysis successfully archived into Vector Database.", model=model)
            
        return final_report