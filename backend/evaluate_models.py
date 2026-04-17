import asyncio
import json
import httpx
import time

# Simple Mock Dataset for Evaluation
# Gerekirse bu listeyi genisletebilir veya bir CSV dosyasindan okuyabilirsiniz.
MOCK_DATASET = [
    {"text": "Your account has been suspended. Click here to verify your identity: http://secure-update-paypal.com", "label": "phishing"},
    {"text": "Hey Mom, just letting you know I arrived safely at the airport.", "label": "safe"},
    {"text": "URGENT: You have won a $1,000 Amazon gift card! Claim now at http://amazon-gifts-free.net", "label": "phishing"},
    {"text": "Reminder: Team meeting tomorrow at 10 AM in the main conference room.", "label": "safe"},
]

async def analyze_text(client_url, text, model):
    prompt = f"Analyze this SMS/Email and determine if it is phishing or safe. Text: '{text}'"
    payload = {"model": model, "prompt": prompt, "stream": False}
    
    start = time.time()
    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(client_url, json=payload, timeout=300.0)
            response.raise_for_status()  # Check for 404 (model missing)
            result_text = response.json().get("response", "").lower()
            prediction = "phishing" if "phishing" in result_text else "safe"
            elapsed = time.time() - start
            return prediction, elapsed, result_text
        except httpx.HTTPStatusError as e:
            err_msg = e.response.text
            print(f"Ollama returned error status for {model}: {err_msg}")
            return "error", time.time() - start, err_msg
        except Exception as e:
            print(f"Error connecting to Ollama for {model} - Type: {type(e).__name__}, Detail: {str(e)}")
            return "error", time.time() - start, str(e)


async def main():
    print("🚀 Starting Model Evaluation...")
    url = "http://localhost:11434/api/generate"
    models = ["qwen2.5:7b", "gemma:7b"]
    
    results = {
        model: {"correct": 0, "total": len(MOCK_DATASET), "avg_time": 0.0, "total_time": 0.0}
        for model in models
    }

    for i, data in enumerate(MOCK_DATASET):
        print(f"\nEvaluating Item {i+1}/{len(MOCK_DATASET)}")
        print(f"Text: {data['text']}")
        print(f"True Label: {data['label'].upper()}")
        print("-" * 40)
        
        for model in models:
            pred, elapsed, reasoning = await analyze_text(url, data["text"], model)
            is_correct = pred == data["label"]
            
            if is_correct:
                results[model]["correct"] += 1
            results[model]["total_time"] += elapsed
            
            print(f"[{model}] Pred: {pred.upper()} | Correct: {is_correct} | Time: {elapsed:.2f}s")
            
    print("\n" + "="*50)
    print("📊 FINAL ACCURACY COMPARISON REPORT")
    print("="*50)
    for model in models:
        acc = (results[model]["correct"] / results[model]["total"]) * 100
        avg_t = results[model]["total_time"] / results[model]["total"]
        print(f"Model: {model}")
        print(f"Accuracy: {acc}% ({results[model]['correct']}/{results[model]['total']})")
        print(f"Avg Response Time: {avg_t:.2f} seconds")
        print("-" * 50)

if __name__ == "__main__":
    asyncio.run(main())
