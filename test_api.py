import asyncio
import httpx

async def test():
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.post("http://127.0.0.1:8000/api/v1/detect/agentic", json={"content":"test phishing", "model":"qwen2.5:7b"})
            print(resp.status_code)
            print(resp.json())
    except Exception as e:
        print("Error:", e)

asyncio.run(test())
