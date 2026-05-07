import os
import chromadb
from chromadb.utils import embedding_functions

# Get absolute path for chroma DB storage so it survives restarts
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "../../chroma_db")

class RAGManager:
    def __init__(self):
        self.client = chromadb.PersistentClient(path=DB_PATH)
        # We use standard lightweight models by default
        self.embedding_func = embedding_functions.DefaultEmbeddingFunction()
        self.collection = self.client.get_or_create_collection(
            name="phishing_attacks",
            embedding_function=self.embedding_func
        )

    def add_attack_to_memory(self, text: str, verdict: str, explanation: str):
        """Stores an analyzed message in the vector DB."""
        # Only store substantial text to avoid polluting memory with empty queries
        if not text or len(text) < 10:
            return

        doc_id = f"attack_{self.collection.count() + 1}"
        metadata = {
            "verdict": verdict,
            # We keep a tiny substring to prevent metadata overflow
            "explanation": explanation[:200]
        }
        self.collection.add(
            documents=[text],
            metadatas=[metadata],
            ids=[doc_id]
        )

    def find_similar_attacks(self, text: str, threshold: float = 1.0):
        """Searches for similar attacks in memory."""
        if not text or len(text) < 10:
            return "RAG MEMORY: Text too short for semantic comparison."
            
        if self.collection.count() == 0:
            return "RAG MEMORY: Clean database. No historical records found."
            
        results = self.collection.query(
            query_texts=[text],
            n_results=1
        )
        
        if not results['documents'] or not results['documents'][0]:
            return "RAG MEMORY: No highly similar past attacks found."
            
        # Distances are returned (L2 distance by default). Lower = more similar.
        distance = results['distances'][0][0]
        if distance < threshold:
            doc = results['documents'][0][0]
            meta = results['metadatas'][0][0]
            verdict = meta.get("verdict", "Unknown")
            return f"RAG MEMORY TRIGGERED: Found a highly similar previous analysis (Distance: {distance:.2f}). Past Verdict: {verdict}. \nPast Attack Text Snippet: {doc[:100]}..."
        else:
            return "RAG MEMORY: Checked database. No historically identical threats found."

rag_manager = RAGManager()
