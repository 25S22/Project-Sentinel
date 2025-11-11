import chromadb
import google.generativeai as genai
from chromadb.errors import CollectionNotFoundError

# --- RAG CONFIGURATION ---
CHROMA_DB_PATH = "./chroma_db"
COLLECTION_NAME = "sentinel_kb"
EMBEDDING_MODEL = "models/text-embedding-004"
N_RESULTS = 2 # How many documents to retrieve

def _format_history(history):
    """Helper function to format the history list into a string."""
    if not history:
        return "No previous conversation history."
    
    formatted = ""
    for q, a in history:
        formatted += f"User: {q}\nSentinel (KB): {a}\n---\n"
    return formatted

def run_rag_query(question, history, llm_function):
    """
    Performs Conversational RAG using ChromaDB and a provided LLM function.
    
    Args:
        question (str): The user's new question.
        history (list): A list of (question, answer) tuples.
        llm_function (function): The function to call for generative analysis
                                 (e.g., sentinel.get_generative_analysis)
    """
    try:
        print(f"Sentinel (RAG): Initializing knowledge base...")
        client = chromadb.PersistentClient(path=CHROMA_DB_PATH)
        collection = client.get_collection(name=COLLECTION_NAME)
        
        # 1. Embed the user's question
        print(f"Sentinel (RAG): Embedding question...")
        q_embed = genai.embed_content(
            model=EMBEDDING_MODEL,
            content=question
        )['embedding']
        
        # 2. Query ChromaDB for relevant documents
        print(f"Sentinel (RAG): Retrieving relevant context...")
        results = collection.query(
            query_embeddings=[q_embed],
            n_results=N_RESULTS
        )
        
        if not results['documents']:
            return "No relevant context found in the knowledge base."
            
        context = "\n---\n".join(results['documents'][0])
        formatted_history = _format_history(history)
        
        # 3. Build the NEW Conversational RAG prompt
        prompt = f"""You are Sentinel, a security agent. Use the Chat History to understand the user's Latest Question.
Then, answer the Latest Question based *ONLY* on the provided Context Documents.
If the answer is not in the Context Documents, say "I do not have that information in my knowledge base."

---
Chat History:
{formatted_history}
---
Context Documents:
{context}
---

Latest Question:
{question}

Answer (based *only* on the Context Documents):"""

        print(f"Sentinel (RAG): Generating answer...")
        
        # 4. Generate the answer using the passed-in LLM function
        answer = llm_function(prompt)
        return answer
        
    except CollectionNotFoundError:
        return "[ERROR] Knowledge base not found. Please run the 'ingest.py' script first."
    except Exception as e:
        return f"[ERROR] Could not perform RAG query: {e}"
