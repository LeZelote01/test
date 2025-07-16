"""
Simple test server to check if FastAPI works
"""
from fastapi import FastAPI

app = FastAPI(title="Test Server")

@app.get("/api/health")
async def health():
    return {"status": "healthy"}

@app.get("/api/")
async def root():
    return {"message": "Test server working"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("test_server:app", host="0.0.0.0", port=8001)