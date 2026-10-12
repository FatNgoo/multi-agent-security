
from fastapi import FastAPI

app = FastAPI(
    title="Multi-Agent Security Investigation",
    description="AI-assisted Persistence and C2 Investigation",
    version="0.1.0",
)


@app.get("/")
def root():
    return {
        "project": "Multi-Agent Security Investigation",
        "version": "0.1.0",
        "status": "running",
    }


@app.get("/health")
def health():
    return {
        "status": "healthy",
        "service": "backend-api",
    }
