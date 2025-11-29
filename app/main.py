import logging
from fastapi import FastAPI
from pathlib import Path
from dotenv import load_dotenv

from app.api.routes import ingestion, reports


# Configure logging BEFORE creating the app
logging.basicConfig(
    level=logging.INFO,
    format='%(levelname)s: %(message)s',
    handlers=[logging.StreamHandler()]
)

env_path = Path(__file__).parent.parent / ".env"
if env_path.exists():
    load_dotenv(env_path)

app = FastAPI(
    title="Cybersecurity Risk Intelligence",
    description="Phase 1: Automated Report Generator with AI-powered analysis",
    version="1.0.0",
)


@app.get("/healthz")
def healthz():
    return {"status": "ok", "phase": "1", "features": ["ingestion", "parsing", "ai-processing", "report-rendering"]}


app.include_router(ingestion.router)
