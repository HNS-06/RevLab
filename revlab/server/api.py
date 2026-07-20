"""
FastAPI REST API Server Module
"""
import tempfile
import os
from typing import Dict, Any, List

try:
    from fastapi import FastAPI, File, UploadFile, HTTPException
    import uvicorn
    HAS_FASTAPI = True
except ImportError:
    HAS_FASTAPI = False

from ..parsers.loader import load_binary
from ..analysis.statistics import generate_summary_statistics
from ..database.sqlite import get_history, log_analysis

if HAS_FASTAPI:
    api_app = FastAPI(
        title="RevLab Static Binary Analysis API",
        description="REST API service for static binary analysis, reverse engineering telemetry, & history tracking.",
        version="1.0.0"
    )

    @api_app.get("/api/v1/health")
    def health_check():
        return {"status": "ok", "service": "RevLab API", "version": "1.0.0"}

    @api_app.get("/api/v1/history")
    def history(limit: int = 20):
        return {"history": get_history(limit=limit)}

    @api_app.post("/api/v1/analyze")
    async def analyze_file(file: UploadFile = File(...)):
        try:
            with tempfile.NamedTemporaryFile(delete=False, suffix=f"_{file.filename}") as tmp:
                content = await file.read()
                tmp.write(content)
                tmp_path = tmp.name

            bin_obj = load_binary(tmp_path)
            summary = generate_summary_statistics(bin_obj)
            summary["filename"] = file.filename
            log_analysis(summary)

            os.remove(tmp_path)
            return {"status": "success", "analysis": summary}
        except Exception as e:
            raise HTTPException(status_code=400, detail=str(e))
else:
    api_app = None

def start_server(host: str = "127.0.0.1", port: int = 8000):
    """Starts Uvicorn server for RevLab API."""
    if not HAS_FASTAPI:
        raise RuntimeError("FastAPI or Uvicorn missing. Run: pip install fastapi uvicorn")
    uvicorn.run(api_app, host=host, port=port)
