"""
Scam Saathi — FastAPI Backend
Serves the static frontend and provides the /api/analyze endpoint.
"""
from __future__ import annotations

import os
import sys
import traceback
from pathlib import Path

# Ensure the backend directory is on sys.path so agents.py is importable
_BACKEND_DIR = Path(__file__).parent
if str(_BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(_BACKEND_DIR))

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, field_validator

load_dotenv()

from agents import sarvam_full_analysis, demo_full_analysis  # noqa: E402

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

SARVAM_API_KEY = os.getenv("SARVAM_API_KEY", "")
SARVAM_MODEL = os.getenv("SARVAM_MODEL", "sarvam-105b")
DEMO_MODE = not bool(SARVAM_API_KEY.strip())
MAX_MESSAGE_LENGTH = 4000

BASE_DIR = Path(__file__).parent.parent

# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------

app = FastAPI(title="Scam Saathi API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Request / Response schemas
# ---------------------------------------------------------------------------

class AnalyzeRequest(BaseModel):
    message: str
    output_language: str = "en"

    @field_validator("message")
    @classmethod
    def validate_message(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("Message cannot be empty.")
        if len(v) > MAX_MESSAGE_LENGTH:
            raise ValueError(f"Message exceeds {MAX_MESSAGE_LENGTH} character limit.")
        return v

    @field_validator("output_language")
    @classmethod
    def validate_language(cls, v: str) -> str:
        allowed = {"en", "hi", "bn", "ta", "te", "mr", "gu", "kn", "ml", "pa"}
        v = v.strip().lower()
        if v not in allowed:
            return "en"
        return v


# ---------------------------------------------------------------------------
# API Routes
# ---------------------------------------------------------------------------

@app.get("/api/status")
async def status():
    return {
        "status": "ok",
        "demo_mode": DEMO_MODE,
        "model": SARVAM_MODEL if not DEMO_MODE else None,
    }


@app.post("/api/analyze")
async def analyze(req: AnalyzeRequest):
    try:
        if DEMO_MODE:
            result = demo_full_analysis(req.message, req.output_language)
        else:
            result = await sarvam_full_analysis(
                message=req.message,
                output_language=req.output_language,
                api_key=SARVAM_API_KEY,
                model_name=SARVAM_MODEL,
            )

        return JSONResponse({
            "detectedLanguage": result.detected_language,
            "outputLanguage": result.output_language,
            "riskLevel": result.risk_level,
            "scamCategory": result.scam_category,
            "summary": result.summary,
            "assessmentConfidence": result.assessment_confidence,
            "confidenceExplanation": result.confidence_explanation,
            "redFlags": result.red_flags,
            "recommendedActions": result.recommended_actions,
            "alreadyActedAdvice": result.already_acted_advice,
            "limitations": result.limitations,
            "demoMode": result.demo_mode,
        })

    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))
    except Exception as e:
        # If live AI fails, try demo fallback
        tb = traceback.format_exc()
        print(f"[ERROR] Analysis failed: {e}\n{tb}")
        try:
            fallback = demo_full_analysis(req.message, req.output_language)
            fallback.demo_mode = True
            return JSONResponse({
                "detectedLanguage": fallback.detected_language,
                "outputLanguage": fallback.output_language,
                "riskLevel": fallback.risk_level,
                "scamCategory": fallback.scam_category,
                "summary": fallback.summary,
                "assessmentConfidence": fallback.assessment_confidence,
                "confidenceExplanation": fallback.confidence_explanation,
                "redFlags": fallback.red_flags,
                "recommendedActions": fallback.recommended_actions,
                "alreadyActedAdvice": fallback.already_acted_advice,
                "limitations": fallback.limitations,
                "demoMode": True,
                "fallbackWarning": "Live AI analysis failed. Showing rule-based Demo Mode results.",
            })
        except Exception as fe:
            raise HTTPException(status_code=500, detail="Analysis failed. Please try again.")


# ---------------------------------------------------------------------------
# Static files (serve the frontend)
# ---------------------------------------------------------------------------

frontend_dir = BASE_DIR / "frontend"

if frontend_dir.exists():
    app.mount("/static", StaticFiles(directory=str(frontend_dir / "static")), name="static")

    @app.get("/", response_class=FileResponse)
    async def root():
        return FileResponse(str(frontend_dir / "index.html"))

    @app.get("/{path:path}", response_class=FileResponse)
    async def catch_all(path: str):
        file_path = frontend_dir / path
        if file_path.exists() and file_path.is_file():
            return FileResponse(str(file_path))
        return FileResponse(str(frontend_dir / "index.html"))


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
