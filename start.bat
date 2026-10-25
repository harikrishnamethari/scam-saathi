@echo off
echo.
echo  =======================================
echo   Scam Saathi - Starting Server
echo  =======================================
echo.
echo  Opening at: http://localhost:8000
echo  Press Ctrl+C to stop.
echo.
python -m uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload
