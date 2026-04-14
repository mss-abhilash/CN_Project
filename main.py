"""
IoT VPN + Two-Phase Authentication — Application Entry Point
==============================================================
Run the entire project with a single command:

    python main.py

This starts the FastAPI server with auto-reload enabled.
API docs available at: http://127.0.0.1:8000/docs
"""

import os
import uvicorn
from dotenv import load_dotenv

load_dotenv()

HOST = os.getenv("HOST", "127.0.0.1")
PORT = int(os.getenv("PORT", "8000"))
DEBUG = os.getenv("DEBUG", "true").lower() == "true"
LOG_LEVEL = os.getenv("LOG_LEVEL", "info")


def main():
    """Launch the FastAPI application via Uvicorn."""
    print("=" * 60)
    print("  IoT VPN + 2FA — Secure Home Network")
    print("=" * 60)
    print(f"  Server  : http://{HOST}:{PORT}")
    print(f"  API Docs: http://{HOST}:{PORT}/docs")
    print(f"  ReDoc   : http://{HOST}:{PORT}/redoc")
    print(f"  Debug   : {DEBUG}")
    print("=" * 60)

    uvicorn.run(
        "backend.main:app",
        host=HOST,
        port=PORT,
        reload=DEBUG,
        log_level=LOG_LEVEL,
    )


if __name__ == "__main__":
    main()
