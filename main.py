"""Compatibility entry point; the application lives in audit/app.py."""
from audit.app import app  # noqa: F401

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8000)
