"""Local demo: start the audited HTTP service on 127.0.0.1:8000.

Storage lives in ./audit-data (override with AUDIT_STORE).
"""
from __future__ import annotations

import uvicorn

from audit.app import app

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)
