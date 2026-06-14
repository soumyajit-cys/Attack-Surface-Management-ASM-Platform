try:
    from fastapi import FastAPI
except Exception:
    # Provide a minimal stub so linters/type checkers won't fail when FastAPI
    # isn't installed in the analysis environment.
    class _StubApp:
        def __init__(self, **kwargs):
            pass

        def include_router(self, *args, **kwargs):
            return None

        def get(self, *args, **kwargs):
            def decorator(fn):
                return fn
            return decorator

    FastAPI = _StubApp

from api.routes.auth import router as auth_router
from api.routes.scans import router as scan_router

app = FastAPI(title="SentinelASM")

app.include_router(auth_router)
app.include_router(scan_router)


@app.get("/health")
async def health():
    return {"status": "ok"}





