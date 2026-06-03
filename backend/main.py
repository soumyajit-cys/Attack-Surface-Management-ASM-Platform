from fastapi import FastAPI

from api.routes.auth import router as auth_router

from api.routes.scans import router as scan_router

app = FastAPI(
    title="SentinelASM"
)

app.include_router(auth_router)

app.include_router(scan_router)


@app.get("/health")

async def health():

    return {
        "status": "ok"
    }





