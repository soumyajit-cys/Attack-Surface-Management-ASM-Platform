from fastapi import FastAPI

app = FastAPI(
    title="SentinelASM",
    version="1.0"
)

@app.get("/health")

async def health():

    return {
        "status": "ok"
    }


