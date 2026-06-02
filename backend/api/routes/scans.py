from fastapi import APIRouter

from schemas.scan import ScanRequest

from tasks.discovery_tasks import run_discovery

router = APIRouter(
    prefix="/scan",
    tags=["scan"]
)


@router.post("/")

async def scan(
    data: ScanRequest
):

    result = await run_discovery(
        data.domain
    )

    return result


