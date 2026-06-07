from fastapi import APIRouter

router = APIRouter(
    prefix="/findings",
    tags=["findings"]
)


@router.get("/")

async def findings():

    return []