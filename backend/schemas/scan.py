from pydantic import BaseModel, Field


class ScanRequest(BaseModel):

    domain: str = Field(
        min_length=3,
        max_length=253,
        description="Domain to scan, e.g. example.com"
    )


    