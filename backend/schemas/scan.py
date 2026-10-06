from pydantic import BaseModel, Field


class ScanRequest(BaseModel):

    domain: str = Field(
        min_length=3,
        max_length=253,
        description="Domain to scan, e.g. example.com"
    )

    # Only used by POST /scans/verify-ownership; ignored by POST /scans.
    method: str = Field(
        default="dns_txt",
        pattern="^(dns_txt|http_file)$",
        description="Verification method for ownership challenges",
    )


    