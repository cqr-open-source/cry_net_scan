from typing import Optional

from pydantic import BaseModel, Field


class RawHttpExchange(BaseModel):
    request: Optional[str] = Field(
        default="",
        description="The raw HTTP request sent by Nuclei (for http type).",
    )
    response: Optional[str] = Field(
        default="",
        description="The raw HTTP response received by Nuclei (for http type).",
    )
