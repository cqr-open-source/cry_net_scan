from pydantic import BaseModel, Field

from app.models.target_type_config import TargetType


class SourceTarget(BaseModel):
    """
    Represents an original target string that resolved to a particular IP.
    """

    value: str = Field(
        ...,
        description="The original target string (e.g., 'example.com', '192.168.1.1').",
    )
    type: TargetType = Field(..., description="The type of the original target.")
