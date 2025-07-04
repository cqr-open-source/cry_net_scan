import enum  # noqa: A005
from typing import Optional

from pydantic import BaseModel, Field


@enum.unique
class AiModelConfig(enum.StrEnum):
    OPENAI__GPT4 = "openai__gpt_4"
    ANTHROPIC__CLAUDE3 = "anthropic__claude_3_7_sonnet"


class AiModelConfigMeta(BaseModel):
    model_name: str = Field(max_length=100)
    model_name_readable: str = Field(max_length=100)

    provider: str = Field(max_length=100)
    provider_readable: str = Field(max_length=100)

    provider_with_model: str = Field(max_length=100)

    api_type: str = Field(max_length=100)

    base_url: Optional[str] = Field(None, max_length=200)

    is_enabled: bool = Field(default=True)


MODEL_TYPE_META: dict[AiModelConfig, AiModelConfigMeta] = {
    AiModelConfig.OPENAI__GPT4: AiModelConfigMeta(
        provider="openai",
        provider_readable="OpenAI",
        model_name="gpt-4",
        model_name_readable="GPT-4",
        provider_with_model="OpenAI: GPT-4",
        api_type="OpenAI",
        base_url="https://api.openai.com/v1",
    ),
    AiModelConfig.ANTHROPIC__CLAUDE3: AiModelConfigMeta(
        provider="anthropic",
        provider_readable="Anthropic",
        model_name="claude-3-7-sonnet-20250219",
        model_name_readable="Claude-3-7",
        provider_with_model="Anthropic: Claude-3-7",
        api_type="Anthropic",
        base_url=None,
    ),
}
