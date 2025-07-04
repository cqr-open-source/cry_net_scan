from typing import Dict, cast

from openai import OpenAI
from openai.types.responses import EasyInputMessageParam

from app.models.ai_interaction_config import (
    AiInteractionType,
    AI_INTERACTIONS,
    AiInteractionConfig,
    OpenAIChatRole,
)
from app.models.ai_model_config import AiModelConfig, MODEL_TYPE_META


async def make_ai_request(
    ai_client: OpenAI,
    ai_interaction_type: AiInteractionType,
    finding_data: str,
    ai_model: AiModelConfig,
):
    """AI request for one target"""
    messages: Dict[AiInteractionConfig, str] = AI_INTERACTIONS[ai_interaction_type]

    response = ai_client.responses.create(
        model=str(MODEL_TYPE_META[ai_model].model_name),
        input=[
            EasyInputMessageParam(
                role=cast(OpenAIChatRole, AiInteractionConfig.SYSTEM.value),
                content=messages[AiInteractionConfig.SYSTEM],
            ),
            EasyInputMessageParam(
                role=cast(OpenAIChatRole, AiInteractionConfig.USER.value),
                content=messages[AiInteractionConfig.USER],
            ),
            EasyInputMessageParam(
                role=cast(OpenAIChatRole, AiInteractionConfig.ASSISTANT.value),
                content=messages[AiInteractionConfig.ASSISTANT],
            ),
            EasyInputMessageParam(
                role=cast(OpenAIChatRole, AiInteractionConfig.USER.value),
                content=finding_data,
            ),
        ],
        max_output_tokens=500,
        temperature=0.0,
        stream=False,
    )

    return response.output_text
