import logging

from openai import OpenAI

from app.models.ai_interaction_config import AiClient
from app.models.ai_model_config import AiModelConfig, MODEL_TYPE_META


def create_ai_client(
    ai_api_key: str,
    ai_model: AiModelConfig,
) -> AiClient:
    """Create AI client"""
    logger = logging.getLogger(__name__)

    match ai_model:
        case AiModelConfig.OPENAI__GPT4:
            logger.info(f"Chosen model: {MODEL_TYPE_META[ai_model].model_name}")

            try:
                return OpenAI(
                    api_key=ai_api_key,
                    base_url=str(MODEL_TYPE_META[ai_model].base_url),
                )
            except Exception as e:
                logger.error(f"Failed to create AI client: {e}")
                return None

        case AiModelConfig.ANTHROPIC__CLAUDE3:
            logger.warning(
                f"{ai_model} is not implemented yet. AI requests are disabled."
            )
            return None
        case _:
            logger.warning(f"{ai_model} is not supported. AI requests are disabled.")
            return None
