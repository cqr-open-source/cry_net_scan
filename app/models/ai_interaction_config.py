import enum
from typing import Literal, Dict, Optional

from openai import OpenAI

from app.modules.ai.ai_messages import (
    system_message_nse,
    user_message_nse,
    assistant_message_nse,
)

AiClient = Optional[OpenAI]


@enum.unique
class AiInteractionType(enum.StrEnum):
    NSE = "nse"


@enum.unique
class AiInteractionConfig(enum.StrEnum):
    SYSTEM = "system"
    USER = "user"
    ASSISTANT = "assistant"


OpenAIChatRole = Literal["user", "assistant", "system"]

AI_INTERACTIONS: Dict[
    Literal[AiInteractionType.NSE], Dict[AiInteractionConfig, str]
] = {
    AiInteractionType.NSE: {
        AiInteractionConfig.SYSTEM: system_message_nse,
        AiInteractionConfig.USER: user_message_nse,
        AiInteractionConfig.ASSISTANT: assistant_message_nse,
    }
}
