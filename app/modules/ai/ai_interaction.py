from typing import List

from app.models.ai_interaction_config import AiClient
from app.models.ai_model_config import AiModelConfig
from app.models.host_config import Host
from app.modules.ai.ai_client import create_ai_client
from app.modules.ai.ai_nse import get_nse_scripts


async def interact_with_ai(
    ai_api_key: str,
    live_hosts: List[Host],
    ai_model: AiModelConfig = AiModelConfig.OPENAI__GPT4,
) -> None:
    """
    Processes multiple targets by making asynchronous AI requests and gathering results.
    """
    # Create ai_client
    ai_client: AiClient = create_ai_client(
        ai_api_key=ai_api_key,
        ai_model=ai_model,
    )

    # If invalid token/model name or smth else - will be exception and ai_client is None
    if not ai_client:
        return None

    # Select 3 top vulnerabilities/technologies, create NSE scripts for them, make AI request, parse and validate it
    await get_nse_scripts(
        ai_client=ai_client,
        live_hosts=live_hosts,
        ai_model=ai_model,
    )

    # TODO: continue
    # Give NSE for Nmap
    ...
    # Validate with AI
    ...

    return None
