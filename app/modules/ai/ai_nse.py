import asyncio
from typing import List

from app.models.ai_interaction_config import AiInteractionType, AiClient
from app.models.ai_model_config import AiModelConfig
from app.models.host_config import Host
from app.modules.ai.ai_request import make_ai_request


async def get_nse_scripts(
    ai_client: AiClient,
    live_hosts: List[Host],
    ai_model: AiModelConfig,
):
    # Gather tasks for creating NSE scripts.
    tasks = []
    for target_data in live_hosts:
        # Convert the target_data dict to a JSON string for the AI prompt
        # finding_data = target_data.model_dump() # make JSON, like .loads
        finding_data = target_data.model_dump_json()  # make string, like .dumps

        tasks.append(
            make_ai_request(
                ai_client=ai_client,
                ai_interaction_type=AiInteractionType.NSE,
                finding_data=finding_data,
                ai_model=ai_model,
            )
        )

    # Run all tasks concurrently and gather their results
    results = await asyncio.gather(*tasks, return_exceptions=True)  # noqa:F841

    # TODO: continue
    return None
