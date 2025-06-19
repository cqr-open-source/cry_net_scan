import json
from typing import List
from venv import logger


async def parse_jsonl(jsonl_content: str) -> List[dict] | List[None]:
    """
    Parse a JSONL (JSON Lines) formatted string into a list of dictionaries.
    """
    processed_result = jsonl_content.strip()

    # Split the string by the unique JSON object
    raw_json_objects = processed_result.split("}\n{")

    parsed_objects = []
    if not raw_json_objects:
        return [None]

    # Reconstruct each JSON object
    for i, part in enumerate(raw_json_objects):
        if len(raw_json_objects) > 1:
            if i == 0:
                # First part should already start with '{'
                full_json_str = part + "}"
            elif i == len(raw_json_objects) - 1:
                # Last part should already end with '}'
                full_json_str = "{" + part
            else:
                # Middle parts need both '{' and '}'
                full_json_str = "{" + part + "}"
        else:
            # If there's only one part, it should be a complete JSON object
            full_json_str = part

        try:
            parsed_objects.append(json.loads(full_json_str))
        except json.JSONDecodeError as e:
            logger.warning(
                f"Error decoding JSON segment: {e}\nSegment: {full_json_str.strip()}"
            )
            continue

    return parsed_objects
