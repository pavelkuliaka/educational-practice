import re
from typing import Any, Callable


def is_email(string: str) -> bool:
    email_regex = r"^[\w\.-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    return bool(re.match(email_regex, string))


def flatten_to_strings(data: Any) -> list[str]:
    stack = [data]
    result = []
    while stack:
        item = stack.pop()
        if isinstance(item, str):
            result.append(item)
        elif isinstance(item, dict):
            stack.extend(item.values())
        elif isinstance(item, list):
            stack.extend(item)
        else:
            result.append(str(item))
    return result


def extract_email(user_data: str | dict | list) -> str | None:
    if isinstance(user_data, str) and is_email(user_data):
        return user_data

    flat_strings = flatten_to_strings(user_data)

    for string in flat_strings:
        if is_email(string):
            return string
    return None


def build_headers(headers: Callable | dict, **params) -> dict:
    if callable(headers):
        return headers(**params)
    return headers


def validate_provider_config(provider: str | None, configs: dict) -> dict:
    from flask import abort

    if provider not in configs:
        abort(400, description=f'Provider "{provider}" not supported')

    assert provider is not None
    config = configs[provider]
    if not config:
        abort(
            400,
            description=f"Error in the provider's configuration file: missing {provider}'s config",
        )

    required_fields = ["client_id", "scope", "auth_type", "auth_url"]
    for field in required_fields:
        if not config.get(field):
            abort(
                400,
                description=f'Error in the provider\'s configuration file: missing "{field}"',
            )

    if not config.get("auth_type", {}).get("type"):
        abort(
            400,
            description='Error in the provider\'s configuration file: missing "type"',
        )

    return config
