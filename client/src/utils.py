import re
from collections.abc import Callable
from typing import Any


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


def validate_configs(configs: dict) -> None:
    if not configs:
        raise ValueError("No providers configured")

    for provider, config in configs.items():
        if not config:
            raise ValueError(
                f"Error in the provider's configuration file: \
                    missing {provider}'s config"
            )

        common_fields = [
            "name",
            "client_id",
            "client_secret",
            "auth_url",
            "token_url",
            "scope",
            "auth_type",
            "token_request_headers",
        ]
        for field in common_fields:
            if not config.get(field):
                raise ValueError(
                    f'Error in the provider\'s configuration \
                        file: "{provider}" missing "{field}"'
                )

        auth_type = config.get("auth_type", {})
        auth_type_value = auth_type.get("type")
        if not auth_type_value:
            raise ValueError(
                f'Error in the provider\'s configuration \
                    file: "{provider}" missing "type" in "auth_type"'
            )

        params = auth_type.get("params")
        if not params:
            raise ValueError(
                f'Error in the provider\'s configuration \
                    file: "{provider}" missing "params" in "auth_type"'
            )

        if auth_type_value == "OIDC":
            for field in ["jwks_uri", "algorithms", "issuer"]:
                if not params.get(field):
                    raise ValueError(
                        f'Error in the provider\'s configuration \
                            file: "{provider}" missing "{field}" in OIDC params'
                    )
        elif auth_type_value == "OAuth2":
            for field in ["user_info_url", "email_request_headers"]:
                if not params.get(field):
                    raise ValueError(
                        f'Error in the provider\'s configuration \
                            file: "{provider}" missing "{field}" in OAuth2 params'
                    )
        else:
            raise ValueError(
                f'Error in the provider\'s configuration \
                    file: "{provider}" unsupported auth_type "{auth_type_value}"'
            )
