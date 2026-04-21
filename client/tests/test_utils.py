import pytest
from src.utils import (
    is_email,
    flatten_to_strings,
    extract_email,
    build_headers,
    validate_configs,
)


class TestIsEmail:
    def test_valid_email(self):
        assert is_email("user@example.com") is True

    def test_valid_email_with_dots(self):
        assert is_email("user.name@example.com") is True

    def test_valid_email_with_dash(self):
        assert is_email("user-name@example-domain.com") is True

    def test_invalid_email_no_at(self):
        assert is_email("userexample.com") is False

    def test_invalid_email_no_domain(self):
        assert is_email("user@") is False

    def test_invalid_email_no_local_part(self):
        assert is_email("@example.com") is False

    def test_invalid_email_empty(self):
        assert is_email("") is False

    def test_invalid_email_spaces(self):
        assert is_email("user @example.com") is False


class TestFlattenToStrings:
    def test_flatten_string(self):
        assert flatten_to_strings("hello") == ["hello"]

    def test_flatten_list(self):
        result = flatten_to_strings([1, 2, 3])
        assert "1" in result and "2" in result and "3" in result
        assert len(result) == 3

    def test_flatten_dict(self):
        result = flatten_to_strings({"a": "hello", "b": 42})
        assert "hello" in result
        assert "42" in result

    def test_flatten_nested(self):
        data = {"a": [1, {"b": "test"}]}
        result = flatten_to_strings(data)
        assert "1" in result
        assert "test" in result

    def test_flatten_empty_list(self):
        assert flatten_to_strings([]) == []

    def test_flatten_empty_dict(self):
        assert flatten_to_strings({}) == []


class TestExtractEmail:
    def test_extract_from_string(self):
        assert extract_email("user@example.com") == "user@example.com"

    def test_extract_from_dict(self):
        data = {"email": "user@example.com", "name": "Test"}
        assert extract_email(data) == "user@example.com"

    def test_extract_from_nested_dict(self):
        data = {"user": {"email": "user@example.com"}}
        assert extract_email(data) == "user@example.com"

    def test_extract_from_list(self):
        data = [{"email": "user@example.com"}]
        assert extract_email(data) == "user@example.com"

    def test_extract_not_an_email(self):
        assert extract_email("not an email") is None

    def test_extract_no_email_in_dict(self):
        assert extract_email({"name": "Test"}) is None

    def test_extract_empty(self):
        assert extract_email({}) is None

    def test_extract_list_no_email(self):
        assert extract_email([1, 2, 3]) is None


class TestBuildHeaders:
    def test_build_headers_dict(self):
        headers = {"Content-Type": "application/json"}
        assert build_headers(headers) == headers

    def test_build_headers_callable(self):
        def get_headers(access_token):
            return {"Authorization": f"Bearer {access_token}"}

        result = build_headers(get_headers, access_token="test123")
        assert result == {"Authorization": "Bearer test123"}

    def test_build_headers_callable_empty(self):
        def get_headers():
            return {"Content-Type": "application/json"}

        result = build_headers(get_headers)
        assert result == {"Content-Type": "application/json"}


class TestValidateConfigs:
    def test_validate_empty_configs(self):
        with pytest.raises(ValueError, match="No providers configured"):
            validate_configs({})

    def test_validate_missing_provider_config(self):
        with pytest.raises(ValueError, match="missing"):
            validate_configs({"google": {}})

    def test_validate_missing_client_id(self):
        config = {
            "google": {
                "name": "Google",
                "client_secret": "secret",
                "auth_url": "https://accounts.google.com/o/oauth2/v2/auth",
                "token_url": "https://oauth2.googleapis.com/token",
                "scope": "openid email",
                "auth_type": {"type": "OIDC", "params": {}},
                "token_request_headers": {},
            }
        }
        with pytest.raises(ValueError, match="missing"):
            validate_configs(config)

    def test_validate_missing_auth_type(self):
        config = {
            "google": {
                "name": "Google",
                "client_id": "id",
                "client_secret": "secret",
                "auth_url": "https://accounts.google.com/o/oauth2/v2/auth",
                "token_url": "https://oauth2.googleapis.com/token",
                "scope": "openid email",
                "token_request_headers": {},
            }
        }
        with pytest.raises(ValueError, match="missing"):
            validate_configs(config)

    def test_validate_oidc_missing_params(self):
        config = {
            "google": {
                "name": "Google",
                "client_id": "id",
                "client_secret": "secret",
                "auth_url": "https://accounts.google.com/o/oauth2/v2/auth",
                "token_url": "https://oauth2.googleapis.com/token",
                "scope": "openid email",
                "auth_type": {"type": "OIDC", "params": {}},
                "token_request_headers": {},
            }
        }
        with pytest.raises(ValueError, match="missing"):
            validate_configs(config)

    def test_validate_oauth2_missing_params(self):
        config = {
            "github": {
                "name": "GitHub",
                "client_id": "id",
                "client_secret": "secret",
                "auth_url": "https://github.com/login/oauth/authorize",
                "token_url": "https://github.com/login/oauth/access_token",
                "scope": "user:email",
                "auth_type": {"type": "OAuth2", "params": {}},
                "token_request_headers": {},
            }
        }
        with pytest.raises(ValueError, match="missing"):
            validate_configs(config)
