from unittest.mock import MagicMock, patch

import pytest


class TestBuildAuthUrl:
    def test_build_auth_url_oidc(self, app):
        with app.test_request_context():
            from src.oauth import build_auth_url

            url = build_auth_url(
                "google",
                "client_id",
                "openid email",
                "OIDC",
                "https://accounts.google.com/o/oauth2/v2/auth",
            )

            assert "https://accounts.google.com/o/oauth2/v2/auth" in url
            assert "client_id=client_id" in url
            assert "scope=openid+email" in url
            assert "response_type=code" in url
            assert "nonce=" in url

    def test_build_auth_url_oauth2(self, app):
        with app.test_request_context():
            from src.oauth import build_auth_url

            url = build_auth_url(
                "github",
                "client_id",
                "user:email",
                "OAuth2",
                "https://github.com/login/oauth/authorize",
            )

            assert "https://github.com/login/oauth/authorize" in url
            assert "client_id=client_id" in url
            assert "scope=user%3Aemail" in url
            assert "response_type=code" in url
            assert "nonce" not in url


class TestGetTokens:
    @patch("src.oauth.requests.post")
    def test_get_tokens_success(self, mock_post, app):
        with app.test_request_context():
            from src.oauth import get_tokens

            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {
                "access_token": "test_access_token",
                "id_token": "test_id_token",
            }
            mock_post.return_value = mock_response

            result = get_tokens(
                "google",
                "auth_code",
                "client_id",
                "client_secret",
                "https://oauth2.googleapis.com/token",
                {},
            )

            assert result["access_token"] == "test_access_token"
            assert result["id_token"] == "test_id_token"

    @patch("src.oauth.requests.post")
    def test_get_tokens_error(self, mock_post, app):
        with app.test_request_context():
            from src.oauth import get_tokens

            mock_response = MagicMock()
            mock_response.status_code = 400
            mock_response.json.return_value = {"error": "invalid_grant"}
            mock_post.return_value = mock_response

            with pytest.raises(Exception) as exc_info:
                get_tokens(
                    "google",
                    "auth_code",
                    "client_id",
                    "client_secret",
                    "https://oauth2.googleapis.com/token",
                    {},
                )

            assert "invalid_grant" in str(exc_info.value)


class TestGetEmailOAuth2:
    @patch("src.oauth.requests.get")
    def test_get_email_oauth2_success(self, mock_get, app):
        with app.test_request_context():
            from src.oauth import get_email_OAuth2

            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {"email": "user@example.com"}
            mock_get.return_value = mock_response

            result = get_email_OAuth2(
                "https://api.github.com/user", {"Authorization": "Bearer token"}
            )

            assert result == "user@example.com"

    @patch("src.oauth.requests.get")
    def test_get_email_oauth2_error(self, mock_get, app):
        with app.test_request_context():
            from src.oauth import get_email_OAuth2

            mock_response = MagicMock()
            mock_response.status_code = 401
            mock_response.json.return_value = {"error": "unauthorized"}
            mock_get.return_value = mock_response

            with pytest.raises(Exception):
                get_email_OAuth2(
                    "https://api.github.com/user", {"Authorization": "Bearer token"}
                )
