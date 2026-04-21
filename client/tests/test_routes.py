from unittest.mock import patch


class TestErrorHandlers:
    def test_404_error(self, client):
        response = client.get("/nonexistent")
        assert response.status_code == 404
        assert b"404" in response.data

    def test_400_error_handler(self, client):
        with client.session_transaction() as sess:
            sess["oauth2_state"] = "test_state"

        response = client.get("/callback/google?state=wrong_state&code=test")
        assert response.status_code == 400


class TestLoginProvider:
    def test_login_provider_google(self, client):
        response = client.get("/login/google", follow_redirects=False)
        assert response.status_code == 302
        assert "accounts.google.com" in response.location

    def test_login_provider_github(self, client):
        response = client.get("/login/github", follow_redirects=False)
        assert response.status_code == 302
        assert "github.com" in response.location

    def test_login_provider_yandex(self, client):
        response = client.get("/login/yandex", follow_redirects=False)
        assert response.status_code == 302
        assert "oauth.yandex.ru" in response.location

    def test_login_provider_invalid(self, client):
        response = client.get("/login/invalid_provider")
        assert response.status_code == 404


class TestCallback:
    def test_callback_no_code(self, client):
        with client.session_transaction() as sess:
            sess["oauth2_state"] = "test_state"

        response = client.get("/callback/google?state=test_state")

        assert response.status_code == 400

    def test_callback_invalid_state(self, client):
        with client.session_transaction() as sess:
            sess["oauth2_state"] = "test_state"

        response = client.get("/callback/google?state=wrong_state&code=test")

        assert response.status_code == 400

    @patch("src.oauth.get_tokens")
    def test_callback_token_error(self, mock_tokens, client):
        with client.session_transaction() as sess:
            sess["oauth2_state"] = "test_state"

        mock_tokens.side_effect = Exception("Invalid code")

        response = client.get("/callback/google?state=test_state&code=test")

        assert response.status_code == 400

    @patch("src.oauth.get_tokens")
    @patch("src.oauth.get_email_OAuth2")
    def test_callback_get_email_error(self, mock_get_email, mock_tokens, client):
        with client.session_transaction() as sess:
            sess["oauth2_state"] = "test_state"

        mock_tokens.return_value = {"access_token": "test_token"}
        mock_get_email.side_effect = Exception("Failed to get email")

        response = client.get("/callback/github?state=test_state&code=test_code")

        assert response.status_code == 400


class TestHome:
    def test_home_not_logged_in(self, client):
        response = client.get("/")
        assert response.status_code == 302
        assert "/login" in response.location

    def test_home_logged_in(self, client, logged_in_client):
        response = logged_in_client.get("/")
        assert response.status_code == 302
        assert "/dashboard" in response.location
