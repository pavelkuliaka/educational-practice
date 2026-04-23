class TestVerifyUser:
    def test_verify_user_none_email(self, app_context):
        from src.auth import verify_user

        result = verify_user(None, "password")
        assert result is False

    def test_verify_user_none_password(self, app_context):
        from src.auth import verify_user

        result = verify_user("user@example.com", None)
        assert result is False

    def test_verify_user_empty_email(self, app_context):
        from src.auth import verify_user

        result = verify_user("", "password")
        assert result is False

    def test_verify_user_empty_password(self, app_context):
        from src.auth import verify_user

        result = verify_user("user@example.com", "")
        assert result is False


class TestRegisterUser:
    def test_register_user_none_email(self, app_context):
        from src.auth import register_user

        result = register_user(None, "password")
        assert result is False

    def test_register_user_none_password(self, app_context):
        from src.auth import register_user

        result = register_user("user@example.com", None)
        assert result is False

    def test_register_user_empty_email(self, app_context):
        from src.auth import register_user

        result = register_user("", "password")
        assert result is False

    def test_register_user_empty_password(self, app_context):
        from src.auth import register_user

        result = register_user("user@example.com", "")
        assert result is False
