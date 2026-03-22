from flask import (
    Flask,
    request,
    render_template,
    session,
    redirect,
    url_for,
    flash,
    abort,
)

from typing import Any

from config import CONFIGS, PERMANENT_SESSION_LIFETIME, APP_SECRET_KEY
from database import init_database, close_database, get_database
from auth import verify_user, register_user
from oauth2 import build_auth_url, get_tokens, get_email_OAuth2, get_email_OIDC
from utils import build_headers, validate_provider_config


app = Flask(__name__)
app.secret_key = APP_SECRET_KEY

init_database()

app.teardown_appcontext(close_database)

app.config["PERMANENT_SESSION_LIFETIME"] = PERMANENT_SESSION_LIFETIME
app.config["SESSION_REFRESH_EACH_REQUEST"] = True


@app.route(rule="/login", methods=["GET", "POST"])
def login_page():
    if "user" in session:
        return redirect(url_for("dashboard_page"))
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        verify = verify_user(email, password)

        if isinstance(verify, str):
            verify_provider_name = CONFIGS[verify].get("name")
            if not verify_provider_name:
                abort(
                    400,
                    description=f'The provider with the id "{verify}" is not in the configuration file',
                )

            flash(f"Войдите через {verify_provider_name}", "info")
            return redirect(url_for("login_page"))
        elif verify:
            session["user"] = email
            session.permanent = True
            return redirect(url_for("dashboard_page"))
        else:
            flash("Неверный email или пароль", "error")
            return redirect(url_for("login_page"))

    providers = [
        {"id": key, "name": CONFIGS[key].get("name"), "icon": CONFIGS[key].get("icon")}
        for key in CONFIGS
    ]
    return render_template("login.html", providers=providers)


@app.route(rule="/register", methods=["GET", "POST"])
def register_page():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        registration = register_user(email, password)

        if isinstance(registration, str):
            provider_id = CONFIGS.get(registration)
            if not provider_id:
                abort(
                    400,
                    description=f'The provider with the name "{provider_id}" is not in the configuration file',
                )

            name = provider_id.get("name")
            if not name:
                abort(
                    400,
                    description=f'The provider with the name "{name}" is not in the configuration file',
                )

            flash(f"Войдите через {name}", "info")
            return redirect(url_for("login_page"))
        elif registration:
            flash("Регистрация прошла успешно. Войдите в аккаунт", "success")
            return redirect(url_for("login_page"))
        else:
            flash("У Вас уже есть аккаунт. Войдите при помощи пароля", "error")
            return redirect(url_for("login_page"))

    return render_template("register.html")


@app.route(rule="/")
def home_page():
    if "user" in session:
        return redirect(url_for("dashboard_page"))

    session.clear()
    return redirect(url_for("login_page"))


@app.errorhandler(code_or_exception=404)
def page_not_found(error: Any):
    return render_template("404.html"), 404


@app.errorhandler(code_or_exception=400)
def bad_request(error: Any):
    return render_template("400.html", error=error.description), 400


@app.route(rule="/login/<provider>")
def login_provider(provider: str | None):
    config = validate_provider_config(provider, CONFIGS)
    assert provider is not None

    return redirect(
        build_auth_url(
            provider,
            config["client_id"],
            config["scope"],
            config["auth_type"]["type"],
            config["auth_url"],
        )
    )


@app.route(rule="/callback/<provider>")
def callback(provider: str):
    if provider not in CONFIGS:
        abort(400, description="Provider not supported")

    if request.args.get("state") != session.get("oauth2_state"):
        session.pop("oauth2_state")
        abort(400, description="Invalid state")

    session.pop("oauth2_state")

    code = request.args.get("code")
    if not code:
        abort(400, description="No code received")

    provider_config = CONFIGS.get(provider)
    if not provider_config:
        abort(
            400,
            description=f"Error in the provider's configuration file: {provider}'s config is empty",
        )

    auth_type = provider_config.get("auth_type")
    if not auth_type:
        abort(
            400,
            description='Error in the provider\'s configuration file: missing "auth_type"',
        )

    auth_type_value = auth_type.get("type")
    if not auth_type_value:
        abort(
            400,
            description='Error in the provider\'s configuration file: missing "type" in "auth_type"',
        )

    client_id = provider_config.get("client_id")
    if not client_id:
        abort(
            400,
            description='Error in the provider\'s configuration file: missing "client_id"',
        )

    client_secret = provider_config.get("client_secret")
    if not client_secret:
        abort(
            400,
            description='Error in the provider\'s configuration file: missing "client_secret"',
        )

    token_url = provider_config.get("token_url")
    if not token_url:
        abort(
            400,
            description='Error in the provider\'s configuration file: missing "token_url"',
        )

    token_request_headers = provider_config.get("token_request_headers")
    if not token_request_headers:
        abort(
            400,
            description='Error in the provider\'s configuration file: missing "token_request_headers"',
        )

    tokens = get_tokens(
        provider,
        code,
        client_id,
        client_secret,
        token_url,
        token_request_headers,
    )

    params = auth_type.get("params")
    if not params:
        abort(
            400,
            description='Error in the provider\'s configuration file: missing "params"',
        )

    email = None
    if auth_type_value == "OIDC":
        id_token = tokens.get("id_token")

        if not id_token:
            abort(400, description="Failed to obtain ID token")

        jwks_uri = params.get("jwks_uri")
        if not jwks_uri:
            abort(
                400,
                description='Error in the provider\'s configuration file: missing "jwks_uri"',
            )

        algorithms = params.get("algorithms")
        if not algorithms:
            abort(
                400,
                description='Error in the provider\'s configuration file: missing "algorithms"',
            )

        issuer = params.get("issuer")
        if not issuer:
            abort(
                400,
                description='Error in the provider\'s configuration file: missing "issuer"',
            )

        email = get_email_OIDC(
            id_token,
            jwks_uri,
            algorithms,
            client_id,
            issuer,
        )
    elif auth_type_value == "OAuth2":
        access_token = tokens.get("access_token")
        if not access_token:
            abort(400, description="Failed to obtain access token")

        user_info_url = params.get("user_info_url")
        if not user_info_url:
            abort(
                400,
                description='Error in the provider\'s configuration file: missing "user_info_url"',
            )

        email_request_headers = params.get("email_request_headers")
        if not email_request_headers:
            abort(
                400,
                description='Error in the provider\'s configuration file: missing "email_request_headers"',
            )

        email_request_headers = build_headers(
            email_request_headers, access_token=access_token
        )
        if not email_request_headers:
            abort(
                400,
                description='Error in the provider\'s configuration file: "email_request_headers" is empty',
            )

        email = get_email_OAuth2(user_info_url, email_request_headers)
    else:
        abort(400, description="Authorization method is not supported")

    if not email:
        abort(400, description="Failed to obtain email")

    database = get_database()
    cursor = database.cursor()

    cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
    existing_user = cursor.fetchone()

    if existing_user:
        user_provider = existing_user.get("provider")

        if not user_provider:
            flash("У Вас уже есть аккаунт. Войдите при помощи пароля", "error")
            return redirect(url_for("login_page"))
        elif user_provider and user_provider != provider:
            user_provider_config = CONFIGS.get(user_provider)
            if not user_provider_config:
                abort(
                    400,
                    description=f'The provider configuration with the id "{provider}" is absent',
                )

            user_provider_name = user_provider_config.get("name")
            if not user_provider_name:
                abort(
                    400,
                    description=f'The provider with the id "{provider}" is missing a name',
                )

            flash(f"Войдите через {user_provider_name}", "error")
            return redirect(url_for("login_page"))
        else:
            session["user"] = email
            session.permanent = True

            return redirect(url_for("dashboard_page"))

    cursor.execute(
        "INSERT INTO users (email, password_hash, provider) VALUES (?, ?, ?)",
        (email, None, provider),
    )
    database.commit()

    session["user"] = email
    session.permanent = True

    flash("Вы успешно вошли", "success")
    return redirect(url_for("dashboard_page"))


@app.route(rule="/dashboard")
def dashboard_page():
    if "user" not in session:
        return redirect(url_for("logout"))
    return render_template("dashboard.html", user_email=session["user"])


@app.route(rule="/logout")
def logout():
    session.clear()
    return redirect(url_for("login_page"))


def main() -> None:
    app.run(port=5000, debug=True)


if __name__ == "__main__":
    main()
