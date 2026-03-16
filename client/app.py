from flask import (
    Flask,
    request,
    render_template,
    session,
    redirect,
    url_for,
    flash,
    abort,
    Response
)

from typing import Any

from config import CONFIGS, PERMANENT_SESSION_LIFETIME, APP_SECRET_KEY
from database import init_database, close_database, get_database
from auth import verify_user, register_user
from oauth2 import build_auth_url, get_tokens, get_email_OAuth2, get_email_OIDC
from utils import build_headers


app = Flask(__name__)
app.secret_key = APP_SECRET_KEY

init_database()

app.teardown_appcontext(close_database)

app.config["PERMANENT_SESSION_LIFETIME"] = PERMANENT_SESSION_LIFETIME
app.config["SESSION_REFRESH_EACH_REQUEST"] = True


@app.route(rule="/login", methods=["GET", "POST"])
def login_page() -> Response | str:
    if "user" in session:
        return redirect(location=url_for(endpoint="dashboard_page"))
    if request.method == "POST":
        email = request.form.get(key="email", default=None)
        password = request.form.get(key="password", default=None)

        verify = verify_user(email=email, password=password)

        if isinstance(obj=verify, class_or_tuple=str):
            verify_provider_name = CONFIGS[verify].get(key="name", default=None)
            if not verify_provider_name:
                abort(code=400, description=f"The provider with the id \"{verify}\" is not in the configuration file")

            flash(message=f"Войдите через {verify_provider_name}", category="info")
            return redirect(location=url_for(endpoint="login_page"))
        elif verify:
            session["user"] = email
            session.permanent = True
            return redirect(location=url_for(endpoint="dashboard_page"))
        else:
            flash(message="Неверный email или пароль", category="error")
            return redirect(location=url_for(endpoint="login_page"))

    providers = [
        {"id": key, "name": CONFIGS[key].get("name"), "icon": CONFIGS[key].get("icon")}
        for key in CONFIGS
    ]
    return render_template(template_name_or_list="login.html", providers=providers)


@app.route(rule="/register", methods=["GET", "POST"])
def register_page() -> Response | str:
    if request.method == "POST":
        email = request.form.get(key="email", default=None)
        password = request.form.get(key="password", default=None)

        registration = register_user(email=email, password=password)

        if isinstance(obj=registration, class_or_tuple=str):
            provider_id = CONFIGS.get(key=registration, default=None)
            if not provider_id:
                abort(code=400, description=f"The provider with the name \"{provider_id}\" is not in the configuration file")

            name = provider_id.get("name", default=None)
            if not name:
                abort(code=400, description=f"The provider with the name \"{name}\" is not in the configuration file")

            flash(message=f"Войдите через {name}", category="info")
            return redirect(location=url_for(endpoint="login_page"))
        elif registration:
            flash(message="Регистрация прошла успешно. Войдите в аккаунт", category="success")
            return redirect(location=url_for(endpoint="login_page"))
        else:
            flash(message="У Вас уже есть аккаунт. Войдите при помощи пароля", category="error")
            return redirect(location=url_for(endpoint="login_page"))

    return render_template(template_name_or_list="register.html")


@app.route(rule="/")
def home_page() -> Response:
    if "user" in session:
        return redirect(location=url_for(endpoint="dashboard_page"))

    session.clear()
    return redirect(location=url_for(endpoint="login_page"))


@app.errorhandler(code_or_exception=404)
def page_not_found(error: Any) -> tuple[Response, int]:
    return render_template(template_name_or_list="404.html"), 404


@app.errorhandler(code_or_exception=400)
def bad_request(error: Any) -> tuple[Response, int]:
    return render_template(template_name_or_list="400.html", error=error.description), 400


@app.route("/login/<provider>")
def login_provider(provider) -> Response:
    if provider not in CONFIGS:
        abort(code=400, description=f"Provider \"{provider}\" not supported")

    provider_config = CONFIGS.get(key=provider, default=None)
    if not provider_config:
        abort(
            code=400,
            description=f"Error in the provider's configuration file: missing {provider}'s config",
        )

    client_id = provider_config.get("client_id", default=None)
    if not client_id:
        abort(
            code=400,
            description=f'Error in the provider\'s configuration file: missing "client_id"',
        )

    scope = provider_config.get(key="scope", default=None)
    if not scope:
        abort(
            code=400,
            description=f"Error in the provider\'s configuration file: missing \"scope\"",
        )

    auth_type = provider_config.get(key="auth_type", default=None)
    if not auth_type:
        abort(
            code=400,
            description=f'Error in the provider\'s configuration file: missing "auth_type"',
        )

    auth_type_value = auth_type.get(key="type", default=None)
    if not auth_type_value:
        abort(
            code=400,
            description=f"Error in the provider\'s configuration file: missing \"type\"",
        )   

    auth_url = build_auth_url(
        provider=provider,
        client_id=client_id,
        scope=scope,
        auth_type_value=auth_type_value
    )

    return redirect(location=auth_url)


@app.route(rule="/callback/<provider>")
def callback(provider: str):
    if provider not in CONFIGS:
        abort(code=400, description="Provider not supported")

    if request.args.get(key="state", default=None) != session.get(key="oauth2_state", default=None):
        session.pop(key="oauth2_state", default=None)
        abort(code=400, description="Invalid state")

    session.pop(key="oauth2_state", default=None)

    code = request.args.get(key="code", default=None)
    if not code:
        abort(code=400, description="No code received")

    provider_config = CONFIGS.get(key=provider, default=None)
    if not provider_config:
        abort(
            code=400,
            description=f"Error in the provider's configuration file: {provider}'s config is empty",
        )

    auth_type = provider_config.get(key="auth_type", default=None)
    if not auth_type:
        abort(
            code=400,
            description="Error in the provider\'s configuration file: missing \"auth_type\"",
        )

    auth_type_value = auth_type.get(key="type", default=None)
    if not auth_type_value:
        abort(
            code=400,
            description="Error in the provider\'s configuration file: missing \"type\" in \"auth_type\"",
        )

    client_id = provider_config.get(key="client_id", default=None)
    if not client_id:
        abort(
            code=400,
            description="Error in the provider\'s configuration file: missing \"client_id\"",
        )

    client_secret = provider_config.get(key="client_secret", default=None)
    if not client_secret:
        abort(
            code=400,
            description="Error in the provider\'s configuration file: missing \"client_secret\"",
        )

    token_url = provider_config.get(key="token_url", default=None)
    if not token_url:
        abort(
            code=400,
            description="Error in the provider\'s configuration file: missing \"token_url\"",
        )

    token_request_headers = provider_config.get(key="token_request_headers", default=None)
    if not token_request_headers:
        abort(
            code=400,
            description="Error in the provider\'s configuration file: missing \"token_request_headers\"",
        )

    tokens = get_tokens(
        provider=provider,
        code=code,
        client_id=client_id,
        client_secret=client_secret,
        token_request_headers=token_url,
        token_request_headers=token_request_headers
    )

    params = auth_type.get(key="params", default=None)
    if not params:
        abort(
            code=400,
            description="Error in the provider\'s configuration file: missing \"params\"",
        )

    email = None
    if auth_type_value == "OIDC":
        id_token = tokens.get(key="id_token", default=None)

        if not id_token:
            abort(code=400, description="Failed to obtain ID token")

        jwks_uri = params.get(key="jwks_uri", default=None)
        if not jwks_uri:
            abort(
                code=400,
                description="Error in the provider\'s configuration file: missing \"jwks_uri\"",
            )

        algorithms = params.get(key="algorithms", default=None)
        if not algorithms:
            abort(
                code=400,
                description="Error in the provider\'s configuration file: missing \"algorithms\"",
            )

        issuer = params.get(key="issuer", default=None)
        if not issuer:
            abort(
                code=400,
                description="Error in the provider\'s configuration file: missing \"issuer\"",
            )

        email = get_email_OIDC(
            id_token=id_token,
            jwks_uri=jwks_uri,
            algorithms=algorithms,
            client_id=client_id,
            issuer=issuer
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
        user_provider = existing_user["provider"]

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


@app.route("/dashboard")
def dashboard_page():
    if "user" not in session:
        return redirect(url_for("logout"))
    return render_template("dashboard.html", user_email=session["user"])


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login_page"))


def main():
    app.run(debug=True, port=5000)


if __name__ == "__main__":
    main()
