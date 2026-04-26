import os
import sys
from collections.abc import Callable
from typing import Any

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from functools import wraps

from auth import register_user, verify_user
from config import APP_SECRET_KEY, CONFIGS, PERMANENT_SESSION_LIFETIME
from database import (
    close_database,
    create_user,
    get_user_by_email,
    init_database,
)
from flask import (
    Flask,
    abort,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from oauth import build_auth_url, get_email_OAuth2, get_email_OIDC, get_tokens
from utils import build_headers, validate_configs
from werkzeug import Response

validate_configs(CONFIGS)

app = Flask(
    __name__,
    template_folder=os.path.join(os.path.dirname(__file__), "..", "templates"),
    static_folder=os.path.join(os.path.dirname(__file__), "..", "static"),
)
app.secret_key = APP_SECRET_KEY

init_database()

app.teardown_appcontext(close_database)

app.config["PERMANENT_SESSION_LIFETIME"] = PERMANENT_SESSION_LIFETIME
app.config["SESSION_REFRESH_EACH_REQUEST"] = True


def login_required(function: Callable[..., Any]) -> Callable[..., Any]:
    @wraps(function)
    def decorated_function(*args: Any, **kwargs: Any) -> Response:
        if "user_email" not in session:
            return redirect(url_for("login", next=url_for("dashboard")))
        return function(*args, **kwargs)

    return decorated_function


@app.route("/login", methods=["GET", "POST"])
def login() -> Response:
    if "user_email" in session:
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        verify = verify_user(email, password)

        if isinstance(verify, str):
            flash(f"Войдите через {CONFIGS[verify]['name']}", "info")
            return redirect(url_for("login"))
        elif verify:
            session["user_email"] = email
            session.permanent = True
            return redirect(url_for("dashboard"))
        else:
            flash("Неверный email или пароль", "error")
            return redirect(url_for("login"))

    providers = [
        {"id": key, "name": CONFIGS[key].get("name"), "icon": CONFIGS[key].get("icon")}
        for key in CONFIGS
    ]
    return render_template("login.html", providers=providers)


@app.route("/register", methods=["GET", "POST"])
def register() -> Response:
    if "user_email" in session:
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        registration = register_user(email, password)

        if isinstance(registration, str):
            flash(f"Войдите через {CONFIGS[registration]['name']}", "info")
            return redirect(url_for("login"))
        elif registration:
            flash("Регистрация прошла успешно. Войдите в аккаунт", "success")
            return redirect(url_for("login"))
        else:
            flash("У Вас уже есть аккаунт. Войдите при помощи пароля", "error")
            return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/")
def home() -> Response:
    if "user_email" in session:
        return redirect(url_for("dashboard"))

    session.clear()
    return redirect(url_for("login"))


@app.errorhandler(404)
def page_not_found(error: Any) -> tuple[str, int]:
    return render_template("404.html"), 404


@app.errorhandler(400)
def bad_request(error: Any) -> tuple[str, int]:
    return render_template("400.html", error=str(error)), 400


@app.route("/login/<provider>")
def login_provider(provider: str) -> Response:
    if provider not in CONFIGS:
        abort(404, description="Provider not found")

    config = CONFIGS[provider]
    auth_type = config["auth_type"]

    return redirect(
        build_auth_url(
            provider,
            config["client_id"],
            config["scope"],
            auth_type["type"],
            config["auth_url"],
        )
    )


@app.route("/callback/<provider>")
def callback(provider: str) -> Response:
    if provider not in CONFIGS:
        abort(404, description="Provider not found")

    if request.args.get("state") != session.get("oauth2_state"):
        session.pop("oauth2_state")
        abort(400, description="Invalid state")

    session.pop("oauth2_state")

    code = request.args.get("code")
    if not code:
        abort(400, description="No code received")

    provider_config = CONFIGS[provider]
    client_id = provider_config["client_id"]
    client_secret = provider_config["client_secret"]
    token_url = provider_config["token_url"]
    token_request_headers = provider_config["token_request_headers"]

    tokens = get_tokens(
        provider,
        code,
        client_id,
        client_secret,
        token_url,
        token_request_headers,
    )

    auth_type = provider_config["auth_type"]
    auth_type_value = auth_type["type"]
    params = auth_type["params"]

    email = ""
    if auth_type_value == "OIDC":
        id_token = tokens.get("id_token")

        if not id_token:
            abort(400, description="Failed to obtain ID token")

        email = get_email_OIDC(
            id_token,
            params["jwks_uri"],
            params["algorithms"],
            client_id,
            params["issuer"],
        )
    elif auth_type_value == "OAuth2":
        access_token = tokens.get("access_token")
        if not access_token:
            abort(400, description="Failed to obtain access token")

        email_request_headers = build_headers(
            params["email_request_headers"], access_token=access_token
        )

        email = get_email_OAuth2(params["user_info_url"], email_request_headers)
    else:
        abort(400, description="Authorization method is not supported")

    if not email:
        abort(400, description="Failed to obtain email")

    existing_user = get_user_by_email(email)

    if existing_user:
        user_provider = existing_user["provider"]

        if not user_provider:
            flash("У Вас уже есть аккаунт. Войдите при помощи пароля", "error")
            return redirect(url_for("login"))
        elif user_provider and user_provider != provider:
            user_provider_name = CONFIGS[user_provider]["name"]

            flash(f"Войдите через {user_provider_name}", "error")
            return redirect(url_for("login"))
        else:
            session["user_email"] = email
            session.permanent = True

            return redirect(url_for("dashboard"))

    create_user(email, None, provider)

    session["user_email"] = email
    session.permanent = True

    flash("Вы успешно вошли", "success")
    return redirect(url_for("dashboard"))


@app.route("/dashboard")
@login_required
def dashboard() -> str:
    return render_template("dashboard.html", user_email=session["user_email"])


@app.route("/logout")
def logout() -> Response:
    session.clear()
    return redirect(url_for("login"))


def main() -> None:
    app.run(port=5000, debug=True)


if __name__ == "__main__":
    main()
