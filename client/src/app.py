import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

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
from functools import wraps
from typing import Any

from config import CONFIGS, PERMANENT_SESSION_LIFETIME, APP_SECRET_KEY
from database import (
    init_database,
    close_database,
    get_user_by_email,
    create_user,
)
from auth import verify_user, register_user
from oauth import build_auth_url, get_tokens, get_email_OAuth2, get_email_OIDC
from utils import build_headers, validate_configs


validate_configs(CONFIGS)

app = Flask(__name__)
app.secret_key = APP_SECRET_KEY

init_database()

app.teardown_appcontext(close_database)

app.config["PERMANENT_SESSION_LIFETIME"] = PERMANENT_SESSION_LIFETIME
app.config["SESSION_REFRESH_EACH_REQUEST"] = True


def login_required(function):
    @wraps(function)
    def decorated_function(*args, **kwargs):
        if "user_email" not in session:
            return redirect(url_for("login", next=url_for("dashboard")))
        return function(*args, **kwargs)

    return decorated_function


@app.route(rule="/login", methods=["GET", "POST"])
def login():
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


@app.route(rule="/register", methods=["GET", "POST"])
def register():
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


@app.route(rule="/")
def home():
    if "user_email" in session:
        return redirect(url_for("dashboard"))

    session.clear()
    return redirect(url_for("login"))


@app.errorhandler(code_or_exception=404)
def page_not_found(error: Any):
    return render_template("404.html"), 404


@app.errorhandler(code_or_exception=400)
def bad_request(error: Any):
    return render_template("400.html", error=error.description), 400


@app.route(rule="/login/<provider>")
def login_provider(provider: str):
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


@app.route(rule="/callback/<provider>")
def callback(provider: str):
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


@app.route(rule="/dashboard")
def dashboard():
    if "user_email" not in session:
        return redirect(url_for("logout"))
    return render_template("dashboard.html", user_email=session["user_email"])


@app.route(rule="/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


def main() -> None:
    app.run(port=5000, debug=True)


if __name__ == "__main__":
    main()
