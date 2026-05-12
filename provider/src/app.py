import os
import sys
from collections.abc import Callable
from typing import Any

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import secrets
from datetime import UTC, datetime, timedelta
from functools import wraps
from urllib.parse import urlparse

import jwt
from config import (
    APP_SECRET_KEY,
    ISSUER_URL,
    PERMANENT_SESSION_LIFETIME,
    PRIVATE_KEY,
)
from crypto import build_jwks, verify_pkce
from database import (
    close_database,
    create_access_token,
    create_app,
    create_auth_code,
    create_user,
    delete_auth_code,
    get_access_token,
    get_app_by_client_id,
    get_apps_by_owner,
    get_auth_code,
    get_user_by_email,
    init_database,
    update_app_secret,
)
from database import (
    delete_app as db_delete_app,
)
from flask import (
    Flask,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from werkzeug import Response
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(
    __name__,
    template_folder=os.path.join(os.path.dirname(__file__), "..", "templates"),
)
app.secret_key = APP_SECRET_KEY

init_database()

app.teardown_appcontext(close_database)

app.config["PERMANENT_SESSION_LIFETIME"] = PERMANENT_SESSION_LIFETIME
app.config["SESSION_REFRESH_EACH_REQUEST"] = True


@app.errorhandler(404)
def not_found(error: Any) -> tuple[str, int]:
    return render_template("404.html"), 404


@app.errorhandler(400)
def bad_request(error: Any) -> tuple[str, int]:
    return render_template("400.html", error=str(error)), 400


ALLOWED_HOSTS = ["localhost", "127.0.0.1"]


def login_required(function: Callable[..., Any]) -> Callable[..., Any]:
    @wraps(function)
    def decorated_function(*args, **kwargs):
        if "user_email" not in session:
            next_url = request.args.get("next", url_for("dashboard"))
            parsed = urlparse(next_url)
            if parsed.netloc and parsed.netloc not in ALLOWED_HOSTS:
                next_url = url_for("dashboard")
            return redirect(url_for("login", next=next_url))
        return function(*args, **kwargs)

    return decorated_function


@app.route("/login", methods=["GET", "POST"])
def login() -> Response:
    if request.method == "GET":
        next_url = request.args.get("next", url_for("dashboard"))
        return render_template("login_form.html", next_url=next_url)

    email = request.form.get("email")
    password = request.form.get("password")
    next_url = request.form.get("next", url_for("dashboard"))

    if not email or not password:
        flash("Заполните все поля", category="error")
        return redirect(url_for("login", next=next_url))

    user = get_user_by_email(email)

    if not user or not check_password_hash(user["password_hash"], password):
        flash("Неверный логин или пароль", category="error")
        return redirect(url_for("login", next=next_url))

    session["user_email"] = email
    return redirect(next_url)


@app.route("/logout")
def logout() -> Response:
    session.pop("user_email", None)
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required
def dashboard() -> str:
    apps = get_apps_by_owner(session["user_email"])
    return render_template("dashboard.html", email=session["user_email"], apps=apps)


@app.route("/oauth/.well-known/openid-configuration")
def openid_config() -> Response:
    return jsonify(
        {
            "issuer": ISSUER_URL,
            "authorization_endpoint": f"{ISSUER_URL}/oauth/authorize",
            "token_endpoint": f"{ISSUER_URL}/oauth/token",
            "userinfo_endpoint": f"{ISSUER_URL}/oauth/userinfo",
            "jwks_uri": f"{ISSUER_URL}/oauth/jwks.json",
            "response_types_supported": ["code"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"],
            "scopes_supported": ["openid", "profile", "email"],
        }
    )


@app.route("/oauth/authorize", methods=["GET", "POST"])
def authorize() -> tuple[Response, int] | str:
    client_id = request.args.get("client_id")
    redirect_uri = request.args.get("redirect_uri")
    scope = request.args.get("scope")
    response_type = request.args.get("response_type")
    state = request.args.get("state")
    nonce = request.args.get("nonce")
    code_challenge = request.args.get("code_challenge")
    code_challenge_method = request.args.get("code_challenge_method") or "plain"

    if not state:
        return jsonify({"error": "invalid_request"}), 400

    origin = request.headers.get("Origin")
    if origin and origin != request.host_url.rstrip("/"):
        return jsonify({"error": "invalid_request"}), 400

    ALLOWED_SCOPES = {"openid", "profile", "email"}

    if not scope:
        return jsonify({"error": "invalid_scope"}), 400

    requested_scopes = scope.split()
    if not all(s in ALLOWED_SCOPES for s in requested_scopes):
        return jsonify({"error": "invalid_scope"}), 400

    client = get_app_by_client_id(client_id)
    if client is None:
        return jsonify({"error": "invalid_client"}), 400

    client_redirect_uris = [client["redirect_uri"]]

    if redirect_uri not in client_redirect_uris:
        return jsonify({"error": "invalid_redirect_uri"}), 400

    if response_type != "code":
        return jsonify({"error": "unsupported_response_type"}), 400

    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        user = get_user_by_email(email)

        if user and check_password_hash(user["password_hash"], password):
            code = secrets.token_hex(32)
            create_auth_code(
                code,
                client_id,
                user["user_id"],
                email,
                (datetime.now(UTC) + timedelta(minutes=10)).isoformat(),
                nonce,
                code_challenge,
                code_challenge_method,
                scope,
            )

            callback_url = f"{redirect_uri}?code={code}"
            if state:
                callback_url += f"&state={state}"
            return redirect(callback_url)
        else:
            return jsonify({"error": "invalid_credentials"}), 401

    return render_template("login_form.html")


@app.route("/oauth/token", methods=["POST"])
def token() -> tuple[Response, int] | Response:
    grant_type = request.form.get("grant_type")
    code = request.form.get("code")
    client_id = request.form.get("client_id")
    client_secret = request.form.get("client_secret")
    redirect_uri = request.form.get("redirect_uri")
    code_verifier = request.form.get("code_verifier")

    if grant_type != "authorization_code":
        return jsonify({"error": "unsupported_grant_type"}), 400

    client = get_app_by_client_id(client_id)
    if not client or client["client_secret"] != client_secret:
        return jsonify({"error": "invalid_client"}), 401

    db_code = get_auth_code(code)
    if not db_code:
        return jsonify({"error": "invalid_grant"}), 400

    expires_at = datetime.fromisoformat(db_code["expires_at"])
    if expires_at < datetime.now(UTC):
        delete_auth_code(code)
        return jsonify({"error": "invalid_grant"}), 400

    if db_code["client_id"] != client_id or client["redirect_uri"] != redirect_uri:
        return jsonify({"error": "invalid_grant"}), 400

    if db_code.get("code_challenge"):
        if not code_verifier:
            return jsonify({"error": "invalid_grant"}), 400
        if not verify_pkce(
            code_verifier,
            db_code["code_challenge"],
            db_code["code_challenge_method"],
        ):
            return jsonify({"error": "invalid_grant"}), 400

    nonce = db_code["nonce"]
    user_email = db_code["email"]
    user_sub = db_code["user_id"]
    auth_scope = db_code.get("scope", "")
    scope_list = auth_scope.split() if auth_scope else []

    delete_auth_code(code)

    access_token = secrets.token_hex(32)

    now = datetime.now(UTC)

    if "openid" in scope_list:
        id_token_payload = {
            "iss": ISSUER_URL,
            "sub": user_sub,
            "aud": client_id,
            "exp": now + timedelta(hours=1),
            "iat": now,
            "auth_time": int(now.timestamp()),
            "email": user_email,
        }
        if nonce:
            id_token_payload["nonce"] = nonce

        id_token = jwt.encode(
            id_token_payload, PRIVATE_KEY, algorithm="RS256", headers={"kid": "default"}
        )

    create_access_token(
        access_token,
        user_sub,
        user_email,
        auth_scope,
        (now + timedelta(hours=1)).isoformat(),
    )

    response = {
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": 3600,
        "scope": auth_scope,
    }
    if "openid" in scope_list:
        response["id_token"] = id_token

    return jsonify(response)


@app.route("/oauth/userinfo")
def userinfo() -> tuple[Response, int] | Response:
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return jsonify({"error": "unauthorized"}), 401

    token = auth_header.split(" ")[1]

    token_data = get_access_token(token)
    if not token_data:
        return jsonify({"error": "invalid_token"}), 401

    token_expires = datetime.fromisoformat(token_data["expires_at"])
    if token_expires < datetime.now(UTC):
        return jsonify({"error": "invalid_token"}), 401

    scope_list = token_data.get("scope", "").split() if token_data.get("scope") else []

    result = {}
    if "openid" in scope_list or "profile" in scope_list:
        result["sub"] = token_data["user_id"]
    if "email" in scope_list:
        result["email"] = token_data["email"]
        result["email_verified"] = True

    if not result:
        return jsonify({"error": "insufficient_scope"}), 403

    return jsonify(result)


@app.route("/register/user", methods=["GET", "POST"])
def register_user() -> str | tuple[Response, int] | Response:
    if request.method == "GET":
        return render_template("register_user.html")

    if request.is_json:
        data = request.get_json()
        if not data or not data.get("email") or not data.get("password"):
            return jsonify({"error": "missing_email_or_password"}), 400
        email = data["email"]
        password = data["password"]
    else:
        email = request.form.get("email")
        password = request.form.get("password")
        if not email or not password:
            flash("Заполните все поля", category="warning")
            return redirect(url_for("register_user"))

    user = get_user_by_email(email)
    if user:
        if request.is_json:
            return jsonify({"error": "user_already_exists"}), 400

        flash("Пользователь уже существует", category="error")
        return redirect(url_for("register_user"))

    password_hash = generate_password_hash(password)

    create_user(email, password_hash)

    if request.is_json:
        return jsonify({"email": email}), 201

    flash("Аккаунт успешно создан", category="success")
    return redirect(url_for("login"))


@app.route("/register/app", methods=["GET", "POST"])
@login_required
def register_app() -> str | tuple[Response, int] | Response:
    if request.method == "GET":
        return render_template("register_app_form.html", next=url_for("login"))

    if request.is_json:
        data = request.get_json()
        if not data or not data.get("redirect_uri"):
            return jsonify({"error": "missing_redirect_uri"}), 400
        redirect_uri = data["redirect_uri"]
    else:
        redirect_uri = request.form.get("redirect_uri")
        if not redirect_uri:
            flash("Укажите Redirect URI", category="warning")
            return redirect(url_for("register_app"))

    client_id = secrets.token_hex(16)
    client_secret = secrets.token_hex(32)
    name = (
        request.form.get("name") if not request.is_json else data.get("name", "My app")
    )
    owner_email = session["user_email"]

    create_app(client_id, client_secret, name, redirect_uri, owner_email)

    if request.is_json:
        return jsonify(
            {
                "client_id": client_id,
                "client_secret": client_secret,
                "redirect_uri": redirect_uri,
            }
        ), 201

    return render_template(
        "register_app_result.html",
        client_id=client_id,
        client_secret=client_secret,
        redirect_uri=redirect_uri,
    )


@app.route("/app/<client_id>/delete", methods=["POST"])
@login_required
def delete_app(client_id: str) -> Response:
    db_delete_app(client_id, session["user_email"])

    return redirect(url_for("dashboard"))


@app.route("/app/<client_id>/regenerate", methods=["POST"])
@login_required
def regenerate_secret(client_id: str) -> str:
    new_secret = secrets.token_hex(32)
    update_app_secret(client_id, new_secret, session["user_email"])

    app = get_app_by_client_id(client_id)

    return render_template(
        "register_app_result.html",
        client_id=client_id,
        client_secret=new_secret,
        redirect_uri=app["redirect_uri"] if app else "",
    )


def jwks() -> Response:
    return jsonify(build_jwks(PRIVATE_KEY))


app.add_url_rule("/oauth/jwks.json", "jwks", jwks)


if __name__ == "__main__":
    app.run(port=5001)
