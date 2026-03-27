import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import (
    Flask,
    jsonify,
    request,
    redirect,
    render_template,
    session,
    url_for,
    flash,
)
import base64
import secrets
from datetime import datetime, timedelta
import jwt
from functools import wraps
from werkzeug.security import check_password_hash, generate_password_hash

from config import (
    APP_SECRET_KEY,
    ISSUER_URL,
    PERMANENT_SESSION_LIFETIME,
    PRIVATE_KEY,
)
from database import (
    init_database,
    close_database,
    get_user_by_email,
    create_user,
    get_app_by_client_id,
    create_app,
    delete_app as db_delete_app,
    update_app_secret,
    get_apps_by_owner,
    create_auth_code,
    get_auth_code,
    delete_auth_code,
    create_access_token,
    get_access_token,
)


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
def not_found(error):
    return render_template("404.html"), 404


@app.errorhandler(400)
def bad_request(error):
    return render_template("400.html", error=str(error)), 400


def login_required(function):
    @wraps(function)
    def decorated_function(*args, **kwargs):
        if "user_email" not in session:
            return redirect(url_for("login", next=url_for("dashboard")))
        return function(*args, **kwargs)

    return decorated_function


@app.route("/login", methods=["GET", "POST"])
def login():
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

    if not user:
        flash("Аккаунта с таким email нет", category="error")
        return redirect(url_for("login", next=next_url))

    if not check_password_hash(user["password_hash"], password):
        flash("Неверный логин или пароль", category="error")
        return redirect(url_for("login", next=next_url))

    session["user_email"] = email
    return redirect(next_url)


@app.route("/logout")
def logout():
    session.pop("user_email", None)
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required
def dashboard():
    apps = get_apps_by_owner(session["user_email"])
    return render_template("dashboard.html", email=session["user_email"], apps=apps)


@app.route("/oauth/.well-known/openid-configuration")
def openid_config():
    return jsonify(
        {
            "issuer": ISSUER_URL,
            "authorization_endpoint": f"{ISSUER_URL}/oauth/authorize",
            "token_endpoint": f"{ISSUER_URL}/oauth/token",
            "userinfo_endpoint": f"{ISSUER_URL}/oauth/userinfo",
            "jwks_uri": f"{ISSUER_URL}/oauth/jwks.json",
            "response_types_supported": ["code"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["HS256"],
        }
    )


@app.route("/oauth/authorize", methods=["GET", "POST"])
def authorize():
    client_id = request.args.get("client_id")
    redirect_uri = request.args.get("redirect_uri")
    scope = request.args.get("scope")
    response_type = request.args.get("response_type")
    state = request.args.get("state")
    nonce = request.args.get("nonce")

    if not scope or "openid" not in scope.split():
        return jsonify({"error": "invalid_scope"}), 400

    client = get_app_by_client_id(client_id)
    if not client_id or client is None:
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
                email,
                (datetime.now() + timedelta(minutes=10)).isoformat(),
                nonce,
            )

            callback_url = f"{redirect_uri}?code={code}"
            if state:
                callback_url += f"&state={state}"
            return redirect(callback_url)
        else:
            return "Invalid credentials", 401

    return render_template("login_form.html")


@app.route("/oauth/token", methods=["POST"])
def token():
    grant_type = request.form.get("grant_type")
    code = request.form.get("code")
    client_id = request.form.get("client_id")
    client_secret = request.form.get("client_secret")
    redirect_uri = request.form.get("redirect_uri")

    if grant_type != "authorization_code":
        return jsonify({"error": "unsupported_grant_type"}), 400

    client = get_app_by_client_id(client_id)
    if not client or client["client_secret"] != client_secret:
        return jsonify({"error": "invalid_client"}), 401

    db_code = get_auth_code(code)
    if not db_code:
        return jsonify({"error": "invalid_grant"}), 400

    expires_at = datetime.fromisoformat(db_code["expires_at"])
    if expires_at < datetime.now():
        delete_auth_code(code)
        return jsonify({"error": "invalid_grant"}), 400

    if db_code["client_id"] != client_id or client["redirect_uri"] != redirect_uri:
        return jsonify({"error": "invalid_grant"}), 400

    nonce = db_code["nonce"]
    user_email = db_code["email"]
    user_sub = user_email

    delete_auth_code(code)

    access_token = secrets.token_hex(32)

    now = datetime.now()
    id_token_payload = {
        "iss": ISSUER_URL,
        "sub": user_sub,
        "aud": client_id,
        "exp": now + timedelta(hours=1),
        "iat": now,
        "email": user_email,
    }
    if nonce:
        id_token_payload["nonce"] = nonce

    id_token = jwt.encode(
        id_token_payload, PRIVATE_KEY, algorithm="RS256", headers={"kid": "default"}
    )

    create_access_token(
        access_token, user_email, (now + timedelta(hours=1)).isoformat()
    )

    return jsonify(
        {
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": 3600,
            "id_token": id_token,
        }
    )


@app.route("/oauth/userinfo")
def userinfo():
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return jsonify({"error": "unauthorized"}), 401

    token = auth_header.split(" ")[1]

    token_data = get_access_token(token)
    if not token_data:
        return jsonify({"error": "invalid_token"}), 401

    token_expires = datetime.fromisoformat(token_data["expires_at"])
    if token_expires < datetime.now():
        return jsonify({"error": "invalid_token"}), 401

    user_email = token_data["email"]

    return jsonify({"sub": user_email, "email": user_email, "email_verified": True})


@app.route("/register/user", methods=["GET", "POST"])
def register_user():
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
def register_app():
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
def delete_app(client_id):
    db_delete_app(client_id, session["user_email"])

    return redirect(url_for("dashboard"))


@app.route("/app/<client_id>/regenerate", methods=["POST"])
@login_required
def regenerate_secret(client_id):
    new_secret = secrets.token_hex(32)
    update_app_secret(client_id, new_secret, session["user_email"])

    app = get_app_by_client_id(client_id)

    return render_template(
        "register_app_result.html",
        client_id=client_id,
        client_secret=new_secret,
        redirect_uri=app["redirect_uri"] if app else "",
    )


def jwks():

    public_key = PRIVATE_KEY.public_key()

    n = public_key.public_numbers().n
    e = public_key.public_numbers().e

    def int_to_base64url(i):
        byte_length = (i.bit_length() + 7) // 8
        return (
            base64.urlsafe_b64encode(i.to_bytes(byte_length, "big"))
            .rstrip(b"=")
            .decode("utf-8")
        )

    return jsonify(
        {
            "keys": [
                {
                    "kid": "default",
                    "kty": "RSA",
                    "use": "sig",
                    "alg": "RS256",
                    "n": int_to_base64url(n),
                    "e": int_to_base64url(e),
                }
            ]
        }
    )


app.add_url_rule("/oauth/jwks.json", "jwks", jwks)


if __name__ == "__main__":
    app.run(debug=True, port=5001)
