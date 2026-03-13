from flask import Flask, request, render_template, session, redirect, url_for, flash

from config import CONFIGS, PERMANENT_SESSION_LIFETIME, APP_SECRET_KEY
from database import init_database, close_database, get_database
from auth import verify_user, register_user
from oauth import build_auth_url, get_tokens, get_email_oidc, get_email_oauth2


app = Flask(__name__)
app.secret_key = APP_SECRET_KEY

init_database()
app.teardown_appcontext(close_database)

app.config["PERMANENT_SESSION_LIFETIME"] = PERMANENT_SESSION_LIFETIME
app.config["SESSION_REFRESH_EACH_REQUEST"] = True


@app.route("/login", methods=["GET", "POST"])
def login_page():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        verify = verify_user(email, password)

        if isinstance(verify, str):
            flash(f"Войдите через {CONFIGS[verify]['name']}", "info")
            return redirect(url_for("login_page"))
        elif verify:
            session["user"] = email
            session.permanent = True
            return redirect(url_for("dashboard_page"))
        else:
            flash("Неверный email или пароль", "error")
            return redirect(url_for("login_page"))

    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register_page():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        registration = register_user(email, password)

        if isinstance(registration, str):
            flash(f"Войдите через {CONFIGS[registration]['name']}", "info")
            return redirect(url_for("login_page"))
        elif registration:
            flash("Регистрация прошла успешно. Войдите в аккаунт", "success")
            return redirect(url_for("login_page"))
        else:
            flash("У Вас уже есть аккаунт. Войдите при помощи пароля", "error")
            return redirect(url_for("login_page"))

    return render_template("register.html")


@app.route("/")
def home_page():
    if "user" in session:
        return redirect(url_for("dashboard_page"))

    session.clear()
    return redirect(url_for("login_page"))


@app.errorhandler(404)
def page_not_found(error):
    return render_template("404.html")


@app.errorhandler(400)
def bad_request(error):
    return render_template("400.html", error=error)


@app.route("/login/<provider>")
def login_provider(provider):
    if provider not in CONFIGS:
        return "Provider not supported", 400

    auth_url = build_auth_url(provider)

    return redirect(auth_url)


@app.route("/callback/<provider>")
def callback(provider):
    if provider not in CONFIGS:
        return "Provider not supported", 400

    if request.args.get("state") != session.get("oauth_state"):
        return "Invalid state", 400

    code = request.args.get("code")
    if not code:
        return "No code received", 400

    tokens = get_tokens(provider, code)

    email = None
    if provider in ("google", "my_service"):
        if not tokens.get("id_token"):
            return "Failed to obtain tokens", 400
        email = get_email_oidc(provider, tokens["id_token"])
    else:
        if not tokens.get("access_token"):
            return "Failed to obtain tokens", 400
        email = get_email_oauth2(provider, tokens["access_token"])

    if not email:
        return "Failed to obtain email", 400

    database = get_database()
    cursor = database.cursor()

    cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
    existing_user = cursor.fetchone()

    if existing_user:
        user_provider = existing_user["provider"]

        if not user_provider:
            flash("У Вас уже есть аккаунт. Войдите при помощи пароля", "error")
        elif user_provider and user_provider != provider:
            flash(f"Войдите через {CONFIGS[user_provider]['name']}", "error")
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
