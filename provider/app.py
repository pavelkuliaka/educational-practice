from flask import Flask


from config import APP_SECRET_KEY, PERMANENT_SESSION_LIFETIME
from database import init_database, close_database

app = Flask(__name__)
app.secret_key = APP_SECRET_KEY

init_database()

app.teardown_appcontext(close_database)

app.config["PERMANENT_SESSION_LIFETIME"] = PERMANENT_SESSION_LIFETIME
app.config["SESSION_REFRESH_EACH_REQUEST"] = True

app.route("oauth/authorize", methods=["POST"])
def authorize():
    pass

app.route("oauth/token", methods=["POST", "GET"])
def handle_token_exchange():
    pass

app.route("oauth/user_info", methods=["POST", "GET"])
def handle_token_exchange():
    pass

def main() -> None:
    app.run(port=5001, debug=True)

if __name__ == "__main__":
    main()
