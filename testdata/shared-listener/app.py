from flask import Flask

app = Flask(__name__)


@app.route("/")
def index():
    return "ok"


@app.route("/admin")
def admin():
    return "admin"
