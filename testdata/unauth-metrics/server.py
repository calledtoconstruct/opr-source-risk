from flask import Flask

app = Flask(__name__)


@app.route("/metrics")
def metrics():
    return "ok"
