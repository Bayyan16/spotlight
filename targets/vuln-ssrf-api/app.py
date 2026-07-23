import requests
from flask import Flask, jsonify, request

app = Flask(__name__)


@app.post("/fetch")
def fetch_url():
    url = request.args.get("url", "")
    response = requests.get(url, timeout=3)
    return jsonify({"body": response.text})
