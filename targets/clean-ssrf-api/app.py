from urllib.parse import urlparse

import requests
from flask import Flask, jsonify, request

app = Flask(__name__)
ALLOWED_HOSTS = {"api.example.com"}


@app.post("/fetch")
def fetch_url():
    url = request.args.get("url", "")
    if urlparse(url).hostname not in ALLOWED_HOSTS:
        return jsonify({"error": "host not allowed"}), 403
    response = requests.get(url, timeout=3)
    return jsonify({"body": response.text})
