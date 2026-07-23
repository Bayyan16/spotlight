"""CMDI reproduction fixture. Never run outside Spotlight's sandbox."""
import subprocess

from flask import Flask, jsonify, request

app = Flask(__name__)


@app.post("/run")
def run_command():
    command = request.args.get("command", "")
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    return jsonify({"stdout": result.stdout})
