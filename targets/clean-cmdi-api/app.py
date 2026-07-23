import subprocess

from flask import Flask, jsonify, request

app = Flask(__name__)
ALLOWED = {"date": ["date"], "uptime": ["uptime"]}


@app.post("/run")
def run_command():
    command_name = request.args.get("command", "")
    argv = ALLOWED.get(command_name)
    if argv is None:
        return jsonify({"error": "command not allowed"}), 400
    result = subprocess.run(argv, shell=False, capture_output=True, text=True)
    return jsonify({"stdout": result.stdout})
