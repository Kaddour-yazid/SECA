# pc1_server.py
from flask import Flask, request, jsonify
import csv
from datetime import datetime

app = Flask(__name__)
LOG_FILE = "url_logs.csv"

# Crée le fichier avec header si inexistant
try:
    with open(LOG_FILE, "x", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["timestamp", "pc_name", "url"])
except FileExistsError:
    pass

@app.route("/log", methods=["POST"])
def log_url():
    data = request.json
    timestamp = data.get("timestamp", str(datetime.now()))
    pc_name = data.get("pc_name", "unknown")
    url = data.get("url", "")
    # Sauvegarde dans CSV
    with open(LOG_FILE, "a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([timestamp, pc_name, url])
    return jsonify({"status": "ok"})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)  # écoute sur tout le réseau
