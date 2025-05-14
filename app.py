from flask import Flask, request, jsonify
from datetime import datetime, timedelta
app = Flask(__name__)
messages = {}
EXPIRY_TIME = timedelta(days=1)
@app.route("/send/<message_id>", methods=["POST"])
def send_message(message_id):
    data = request.get_json()
    if not data or "data" not in data:
        return jsonify({"error": "Missing 'data' in JSON"}), 400
    messages[message_id] = {
        "data": data["data"],
        "timestamp": datetime.utcnow()
    }
    return jsonify({"status": "ok"}), 200
@app.route("/get/<message_id>", methods=["GET"])
def get_message(message_id):
    if message_id not in messages:
        return jsonify({"error": "Not found"}), 404
    entry = messages[message_id]
    now = datetime.utcnow()
    if now - entry["timestamp"] > EXPIRY_TIME:
        del messages[message_id]
        return jsonify({"error": "Message expired"}), 410
    return jsonify({"data": entry["data"]}), 200
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
