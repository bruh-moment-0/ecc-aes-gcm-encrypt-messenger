from flask import Flask, request, jsonify
from datetime import datetime, timedelta, timezone

app = Flask(__name__)
messages = {}
message_counters = {}
EXPIRY_TIME = timedelta(days=1)

@app.route("/send/<message_id>", methods=["POST"])
def send_message(message_id):
    data = request.get_json()
    if not data or "data" not in data:
        return jsonify({"error": "Missing 'data' in JSON"}), 400
    sender = data.get("sender")
    receiver = data.get("receiver")
    if sender and receiver:
        pair_key = sender + receiver
        if pair_key not in message_counters:
            message_counters[pair_key] = 0
        message_counters[pair_key] += 1
        msgcount = message_counters[pair_key]
    else:
        return jsonify({"error": "Missing 'sender' or 'receiver'"}), 400
    messages[message_id] = {
        "data": data["data"],
        "timestamp": datetime.now(timezone.utc),
        "sender": sender,
        "receiver": receiver,
        "msgcount": msgcount
    }
    return jsonify({"status": "ok", "msgcount": msgcount}), 200

@app.route("/get/<message_id>", methods=["GET"])
def get_message(message_id):
    if message_id not in messages:
        return jsonify({"error": "Not found"}), 404
    entry = messages[message_id]
    now = datetime.now(timezone.utc)
    if now - entry["timestamp"] > EXPIRY_TIME:
        del messages[message_id]
        return jsonify({"error": "Message expired"}), 410
    return jsonify({"data": entry["data"], "msgcount": entry["msgcount"]}), 200

@app.route("/nextid", methods=["POST"])
def get_next_id():
    data = request.get_json()
    if not data or "sender" not in data or "receiver" not in data:
        return jsonify({"error": "Missing 'sender' or 'receiver'"}), 400
    pair_key = data["sender"] + data["receiver"]
    count = message_counters.get(pair_key, 0)
    next_id = f"{data['sender']}{data['receiver']}{count + 1}"
    return jsonify({"id": next_id}), 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
