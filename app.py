from flask import Flask, request, jsonify

app = Flask(__name__)
messages = {}

@app.route("/send/<message_id>", methods=["POST"])
def send_message(message_id):
    data = request.get_json()
    if not data or "message" not in data:
        return jsonify({"error": "Missing 'message' in JSON"}), 400
    messages[message_id] = data["message"]
    return jsonify({"status": "ok"}), 200

@app.route("/get/<message_id>", methods=["GET"])
def get_message(message_id):
    if message_id not in messages:
        return jsonify({"error": "Not found"}), 404
    return jsonify({"message": messages[message_id]}), 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
