from flask import Flask, request, jsonify
from datetime import datetime, timedelta, timezone
import os, hashlib, base64

app = Flask(__name__)

users = {}
messages = {}
message_counters = {}

EXPIRY_TIME = timedelta(days=1)

def hash_password(password: str, salt: bytes):
    return hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100_000)

def verify_password(stored_hash, salt, password_attempt):
    return stored_hash == hash_password(password_attempt, salt)

def get_user_publickey(username):
    user = users.get(username)
    return user["publickey"] if user else None

def pair_key(sender_pk, receiver_pk):
    return sender_pk + receiver_pk

@app.route("/transfer/post/<message_id>", methods=["POST"])
def send_message(message_id):
    data = request.get_json()
    if not data or "data" not in data or "sender" not in data or "receiver" not in data:
        return jsonify({"error": "Missing 'data', 'sender' or 'receiver'"}), 400
    sender_username = data["sender"]
    receiver_username = data["receiver"]
    sender_pk = get_user_publickey(sender_username)
    receiver_pk = get_user_publickey(receiver_username)
    if not sender_pk or not receiver_pk:
        return jsonify({"error": "Sender or receiver username not found"}), 404
    key = pair_key(sender_pk, receiver_pk)
    message_counters[key] = message_counters.get(key, 0) + 1
    msgcount = message_counters[key]
    messages[message_id] = {
        "data": data["data"],
        "timestamp": datetime.now(timezone.utc),
        "sender": sender_username,
        "receiver": receiver_username,
        "msgcount": msgcount
    }
    return jsonify({"status": "ok", "msgcount": msgcount}), 200

@app.route("/transfer/get/<message_id>", methods=["GET"])
def get_message(message_id):
    if message_id not in messages:
        return jsonify({"error": "Not found"}), 404
    entry = messages[message_id]
    if datetime.now(timezone.utc) - entry["timestamp"] > EXPIRY_TIME:
        del messages[message_id]
        return jsonify({"error": "Message expired"}), 410
    return jsonify({"data": entry["data"], "msgcount": entry["msgcount"]}), 200

@app.route("/transfer/nextid", methods=["POST"])
def get_next_id():
    data = request.get_json()
    if not data or "sender" not in data or "receiver" not in data:
        return jsonify({"error": "Missing 'sender' or 'receiver'"}), 400
    sender_username = data["sender"]
    receiver_username = data["receiver"]
    sender_pk = get_user_publickey(sender_username)
    receiver_pk = get_user_publickey(receiver_username)
    if not sender_pk or not receiver_pk:
        return jsonify({"error": "Sender or receiver username not found"}), 404
    key = pair_key(sender_pk, receiver_pk)
    count = message_counters.get(key, 0)
    next_id = f"{sender_pk}{receiver_pk}{count + 1}"
    return jsonify({"id": next_id}), 200

@app.route("/user/create", methods=["POST"])
def user_create():
    data = request.get_json()
    if not data or "username" not in data or "publickey" not in data or "password" not in data:
        return jsonify({"error": "Missing 'username', 'publickey' or 'password'"}), 400
    username = data["username"]
    if username in users:
        return jsonify({"error": "User already exists"}), 409
    salt = os.urandom(16)
    pass_hash = hash_password(data["password"], salt)
    users[username] = {
        "publickey": data["publickey"],
        "created_at": datetime.now(timezone.utc).isoformat(),
        "salt": base64.b64encode(salt).decode(),
        "pass_hash": base64.b64encode(pass_hash).decode()
    }
    return jsonify({"status": "user created"}), 201

@app.route("/user/get", methods=["POST"])
def user_get():
    data = request.get_json()
    if not data or "username" not in data:
        return jsonify({"error": "Missing 'username'"}), 400
    username = data["username"]
    user = users.get(username)
    if not user:
        return jsonify({"error": "User not found"}), 404
    return jsonify({
        "username": username,
        "publickey": user["publickey"],
        "created_at": user["created_at"]
    }), 200

@app.route("/user/change", methods=["POST"])
def user_change():
    data = request.get_json()
    if not data or "username" not in data or "password" not in data or "new_publickey" not in data:
        return jsonify({"error": "Missing required fields"}), 400
    username = data["username"]
    user = users.get(username)
    if not user:
        return jsonify({"error": "User not found"}), 404
    salt = base64.b64decode(user["salt"])
    stored_hash = base64.b64decode(user["pass_hash"])
    if not verify_password(stored_hash, salt, data["password"]):
        return jsonify({"error": "Invalid password"}), 403
    user["publickey"] = data["new_publickey"]
    return jsonify({"status": "publickey updated"}), 200

@app.route("/user/remove", methods=["POST"])
def user_remove():
    data = request.get_json()
    if not data or "username" not in data or "password" not in data:
        return jsonify({"error": "Missing 'username' or 'password'"}), 400
    username = data["username"]
    user = users.get(username)
    if not user:
        return jsonify({"error": "User not found"}), 404
    salt = base64.b64decode(user["salt"])
    stored_hash = base64.b64decode(user["pass_hash"])
    if not verify_password(stored_hash, salt, data["password"]):
        return jsonify({"error": "Invalid password"}), 403
    del users[username]
    return jsonify({"status": "user removed"}), 200

@app.route("/")
def index():
    return send_from_directory("static", "index.html")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
