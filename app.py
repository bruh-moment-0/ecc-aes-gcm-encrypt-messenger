from flask import Flask, request, jsonify, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta, timezone
import os, hashlib, base64

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL", "sqlite:///app.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)

EXPIRY_TIME = timedelta(days=1)

class User(db.Model):
    username = db.Column(db.String, primary_key=True)
    publickey = db.Column(db.String, nullable=False)
    salt = db.Column(db.String, nullable=False)
    pass_hash = db.Column(db.String, nullable=False)
    created_at = db.Column(db.String, nullable=False)

class Message(db.Model):
    message_id = db.Column(db.String, primary_key=True)
    data = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False)
    sender = db.Column(db.String, nullable=False)
    receiver = db.Column(db.String, nullable=False)
    msgcount = db.Column(db.Integer, nullable=False)

def hash_password(password, salt):
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100_000)

def verify_password(stored_hash, salt, attempt):
    return stored_hash == hash_password(attempt, salt)

def get_user_publickey(username):
    user = User.query.filter_by(username=username).first()
    return user.publickey if user else None

def pair_key(sender_pk, receiver_pk):
    return sender_pk + receiver_pk

def get_msgcount(sender_pk, receiver_pk):
    return Message.query.filter_by(sender=sender_pk, receiver=receiver_pk).count()

@app.route("/transfer/post/<message_id>", methods=["POST"])
def send_message(message_id):
    data = request.get_json()
    if not data or "data" not in data or "sender" not in data or "receiver" not in data:
        return jsonify({"error": "Missing fields"}), 400

    sender = data["sender"]
    receiver = data["receiver"]
    sender_pk = get_user_publickey(sender)
    receiver_pk = get_user_publickey(receiver)

    if not sender_pk or not receiver_pk:
        return jsonify({"error": "Invalid usernames"}), 404

    msgcount = get_msgcount(sender_pk, receiver_pk) + 1
    msg = Message(
        message_id=message_id,
        data=data["data"],
        timestamp=datetime.now(timezone.utc),
        sender=sender,
        receiver=receiver,
        msgcount=msgcount
    )

    db.session.add(msg)
    db.session.commit()
    return jsonify({"status": "ok", "msgcount": msgcount}), 200

@app.route("/transfer/get/<message_id>", methods=["GET"])
def get_message(message_id):
    msg = Message.query.get(message_id)
    if not msg:
        return jsonify({"error": "Not found"}), 404

    if datetime.now(timezone.utc) - msg.timestamp > EXPIRY_TIME:
        db.session.delete(msg)
        db.session.commit()
        return jsonify({"error": "Expired"}), 410

    return jsonify({"data": msg.data, "msgcount": msg.msgcount}), 200

@app.route("/transfer/nextid", methods=["POST"])
def get_next_id():
    data = request.get_json()
    if not data or "sender" not in data or "receiver" not in data:
        return jsonify({"error": "Missing fields"}), 400

    sender_pk = get_user_publickey(data["sender"])
    receiver_pk = get_user_publickey(data["receiver"])

    if not sender_pk or not receiver_pk:
        return jsonify({"error": "Invalid usernames"}), 404

    count = get_msgcount(sender_pk, receiver_pk)
    return jsonify({"id": f"{sender_pk}{receiver_pk}{count+1}"}), 200

@app.route("/user/create", methods=["POST"])
def user_create():
    data = request.get_json()
    if not data or "username" not in data or "publickey" not in data or "password" not in data:
        return jsonify({"error": "Missing fields"}), 400

    if User.query.get(data["username"]):
        return jsonify({"error": "User exists"}), 409

    salt = os.urandom(16)
    hash_ = hash_password(data["password"], salt)
    user = User(
        username=data["username"],
        publickey=data["publickey"],
        salt=base64.b64encode(salt).decode(),
        pass_hash=base64.b64encode(hash_).decode(),
        created_at=datetime.now(timezone.utc).isoformat()
    )

    db.session.add(user)
    db.session.commit()
    return jsonify({"status": "user created"}), 201

@app.route("/user/get", methods=["POST"])
def user_get():
    data = request.get_json()
    if not data or "username" not in data:
        return jsonify({"error": "Missing username"}), 400

    user = User.query.get(data["username"])
    if not user:
        return jsonify({"error": "User not found"}), 404

    return jsonify({
        "username": user.username,
        "publickey": user.publickey,
        "created_at": user.created_at
    }), 200

@app.route("/user/change", methods=["POST"])
def user_change():
    data = request.get_json()
    if not data or "username" not in data or "password" not in data or "new_publickey" not in data:
        return jsonify({"error": "Missing fields"}), 400

    user = User.query.get(data["username"])
    if not user:
        return jsonify({"error": "User not found"}), 404

    salt = base64.b64decode(user.salt)
    hash_ = base64.b64decode(user.pass_hash)

    if not verify_password(hash_, salt, data["password"]):
        return jsonify({"error": "Invalid password"}), 403

    user.publickey = data["new_publickey"]
    db.session.commit()
    return jsonify({"status": "publickey updated"}), 200

@app.route("/user/remove", methods=["POST"])
def user_remove():
    data = request.get_json()
    if not data or "username" not in data or "password" not in data:
        return jsonify({"error": "Missing fields"}), 400

    user = User.query.get(data["username"])
    if not user:
        return jsonify({"error": "User not found"}), 404

    salt = base64.b64decode(user.salt)
    hash_ = base64.b64decode(user.pass_hash)

    if not verify_password(hash_, salt, data["password"]):
        return jsonify({"error": "Invalid password"}), 403

    db.session.delete(user)
    db.session.commit()
    return jsonify({"status": "user removed"}), 200

@app.route("/")
def index():
    return send_from_directory("static", "index.html")

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(host="0.0.0.0", port=5000)
