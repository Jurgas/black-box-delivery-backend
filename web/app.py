from flask import Flask, request, make_response, session
from flask_session import Session
from flask_cors import CORS, cross_origin
from dotenv import load_dotenv
from bcrypt import hashpw, gensalt, checkpw
from os import getenv
from datetime import datetime
import re
import uuid
from redis import Redis

db = Redis(host='redis', port=6379, db=0)

load_dotenv()

SESSION_TYPE = 'redis'
SESSION_REDIS = db
app = Flask(__name__)
app.config.from_object(__name__)
app.secret_key = getenv("SECRET_KEY")
ses = Session(app)
cors = CORS(app)
app.config['CORS_HEADERS'] = 'Content-Type'


def create_response(msg, status):
    response = make_response({"message": msg}, status)
    return response


def user_exists(username):
    if db.hexists(f"user:{username}", "password"):
        return True
    return False


def save_user(username, password, firstname, lastname, email, address):
    salt = gensalt(4)
    password = password.encode()
    hashed_pass = hashpw(password, salt)
    db.hset(f"user:{username}", "password", hashed_pass)
    db.hset(f"user:{username}", "firstname", firstname)
    db.hset(f"user:{username}", "lastname", lastname)
    db.hset(f"user:{username}", "email", email)
    db.hset(f"user:{username}", "address", address)
    return True


def verify_user(username, password):
    password = password.encode()
    hashed = db.hget(f"user:{username}", "password")
    if not hashed:
        return False
    return checkpw(password, hashed)


def save_label(label_id, username, receiver, size, po_box_id):
    db.hset(f"label:{label_id}", "username", f"{username}")
    db.hset(f"label:{label_id}", "receiver", f"{receiver}")
    db.hset(f"label:{label_id}", "size", f"{size}")
    db.hset(f"label:{label_id}", "POBoxId", f"{po_box_id}")
    return True


@app.route('/sender/available', methods=["POST"])
@cross_origin(supports_credentials=True)
def sender_available():
    username = request.json.get('username')
    if user_exists(username):
        return create_response("Username already exists", 409)
    return create_response("Available", 200)


@app.route('/sender/create', methods=["POST"])
@cross_origin(supports_credentials=True)
def sender_create():
    firstname = request.json.get('firstname')
    lastname = request.json.get('lastname')
    username = request.json.get('username')
    password = request.json.get('password')
    email = request.json.get('email')
    address = request.json.get('address')

    PL = 'ĄĆĘŁŃÓŚŹŻ'
    pl = 'ąćęłńóśźż'
    if not re.compile(f'[A-Z{PL}][a-z{pl}]+').match(firstname):
        return create_response("Invalid firstname", 400)
    if not re.compile(f'[A-Z{PL}][a-z{pl}]+').match(lastname):
        return create_response("Invalid lastname", 400)
    if not re.compile('[a-z]{3,12}').match(username):
        return create_response("Invalid username", 400)
    if not re.compile('.{8,}').match(password.strip()):
        return create_response("Invalid password", 400)
    if not re.compile(
            '(?:[A-Za-z0-9!#$%&\'*+/=?^_`{|}~-]+(?:\\.[A-Za-z0-9!#$%&\'*+/=?^_`{|}~-]+)*|"(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21\x23-\x5b\x5d-\x7f]|\\\\[\x01-\x09\x0b\x0c\x0e-\x7f])*")@(?:(?:[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?\\.)+[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?|\\[(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?|[A-Za-z0-9-]*[A-Za-z0-9]:(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21-\x5a\x53-\x7f]|\\\\[\x01-\x09\x0b\x0c\x0e-\x7f])+)\\])').match(
        email):
        return create_response("Invalid email", 400)
    if address is None:
        return create_response("Empty address", 400)

    if user_exists(username):
        return create_response("Username already exists", 400)

    if not save_user(username, password, firstname, lastname, email, address):
        return create_response("An error occurred", 500)

    return create_response("Account created", 201)


@app.route('/sender/label', methods=["GET"])
@cross_origin(supports_credentials=True)
def sender_get_labels():
    if not session.get("username"):
        return create_response("Unauthorized", 401)
    username = session.get("username")
    keys = db.keys(pattern='label*')
    data = []
    for key in keys:
        db_user = db.hget(key, "username").decode()
        if username == db_user:
            receiver = db.hget(key, "receiver").decode()
            size = db.hget(key, "size").decode()
            po_box_id = db.hget(key, "POBoxId").decode()
            label_id = key.decode().split(":")[1]
            json_string = {
                "labelId": label_id,
                "username": db_user,
                "receiver": receiver,
                "size": size,
                "POBoxId": po_box_id
            }
            data.append(json_string)
    return make_response({"data": data}, 200)


@app.route('/sender/label', methods=["POST"])
@cross_origin(supports_credentials=True)
def sender_add_label():
    if not session.get("username"):
        return create_response("Unauthorized", 401)
    username = session.get("username")
    receiver = request.json.get('receiver')
    size = request.json.get('size')
    po_box_id = request.json.get('POBoxId')
    if receiver is None:
        return create_response("Invalid receiver", 400)
    if size is None:
        return create_response("Invalid size", 400)
    if po_box_id is None:
        return create_response("Invalid PO box id", 400)
    label_id = uuid.uuid4()

    if not save_label(label_id, username, receiver, size, po_box_id):
        return create_response("An error occurred", 500)

    response = make_response({"labelId": label_id,
                              "username": username,
                              "receiver": receiver,
                              "size": size,
                              "POBoxId": po_box_id}, 201)
    return response


@app.route('/sender/label/<label_id>', methods=["DELETE"])
@cross_origin(supports_credentials=True)
def sender_delete_label(label_id):
    if not session.get("username"):
        return create_response("Unauthorized", 401)
    username = session.get("username")
    db_user = db.hget(f"label:{label_id}", "username").decode()
    if username != db_user:
        return create_response(f"Label with {label_id} does not exist", 400)
    receiver = db.hget(f"label:{label_id}", "receiver").decode()
    size = db.hget(f"label:{label_id}", "size").decode()
    po_box_id = db.hget(f"label:{label_id}", "POBoxId").decode()
    db.delete(f"label:{label_id}")
    return make_response({"labelId": label_id,
                          "username": username,
                          "receiver": receiver,
                          "size": size,
                          "POBoxId": po_box_id}, 200)


@app.route('/auth/login', methods=["POST"])
@cross_origin(supports_credentials=True)
def auth_login():
    username = request.json.get('username')
    password = request.json.get('password')

    if not verify_user(username, password):
        return create_response("Incorrect username or/and password", 400)

    session["username"] = username
    session["logged-at"] = datetime.now()

    return create_response("Login success", 200)


@app.route('/auth/logout', methods=["POST"])
@cross_origin(supports_credentials=True)
def auth_logout():
    session.clear()
    return create_response("Logout success", 200)


@app.route('/auth/logged', methods=["GET"])
@cross_origin(supports_credentials=True)
def auth_logged_in():
    if not session.get("username"):
        return create_response("Unauthorized", 401)
    return create_response("Is logged in", 200)


if __name__ == '__main__':
    app.run(host="0.0.0.0", port=4000)
