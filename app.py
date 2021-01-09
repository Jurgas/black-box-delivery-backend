from flask import Flask, request, make_response, g
from flask_hal import HAL
from flask_hal.document import Document, Embedded
from flask_hal.link import Link
from dotenv import load_dotenv
from bcrypt import hashpw, gensalt, checkpw
from os import getenv
from datetime import datetime, timedelta
import re
import uuid
from redis import Redis, StrictRedis
from jwt import encode, decode, InvalidTokenError
from flask_cors import CORS, cross_origin

# db = Redis(host='redis', port=6379, db=0)

load_dotenv()
REDIS_HOST = getenv("REDIS_HOST")
REDIS_PASS = getenv("REDIS_PASS")
db = StrictRedis(REDIS_HOST, db=0, password=REDIS_PASS, port=32179)
JWT_SECRET = getenv("JWT_SECRET")

app = Flask(__name__)
app.config.from_object(__name__)
app.secret_key = getenv("SECRET_KEY")
app.config['CORS_HEADERS'] = 'Content-Type'
app.config['CORS_ORIGINS'] = ['http://localhost:5000', 'http://localhost:3000',
                              'https://black-box-delivery.herokuapp.com']
HAL(app)


def generate_auth_token(username):
    payload = {
        "sub": username,
        "role": "sender",
        "iat": datetime.utcnow(),
        "exp": datetime.utcnow() + timedelta(hours=1),
    }
    token = encode(payload, JWT_SECRET, algorithm='HS256')
    return token


def allowed_methods(methods):
    if 'OPTIONS' not in methods:
        methods.append('OPTIONS')
    response = make_response('', 204)
    response.headers['Allow'] = ', '.join(methods)
    return response


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


def user_not_register(email):
    if db.hexists(f"auth:{email}", "sub"):
        return False
    return True


def save_auth0_user(email, sub):
    salt = gensalt(4)
    password = sub.encode()
    hashed_sub = hashpw(password, salt)
    db.hset(f"auth:{email}", "sub", hashed_sub)
    return True


def verify_user(username, password):
    password = password.encode()
    hashed = db.hget(f"user:{username}", "password")
    if not hashed:
        return False
    return checkpw(password, hashed)


def verify_auth0_user(email, sub):
    sub = sub.encode()
    hashed = db.hget(f"auth:{email}", "sub")
    if not hashed:
        return False
    return checkpw(sub, hashed)


def save_label(label_id, username, receiver, size, po_box_id):
    db.hset(f"label:{label_id}", "username", f"{username}")
    db.hset(f"label:{label_id}", "receiver", f"{receiver}")
    db.hset(f"label:{label_id}", "size", f"{size}")
    db.hset(f"label:{label_id}", "POBoxId", f"{po_box_id}")
    db.hset(f"label:{label_id}", "sent", "False")
    return True


def save_package(package_id, label_id):
    db.hset(f"package:{package_id}", "labelId", f"{label_id}")
    db.hset(f"package:{package_id}", "status", "On the way")
    return True


@app.before_request
def before_request_func():
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    try:
        g.authorization = decode(token, JWT_SECRET, algorithms=['HS256'])
    except InvalidTokenError as e:
        g.authorization = None
    return


@app.route('/', methods=['GET', 'OPTIONS'])
@cross_origin()
def root():
    if request.method == 'OPTIONS':
        return allowed_methods(['GET'])
    links = [Link('auth', '/auth'),
             Link('user', '/user'),
             Link('labels', '/labels'),
             Link('packages', '/packages')]
    document = Document(data={}, links=links)
    return document.to_json()


@app.route('/auth', methods=['GET', 'OPTIONS'])
@cross_origin()
def auth():
    if request.method == 'OPTIONS':
        return allowed_methods(['GET'])
    links = [Link('register', '/auth/register'),
             Link('login', '/auth/login')]
    document = Document(data={}, links=links)
    return document.to_json()


@app.route('/auth/register', methods=['POST', 'OPTIONS'])
@cross_origin()
def auth_register():
    if request.method == 'OPTIONS':
        return allowed_methods(['POST'])
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

    links = [Link('next', '/auth/login')]
    data = {'message': 'Account created'}
    document = Document(data=data, links=links)

    return document.to_json()


@app.route('/auth/login', methods=['POST', 'OPTIONS'])
@cross_origin(expose_headers=['Authorization'])
def auth_login():
    if request.method == 'OPTIONS':
        return allowed_methods(['POST'])
    username = request.json.get('username')
    password = request.json.get('password')

    if not verify_user(username, password):
        return create_response("Incorrect username or/and password", 400)

    token = generate_auth_token(username)
    response = make_response('', 200)
    response.headers['Authorization'] = 'Bearer ' + token.decode()
    return response


@app.route('/auth/auth0', methods=['POST'])
@cross_origin(expose_headers=['Authorization'])
def auth_auth0():
    email = request.json.get('email')
    sub = request.json.get('sub')

    if user_exists(email):
        return create_response("Username already exists", 400)

    if user_not_register(email):
        if not save_auth0_user(email, sub):
            return create_response("An error occurred", 500)

    if not verify_auth0_user(email, sub):
        return create_response("An error occurred", 400)

    token = generate_auth_token(email)
    response = make_response('', 200)
    response.headers['Authorization'] = 'Bearer ' + token.decode()
    return response


@app.route('/user', methods=['GET', 'OPTIONS'])
@cross_origin()
def user():
    if request.method == 'OPTIONS':
        return allowed_methods(['GET'])
    links = [Link('available', '/user/available'),
             Link('current', '/user/current')]
    document = Document(data={}, links=links)
    return document.to_json()


@app.route('/user/available', methods=['POST', 'OPTIONS'])
@cross_origin()
def user_available():
    if request.method == 'OPTIONS':
        return allowed_methods(['POST'])
    username = request.json.get('username')
    if user_exists(username):
        return create_response("Username already exists", 409)
    data = {'message': 'Available'}
    document = Document(data=data)
    return document.to_json()


@app.route('/user/current', methods=['GET', 'OPTIONS'])
@cross_origin(headers=['Authorization'])
def user_current():
    if request.method == 'OPTIONS':
        return allowed_methods(['GET'])
    if g.authorization is None:
        return create_response("Unauthorized", 401)
    data = {'username': g.authorization.get('sub')}
    document = Document(data=data)
    return document.to_json()


@app.route('/labels', methods=['GET', 'OPTIONS'])
@cross_origin(headers=['Authorization'])
def labels_get():
    if request.method == 'OPTIONS':
        return allowed_methods(['GET', 'POST'])
    if g.authorization is None:
        return create_response("Unauthorized", 401)
    username = g.authorization.get('sub')
    keys = db.keys(pattern='label*')
    data = []
    for key in keys:
        db_user = db.hget(key, "username").decode()
        if username == db_user or g.authorization.get('role') == 'courier':
            receiver = db.hget(key, "receiver").decode()
            size = db.hget(key, "size").decode()
            po_box_id = db.hget(key, "POBoxId").decode()
            sent = db.hget(key, "sent").decode()
            label_id = key.decode().split(":")[1]
            link = Link('self', '/labels/' + label_id)
            item = {
                "labelId": label_id,
                "username": db_user,
                "receiver": receiver,
                "size": size,
                "POBoxId": po_box_id,
                "sent": sent
            }
            data.append(Embedded(data=item, links=[link]))
    links = [Link('find', '/labels/{id}', templated=True)]
    document = Document(embedded={'data': Embedded(data=data)},
                        links=links)
    return document.to_json()


@app.route('/labels', methods=["POST"])
@cross_origin(headers=['Authorization'])
def labels_add():
    if g.authorization is None:
        return create_response("Unauthorized", 401)
    username = g.authorization.get('sub')
    receiver = request.json.get('receiver')
    size = request.json.get('size')
    po_box_id = request.json.get('POBoxId')
    if receiver is None:
        return create_response("Invalid receiver", 400)
    if size is None:
        return create_response("Invalid size", 400)
    if po_box_id is None:
        return create_response("Invalid PO box id", 400)
    label_id = str(uuid.uuid4())

    if not save_label(label_id, username, receiver, size, po_box_id):
        return create_response("An error occurred", 500)

    data = {"labelId": label_id,
            "username": username,
            "receiver": receiver,
            "size": size,
            "POBoxId": po_box_id}
    links = [Link('find', '/labels/' + label_id)]
    document = Document(data=data, links=links)
    return document.to_json()


@app.route('/labels/<label_id>', methods=['GET', 'OPTIONS'])
@cross_origin(headers=['Authorization'])
def labels_single(label_id):
    if request.method == 'OPTIONS':
        return allowed_methods(['GET', 'DELETE'])
    if g.authorization is None:
        return create_response("Unauthorized", 401)
    username = g.authorization.get('sub')
    if not db.hexists(f"label:{label_id}", "username"):
        return create_response(f"Label not found", 404)
    db_user = db.hget(f"label:{label_id}", "username").decode()
    if username != db_user:
        return create_response(f"Label not found", 404)
    receiver = db.hget(f"label:{label_id}", "receiver").decode()
    size = db.hget(f"label:{label_id}", "size").decode()
    po_box_id = db.hget(f"label:{label_id}", "POBoxId").decode()
    sent = db.hget(f"label:{label_id}", "sent").decode()
    data = {"labelId": label_id,
            "username": username,
            "receiver": receiver,
            "size": size,
            "POBoxId": po_box_id,
            "sent": sent}
    document = Document(data=data)
    return document.to_json()


@app.route('/labels/<label_id>', methods=["DELETE"])
@cross_origin(headers=['Authorization'])
def labels_delete(label_id):
    if g.authorization is None:
        return create_response("Unauthorized", 401)
    username = g.authorization.get('sub')
    if not db.hexists(f"label:{label_id}", "username"):
        return create_response(f"Label not found", 404)
    db_user = db.hget(f"label:{label_id}", "username").decode()
    if username != db_user:
        return create_response(f"Label with {label_id} does not exist", 400)
    db.delete(f"label:{label_id}")
    links = [Link('next', '/labels')]
    document = Document(data={}, links=links)
    return document.to_json()


@app.route('/packages', methods=['GET', 'OPTIONS'])
@cross_origin(headers=['Authorization'])
def packages_get():
    if request.method == 'OPTIONS':
        return allowed_methods(['GET', 'POST'])
    if g.authorization is None or g.authorization.get('role') != 'courier':
        return create_response("Unauthorized", 401)
    keys = db.keys(pattern='package*')
    data = []
    for key in keys:
        package_id = key.decode().split(":")[1]
        label_id = db.hget(key, "labelId").decode()
        status = db.hget(key, "status").decode()
        link = Link('self', '/package/' + package_id)
        item = {
            "packageId": package_id,
            "labelId": label_id,
            "status": status,
        }
        data.append(Embedded(data=item, links=[link]))
    links = [Link('find', '/package/{id}', templated=True)]
    document = Document(embedded={'data': Embedded(data=data)},
                        links=links)
    return document.to_json()


@app.route('/packages', methods=['POST'])
@cross_origin(headers=['Authorization'])
def packages_create():
    if g.authorization is None or g.authorization.get('role') != 'courier':
        return create_response("Unauthorized", 401)
    label_id = request.json.get('labelId')
    if not db.hexists(f"label:{label_id}", "username"):
        return create_response("Label does not exists", 404)
    if db.hget(f"label:{label_id}", "sent").decode() == "True":
        return create_response("Label already sent", 400)
    package_id = str(uuid.uuid4())
    if not save_package(package_id, label_id):
        return create_response("An error occurred", 500)
    db.hset(f"label:{label_id}", "sent", "True")

    data = {"packageId": package_id,
            "labelId": label_id,
            "status": "On the way"}
    links = [Link('find', '/packages/' + package_id)]
    document = Document(data=data, links=links)
    return document.to_json()


@app.route('/packages/<package_id>', methods=['GET', 'OPTIONS'])
@cross_origin(headers=['Authorization'])
def packages_single_get(package_id):
    if request.method == 'OPTIONS':
        return allowed_methods(['GET', 'PUT'])
    if g.authorization is None or g.authorization.get('role') != 'courier':
        return create_response("Unauthorized", 401)
    if not db.hexists(f"package:{package_id}", "labelId"):
        return create_response("Package not found", 404)
    label_id = db.hget(f"package:{package_id}", "labelId").decode()
    status = db.hget(f"package:{package_id}", "status").decode()
    data = {"packageId": package_id,
            "labelId": label_id,
            "status": status}
    document = Document(data=data)
    return document.to_json()


@app.route('/packages/<package_id>', methods=['PUT'])
@cross_origin(headers=['Authorization'])
def packages_update(package_id):
    if g.authorization is None or g.authorization.get('role') != 'courier':
        return create_response("Unauthorized", 401)
    if not db.hexists(f"package:{package_id}", "labelId"):
        return create_response("Package not found", 404)
    status = request.json.get('status')
    statuses = ["On the way", "Delivered", "Picked up"]
    if status not in statuses:
        return create_response("Invalid status", 400)
    db.hset(f"package:{package_id}", "status", status)
    label_id = db.hget(f"package:{package_id}", "labelId").decode()
    data = {"packageId": package_id,
            "labelId": label_id,
            "status": status}
    document = Document(data=data)
    return document.to_json()


if __name__ == '__main__':
    app.run(host="0.0.0.0", port=4000)
