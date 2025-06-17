from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_cors import CORS
from flask_jwt_extended import (
    JWTManager, create_access_token,
    jwt_required, get_jwt_identity
)
from flask_socketio import SocketIO, join_room, emit
import jwt as pyjwt 

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///chat.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'starwars'

db = SQLAlchemy(app)
jwt = JWTManager(app)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='eventlet')
CORS(app, supports_credentials=True)

### MODELLER ###

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

class Room(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), unique=True, nullable=False)
    admin_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    admin = db.relationship('User', backref='rooms')

class JoinRequest(db.Model):
    __table_args__ = (db.UniqueConstraint('user_id', 'room_id'),)
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    room_id = db.Column(db.Integer, db.ForeignKey('room.id'), nullable=False)
    status = db.Column(db.String(20), default='pending')  # pending, approved, rejected

    user = db.relationship('User')
    room = db.relationship('Room')

class RoomMember(db.Model):
    __table_args__ = (db.UniqueConstraint('user_id', 'room_id'),)

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    room_id = db.Column(db.Integer, db.ForeignKey('room.id'), nullable=False)

    user = db.relationship('User')
    room = db.relationship('Room')

### AUTH ###

@app.route("/register", methods=['POST'])
def register():
  
    data = request.get_json()
    username, email, password = data.get('username'), data.get('email'), data.get('password')

    if not username or not email or not password:
        return jsonify({'status': 'error', 'message': 'Missing fields'}), 400

    if User.query.filter((User.username == username) | (User.email == email)).first():
        return jsonify({'status': 'error', 'message': 'Username or email already exists'}), 409

    user = User(
        username=username,
        email=email,
        password=generate_password_hash(password)
    )
    db.session.add(user)
    db.session.commit()
    return jsonify({'status': 'success', 'message': 'User registered'}), 200

@app.route("/login", methods=['POST'])
def login():
    data = request.get_json()
    username, password = data.get('username'), data.get('password')

    user = User.query.filter_by(username=username).first()
    if user and check_password_hash(user.password, password):
        token = create_access_token(identity=str(user.id))
        return jsonify({'status': 'success', 'token': token}), 200

    return jsonify({'status': 'error', 'message': 'Invalid credentials'}), 401

@app.route("/profile", methods=['GET'])
@jwt_required()
def profile():
    user_id = int(get_jwt_identity())
    user = User.query.get(user_id)
    return jsonify({
        'status': 'success',
        'user_id': user.id,
        'username': user.username,
        'email': user.email
    })

### ROOMS ###

@app.route("/rooms", methods=['POST'])
@jwt_required()
def create_room():
    data = request.get_json()
    name = data.get('name')
    user_id = int(get_jwt_identity())

    if not name:
        return jsonify({'status': 'error', 'message': 'Room name required'}), 400

    if Room.query.filter_by(name=name).first():
        return jsonify({'status': 'error', 'message': 'Room name taken'}), 409

    room = Room(name=name, admin_id=user_id)
    db.session.add(room)
    db.session.commit()
    return jsonify({'status': 'success', 'message': 'Room created'}), 200

@app.route("/rooms", methods=['GET'])
@jwt_required()
def list_rooms():
    rooms = Room.query.all()
    data = [{'id': r.id, 'name': r.name, 'admin_id': r.admin_id} for r in rooms]
    return jsonify({'status': 'success', 'rooms': data})

@app.route("/rooms/<int:room_id>/join", methods=['POST'])
@jwt_required()
def join_request(room_id):
    user_id = int(get_jwt_identity())

    room = Room.query.get(room_id)
    if not room:
        return jsonify({'status': 'error', 'message': 'Room not found'}), 404

    existing = JoinRequest.query.filter_by(user_id=user_id, room_id=room_id).first()
    if existing:
        if existing.status == 'approved':
            return jsonify({'status': 'success', 'message': 'Already approved'})
        elif existing.status == 'pending':
            return jsonify({'status': 'info', 'message': 'Request pending'})
        elif existing.status == 'rejected':
            existing.status = 'pending'
            db.session.commit()
            return jsonify({'status': 'info', 'message': 'Request resent'})

    jr = JoinRequest(user_id=user_id, room_id=room_id)
    db.session.add(jr)
    db.session.commit()
    return jsonify({'status': 'success', 'message': 'Request sent'})

@app.route("/rooms/<int:room_id>/requests", methods=['GET'])
@jwt_required()
def list_join_requests(room_id):
    user_id = int(get_jwt_identity())
    room = Room.query.get(room_id)

    
    if not room:
        return jsonify({'status': 'error', 'message': 'Room not found'}), 404
    if room.admin_id != user_id:
        return jsonify({'status': 'error', 'message': 'Not authorized'}), 403

    reqs = JoinRequest.query.filter_by(room_id=room_id, status='pending').all()
    data = [{'id': r.id, 'username': r.user.username} for r in reqs]
    return jsonify({'status': 'success', 'requests': data})

@app.route("/requests/<int:req_id>/approve", methods=['POST'])
@jwt_required()
def approve_join_request(req_id):
    user_id = int(get_jwt_identity())
    jr = JoinRequest.query.get(req_id)

    if not jr:
        return jsonify({'status': 'error', 'message': 'Request not found'}), 404

    room = Room.query.get(jr.room_id)
    if room.admin_id != user_id:
        return jsonify({'status': 'error', 'message': 'Not authorized'}), 403

    jr.status = 'approved'
    member = RoomMember(user_id=jr.user_id, room_id=jr.room_id)
    db.session.add(member)
    db.session.commit()

    return jsonify({'status': 'success', 'message': 'Approved'}), 200

### SOCKETIO ###

@socketio.on('join_room')
def on_join(data):
    token = data.get('token')
    room_id = data.get('room_id')

    if not token or not room_id:
        emit('error', {'message': 'Token and room ID required'})
        return

    try:
        payload = pyjwt.decode(token, app.config['JWT_SECRET_KEY'], algorithms=['HS256'])
        user_id = int(payload['sub'])
    except Exception:
        emit('error', {'message': 'Invalid token'})
        return

    room = Room.query.get(room_id)
    if not room:
        emit('error', {'message': 'Room not found'})
        return

    is_member = RoomMember.query.filter_by(user_id=user_id, room_id=room_id).first()
    if not is_member and room.admin_id != user_id:
        emit('error', {'message': 'Not authorized to join'})
        return

    join_room(str(room_id))
    emit('joined', {'message': 'Room joined'}, room=str(room_id))

@socketio.on('send_message')
def on_message(data):
    token = data.get('token')
    room_id = data.get('room_id')
    message = data.get('message')

    if not token or not room_id or not message:
        return

    try:
        payload = pyjwt.decode(token, app.config['JWT_SECRET_KEY'], algorithms=['HS256'])
        user_id = int(payload['sub'])
    except Exception:
        return

    user = User.query.get(user_id)
    emit('receive_message', {
        'username': user.username,
        'message': message
    }, room=str(room_id))

### BAŞLAT ###
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    socketio.run(app, debug=True)
