import os
import hashlib
import base64
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_socketio import SocketIO, emit
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(32).hex()
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///nexus_chat.db'
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

db = SQLAlchemy(app)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='eventlet')
login_manager = LoginManager(app)
login_manager.login_view = 'login'

ALLOWED_EXTENSIONS = {
    'image': {'png', 'jpg', 'jpeg', 'gif', 'webp', 'svg', 'bmp'},
    'video': {'mp4', 'webm', 'ogg', 'mov', 'avi'},
    'audio': {'mp3', 'wav', 'ogg', 'aac', 'flac', 'm4a'},
    'document': {'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'txt', 'csv', 'zip', 'rar', '7z'},
}
ALL_ALLOWED = set().union(*ALLOWED_EXTENSIONS.values())

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALL_ALLOWED

def get_file_type(filename):
    ext = filename.rsplit('.', 1)[1].lower() if '.' in filename else ''
    for ftype, exts in ALLOWED_EXTENSIONS.items():
        if ext in exts:
            return ftype
    return 'document'

# --- Encryption Utilities ---
# Each pair (A,B) gets a unique XOR key derived from both usernames + a shared salt
# Different pairs get completely different keys

ENCRYPTION_SALT = "nexus_secure_salt_v1"

def get_pair_key(user_a: str, user_b: str) -> bytes:
    """Generate a unique 32-byte key for each user pair (order-independent)."""
    pair = tuple(sorted([user_a.lower(), user_b.lower()]))
    raw = f"{ENCRYPTION_SALT}:{pair[0]}:{pair[1]}"
    # Use SHA-256 to derive key, then expand to 256 bytes for longer messages
    key = hashlib.sha256(raw.encode()).digest()
    return key

def encrypt_message(plaintext: str, user_a: str, user_b: str) -> str:
    """Encrypt message using pair-unique key (XOR cipher with key stretching)."""
    if not plaintext:
        return plaintext
    key = get_pair_key(user_a, user_b)
    text_bytes = plaintext.encode('utf-8')
    # Stretch key to match message length
    stretched = bytes([key[i % len(key)] for i in range(len(text_bytes))])
    encrypted = bytes([b ^ k for b, k in zip(text_bytes, stretched)])
    return base64.b64encode(encrypted).decode('ascii')

def decrypt_message(ciphertext: str, user_a: str, user_b: str) -> str:
    """Decrypt message using pair-unique key."""
    if not ciphertext:
        return ciphertext
    try:
        key = get_pair_key(user_a, user_b)
        encrypted = base64.b64decode(ciphertext.encode('ascii'))
        stretched = bytes([key[i % len(key)] for i in range(len(encrypted))])
        decrypted = bytes([b ^ k for b, k in zip(encrypted, stretched)])
        return decrypted.decode('utf-8')
    except Exception:
        return "[Decryption Error]"

# --- Models ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(300), nullable=False)
    display_name = db.Column(db.String(150))
    avatar_color = db.Column(db.String(20), default='#6366f1')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)
    bio = db.Column(db.String(200), default='')

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender = db.Column(db.String(150), nullable=False)
    recipient = db.Column(db.String(150), nullable=False)
    content = db.Column(db.Text)  # stored encrypted
    file_url = db.Column(db.String(500))
    file_type = db.Column(db.String(20))  # image/video/audio/document
    file_name = db.Column(db.String(200))
    is_file = db.Column(db.Boolean, default=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    is_read = db.Column(db.Boolean, default=False)
    reaction = db.Column(db.String(10))

    def to_dict(self, viewer_username):
        """Return message dict with decrypted content for the viewer."""
        content = self.content
        if content and not self.is_file:
            content = decrypt_message(self.content, self.sender, self.recipient)
        return {
            'id': self.id,
            'sender': self.sender,
            'recipient': self.recipient,
            'content': content,
            'file_url': self.file_url,
            'file_type': self.file_type,
            'file_name': self.file_name,
            'is_file': self.is_file,
            'timestamp': self.timestamp.strftime('%H:%M'),
            'date': self.timestamp.strftime('%b %d, %Y'),
            'is_read': self.is_read,
            'reaction': self.reaction,
            'is_mine': self.sender == viewer_username,
        }

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- Routes ---
@app.route('/')
@login_required
def index():
    users = User.query.filter(User.id != current_user.id).order_by(User.last_seen.desc()).all()
    return render_template('index.html', users=users, current_user=current_user)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        action = request.form.get('action', 'login')

        if not username or not password:
            return jsonify({'error': 'Username and password required'}), 400

        user = User.query.filter_by(username=username).first()

        if action == 'register':
            if user:
                flash('Username already taken')
                return redirect(url_for('login'))
            colors = ['#6366f1','#ec4899','#14b8a6','#f59e0b','#ef4444','#8b5cf6','#06b6d4','#10b981']
            import random
            new_user = User(
                username=username,
                password=generate_password_hash(password, method='pbkdf2:sha256'),
                display_name=username,
                avatar_color=random.choice(colors)
            )
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)
            return redirect(url_for('index'))
        else:
            if user and check_password_hash(user.password, password):
                login_user(user)
                return redirect(url_for('index'))
            flash('Invalid username or password')
            return redirect(url_for('login'))
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/api/messages/<other_username>')
@login_required
def get_messages(other_username):
    other = User.query.filter_by(username=other_username).first_or_404()
    msgs = Message.query.filter(
        ((Message.sender == current_user.username) & (Message.recipient == other_username)) |
        ((Message.sender == other_username) & (Message.recipient == current_user.username))
    ).order_by(Message.timestamp.asc()).all()

    # Mark unread as read
    for m in msgs:
        if m.recipient == current_user.username and not m.is_read:
            m.is_read = True
    db.session.commit()

    return jsonify([m.to_dict(current_user.username) for m in msgs])

@app.route('/api/unread_counts')
@login_required
def unread_counts():
    from sqlalchemy import func
    counts = db.session.query(Message.sender, func.count(Message.id)).filter(
        Message.recipient == current_user.username,
        Message.is_read == False
    ).group_by(Message.sender).all()
    return jsonify({sender: count for sender, count in counts})

@app.route('/upload', methods=['POST'])
@login_required
def upload_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file'}), 400
    file = request.files['file']
    if file.filename == '' or not allowed_file(file.filename):
        return jsonify({'error': 'Invalid file'}), 400

    filename = secure_filename(file.filename)
    # Add timestamp to avoid collisions
    ts = datetime.utcnow().strftime('%Y%m%d%H%M%S%f')
    filename = f"{ts}_{filename}"
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(filepath)

    ftype = get_file_type(filename)
    return jsonify({
        'url': f"/static/uploads/{filename}",
        'type': ftype,
        'name': file.filename
    })

@app.route('/api/react/<int:msg_id>', methods=['POST'])
@login_required
def react_message(msg_id):
    msg = Message.query.get_or_404(msg_id)
    emoji = request.json.get('emoji', '')
    msg.reaction = emoji
    db.session.commit()
    return jsonify({'ok': True})

@app.route('/api/users')
@login_required
def get_users():
    users = User.query.filter(User.id != current_user.id).all()
    return jsonify([{
        'username': u.username,
        'display_name': u.display_name or u.username,
        'avatar_color': u.avatar_color,
        'last_seen': u.last_seen.isoformat()
    } for u in users])

# --- Socket.IO ---
connected_users = {}  # username -> sid

@socketio.on('connect')
def handle_connect():
    if current_user.is_authenticated:
        connected_users[current_user.username] = request.sid
        current_user.last_seen = datetime.utcnow()
        db.session.commit()
        emit('update_presence', {'username': current_user.username, 'online': True}, broadcast=True)

@socketio.on('disconnect')
def handle_disconnect():
    if current_user.is_authenticated and current_user.username in connected_users:
        del connected_users[current_user.username]
        current_user.last_seen = datetime.utcnow()
        db.session.commit()
        emit('update_presence', {'username': current_user.username, 'online': False}, broadcast=True)

@socketio.on('send_message')
def handle_message(data):
    recipient = data.get('recipient', '')
    content = data.get('content', '')
    is_file = data.get('is_file', False)
    file_url = data.get('file_url', '')
    file_type = data.get('file_type', '')
    file_name = data.get('file_name', '')

    if not recipient or (not content and not is_file):
        return

    # Encrypt text content
    encrypted_content = ''
    if content and not is_file:
        encrypted_content = encrypt_message(content, current_user.username, recipient)
    elif is_file:
        encrypted_content = file_url  # file URLs stored as-is

    new_msg = Message(
        sender=current_user.username,
        recipient=recipient,
        content=encrypted_content if not is_file else '',
        file_url=file_url if is_file else None,
        file_type=file_type if is_file else None,
        file_name=file_name if is_file else None,
        is_file=is_file,
    )
    db.session.add(new_msg)

    # Auto-delete messages older than 24 hours
    cutoff = datetime.utcnow() - timedelta(hours=24)
    Message.query.filter(Message.timestamp < cutoff).delete()
    db.session.commit()

    msg_dict = new_msg.to_dict(current_user.username)

    # Send to recipient if online
    if recipient in connected_users:
        recipient_dict = new_msg.to_dict(recipient)
        emit('receive_message', recipient_dict, room=connected_users[recipient])

    # Confirm to sender
    emit('message_sent', msg_dict)

@socketio.on('typing')
def handle_typing(data):
    recipient = data.get('recipient')
    if recipient and recipient in connected_users:
        emit('user_typing', {'username': current_user.username, 'typing': data.get('typing', False)},
             room=connected_users[recipient])

# WebRTC signaling
@socketio.on('webrtc_offer')
def webrtc_offer(data):
    target = data.get('target')
    if target and target in connected_users:
        emit('webrtc_offer', {
            'sender': current_user.username,
            'sdp': data['sdp'],
            'call_type': data.get('call_type', 'video')
        }, room=connected_users[target])

@socketio.on('webrtc_answer')
def webrtc_answer(data):
    target = data.get('target')
    if target and target in connected_users:
        emit('webrtc_answer', {'sender': current_user.username, 'sdp': data['sdp']},
             room=connected_users[target])

@socketio.on('webrtc_ice_candidate')
def webrtc_ice(data):
    target = data.get('target')
    if target and target in connected_users:
        emit('webrtc_ice_candidate', {'sender': current_user.username, 'candidate': data['candidate']},
             room=connected_users[target])

@socketio.on('call_rejected')
def call_rejected(data):
    target = data.get('target')
    if target and target in connected_users:
        emit('call_rejected', {'sender': current_user.username}, room=connected_users[target])

@socketio.on('call_ended')
def call_ended(data):
    target = data.get('target')
    if target and target in connected_users:
        emit('call_ended', {'sender': current_user.username}, room=connected_users[target])

@socketio.on('get_online_users')
def get_online_users():
    emit('online_users_list', list(connected_users.keys()))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    socketio.run(app, debug=True, port=4040, allow_unsafe_werkzeug=True)