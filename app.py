import os
import json
import hashlib
import base64
import tempfile
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_socketio import SocketIO, emit
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
import random

# --- Google API Imports ---
import gspread
from google.oauth2.service_account import Credentials
from googleapiclient.discovery import build
from googleapiclient.http import MediaFileUpload
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
import pickle

app = Flask(__name__)
# Stable SECRET_KEY so sessions survive restarts. Change this in production!
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'nexus-stable-secret-key-change-me')

# ==========================================
# 1. CONFIGURATION
# ==========================================
ADMIN_EMAIL = "manikchandrabiswas72@gmail.com"
CONFIG_FILE = 'nexus_config.json'
SCOPES = [
    'https://www.googleapis.com/auth/spreadsheets',
    'https://www.googleapis.com/auth/drive'
]

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'pdf', 'doc', 'docx', 'txt', 'mp4', 'mp3'}
ENCRYPTION_SALT = "nexus_secure_salt_v2"

# --- Globals set during startup ---
gc = None
drive_service = None
users_ws = None
messages_ws = None
SPREADSHEET_ID = None
DRIVE_FOLDER_ID = None

# ==========================================
# 2. GOOGLE AUTH
# ==========================================
def get_user_creds():
    creds = None
    if os.path.exists('token.pickle'):
        with open('token.pickle', 'rb') as token:
            creds = pickle.load(token)

    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            try:
                creds.refresh(Request())
            except Exception as e:
                print(f"Warning: Token refresh failed ({e}), re-authenticating...")
                creds = None

        if not creds:
            if not os.path.exists('client_secrets.json'):
                print("=" * 60)
                print("MISSING: client_secrets.json")
                print("")
                print("   Steps to fix:")
                print("   1. Go to https://console.cloud.google.com/")
                print("   2. Select your project (or create one)")
                print("   3. APIs & Services -> Credentials")
                print("   4. Create OAuth 2.0 Client ID -> Desktop app")
                print("   5. Download JSON -> rename to: client_secrets.json")
                print("   6. Place it in the same folder as app.py")
                print("   7. Also enable: Google Sheets API + Google Drive API")
                print("=" * 60)
                raise FileNotFoundError("client_secrets.json not found. See setup instructions above.")
            flow = InstalledAppFlow.from_client_secrets_file('client_secrets.json', SCOPES)
            creds = flow.run_local_server(port=0)

        with open('token.pickle', 'wb') as token:
            pickle.dump(creds, token)

    return creds


def setup_google_workspace():
    """Creates Drive folder and Sheets on first run, returns config."""
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, 'r') as f:
            return json.load(f)

    print("First run! Setting up Google Workspace...")

    # Create Drive folder
    folder_metadata = {
        'name': 'NexusChat_Uploads',
        'mimeType': 'application/vnd.google-apps.folder'
    }
    folder = drive_service.files().create(body=folder_metadata, fields='id').execute()
    folder_id = folder.get('id')

    drive_service.permissions().create(
        fileId=folder_id,
        body={'type': 'anyone', 'role': 'reader'}
    ).execute()

    # Create Spreadsheet
    sheet = gc.create('NexusChat_Database')
    sheet_id = sheet.id

    if ADMIN_EMAIL and "@" in ADMIN_EMAIL:
        sheet.share(ADMIN_EMAIL, perm_type='user', role='editor')

    users_sheet = sheet.get_worksheet(0)
    users_sheet.update_title('Users')
    users_sheet.append_row(['id', 'username', 'password', 'display_name', 'avatar_color', 'created_at', 'last_seen'])

    messages_sheet = sheet.add_worksheet(title='Messages', rows=1000, cols=11)
    messages_sheet.append_row(['id', 'sender', 'recipient', 'content', 'file_url', 'file_type', 'file_name', 'is_file', 'timestamp', 'is_read', 'reaction'])

    config_data = {
        'DRIVE_FOLDER_ID': folder_id,
        'SPREADSHEET_ID': sheet_id
    }
    with open(CONFIG_FILE, 'w') as f:
        json.dump(config_data, f)

    print(f"Setup complete! Spreadsheet ID: {sheet_id}")
    return config_data


def init_google_services():
    """Called once at startup. Authenticates and connects to Google."""
    global gc, drive_service, users_ws, messages_ws, SPREADSHEET_ID, DRIVE_FOLDER_ID

    print("Authenticating with Google...")
    user_creds = get_user_creds()
    gc = gspread.authorize(user_creds)
    drive_service = build('drive', 'v3', credentials=user_creds)
    print("Google auth successful.")

    app_config = setup_google_workspace()
    SPREADSHEET_ID = app_config['SPREADSHEET_ID']
    DRIVE_FOLDER_ID = app_config['DRIVE_FOLDER_ID']

    sheet = gc.open_by_key(SPREADSHEET_ID)
    users_ws = sheet.worksheet('Users')
    messages_ws = sheet.worksheet('Messages')
    print("Connected to Google Sheets.")


# ==========================================
# 3. FLASK-LOGIN & SOCKETIO SETUP
# ==========================================
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='eventlet')
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# ==========================================
# 4. CACHE & ENCRYPTION
# ==========================================
user_cache = {}
connected_users = {}  # username -> socket SID


def get_pair_key(user_a: str, user_b: str) -> bytes:
    pair = tuple(sorted([user_a.lower(), user_b.lower()]))
    raw = f"{ENCRYPTION_SALT}:{pair[0]}:{pair[1]}"
    return hashlib.sha256(raw.encode()).digest()


def encrypt_message(plaintext: str, user_a: str, user_b: str) -> str:
    if not plaintext: return plaintext
    key = get_pair_key(user_a, user_b)
    text_bytes = plaintext.encode('utf-8')
    stretched = bytes([key[i % len(key)] for i in range(len(text_bytes))])
    encrypted = bytes([b ^ k for b, k in zip(text_bytes, stretched)])
    return base64.b64encode(encrypted).decode('ascii')


def decrypt_message(ciphertext: str, user_a: str, user_b: str) -> str:
    if not ciphertext: return ciphertext
    try:
        key = get_pair_key(user_a, user_b)
        encrypted = base64.b64decode(ciphertext.encode('ascii'))
        stretched = bytes([key[i % len(key)] for i in range(len(encrypted))])
        decrypted = bytes([b ^ k for b, k in zip(encrypted, stretched)])
        return decrypted.decode('utf-8')
    except Exception:
        return "[Encrypted]"


# ==========================================
# 5. USER MODEL
# ==========================================
class User(UserMixin):
    def __init__(self, id, username, password, display_name, avatar_color, created_at, last_seen):
        self.id = str(id)
        self.username = username
        self.password = password
        self.display_name = display_name
        self.avatar_color = avatar_color
        self.created_at = created_at
        self.last_seen = last_seen


@login_manager.user_loader
def load_user(user_id):
    if user_id in user_cache:
        return user_cache[user_id]
    try:
        records = users_ws.get_all_records()
        for row in records:
            if str(row.get('id')) == str(user_id):
                user = User(row['id'], row['username'], row['password'],
                            row['display_name'], row['avatar_color'],
                            row['created_at'], row['last_seen'])
                user_cache[user_id] = user
                return user
    except Exception as e:
        print(f"Error loading user: {e}")
    return None


# ==========================================
# 6. HTTP ROUTES
# ==========================================
@app.route('/')
@login_required
def index():
    records = users_ws.get_all_records()
    users = [u for u in records if str(u['id']) != str(current_user.id)]
    return render_template('index.html', users=users, current_user=current_user)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        action = request.form.get('action', 'login')

        records = users_ws.get_all_records()
        existing_user = next((r for r in records if r['username'] == username), None)

        if action == 'register':
            if existing_user:
                flash('Username already taken')
                return redirect(url_for('login'))

            colors = ['#6366f1', '#ec4899', '#14b8a6', '#f59e0b', '#ef4444', '#8b5cf6', '#06b6d4', '#10b981']
            new_id = len(records) + 1
            new_user_data = [
                new_id, username, generate_password_hash(password, method='pbkdf2:sha256'),
                username, random.choice(colors),
                datetime.utcnow().isoformat(), datetime.utcnow().isoformat()
            ]
            users_ws.append_row(new_user_data)
            new_user = User(*new_user_data)
            user_cache[str(new_id)] = new_user
            login_user(new_user)
            return redirect(url_for('index'))

        else:  # Login
            if existing_user and check_password_hash(existing_user['password'], password):
                user = User(existing_user['id'], existing_user['username'],
                            existing_user['password'], existing_user['display_name'],
                            existing_user['avatar_color'], existing_user['created_at'],
                            existing_user['last_seen'])
                user_cache[str(user.id)] = user
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
    records = messages_ws.get_all_records()
    msgs = []
    for row in records:
        if (row['sender'] == current_user.username and row['recipient'] == other_username) or \
           (row['sender'] == other_username and row['recipient'] == current_user.username):

            content = row['content']
            if content and str(row.get('is_file', 'FALSE')).upper() != 'TRUE':
                content = decrypt_message(content, row['sender'], row['recipient'])

            msgs.append({
                'id': row['id'],
                'sender': row['sender'],
                'recipient': row['recipient'],
                'content': content,
                'file_url': row.get('file_url', ''),
                'is_file': str(row.get('is_file', 'FALSE')).upper() == 'TRUE',
                'file_type': row.get('file_type', ''),
                'file_name': row.get('file_name', ''),
                'reaction': row.get('reaction', ''),
                'timestamp': str(row.get('timestamp', '')),
                'is_mine': row['sender'] == current_user.username
            })
    return jsonify(msgs)


@app.route('/upload', methods=['POST'], strict_slashes=False)
@login_required
def upload_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file'}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'Invalid file'}), 400

    filename = secure_filename(file.filename)
    ts = datetime.utcnow().strftime('%Y%m%d%H%M%S')
    filename = f"{ts}_{filename}"

    temp_dir = tempfile.gettempdir()
    filepath = os.path.join(temp_dir, filename)
    file.save(filepath)

    mime = file.mimetype or 'application/octet-stream'

    try:
        file_metadata = {
            'name': filename,
            'parents': [DRIVE_FOLDER_ID]
        }
        media = MediaFileUpload(filepath, mimetype=mime, resumable=True)
        uploaded_file = drive_service.files().create(
            body=file_metadata,
            media_body=media,
            fields='id'
        ).execute()

        file_id = uploaded_file.get('id')

        media._fd.close()
        if os.path.exists(filepath):
            os.remove(filepath)

        drive_service.permissions().create(
            fileId=file_id,
            body={'type': 'anyone', 'role': 'reader'}
        ).execute()

        view_url = f"https://drive.google.com/thumbnail?id={file_id}&sz=w1000"

        return jsonify({
            'url': view_url,
            'file_id': file_id,
            'type': 'image' if mime.startswith('image/') else 'document',
            'name': file.filename
        })

    except Exception as e:
        print(f"DRIVE UPLOAD ERROR: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/react/<int:msg_id>', methods=['POST'])
@login_required
def react_to_message(msg_id):
    try:
        data = request.get_json()
        emoji = data.get('emoji', '')
        records = messages_ws.get_all_records()
        for i, row in enumerate(records):
            if str(row.get('id')) == str(msg_id):
                messages_ws.update_cell(i + 2, 11, emoji)
                return jsonify({'ok': True})
        return jsonify({'error': 'Not found'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/unread_counts')
@login_required
def unread_counts():
    try:
        records = messages_ws.get_all_records()
        counts = {}
        for row in records:
            if row.get('recipient') == current_user.username and \
               str(row.get('is_read', 'FALSE')).upper() == 'FALSE':
                sender = row.get('sender', '')
                if sender:
                    counts[sender] = counts.get(sender, 0) + 1
        return jsonify(counts)
    except Exception:
        return jsonify({})


# ==========================================
# 7. SOCKET.IO EVENTS
# ==========================================
@socketio.on('connect')
def handle_connect():
    if current_user.is_authenticated:
        connected_users[current_user.username] = request.sid
        emit('update_presence', {'username': current_user.username, 'online': True}, broadcast=True)


@socketio.on('get_online_users')
def handle_get_online_users():
    emit('online_users_list', list(connected_users.keys()))


@socketio.on('disconnect')
def handle_disconnect():
    if current_user.is_authenticated and current_user.username in connected_users:
        del connected_users[current_user.username]
        emit('update_presence', {'username': current_user.username, 'online': False}, broadcast=True)


@socketio.on('send_message')
def handle_message(data):
    recipient = data.get('recipient', '')
    content = data.get('content', '')
    is_file = data.get('is_file', False)
    file_url = data.get('file_url', '')
    file_type = data.get('file_type', '')
    file_name = data.get('file_name', '')

    if not recipient: return

    encrypted_content = ''
    if content and not is_file:
        encrypted_content = encrypt_message(content, current_user.username, recipient)

    msg_id = random.randint(100000, 999999)
    timestamp_str = datetime.utcnow().strftime('%H:%M')

    new_msg_data = [
        msg_id, current_user.username, recipient, encrypted_content,
        file_url, file_type, file_name, str(is_file).upper(), timestamp_str, 'FALSE', ''
    ]
    messages_ws.append_row(new_msg_data)

    msg_dict = {
        'id': msg_id,
        'sender': current_user.username,
        'recipient': recipient,
        'content': content,
        'file_url': file_url,
        'file_type': file_type,
        'file_name': file_name,
        'is_file': is_file,
        'timestamp': timestamp_str,
        'is_mine': True
    }

    if recipient in connected_users:
        recipient_dict = msg_dict.copy()
        recipient_dict['is_mine'] = False
        emit('receive_message', recipient_dict, room=connected_users[recipient])

    emit('message_sent', msg_dict)


@socketio.on('typing')
def handle_typing(data):
    recipient = data.get('recipient')
    if recipient in connected_users:
        emit('user_typing', {
            'username': current_user.username,
            'typing': data.get('typing', False)
        }, room=connected_users[recipient])


@socketio.on('webrtc_offer')
def webrtc_offer(data):
    target = data.get('target')
    if target in connected_users:
        emit('webrtc_offer', {
            'sender': current_user.username,
            'sdp': data['sdp'],
            'call_type': data.get('call_type', 'video')
        }, room=connected_users[target])
    else:
        emit('call_error', {'message': f"{target} is offline."})


@socketio.on('webrtc_answer')
def webrtc_answer(data):
    target = data.get('target')
    if target in connected_users:
        emit('webrtc_answer', {
            'sender': current_user.username,
            'sdp': data['sdp']
        }, room=connected_users[target])


@socketio.on('webrtc_ice_candidate')
def webrtc_ice(data):
    target = data.get('target')
    if target in connected_users:
        emit('webrtc_ice_candidate', {
            'sender': current_user.username,
            'candidate': data['candidate']
        }, room=connected_users[target])


@socketio.on('call_rejected')
def call_rejected(data):
    target = data.get('target')
    if target in connected_users:
        emit('call_rejected', {'sender': current_user.username}, room=connected_users[target])


@socketio.on('call_ended')
def call_ended(data):
    target = data.get('target')
    if target in connected_users:
        emit('call_ended', {'sender': current_user.username}, room=connected_users[target])


# ==========================================
# 8. ENTRY POINT
# ==========================================
if __name__ == '__main__':
    # Google services init happens HERE, not at module level.
    # If something is missing you'll see a clear error, not a silent crash.
    init_google_services()

    port = int(os.environ.get('PORT', 4440))
    debug = os.environ.get('RENDER', '') == ''
    print(f"\nNexus Chat running at: http://localhost:{port}\n")
    socketio.run(app, host='0.0.0.0', port=port, debug=debug, allow_unsafe_werkzeug=True)
    