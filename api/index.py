# api/index.py
from flask import Flask, request, jsonify
from flask_cors import CORS
import sqlite3
import time
import secrets
import os

app = Flask(__name__)
CORS(app)

BOT_USERNAME = "moneybulletbot"
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'verified.db')

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS verified_users (
        user_id INTEGER PRIMARY KEY,
        timestamp INTEGER,
        ip TEXT,
        fingerprint TEXT
    )''')
    conn.commit()
    conn.close()

init_db()
VERIFICATION_TOKENS = {}

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def add_verified_user(user_id, ip=None, fingerprint=None):
    try:
        conn = get_db()
        c = conn.cursor()
        c.execute("INSERT OR REPLACE INTO verified_users (user_id, timestamp, ip, fingerprint) VALUES (?, ?, ?, ?)",
                  (user_id, int(time.time()), ip, fingerprint))
        conn.commit()
        conn.close()
        return True
    except:
        return False

def is_verified(user_id):
    try:
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT 1 FROM verified_users WHERE user_id = ?", (user_id,))
        result = c.fetchone() is not None
        conn.close()
        return result
    except:
        return False

def get_user_by_fingerprint(fingerprint, current_user_id):
    if not fingerprint:
        return None
    try:
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT user_id FROM verified_users WHERE fingerprint = ? AND user_id != ?", (fingerprint, current_user_id))
        result = c.fetchone()
        conn.close()
        return result['user_id'] if result else None
    except:
        return None

@app.route('/verify', methods=['POST'])
def verify():
    try:
        data = request.get_json()
        if not data:
            return jsonify({"status": "error", "verified": False, "message": "No data"})
        
        user_id = data.get('user_id')
        ip = data.get('ip', 'unknown')
        fingerprint = data.get('fingerprint', 'unknown')
        
        if not user_id:
            return jsonify({"status": "error", "verified": False, "message": "No user_id"})
        
        existing = get_user_by_fingerprint(fingerprint, user_id)
        if existing:
            return jsonify({
                "status": "blocked",
                "verified": False,
                "message": "⚠️ هذا الجهاز مسجل بحساب آخر. لا يمكن إنشاء أكثر من حساب."
            })
        
        add_verified_user(int(user_id), ip, fingerprint)
        token = secrets.token_urlsafe(32)
        VERIFICATION_TOKENS[token] = {'user_id': user_id, 'expires': time.time() + 600}
        
        return jsonify({
            "status": "success",
            "verified": True,
            "token": token,
            "bot_username": BOT_USERNAME
        })
    except Exception as e:
        return jsonify({"status": "error", "verified": False, "message": str(e)})

@app.route('/verify_token/<token>', methods=['GET'])
def verify_token(token):
    if token in VERIFICATION_TOKENS:
        if time.time() < VERIFICATION_TOKENS[token]['expires']:
            return jsonify({"valid": True, "user_id": VERIFICATION_TOKENS[token]['user_id']})
    return jsonify({"valid": False})

@app.route('/check', methods=['GET'])
def check():
    user_id = request.args.get('user_id')
    if user_id:
        return jsonify({"verified": is_verified(int(user_id))})
    return jsonify({"verified": False})

@app.route('/health', methods=['GET'])
def health():
    return jsonify({"status": "ok"})

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)