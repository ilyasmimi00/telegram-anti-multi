# api/index.py
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import sqlite3
import time
import secrets
import os
import json
from datetime import datetime

app = Flask(__name__, static_folder='../public', static_url_path='')
CORS(app)

# ========== إعدادات البوت ==========
BOT_USERNAME = "moneybulletbot"

# ========== قاعدة البيانات ==========
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'verified.db')

def init_db():
    """إنشاء قاعدة البيانات إذا لم تكن موجودة"""
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS verified_users (
            user_id INTEGER PRIMARY KEY,
            timestamp INTEGER,
            ip TEXT,
            fingerprint TEXT,
            device_info TEXT,
            browser TEXT
        )''')
        conn.commit()
        conn.close()
        print(f"✅ Database initialized at {DB_PATH}")
        return True
    except Exception as e:
        print(f"❌ Database init error: {e}")
        return False

init_db()

VERIFICATION_TOKENS = {}

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def add_verified_user(user_id, ip=None, fingerprint=None, device_info=None, browser=None):
    try:
        conn = get_db()
        c = conn.cursor()
        c.execute("INSERT OR REPLACE INTO verified_users (user_id, timestamp, ip, fingerprint, device_info, browser) VALUES (?, ?, ?, ?, ?, ?)",
                  (user_id, int(time.time()), ip, fingerprint, device_info, browser))
        conn.commit()
        conn.close()
        print(f"✅ User {user_id} added")
        return True
    except Exception as e:
        print(f"❌ Error adding user: {e}")
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
    if not fingerprint or fingerprint == 'unknown':
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


# ========== نقاط النهاية ==========

@app.route('/', methods=['GET'])
def home():
    """إرجاع صفحة Mini App"""
    try:
        return send_from_directory('../public', 'index.html')
    except:
        return jsonify({
            "status": "ok",
            "bot": BOT_USERNAME,
            "message": "Verification API is running",
            "endpoints": [
                "GET /health",
                "GET /check?user_id=xxx",
                "POST /verify",
                "GET /verify_token/<token>"
            ]
        })

@app.route('/health', methods=['GET'])
def health():
    return jsonify({"status": "ok", "timestamp": time.time()})

@app.route('/check', methods=['GET'])
def check():
    user_id = request.args.get('user_id')
    if user_id:
        try:
            verified = is_verified(int(user_id))
            return jsonify({"verified": verified})
        except ValueError:
            return jsonify({"verified": False})
    return jsonify({"verified": False})

@app.route('/verify_token/<token>', methods=['GET'])
def verify_token_route(token):
    if token in VERIFICATION_TOKENS:
        token_data = VERIFICATION_TOKENS[token]
        if time.time() < token_data['expires']:
            return jsonify({"valid": True, "user_id": token_data['user_id']})
        del VERIFICATION_TOKENS[token]
    return jsonify({"valid": False})

@app.route('/verify', methods=['POST'])
def verify():
    """نقطة التحقق الرئيسية - فقط POST"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"status": "error", "verified": False, "message": "No data provided"})
        
        user_id = data.get('user_id')
        ip = data.get('ip', 'unknown')
        fingerprint = data.get('fingerprint', 'unknown')
        device_info = data.get('device_info', '')
        browser = data.get('browser', '')
        
        print(f"📥 Verification: user={user_id}, fp={fingerprint[:20] if fingerprint else 'None'}...")
        
        if not user_id:
            return jsonify({"status": "error", "verified": False, "message": "No user_id"})
        
        # منع التعدد عبر البصمة
        existing_fp_user = get_user_by_fingerprint(fingerprint, user_id)
        if existing_fp_user and fingerprint != 'unknown':
            return jsonify({
                "status": "blocked",
                "verified": False,
                "reason": "multiple_accounts_same_device",
                "message": "⚠️ تم اكتشاف أكثر من حساب من نفس الجهاز. مسموح بحساب واحد فقط."
            })
        
        add_verified_user(int(user_id), ip, fingerprint, device_info, browser)
        
        token = secrets.token_urlsafe(32)
        VERIFICATION_TOKENS[token] = {
            'user_id': user_id,
            'expires': time.time() + 600
        }
        
        return jsonify({
            "status": "success",
            "verified": True,
            "user_id": user_id,
            "token": token,
            "bot_username": BOT_USERNAME
        })
        
    except Exception as e:
        print(f"❌ Error: {e}")
        return jsonify({"status": "error", "verified": False, "message": str(e)})

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    print(f"🚀 Running on http://localhost:{port}")
    app.run(host='0.0.0.0', port=port, debug=False)