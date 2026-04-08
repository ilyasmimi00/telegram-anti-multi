# api/index.py
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import sqlite3
import time
import secrets
import os
import json
from datetime import datetime

app = Flask(__name__)
CORS(app)

# ========== إعدادات البوت ==========
BOT_USERNAME = "moneybulletbot"

# ========== قاعدة البيانات ==========
# استخدام مسار آمن للكتابة على Render
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
            browser TEXT,
            screen_resolution TEXT,
            timezone TEXT,
            language TEXT
        )''')
        conn.commit()
        conn.close()
        print(f"✅ Database initialized successfully at {DB_PATH}")
        return True
    except Exception as e:
        print(f"❌ Database init error: {e}")
        return False

# تهيئة قاعدة البيانات
init_db()

# تخزين مؤقت للتوكنات
VERIFICATION_TOKENS = {}

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def add_verified_user(user_id, ip=None, fingerprint=None, device_info=None, browser=None, screen_resolution=None, timezone=None, language=None):
    """إضافة مستخدم موثق إلى قاعدة البيانات"""
    try:
        conn = get_db()
        c = conn.cursor()
        c.execute("""INSERT OR REPLACE INTO verified_users 
                     (user_id, timestamp, ip, fingerprint, device_info, browser, screen_resolution, timezone, language) 
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                  (user_id, int(time.time()), ip, fingerprint, device_info, browser, screen_resolution, timezone, language))
        conn.commit()
        conn.close()
        print(f"✅ User {user_id} added to database")
        return True
    except Exception as e:
        print(f"❌ Error adding user {user_id}: {e}")
        return False

def is_verified(user_id):
    """التحقق من وجود مستخدم في قاعدة البيانات"""
    try:
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT 1 FROM verified_users WHERE user_id = ?", (user_id,))
        result = c.fetchone() is not None
        conn.close()
        return result
    except Exception as e:
        print(f"❌ Error checking user {user_id}: {e}")
        return False

def get_user_by_ip(ip, current_user_id):
    """البحث عن مستخدم بنفس IP (باستثناء المستخدم الحالي)"""
    if not ip or ip == 'unknown':
        return None
    try:
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT user_id FROM verified_users WHERE ip = ? AND user_id != ?", (ip, current_user_id))
        result = c.fetchone()
        conn.close()
        return result['user_id'] if result else None
    except Exception as e:
        print(f"❌ Error checking IP {ip}: {e}")
        return None

def get_user_by_fingerprint(fingerprint, current_user_id):
    """البحث عن مستخدم بنفس البصمة (باستثناء المستخدم الحالي)"""
    if not fingerprint or fingerprint == 'unknown':
        return None
    try:
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT user_id FROM verified_users WHERE fingerprint = ? AND user_id != ?", (fingerprint, current_user_id))
        result = c.fetchone()
        conn.close()
        return result['user_id'] if result else None
    except Exception as e:
        print(f"❌ Error checking fingerprint {fingerprint}: {e}")
        return None

def get_all_users():
    """الحصول على جميع المستخدمين (للتشخيص)"""
    try:
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT user_id, timestamp, ip, fingerprint FROM verified_users ORDER BY timestamp DESC LIMIT 50")
        results = c.fetchall()
        conn.close()
        return results
    except Exception as e:
        print(f"❌ Error getting users: {e}")
        return []


# ========== نقاط النهاية (Endpoints) ==========

@app.route('/health', methods=['GET'])
def health():
    return jsonify({"status": "ok", "timestamp": time.time()})

@app.route('/stats', methods=['GET'])
def stats():
    users = get_all_users()
    return jsonify({
        "total_users": len(users),
        "users": [{"user_id": u['user_id'], "timestamp": u['timestamp'], "ip": u['ip'], "fingerprint": u['fingerprint'][:20] + "..." if u['fingerprint'] else None} for u in users]
    })

@app.route('/check', methods=['GET'])
def check():
    user_id = request.args.get('user_id')
    if user_id:
        try:
            verified = is_verified(int(user_id))
            return jsonify({"verified": verified})
        except ValueError:
            return jsonify({"verified": False, "error": "Invalid user_id"})
    return jsonify({"verified": False, "error": "No user_id provided"})

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
    try:
        data = request.get_json()
        if not data:
            return jsonify({"status": "error", "verified": False, "message": "No data provided"})
        
        user_id = data.get('user_id')
        ip = data.get('ip', 'unknown')
        fingerprint = data.get('fingerprint', 'unknown')
        device_info = data.get('device_info', '')
        browser = data.get('browser', '')
        screen_resolution = data.get('screen_resolution', '')
        timezone = data.get('timezone', '')
        language = data.get('language', '')
        
        print(f"📥 Verification request: user_id={user_id}, fingerprint={fingerprint[:20] if fingerprint else 'None'}...")
        
        if not user_id:
            return jsonify({"status": "error", "verified": False, "message": "No user_id provided"})
        
        # نظام منع التعدد
        existing_ip_user = get_user_by_ip(ip, user_id)
        if existing_ip_user:
            print(f"🚫 Blocked: IP {ip} already used by user {existing_ip_user}")
            return jsonify({
                "status": "blocked",
                "verified": False,
                "reason": "multiple_accounts_same_ip",
                "message": "⚠️ تم اكتشاف أكثر من حساب من نفس عنوان IP. مسموح بحساب واحد فقط."
            })
        
        existing_fp_user = get_user_by_fingerprint(fingerprint, user_id)
        if existing_fp_user and fingerprint != 'unknown':
            print(f"🚫 Blocked: Fingerprint already used by user {existing_fp_user}")
            return jsonify({
                "status": "blocked",
                "verified": False,
                "reason": "multiple_accounts_same_device",
                "message": "⚠️ تم اكتشاف أكثر من حساب من نفس الجهاز. مسموح بحساب واحد فقط."
            })
        
        add_verified_user(int(user_id), ip, fingerprint, device_info, browser, screen_resolution, timezone, language)
        
        token = secrets.token_urlsafe(32)
        VERIFICATION_TOKENS[token] = {
            'user_id': user_id,
            'expires': time.time() + 600
        }
        
        print(f"✅ User {user_id} verified successfully")
        
        return jsonify({
            "status": "success",
            "verified": True,
            "user_id": user_id,
            "token": token,
            "bot_username": BOT_USERNAME,
            "message": "User verified successfully"
        })
        
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({"status": "error", "verified": False, "message": str(e)})

# ========== الصفحة الرئيسية ==========
@app.route('/', methods=['GET'])
def home():
    return jsonify({
        "status": "ok",
        "bot": BOT_USERNAME,
        "message": "Verification API is running",
        "endpoints": [
            "GET /health",
            "GET /stats",
            "GET /check?user_id=xxx",
            "GET /verify_token/<token>",
            "POST /verify"
        ]
    })

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    print(f"🚀 تشغيل الخدمة على http://localhost:{port}")
    print(f"📱 اسم البوت: {BOT_USERNAME}")
    app.run(host='0.0.0.0', port=port, debug=False)