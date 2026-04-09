# api/index.py
from flask import Flask, request, jsonify
from flask_cors import CORS
import time
import secrets
import os

app = Flask(__name__)
CORS(app)

BOT_USERNAME = "moneybulletbot"

# ========== تخزين مؤقت ==========
users = {}              # user_id -> {fingerprint, ip, timestamp}
fingerprint_to_user = {}  # fingerprint -> user_id
ip_to_user = {}           # ip -> set of user_ids
VERIFICATION_TOKENS = {}  # token -> {user_id, expires}

# ========== نقاط نهاية API ==========

@app.route('/health', methods=['GET'])
def health():
    """التحقق من صحة الخدمة"""
    return jsonify({"status": "ok", "timestamp": time.time()})

@app.route('/check', methods=['GET'])
def check():
    """التحقق من حالة المستخدم"""
    user_id = request.args.get('user_id')
    if user_id:
        return jsonify({"verified": user_id in users})
    return jsonify({"verified": False})

@app.route('/stats', methods=['GET'])
def stats():
    """إحصائيات النظام"""
    return jsonify({
        "total_users": len(users),
        "total_fingerprints": len(fingerprint_to_user),
        "users": list(users.keys())
    })

@app.route('/verify', methods=['POST'])
def verify():
    """التحقق من المستخدم ومنع التعدد"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"status": "error", "verified": False, "message": "No data provided"})
        
        user_id = str(data.get('user_id'))
        fingerprint = data.get('fingerprint', 'unknown')
        ip = data.get('ip', 'unknown')
        
        print(f"📥 Verification: user={user_id}, fp={fingerprint[:20] if fingerprint else 'None'}..., ip={ip}")
        
        if not user_id:
            return jsonify({"status": "error", "verified": False, "message": "No user_id"})
        
        # ========== نظام منع التعدد ==========
        
        # 1. التحقق من نفس البصمة لحساب آخر
        if fingerprint != 'unknown' and fingerprint in fingerprint_to_user:
            existing_user = fingerprint_to_user[fingerprint]
            if existing_user != user_id:
                print(f"🚫 BLOCKED: Fingerprint {fingerprint[:20]} already used by user {existing_user}")
                return jsonify({
                    "status": "blocked",
                    "verified": False,
                    "message": "⚠️ هذا الجهاز مسجل بحساب آخر. لا يمكن إنشاء أكثر من حساب."
                })
        
        # 2. التحقق من نفس IP لحساب آخر
        if ip != 'unknown' and ip in ip_to_user:
            if user_id not in ip_to_user[ip] and len(ip_to_user[ip]) >= 1:
                print(f"🚫 BLOCKED: IP {ip} already used by users {ip_to_user[ip]}")
                return jsonify({
                    "status": "blocked",
                    "verified": False,
                    "message": "⚠️ تم اكتشاف أكثر من حساب من نفس عنوان IP. مسموح بحساب واحد فقط."
                })
        
        # ========== تسجيل المستخدم ==========
        
        if user_id not in users:
            users[user_id] = {
                'fingerprint': fingerprint,
                'ip': ip,
                'timestamp': time.time()
            }
            print(f"✅ New user: {user_id}")
        
        # تسجيل البصمة
        if fingerprint != 'unknown' and fingerprint not in fingerprint_to_user:
            fingerprint_to_user[fingerprint] = user_id
        
        # تسجيل IP
        if ip != 'unknown':
            if ip not in ip_to_user:
                ip_to_user[ip] = set()
            ip_to_user[ip].add(user_id)
        
        # إنشاء توكن
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

@app.route('/verify_token/<token>', methods=['GET'])
def verify_token(token):
    """التحقق من صحة التوكن"""
    if token in VERIFICATION_TOKENS:
        token_data = VERIFICATION_TOKENS[token]
        if time.time() < token_data['expires']:
            return jsonify({"valid": True, "user_id": token_data['user_id']})
        del VERIFICATION_TOKENS[token]
    return jsonify({"valid": False})

@app.route('/reset', methods=['POST'])
def reset():
    """إعادة تعيين جميع البيانات"""
    global users, fingerprint_to_user, ip_to_user, VERIFICATION_TOKENS
    users = {}
    fingerprint_to_user = {}
    ip_to_user = {}
    VERIFICATION_TOKENS = {}
    return jsonify({"status": "success", "message": "All data reset"})

@app.route('/', methods=['GET'])
def home():
    return jsonify({
        "status": "ok",
        "bot": BOT_USERNAME,
        "message": "Verification API is running",
        "endpoints": [
            "POST /verify",
            "GET /check?user_id=xxx",
            "GET /health",
            "GET /stats",
            "POST /reset"
        ]
    })

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    print(f"🚀 Running on http://localhost:{port}")
    print(f"📱 Bot username: {BOT_USERNAME}")
    print(f"🔒 Anti-multi account system: ACTIVE")
    app.run(host='0.0.0.0', port=port, debug=False)