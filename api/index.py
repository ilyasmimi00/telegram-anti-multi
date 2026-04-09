# api/index.py
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import time
import secrets
import os

app = Flask(__name__)
CORS(app)

BOT_USERNAME = "moneybulletbot"

# المسار إلى مجلد public
PUBLIC_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'public')

# ========== تخزين مؤقت ==========
users = {}
fingerprint_to_user = {}
ip_to_user = {}
VERIFICATION_TOKENS = {}

# ========== خدمة الملفات الثابتة ==========

@app.route('/')
def serve_index():
    """إرجاع صفحة التحقق HTML"""
    try:
        return send_from_directory(PUBLIC_DIR, 'index.html')
    except Exception as e:
        return jsonify({"error": str(e), "public_dir": PUBLIC_DIR})

@app.route('/<path:path>')
def serve_static(path):
    """إرجاع الملفات الثابتة"""
    try:
        return send_from_directory(PUBLIC_DIR, path)
    except Exception as e:
        return jsonify({"error": str(e)})

# ========== نقاط نهاية API ==========

@app.route('/health', methods=['GET'])
def health():
    return jsonify({"status": "ok", "timestamp": time.time()})

@app.route('/check', methods=['GET'])
def check():
    user_id = request.args.get('user_id')
    if user_id:
        return jsonify({"verified": user_id in users})
    return jsonify({"verified": False})

@app.route('/stats', methods=['GET'])
def stats():
    return jsonify({
        "total_users": len(users),
        "total_fingerprints": len(fingerprint_to_user),
        "users": list(users.keys())
    })

@app.route('/verify', methods=['POST'])
def verify():
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
        
        # منع التعدد - فحص البصمة
        if fingerprint != 'unknown' and fingerprint in fingerprint_to_user:
            existing_user = fingerprint_to_user[fingerprint]
            if existing_user != user_id:
                print(f"🚫 BLOCKED: Fingerprint already used by user {existing_user}")
                return jsonify({
                    "status": "blocked",
                    "verified": False,
                    "message": "⚠️ هذا الجهاز مسجل بحساب آخر. لا يمكن إنشاء أكثر من حساب."
                })
        
        # منع التعدد - فحص IP
        if ip != 'unknown' and ip in ip_to_user:
            if user_id not in ip_to_user[ip] and len(ip_to_user[ip]) >= 1:
                print(f"🚫 BLOCKED: IP {ip} already used by users {ip_to_user[ip]}")
                return jsonify({
                    "status": "blocked",
                    "verified": False,
                    "message": "⚠️ تم اكتشاف أكثر من حساب من نفس عنوان IP."
                })
        
        # تسجيل المستخدم
        if user_id not in users:
            users[user_id] = {'fingerprint': fingerprint, 'ip': ip, 'timestamp': time.time()}
            print(f"✅ New user: {user_id}")
        
        if fingerprint != 'unknown' and fingerprint not in fingerprint_to_user:
            fingerprint_to_user[fingerprint] = user_id
        
        if ip != 'unknown':
            if ip not in ip_to_user:
                ip_to_user[ip] = set()
            ip_to_user[ip].add(user_id)
        
        token = secrets.token_urlsafe(32)
        VERIFICATION_TOKENS[token] = {'user_id': user_id, 'expires': time.time() + 600}
        
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
    if token in VERIFICATION_TOKENS:
        token_data = VERIFICATION_TOKENS[token]
        if time.time() < token_data['expires']:
            return jsonify({"valid": True, "user_id": token_data['user_id']})
        del VERIFICATION_TOKENS[token]
    return jsonify({"valid": False})

@app.route('/api-info', methods=['GET'])
def api_info():
    return jsonify({
        "status": "ok",
        "bot": BOT_USERNAME,
        "message": "Verification API is running",
        "endpoints": [
            "POST /verify",
            "GET /check?user_id=xxx",
            "GET /health",
            "GET /stats"
        ]
    })

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    print(f"🚀 Running on http://localhost:{port}")
    print(f"📁 Public directory: {PUBLIC_DIR}")
    print(f"🔒 Anti-multi account system: ACTIVE")
    app.run(host='0.0.0.0', port=port, debug=False)