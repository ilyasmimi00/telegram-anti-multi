# api/index.py
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import time
import secrets
import os

app = Flask(__name__)
CORS(app)

BOT_USERNAME = "moneybulletbot"

# المسار إلى مجلد public (مجلد الملفات الثابتة)
# Render: المجلد public موجود في نفس مستوى مجلد api
PUBLIC_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'public')

# تخزين مؤقت (بدلاً من قاعدة البيانات)
users = {}              # user_id -> {fingerprint, timestamp}
fingerprint_to_user = {} # fingerprint -> set of user_ids
VERIFICATION_TOKENS = {} # token -> {user_id, expires}

# ========== خدمة الملفات الثابتة ==========

@app.route('/')
def serve_index():
    """الصفحة الرئيسية - Mini App"""
    try:
        return send_from_directory(PUBLIC_DIR, 'index.html')
    except Exception as e:
        return jsonify({"error": str(e), "public_dir": PUBLIC_DIR})

@app.route('/<path:path>')
def serve_static(path):
    """خدمة الملفات الثابتة الأخرى"""
    try:
        return send_from_directory(PUBLIC_DIR, path)
    except Exception as e:
        return jsonify({"error": str(e)})

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

@app.route('/verify', methods=['POST'])
def verify():
    """التحقق من المستخدم ومنع التعدد"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"status": "error", "verified": False, "message": "No data"})
        
        user_id = str(data.get('user_id'))
        fingerprint = data.get('fingerprint', 'unknown')
        
        print(f"📥 Verification request: user_id={user_id}, fingerprint={fingerprint[:20] if fingerprint else 'None'}...")
        
        if not user_id:
            return jsonify({"status": "error", "verified": False, "message": "No user_id"})
        
        # منع التعدد: نفس البصمة مع حساب مختلف
        if fingerprint in fingerprint_to_user:
            existing_users = fingerprint_to_user[fingerprint]
            if user_id not in existing_users:
                print(f"🚫 Blocked: Fingerprint already used by {existing_users}")
                return jsonify({
                    "status": "blocked",
                    "verified": False,
                    "message": "⚠️ هذا الجهاز مسجل بحساب آخر. لا يمكن إنشاء أكثر من حساب."
                })
        
        # تسجيل مستخدم جديد
        if user_id not in users:
            users[user_id] = {
                'fingerprint': fingerprint,
                'timestamp': time.time()
            }
            if fingerprint not in fingerprint_to_user:
                fingerprint_to_user[fingerprint] = set()
            fingerprint_to_user[fingerprint].add(user_id)
            print(f"✅ New user registered: {user_id}")
        else:
            print(f"ℹ️ Existing user: {user_id}")
        
        # إنشاء توكن
        token = secrets.token_urlsafe(32)
        VERIFICATION_TOKENS[token] = {
            'user_id': user_id,
            'expires': time.time() + 600  # 10 دقائق
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

@app.route('/stats', methods=['GET'])
def stats():
    """إحصائيات المستخدمين"""
    return jsonify({
        "total_users": len(users),
        "total_fingerprints": len(fingerprint_to_user),
        "users": list(users.keys())
    })

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    print(f"🚀 Running on http://localhost:{port}")
    print(f"📁 Public directory: {PUBLIC_DIR}")
    print(f"📱 Bot username: {BOT_USERNAME}")
    app.run(host='0.0.0.0', port=port, debug=False)