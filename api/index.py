# api/index.py
from flask import Flask, request, jsonify
from flask_cors import CORS
import time
import os

app = Flask(__name__)
CORS(app)

# تخزين بيانات المستخدمين (في الذاكرة - ستفقد عند إعادة التشغيل)
# للإنتاج، استخدم قاعدة بيانات SQLite
users = {}  # user_id -> {ip, fingerprint, timestamp}
ip_to_user = {}  # ip -> set of user_ids
fingerprint_to_user = {}  # fingerprint -> set of user_ids

BOT_USERNAME = "moneybulletbot"

def init_storage():
    """تهيئة التخزين"""
    global users, ip_to_user, fingerprint_to_user
    users = {}
    ip_to_user = {}
    fingerprint_to_user = {}

@app.route('/health', methods=['GET'])
def health():
    """نقطة نهاية للتحقق من صحة الخدمة"""
    return jsonify({"status": "ok", "timestamp": time.time()})

@app.route('/check', methods=['GET'])
def check():
    """التحقق من حالة المستخدم"""
    user_id = request.args.get('user_id')
    if user_id:
        verified = user_id in users
        return jsonify({"verified": verified})
    return jsonify({"verified": False})

@app.route('/verify', methods=['POST'])
def verify():
    """معالجة طلب التحقق ومنع التعدد"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"status": "error", "verified": False, "message": "No data"})
        
        user_id = str(data.get('user_id'))
        ip = data.get('ip', 'unknown')
        fingerprint = data.get('fingerprint', 'unknown')
        user_agent = data.get('user_agent', 'unknown')
        timestamp = data.get('timestamp', int(time.time()))
        
        print(f"📥 Verification request: user={user_id}, ip={ip}, fingerprint={fingerprint[:20] if fingerprint else 'None'}...")
        
        # التحقق من صحة البيانات
        if ip == 'unknown' or fingerprint == 'unknown':
            return jsonify({
                "status": "error",
                "verified": False,
                "message": "Invalid device data"
            })
        
        # فحص التعدد: نفس IP مع حساب مختلف
        if ip in ip_to_user:
            existing_users = ip_to_user[ip]
            if user_id not in existing_users and len(existing_users) >= 1:
                print(f"🚫 BLOCKED: Multiple accounts from same IP {ip}: {existing_users} + {user_id}")
                return jsonify({
                    "status": "blocked",
                    "verified": False,
                    "reason": "multiple_accounts_same_ip",
                    "message": "⚠️ تم اكتشاف أكثر من حساب من نفس عنوان IP. مسموح بحساب واحد فقط."
                })
        
        # فحص التعدد: نفس بصمة الجهاز مع حساب مختلف
        if fingerprint in fingerprint_to_user:
            existing_fp_users = fingerprint_to_user[fingerprint]
            if user_id not in existing_fp_users and len(existing_fp_users) >= 1:
                print(f"🚫 BLOCKED: Multiple accounts from same device {fingerprint[:20]}: {existing_fp_users} + {user_id}")
                return jsonify({
                    "status": "blocked",
                    "verified": False,
                    "reason": "multiple_accounts_same_device",
                    "message": "⚠️ تم اكتشاف أكثر من حساب من نفس الجهاز. مسموح بحساب واحد فقط."
                })
        
        # تسجيل المستخدم الجديد
        if user_id not in users:
            users[user_id] = {
                'ip': ip,
                'fingerprint': fingerprint,
                'user_agent': user_agent,
                'timestamp': timestamp
            }
            if ip not in ip_to_user:
                ip_to_user[ip] = set()
            ip_to_user[ip].add(user_id)
            
            if fingerprint not in fingerprint_to_user:
                fingerprint_to_user[fingerprint] = set()
            fingerprint_to_user[fingerprint].add(user_id)
            print(f"✅ New user registered: {user_id}")
        else:
            print(f"ℹ️ Existing user: {user_id}")
        
        # إنشاء توكن (للتكامل مع البوت)
        import secrets
        token = secrets.token_urlsafe(32)
        
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
    """التحقق من صحة التوكن (للتكامل مع البوت)"""
    # تخزين مؤقت بسيط
    if token in verify_token.tokens:
        token_data = verify_token.tokens[token]
        if time.time() < token_data['expires']:
            return jsonify({"valid": True, "user_id": token_data['user_id']})
    return jsonify({"valid": False})

# تخزين مؤقت للتوكنات
verify_token.tokens = {}

# إضافة التوكن عند التحقق الناجح
original_verify = verify
def verify_with_token():
    response = original_verify()
    if response.status_code == 200 and response.json.get('verified'):
        token = secrets.token_urlsafe(32)
        verify_token.tokens[token] = {
            'user_id': response.json['user_id'],
            'expires': time.time() + 600
        }
        response.json['token'] = token
    return response

@app.route('/', methods=['GET'])
def home():
    """الصفحة الرئيسية"""
    return jsonify({
        "status": "ok",
        "bot": BOT_USERNAME,
        "message": "Verification API is running",
        "endpoints": [
            "POST /verify - Send verification data",
            "GET /check?user_id=xxx - Check user status",
            "GET /health - Health check"
        ]
    })

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    print(f"🚀 Running on http://localhost:{port}")
    app.run(host='0.0.0.0', port=port, debug=False)