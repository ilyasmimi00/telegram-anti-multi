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
users = {}
fingerprint_to_user = {}
ip_to_user = {}
VERIFICATION_TOKENS = {}

# ========== HTML المدمج ==========

VERIFY_PAGE = '''<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <script src="https://telegram.org/js/telegram-web-app.js"></script>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
            padding: 20px;
        }
        .container {
            background: rgba(255,255,255,0.1);
            backdrop-filter: blur(10px);
            border-radius: 30px;
            padding: 40px 30px;
            width: 100%;
            max-width: 400px;
            text-align: center;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
        }
        h2 { color: white; margin-bottom: 20px; }
        .ip-box {
            background: rgba(0,0,0,0.3);
            padding: 20px;
            border-radius: 20px;
            margin: 20px 0;
            color: white;
        }
        .ip-address {
            font-family: monospace;
            font-size: 20px;
            font-weight: bold;
            background: rgba(0,0,0,0.3);
            padding: 10px;
            border-radius: 10px;
            display: inline-block;
        }
        .button {
            background: white;
            color: #764ba2;
            border: none;
            padding: 16px 40px;
            border-radius: 50px;
            font-size: 18px;
            font-weight: bold;
            cursor: pointer;
            width: 100%;
            margin-top: 20px;
        }
        .spinner {
            width: 50px;
            height: 50px;
            border: 4px solid rgba(255,255,255,0.3);
            border-radius: 50%;
            border-top-color: white;
            animation: spin 1s ease-in-out infinite;
            margin: 20px auto;
        }
        @keyframes spin { to { transform: rotate(360deg); } }
        .success-icon { color: #4ade80; font-size: 70px; margin: 20px 0; }
        .error-icon { color: #f87171; font-size: 70px; margin: 20px 0; }
        .blocked-icon { color: #f59e0b; font-size: 70px; margin: 20px 0; }
    </style>
</head>
<body>
    <div class="container">
        <h2>🔐 التحقق من الجهاز</h2>
        <div id="content"><div class="spinner"></div><p>جاري التحقق...</p></div>
    </div>
    <script>
        const tg = window.Telegram.WebApp;
        tg.ready();
        tg.expand();

        const API_URL = window.location.origin + "/verify";

        function getUserId() {
            let user_id = tg.initDataUnsafe?.user?.id;
            if (user_id) return user_id;
            const urlParams = new URLSearchParams(window.location.search);
            return urlParams.get('user_id');
        }

        async function getIP() {
            try {
                const response = await fetch('https://api.ipify.org?format=json');
                const data = await response.json();
                return data.ip;
            } catch { return 'unknown'; }
        }

        function getFingerprint() {
            const components = [
                screen.width + 'x' + screen.height,
                screen.colorDepth,
                navigator.language,
                navigator.platform,
                navigator.hardwareConcurrency || 'unknown',
                navigator.deviceMemory || 'unknown',
                new Date().getTimezoneOffset(),
                navigator.userAgent,
                !!window.chrome,
                !!navigator.webdriver,
                screen.pixelDepth,
                navigator.maxTouchPoints || 0
            ];
            let hash = 0;
            const str = components.join('|');
            for (let i = 0; i < str.length; i++) {
                hash = ((hash << 5) - hash) + str.charCodeAt(i);
            }
            return Math.abs(hash).toString(16);
        }

        async function main() {
            const content = document.getElementById('content');
            const user_id = getUserId();
            
            if (!user_id) {
                content.innerHTML = '<div class="error-icon">❌</div><h3>خطأ</h3><p>لم يتم العثور على معرف المستخدم</p><button class="button" onclick="tg.close()">إغلاق</button>';
                return;
            }

            const ip = await getIP();
            const fingerprint = getFingerprint();

            content.innerHTML = `
                <div class="ip-box">
                    <div>معرف المستخدم: ${user_id}</div>
                    <div class="ip-address">${ip}</div>
                    <div style="font-size:12px;margin-top:10px;">بصمة: ${fingerprint.substring(0,20)}...</div>
                </div>
                <div class="spinner"></div>
                <p>جاري إرسال البيانات...</p>
            `;

            try {
                const response = await fetch(API_URL, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ user_id, ip, fingerprint, timestamp: Date.now() })
                });
                const result = await response.json();

                if (result.status === 'success' && result.verified === true) {
                    content.innerHTML = `
                        <div class="success-icon">✅</div>
                        <h3>تم التحقق بنجاح!</h3>
                        <div class="ip-box"><div class="ip-address">${ip}</div></div>
                        <button class="button" onclick="tg.close()">العودة للبوت</button>
                    `;
                    setTimeout(() => tg.close(), 2000);
                } else if (result.status === 'blocked') {
                    content.innerHTML = `
                        <div class="blocked-icon">⚠️</div>
                        <h3>تم رفض التحقق</h3>
                        <p>${result.message || 'تم اكتشاف أكثر من حساب'}</p>
                        <button class="button" onclick="tg.close()">إغلاق</button>
                    `;
                } else {
                    throw new Error(result.message || 'فشل التحقق');
                }
            } catch (error) {
                content.innerHTML = `
                    <div class="error-icon">❌</div>
                    <h3>فشل التحقق</h3>
                    <p>${error.message}</p>
                    <button class="button" onclick="location.reload()">إعادة المحاولة</button>
                    <button class="button" onclick="tg.close()">العودة للبوت</button>
                `;
            }
        }

        main();
    </script>
</body>
</html>'''

# ========== نقاط نهاية API ==========

@app.route('/')
def home():
    """إرجاع صفحة التحقق HTML"""
    return VERIFY_PAGE

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
            "GET / - Verification page",
            "POST /verify",
            "GET /check?user_id=xxx",
            "GET /health",
            "GET /stats"
        ]
    })

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    print(f"🚀 Running on http://localhost:{port}")
    print(f"🔒 Anti-multi account system: ACTIVE")
    app.run(host='0.0.0.0', port=port, debug=False)