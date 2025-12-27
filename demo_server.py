import base64
import io
import os
from flask import Flask, render_template_string, request, jsonify, session
from totp import generate_totp, verify_totp, generate_secret, ReplayProtector

app = Flask(__name__)
app.secret_key = 'totp-demo-secret-key-for-development-only'
replay_protector = ReplayProtector(ttl_seconds=90)

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>TOTP Demo - Google Authenticator</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
            padding: 20px;
            color: #fff;
        }
        .container {
            background: rgba(255,255,255,0.1);
            backdrop-filter: blur(10px);
            border-radius: 20px;
            padding: 40px;
            max-width: 500px;
            width: 100%;
            box-shadow: 0 8px 32px rgba(0,0,0,0.3);
        }
        h1 {
            text-align: center;
            margin-bottom: 10px;
            font-size: 28px;
            background: linear-gradient(45deg, #00d2ff, #3a7bd5);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        .subtitle { text-align: center; color: #888; margin-bottom: 30px; font-size: 14px; }
        .step {
            background: rgba(255,255,255,0.05);
            border-radius: 12px;
            padding: 20px;
            margin-bottom: 20px;
        }
        .step-header { display: flex; align-items: center; margin-bottom: 15px; }
        .step-number {
            background: linear-gradient(45deg, #00d2ff, #3a7bd5);
            color: #fff;
            width: 30px;
            height: 30px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: bold;
            margin-right: 10px;
        }
        .step-title { font-weight: 600; }
        .qr-container {
            text-align: center;
            padding: 20px;
            background: #fff;
            border-radius: 10px;
            display: block;
            width: fit-content;
            margin: 0 auto;
        }
        .qr-container img { display: block; }
        .secret-key {
            background: rgba(0,0,0,0.3);
            padding: 12px;
            border-radius: 8px;
            font-family: monospace;
            font-size: 14px;
            word-break: break-all;
            margin-top: 15px;
            text-align: center;
        }
        input[type="text"] {
            width: 100%;
            padding: 15px;
            border: none;
            border-radius: 10px;
            font-size: 24px;
            text-align: center;
            letter-spacing: 8px;
            background: rgba(255,255,255,0.1);
            color: #fff;
            outline: none;
        }
        input[type="text"]::placeholder { letter-spacing: normal; color: #666; }
        button {
            width: 100%;
            padding: 15px;
            border: none;
            border-radius: 10px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            background: linear-gradient(45deg, #00d2ff, #3a7bd5);
            color: #fff;
            margin-top: 15px;
            transition: transform 0.2s, box-shadow 0.2s;
        }
        button:hover { transform: translateY(-2px); box-shadow: 0 5px 20px rgba(0,210,255,0.4); }
        .result { text-align: center; padding: 20px; border-radius: 10px; margin-top: 20px; font-size: 18px; font-weight: 600; display: none; }
        .result.success { background: rgba(0,255,150,0.2); color: #00ff96; display: block; }
        .result.error { background: rgba(255,50,50,0.2); color: #ff6b6b; display: block; }
        .result.replay { background: rgba(255,165,0,0.2); color: #ffa500; display: block; }
        .current-otp { text-align: center; margin-top: 20px; padding: 15px; background: rgba(255,255,255,0.05); border-radius: 10px; }
        .current-otp .otp { font-size: 32px; font-weight: bold; letter-spacing: 5px; color: #00d2ff; font-family: monospace; }
        .timer { margin-top: 10px; font-size: 14px; color: #888; }
        .timer-bar { height: 4px; background: rgba(255,255,255,0.1); border-radius: 2px; margin-top: 10px; overflow: hidden; }
        .timer-bar-fill { height: 100%; background: linear-gradient(45deg, #00d2ff, #3a7bd5); transition: width 1s linear; }
        .info { font-size: 12px; color: #666; margin-top: 10px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔐 TOTP Demo</h1>
        <p class="subtitle">Compatible with Google Authenticator</p>
        
        <div class="step">
            <div class="step-header">
                <div class="step-number">1</div>
                <div class="step-title">Scan QR Code with Google Authenticator</div>
            </div>
            <div class="qr-container">
                <img src="{{ qr_code }}" alt="QR Code" width="200" height="200">
            </div>
            <div class="secret-key"><strong>Secret Key:</strong><br>{{ secret_b32 }}</div>
            <p class="info">Or manually enter the Secret Key in your app</p>
        </div>
        
        <div class="step">
            <div class="step-header">
                <div class="step-number">2</div>
                <div class="step-title">Enter OTP code from app</div>
            </div>
            <form id="verify-form">
                <input type="text" id="otp-input" name="otp" placeholder="000000" maxlength="6" pattern="[0-9]{6}" autocomplete="off">
                <button type="submit">Verify</button>
            </form>
            <div id="result" class="result"></div>
        </div>
        
        <div class="step">
            <div class="step-header">
                <div class="step-number">3</div>
                <div class="step-title">Valid OTPs (window=1)</div>
            </div>
            <div class="current-otp">
                <div style="display:flex;justify-content:space-around;margin-bottom:10px;">
                    <div style="text-align:center;opacity:0.5;"><small>Previous</small><br><span id="prev-otp" style="font-family:monospace;">------</span></div>
                    <div style="text-align:center;"><small>Current</small><br><span class="otp" id="server-otp">------</span></div>
                    <div style="text-align:center;opacity:0.5;"><small>Next</small><br><span id="next-otp" style="font-family:monospace;">------</span></div>
                </div>
                <div class="timer">Expires in: <span id="countdown">30</span>s</div>
                <div class="timer-bar"><div class="timer-bar-fill" id="timer-bar"></div></div>
            </div>
        </div>
    </div>
    
    <script>
        function updateOTP() {
            fetch('/api/current-otp').then(r => r.json()).then(data => {
                document.getElementById('server-otp').textContent = data.otp;
                document.getElementById('prev-otp').textContent = data.prev_otp;
                document.getElementById('next-otp').textContent = data.next_otp;
                document.getElementById('countdown').textContent = data.remaining;
                document.getElementById('timer-bar').style.width = (data.remaining / 30 * 100) + '%';
            });
        }
        setInterval(updateOTP, 1000);
        updateOTP();
        
        document.getElementById('verify-form').addEventListener('submit', function(e) {
            e.preventDefault();
            const otp = document.getElementById('otp-input').value;
            fetch('/api/verify', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({otp: otp})
            }).then(r => r.json()).then(data => {
                const result = document.getElementById('result');
                if (data.valid) {
                    result.className = 'result success';
                    result.textContent = 'Verification successful!';
                } else if (data.error === 'replay') {
                    result.className = 'result replay';
                    result.textContent = '⚠️ Replay Attack Detected! This OTP was already used.';
                } else {
                    result.className = 'result error';
                    result.textContent = 'Invalid OTP code!';
                }
            });
        });
        
        document.getElementById('otp-input').addEventListener('input', function() {
            this.value = this.value.replace(/[^0-9]/g, '');
        });
    </script>
</body>
</html>
"""


def generate_qr_code(uri: str) -> str:
    try:
        import qrcode
        qr = qrcode.QRCode(version=1, box_size=10, border=2)
        qr.add_data(uri)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        buffer = io.BytesIO()
        img.save(buffer, format='PNG')
        buffer.seek(0)
        img_base64 = base64.b64encode(buffer.getvalue()).decode()
        return f"data:image/png;base64,{img_base64}"
    except ImportError:
        import urllib.parse
        return f"https://chart.googleapis.com/chart?chs=200x200&cht=qr&chl={urllib.parse.quote(uri)}"


def get_or_create_secret():
    if 'secret' not in session:
        session['secret'] = base64.b64encode(generate_secret(20)).decode()
    return base64.b64decode(session['secret'])


@app.route('/')
def index():
    secret = get_or_create_secret()
    secret_b32 = base64.b32encode(secret).decode().rstrip('=')
    uri = f"otpauth://totp/TOTP-Demo:demo@example.com?secret={secret_b32}&issuer=TOTP-Demo&algorithm=SHA1&digits=6&period=30"
    qr_code = generate_qr_code(uri)
    return render_template_string(HTML_TEMPLATE, qr_code=qr_code, secret_b32=secret_b32)


@app.route('/api/current-otp')
def current_otp():
    import time
    secret = get_or_create_secret()
    current_time = int(time.time())
    otp = generate_totp(secret, timestamp=current_time, digits=6)
    prev_otp = generate_totp(secret, timestamp=current_time - 30, digits=6)
    next_otp = generate_totp(secret, timestamp=current_time + 30, digits=6)
    remaining = 30 - (current_time % 30)
    secret_hash = base64.b32encode(secret).decode()[:8]
    return jsonify({
        'otp': otp,
        'prev_otp': prev_otp, 
        'next_otp': next_otp,
        'remaining': remaining,
        'timestamp': current_time,
        'secret_prefix': secret_hash
    })


@app.route('/api/verify', methods=['POST'])
def verify():
    import time
    data = request.get_json()
    otp = data.get('otp', '')
    secret = get_or_create_secret()
    current_time = int(time.time())
    
    user_id = session.get('secret', 'anonymous')
    
    is_valid = verify_totp(
        secret=secret,
        otp=otp,
        timestamp=current_time,
        digits=6,
        window=1
    )
    
    if not is_valid:
        print(f"[VERIFY] timestamp={current_time}, INVALID OTP")
        return jsonify({'valid': False, 'error': 'invalid'})
    
    if replay_protector.is_used(user_id, otp):
        print(f"[VERIFY] timestamp={current_time}, REPLAY ATTACK DETECTED!")
        return jsonify({'valid': False, 'error': 'replay'})
    
    replay_protector.mark_used(user_id, otp)
    print(f"[VERIFY] timestamp={current_time}, VALID")
    return jsonify({'valid': True, 'error': None})


if __name__ == '__main__':
    print("=" * 60)
    print("TOTP Demo Server - http://localhost:5000")
    print("=" * 60)
    app.run(host='0.0.0.0', port=5000, debug=True)
