# 🔐 TOTP - RFC 6238 Implementation

A pure Python implementation of the TOTP (Time-Based One-Time Password) algorithm according to RFC 6238, compatible with Google Authenticator.

## ✨ Features

- ✅ 100% RFC 6238 compliant
- ✅ Google Authenticator compatible
- ✅ Constant-time comparison (prevents timing attacks)
- ✅ Supports SHA1, SHA256, SHA512
- ✅ CSPRNG secret generation
- ✅ 27 unit tests passed

## 📁 Project Structure

```
totp/
├── totp.py              # Core TOTP module
├── demo_server.py       # Flask web server with QR code
├── demo_client.py       # CLI demo client
├── test_totp.py         # Unit tests
├── requirements.txt     # Python dependencies
└── README.md            # This file
```

## 🚀 Quick Start

### 1. Install dependencies

```bash
pip install -r requirements.txt
```

### 2. Run tests

```bash
python -m pytest test_totp.py -v
```

### 3. Demo with Google Authenticator

**Option A: Web Server (Beautiful UI)**
```bash
python demo_server.py
```
Open browser → http://localhost:5000 → Scan QR with Google Authenticator

**Option B: Desktop Client (GUI)**
```bash
python demo_client.py
```
Features:
- Paste Base32 secret or `otpauth://` URI
- **Scan QR Code** from image file
- Real-time OTP generation with countdown
- Auto-extracts Issuer/Account metadata from URI

## 📖 Usage

### Basic Usage

```python
from totp import generate_totp, verify_totp, generate_secret

# Generate a cryptographically secure secret (20 bytes default)
secret = generate_secret()

# Generate OTP for current time
otp = generate_totp(secret)
print(f"OTP: {otp}")  # e.g., "123456"

# Verify OTP (with ±1 time step window by default)
is_valid = verify_totp(secret, otp)
print(f"Valid: {is_valid}")  # True
```

### Custom Parameters

```python
# Generate 8-digit OTP with SHA256
otp = generate_totp(
    secret=secret,
    digits=8,              # 6 or 8 digits
    time_step=30,          # Time step in seconds
    hash_algorithm='sha256'  # sha1, sha256, or sha512
)

# Verify with custom window (±2 time steps = ±60 seconds)
is_valid = verify_totp(secret, otp, window=2)
```

### Replay Attack Protection

```python
from totp import ReplayProtector, verify_totp_with_replay_protection

# Create a replay protector (TTL = 90 seconds default)
protector = ReplayProtector(ttl_seconds=90)

# Verify OTP with replay protection
is_valid, reason = verify_totp_with_replay_protection(
    protector=protector,
    user_id="user@example.com",
    secret=secret,
    otp=otp
)

if is_valid:
    print("✅ OTP verified successfully")
elif reason == "replay":
    print("🔄 OTP already used (replay attack detected)")
elif reason == "invalid":
    print("❌ Invalid OTP")
```

### Generate QR Code URI (for Google Authenticator)

```python
import base64

def get_provisioning_uri(secret: bytes, account: str, issuer: str) -> str:
    secret_b32 = base64.b32encode(secret).decode('utf-8').rstrip('=')
    return f"otpauth://totp/{issuer}:{account}?secret={secret_b32}&issuer={issuer}"

uri = get_provisioning_uri(secret, "user@example.com", "MyApp")
# Use this URI to generate a QR code
```

## 🧪 RFC 6238 Test Vectors

| Timestamp | Expected OTP | Result |
|----------:|--------------|--------|
| 59 | 94287082 | ✓ PASS |
| 1111111109 | 07081804 | ✓ PASS |


## 📜 References

- [RFC 6238 - TOTP](https://datatracker.ietf.org/doc/html/rfc6238)
- [RFC 4226 - HOTP](https://datatracker.ietf.org/doc/html/rfc4226)
- [RFC 2104 - HMAC](https://datatracker.ietf.org/doc/html/rfc2104)

## 📄 License

MIT License
