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

**Option B: CLI Client**
```bash
python demo_client.py
```

## 📖 Usage

```python
from totp import generate_totp, verify_totp, generate_secret

# Generate secret
secret = generate_secret()

# Generate OTP
otp = generate_totp(secret)
print(f"OTP: {otp}")

# Verify OTP
is_valid = verify_totp(secret, otp)
print(f"Valid: {is_valid}")
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
