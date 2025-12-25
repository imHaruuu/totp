import hmac
import hashlib
import struct
import time
import secrets


def _encode_counter(counter: int) -> bytes:
    return struct.pack('>Q', counter)


def _dynamic_truncate(hmac_result: bytes, digits: int) -> str:
    offset = hmac_result[-1] & 0x0F
    p = hmac_result[offset:offset + 4]
    binary_code = ((p[0] & 0x7F) << 24) | (p[1] << 16) | (p[2] << 8) | p[3]
    otp = binary_code % (10 ** digits)
    return str(otp).zfill(digits)


def generate_totp(
    secret: bytes,
    timestamp: int = None,
    time_step: int = 30,
    digits: int = 6,
    hash_algorithm: str = 'sha1'
) -> str:
    hash_algorithms = {
        'sha1': hashlib.sha1,
        'sha256': hashlib.sha256,
        'sha512': hashlib.sha512,
    }
    
    if hash_algorithm.lower() not in hash_algorithms:
        raise ValueError(f"Hash algorithm '{hash_algorithm}' is not supported.")
    
    hash_func = hash_algorithms[hash_algorithm.lower()]
    
    if timestamp is None:
        timestamp = int(time.time())
    
    t = timestamp // time_step
    t_bytes = _encode_counter(t)
    hmac_result = hmac.new(secret, t_bytes, hash_func).digest()
    otp = _dynamic_truncate(hmac_result, digits)
    
    return otp


def verify_totp(
    secret: bytes,
    otp: str,
    timestamp: int = None,
    time_step: int = 30,
    digits: int = 6,
    hash_algorithm: str = 'sha1',
    window: int = 1
) -> bool:
    if timestamp is None:
        timestamp = int(time.time())
    
    for offset in range(-window, window + 1):
        check_timestamp = timestamp + (offset * time_step)
        expected_otp = generate_totp(
            secret=secret,
            timestamp=check_timestamp,
            time_step=time_step,
            digits=digits,
            hash_algorithm=hash_algorithm
        )
        if hmac.compare_digest(otp, expected_otp):
            return True
    
    return False


def generate_secret(length: int = 20) -> bytes:
    return secrets.token_bytes(length)


RFC_TEST_SECRET_SHA1 = b'12345678901234567890'
RFC_TEST_SECRET_SHA256 = b'12345678901234567890123456789012'
RFC_TEST_SECRET_SHA512 = b'1234567890123456789012345678901234567890123456789012345678901234'


if __name__ == '__main__':
    print("=" * 60)
    print("TOTP RFC 6238 Test Vectors Verification")
    print("=" * 60)
    
    result1 = generate_totp(RFC_TEST_SECRET_SHA1, timestamp=59, time_step=30, digits=8, hash_algorithm='sha1')
    expected1 = "94287082"
    print(f"\nTest 1: timestamp=59 -> Expected: {expected1}, Got: {result1}, {'PASS' if result1 == expected1 else 'FAIL'}")
    
    result2 = generate_totp(RFC_TEST_SECRET_SHA1, timestamp=1111111109, time_step=30, digits=8, hash_algorithm='sha1')
    expected2 = "07081804"
    print(f"Test 2: timestamp=1111111109 -> Expected: {expected2}, Got: {result2}, {'PASS' if result2 == expected2 else 'FAIL'}")
    
    print("\n" + "=" * 60)
