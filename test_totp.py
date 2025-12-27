import pytest
import time
from totp import (
    generate_totp, verify_totp, generate_secret, _encode_counter, _dynamic_truncate,
    RFC_TEST_SECRET_SHA1, RFC_TEST_SECRET_SHA256, RFC_TEST_SECRET_SHA512,
    ReplayProtector, verify_totp_with_replay_protection,
)


class TestEncodeCounter:
    def test_encode_zero(self):
        assert _encode_counter(0) == b'\x00\x00\x00\x00\x00\x00\x00\x00'

    def test_encode_one(self):
        assert _encode_counter(1) == b'\x00\x00\x00\x00\x00\x00\x00\x01'

    def test_encode_large_number(self):
        t = 1111111109 // 30
        result = _encode_counter(t)
        assert len(result) == 8
        assert result == t.to_bytes(8, byteorder='big')


class TestRFC6238TestVectors:
    def test_sha1_timestamp_59_8digits(self):
        result = generate_totp(RFC_TEST_SECRET_SHA1, timestamp=59, time_step=30, digits=8, hash_algorithm='sha1')
        assert result == "94287082"

    def test_sha1_timestamp_1111111109_8digits(self):
        result = generate_totp(RFC_TEST_SECRET_SHA1, timestamp=1111111109, time_step=30, digits=8, hash_algorithm='sha1')
        assert result == "07081804"
        assert len(result) == 8
        assert result[0] == '0'


class TestZeroPadding:
    def test_output_length_6_digits(self):
        assert len(generate_totp(generate_secret(), timestamp=12345, digits=6)) == 6

    def test_output_length_8_digits(self):
        assert len(generate_totp(generate_secret(), timestamp=12345, digits=8)) == 8

    def test_otp_is_string(self):
        assert isinstance(generate_totp(generate_secret(), timestamp=12345), str)

    def test_otp_all_digits(self):
        assert generate_totp(generate_secret(), timestamp=12345).isdigit()


class TestVerifyTOTP:
    def test_verify_valid_otp(self):
        otp = generate_totp(RFC_TEST_SECRET_SHA1, timestamp=59, digits=8)
        assert verify_totp(RFC_TEST_SECRET_SHA1, otp, timestamp=59, digits=8) is True

    def test_verify_invalid_otp(self):
        assert verify_totp(RFC_TEST_SECRET_SHA1, "00000000", timestamp=59, digits=8) is False

    def test_verify_with_window(self):
        otp = generate_totp(RFC_TEST_SECRET_SHA1, timestamp=1000, digits=6)
        assert verify_totp(RFC_TEST_SECRET_SHA1, otp, timestamp=1030, digits=6, window=1) is True

    def test_verify_outside_window(self):
        otp = generate_totp(RFC_TEST_SECRET_SHA1, timestamp=1000, digits=6)
        assert verify_totp(RFC_TEST_SECRET_SHA1, otp, timestamp=1090, digits=6, window=1) is False


class TestConstantTimeComparison:
    def test_uses_hmac_compare_digest(self):
        iterations = 100
        start1 = time.perf_counter()
        for _ in range(iterations):
            verify_totp(RFC_TEST_SECRET_SHA1, "00000000", timestamp=59, digits=8)
        time1 = time.perf_counter() - start1
        
        start2 = time.perf_counter()
        for _ in range(iterations):
            verify_totp(RFC_TEST_SECRET_SHA1, "99999999", timestamp=59, digits=8)
        time2 = time.perf_counter() - start2
        
        ratio = max(time1, time2) / min(time1, time2)
        assert ratio < 1.5


class TestHashAlgorithms:
    def test_sha1_works(self):
        assert len(generate_totp(RFC_TEST_SECRET_SHA1, timestamp=59, hash_algorithm='sha1')) == 6

    def test_sha256_works(self):
        assert len(generate_totp(RFC_TEST_SECRET_SHA256, timestamp=59, hash_algorithm='sha256')) == 6

    def test_sha512_works(self):
        assert len(generate_totp(RFC_TEST_SECRET_SHA512, timestamp=59, hash_algorithm='sha512')) == 6

    def test_invalid_algorithm_raises(self):
        with pytest.raises(ValueError):
            generate_totp(RFC_TEST_SECRET_SHA1, timestamp=59, hash_algorithm='md5')


class TestSecretGeneration:
    def test_default_length(self):
        assert len(generate_secret()) == 20

    def test_custom_length(self):
        assert len(generate_secret(length=32)) == 32

    def test_randomness(self):
        assert generate_secret() != generate_secret()


class TestAdditionalRFC6238Vectors:
    def test_time_step_boundary(self):
        assert generate_totp(RFC_TEST_SECRET_SHA1, timestamp=30, digits=8) == generate_totp(RFC_TEST_SECRET_SHA1, timestamp=59, digits=8)

    def test_different_time_steps(self):
        assert generate_totp(RFC_TEST_SECRET_SHA1, timestamp=59, digits=8) != generate_totp(RFC_TEST_SECRET_SHA1, timestamp=60, digits=8)


class TestReplayProtection:
    def test_same_otp_rejected_on_reuse(self):
        protector = ReplayProtector(ttl_seconds=90)
        secret = RFC_TEST_SECRET_SHA1
        otp = generate_totp(secret, timestamp=59, digits=6)
        
        is_valid, error = verify_totp_with_replay_protection(
            protector, "user1", secret, otp, timestamp=59, digits=6
        )
        assert is_valid is True
        assert error == ""
        
        is_valid, error = verify_totp_with_replay_protection(
            protector, "user1", secret, otp, timestamp=59, digits=6
        )
        assert is_valid is False
        assert error == "replay"
    
    def test_otp_cleanup_after_expiry(self):
        protector = ReplayProtector(ttl_seconds=1)
        protector.mark_used("user1", "123456")
        
        assert protector.is_used("user1", "123456") is True
        
        time.sleep(1.1)
        
        assert protector.is_used("user1", "123456") is False
    
    def test_different_users_same_otp_allowed(self):
        protector = ReplayProtector(ttl_seconds=90)
        secret = RFC_TEST_SECRET_SHA1
        otp = generate_totp(secret, timestamp=59, digits=6)
        
        is_valid, _ = verify_totp_with_replay_protection(
            protector, "user1", secret, otp, timestamp=59, digits=6
        )
        assert is_valid is True
        
        is_valid, _ = verify_totp_with_replay_protection(
            protector, "user2", secret, otp, timestamp=59, digits=6
        )
        assert is_valid is True
    
    def test_invalid_otp_not_marked_as_used(self):
        protector = ReplayProtector(ttl_seconds=90)
        secret = RFC_TEST_SECRET_SHA1
        
        is_valid, error = verify_totp_with_replay_protection(
            protector, "user1", secret, "000000", timestamp=59, digits=6
        )
        assert is_valid is False
        assert error == "invalid"
        
        assert protector.is_used("user1", "000000") is False


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
