import tempfile
from pathlib import Path
from hotp_auth import HOTPAuth

def test_rfc4226_vectors():
    # RFC 4226 Appendix D vectors
    secret = b"12345678901234567890"
    expected = [
        "755224", "287082", "359152", "969429", "338314",
        "254676", "287922", "162583", "399871", "520489"
    ]
    for i, exp in enumerate(expected):
        calc = HOTPAuth.compute_hotp(secret, i, 6)
        assert calc == exp, f"Mismatch at counter {i}: got {calc}, expected {exp}"
    print("[PASS] RFC 4226 Appendix D vectors verified!")

def test_hotp_auth_flow():
    with tempfile.TemporaryDirectory() as tmpdir:
        cfg_path = Path(tmpdir) / "hotp_config.json"
        auth = HOTPAuth(config_file=cfg_path)
        
        # Test initial state
        info = auth.get_current_info()
        assert info["counter"] == 1
        initial_otp = info["current_otp"]
        
        # Test invalid OTP
        ok, msg, c = auth.verify_and_advance("000000")
        assert not ok, "Fake OTP should fail"
        
        # Test valid OTP
        ok, msg, new_c = auth.verify_and_advance(initial_otp)
        assert ok, f"Valid OTP should succeed: {msg}"
        assert new_c == 2, f"Counter should advance to 2, got {new_c}"
        
        # Test single-use: replaying initial_otp must fail!
        ok, msg, c = auth.verify_and_advance(initial_otp)
        assert not ok, "Replaying used OTP must fail!"
        
        # Test next valid OTP
        info2 = auth.get_current_info()
        assert info2["counter"] == 2
        ok, msg, new_c2 = auth.verify_and_advance(info2["current_otp"])
        assert ok, "Next OTP should succeed"
        assert new_c2 == 3
        
        # Test look-ahead window
        # Current counter is 3. Let's calculate OTP for counter 5 (within look-ahead of 5)
        secret_bytes = auth.get_secret_bytes()
        otp_count_5 = HOTPAuth.compute_hotp(secret_bytes, 5, 6)
        ok, msg, new_c3 = auth.verify_and_advance(otp_count_5)
        assert ok, "OTP within look-ahead window should succeed"
        assert new_c3 == 6, f"Counter should jump to 6, got {new_c3}"
        
        # Old counters (1, 2, 3, 4, 5) must now all be invalid!
        otp_count_4 = HOTPAuth.compute_hotp(secret_bytes, 4, 6)
        ok, msg, _ = auth.verify_and_advance(otp_count_4)
        assert not ok, "Past counter OTP must be rejected!"
        
    print("[PASS] HOTP authentication flow, single-use, and look-ahead verified!")

if __name__ == "__main__":
    test_rfc4226_vectors()
    test_hotp_auth_flow()
    print("ALL TESTS PASSED!")
