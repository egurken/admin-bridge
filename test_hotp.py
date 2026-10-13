import base64
import tempfile
from pathlib import Path
import urllib.parse
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
        caller = {"pid": 1234, "exe": "C:\\Python\\python.exe", "script": "C:\\Utilitario\\client.py"}

        res = auth.provision("SenhaForte@2026", caller_info=caller)
        secret_b32 = urllib.parse.parse_qs(urllib.parse.urlparse(res["uri"]).query)["secret"][0]
        secret_bytes = base64.b32decode(secret_b32)

        # Test initial state (counter == 0)
        st = auth.get_counter_status()
        assert st["counter"] == 0

        # Test invalid OTP (advances counter 0 -> 1)
        ok, msg, c = auth.verify_and_advance("000000", caller_info=caller)
        assert not ok, "Fake OTP should fail"
        assert c == 1

        # Test valid OTP at counter 1 (advances counter 1 -> 2)
        otp_1 = HOTPAuth.compute_hotp(secret_bytes, 1, 6)
        ok, msg, new_c = auth.verify_and_advance(otp_1, caller_info=caller)
        assert ok, f"Valid OTP should succeed: {msg}"
        assert new_c == 2, f"Counter should advance to 2, got {new_c}"

        # Test single-use: replaying otp_1 must fail and advance counter 2 -> 3!
        ok, msg, c_replay = auth.verify_and_advance(otp_1, caller_info=caller)
        assert not ok, "Replaying used OTP must fail!"
        assert c_replay == 3

        # Test look-ahead window: current counter is 3, test counter 5 (within look-ahead of 5)
        otp_count_5 = HOTPAuth.compute_hotp(secret_bytes, 5, 6)
        ok, msg, new_c3 = auth.verify_and_advance(otp_count_5, caller_info=caller)
        assert ok, "OTP within look-ahead window should succeed"
        assert new_c3 == 6, f"Counter should jump to 6, got {new_c3}"

        # Old counters (1, 2, 3, 4, 5) must now all be invalid!
        otp_count_4 = HOTPAuth.compute_hotp(secret_bytes, 4, 6)
        ok, msg, _ = auth.verify_and_advance(otp_count_4, caller_info=caller)
        assert not ok, "Past counter OTP must be rejected!"

    print("[PASS] HOTP authentication flow, single-use, and look-ahead verified!")


if __name__ == "__main__":
    test_rfc4226_vectors()
    test_hotp_auth_flow()
    print("ALL TESTS PASSED!")
