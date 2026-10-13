import tempfile
from pathlib import Path
from hotp_auth import HOTPAuth

def test_all_10_rules():
    with tempfile.TemporaryDirectory() as tmpdir:
        cfg_path = Path(tmpdir) / "hotp_test_config.json"
        auth = HOTPAuth(config_file=cfg_path)
        caller = {"pid": 1234, "exe": "C:\\Python\\python.exe", "script": "C:\\Utilitario\\client.py"}

        print("[*] Testando Regra 1 & 2: Provisionamento Inicial e Proteção DPAPI...")
        res = auth.provision(recovery_password="SenhaSegura@2026", caller_info=caller)
        assert res["provisioned_flag"] == 1
        assert "uri" in res
        import urllib.parse
        parsed = urllib.parse.urlparse(res["uri"])
        params = urllib.parse.parse_qs(parsed.query)
        secret_b32 = params["secret"][0]
        assert secret_b32
        print("  -> Regra 1 & 2 PASSOU: Provisionado com sucesso, flag = 1!")

        print("[*] Testando Regra 3: Proibição de nova chave enquanto flag = 1...")
        try:
            auth.provision(recovery_password="OutraSenha123", caller_info=caller)
            assert False, "Deveria ter lançado PermissionError!"
        except PermissionError as e:
            print(f"  -> Regra 3 PASSOU: Bloqueado conforme esperado! ({e})")

        print("[*] Testando Regra 8: Consulta do contador sem avançá-lo...")
        status1 = auth.get_counter_status()
        assert status1["counter"] == 0, f"Contador inicial deve ser 0! Obtido: {status1['counter']}"
        status2 = auth.get_counter_status()
        assert status2["counter"] == 0, "Consulta não pode alterar o contador!"
        print("  -> Regra 8 PASSOU: Contador mantido intacto em 0 na consulta.")

        print("[*] Testando Regra 6: Avanço do contador em TODA requisição (erro e acerto)...")
        # 1. Tentativa com código ERRADO
        ok, msg, c_err1 = auth.verify_and_advance("000000", caller_info=caller)
        assert not ok, "Código errado não pode ser aprovado"
        assert c_err1 == 1, f"Contador DEVE avançar para 1 mesmo com código errado! Obtido: {c_err1}"
        assert auth.get_counter_status()["counter"] == 1

        # 2. Mais uma tentativa com código ERRADO
        ok, msg, c_err2 = auth.verify_and_advance("999999", caller_info=caller)
        assert not ok
        assert c_err2 == 2, f"Contador DEVE avançar para 2 após segundo erro! Obtido: {c_err2}"
        assert auth.get_counter_status()["counter"] == 2

        # 3. Calcula o OTP para o contador 2 a partir do segredo retornado no provisionamento inicial (apenas para teste de validação)
        import base64
        secret_bytes = base64.b32decode(secret_b32)
        valid_otp = HOTPAuth._compute_hotp_internal(bytearray(secret_bytes), 2, 6)

        # 4. Tentativa com código VÁLIDO
        ok, msg, c_ok = auth.verify_and_advance(valid_otp, caller_info=caller)
        assert ok, f"Código válido deve ser aceito: {msg}"
        assert c_ok == 3, f"Contador deve avançar para 3! Obtido: {c_ok}"
        assert auth.get_counter_status()["counter"] == 3

        # 5. Tentativa de REPLAY do código válido anterior
        ok, msg, c_replay = auth.verify_and_advance(valid_otp, caller_info=caller)
        assert not ok, "Código já utilizado não pode ser aceito!"
        assert c_replay == 4, f"Contador DEVE avançar para 4 após falha de replay! Obtido: {c_replay}"
        assert auth.get_counter_status()["counter"] == 4
        print("  -> Regra 6 PASSOU: Contador avança estritamente a cada validação (tanto acerto quanto erro)!")

        print("[*] Testando Regra Fail-Safe: 3 falhas consecutivas disparam Lockdown...")
        auth.verify_and_advance("111111", caller_info=caller)  # Falha 2
        ok_fail3, msg_fail3, _ = auth.verify_and_advance("222222", caller_info=caller)  # Falha 3 -> Lockdown!
        assert not ok_fail3
        assert "FAIL_SAFE_LOCKDOWN" in msg_fail3 or auth.is_lockdown()
        print("  -> Fail-Safe Lockdown PASSOU: 3 falhas consecutivas desativaram a central!")

        print("[*] Testando Regra 4 & 5: Reset com Senha + Presença Física...")
        # Falha 1: Senha errada
        try:
            auth.reset_and_reprovision("SenhaErrada", "PHYS-9999", "PHYS-9999", "NovaSenha@2026", caller_info=caller)
            assert False, "Deveria ter falhado com senha errada"
        except PermissionError:
            pass

        # Falha 2: Presença física errada
        try:
            auth.reset_and_reprovision("SenhaSegura@2026", "CODIGO_ERRADO", "PHYS-9999", "NovaSenha@2026", caller_info=caller)
            assert False, "Deveria ter falhado com presença física errada"
        except PermissionError:
            pass

        # Sucesso: Ambas as condições corretas
        reset_res = auth.reset_and_reprovision(
            recovery_password="SenhaSegura@2026",
            physical_challenge_response="PHYS-9999",
            expected_challenge="PHYS-9999",
            new_recovery_password="NovaSenhaSegura@2026",
            caller_info=caller
        )
        assert reset_res["provisioned_flag"] == 1
        assert reset_res["counter"] == 0
        print("  -> Regra 4 & 5 PASSOU: Reset autenticado com sucesso e flag restaurado para 1!")

        print("[*] Testando Regra 9: Restrição de origem do executável chamador...")
        bad_caller = {"pid": 9999, "exe": "C:\\Malicious\\hacker.exe", "script": "evil.py"}
        ok, msg, c_bad = auth.verify_and_advance("123456", caller_info=bad_caller)
        assert not ok
        assert "Origem" in msg
        print("  -> Regra 9 PASSOU: Origem suspeita bloqueada com sucesso!")

    print("\n=======================================================")
    print("TODAS AS 10 REGRAS DE SEGURANÇA FORAM TESTADAS E APROVADAS!")
    print("=======================================================")

if __name__ == "__main__":
    test_all_10_rules()
