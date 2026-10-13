import json
import tempfile
from pathlib import Path
from hotp_auth import HOTPAuth, SecurityError

def test_all_security_rules():
    with tempfile.TemporaryDirectory() as tmpdir:
        cfg_path = Path(tmpdir) / "hotp_test_config.json"
        auth = HOTPAuth(config_file=cfg_path)
        caller = {"pid": 1234, "exe": "C:\\Python\\python.exe", "script": "C:\\Utilitario\\client.py"}

        print("[*] 1. Testando Provisionamento Inicial e Proteção Modular DPAPI...")
        res = auth.provision(recovery_password="SenhaSegura@2026", caller_info=caller)
        assert res["counter"] == 0
        assert "uri" in res
        import urllib.parse
        parsed = urllib.parse.urlparse(res["uri"])
        params = urllib.parse.parse_qs(parsed.query)
        secret_b32 = params["secret"][0]
        assert secret_b32
        assert auth.is_provisioned()
        print("  -> PASSOU: Chave provisionada e protegida com DPAPI!")

        print("[*] 2. Testando Bloqueio de Geração Duplicada (Flag=1)...")
        try:
            auth.provision(recovery_password="OutraSenha123", caller_info=caller)
            assert False, "Deveria ter lançado PermissionError!"
        except PermissionError as e:
            print(f"  -> PASSOU: Bloqueado conforme esperado! ({e})")

        print("[*] 3. Testando Assinatura de Integridade (Detecção de Adulteração Manual)...")
        # Simula edição manual externa em Bloco de Notas (adulterando o contador de 0 para 999)
        with open(cfg_path, "r", encoding="utf-8") as f:
            tampered_data = json.load(f)
        tampered_data["counter"] = 999
        with open(cfg_path, "w", encoding="utf-8") as f:
            json.dump(tampered_data, f, indent=2)

        try:
            auth._load_config_raw()
            assert False, "Deveria ter detectado adulteração e lançado SecurityError!"
        except SecurityError as e:
            print(f"  -> PASSOU: Adulteração externa detectada com sucesso! ({e})")

        # Restaura a chave para continuar os testes
        auth = HOTPAuth(config_file=cfg_path)
        res = auth.provision(recovery_password="SenhaSegura@2026", force=True, caller_info=caller)
        secret_b32 = urllib.parse.parse_qs(urllib.parse.urlparse(res["uri"]).query)["secret"][0]

        print("[*] 4. Testando Consulta Passiva do Contador sem Avançar...")
        st1 = auth.get_counter_status()
        assert st1["counter"] == 0
        st2 = auth.get_counter_status()
        assert st2["counter"] == 0
        print("  -> PASSOU: Leitura passiva mantida intacta em 0.")

        print("[*] 5. Testando Avanço Estrito do Contador (+1 em erro e acerto)...")
        # Erro 1
        ok, msg, c_err1 = auth.verify_and_advance("000000", caller_info=caller)
        assert not ok
        assert c_err1 == 1

        # Erro 2
        ok, msg, c_err2 = auth.verify_and_advance("999999", caller_info=caller)
        assert not ok
        assert c_err2 == 2

        # Acerto: calcula OTP válido para o contador 2
        import base64
        secret_bytes = base64.b32decode(secret_b32)
        valid_otp = HOTPAuth._compute_hotp_internal(bytearray(secret_bytes), 2, 6)

        ok, msg, c_ok = auth.verify_and_advance(valid_otp, caller_info=caller)
        assert ok
        assert c_ok == 3, f"Esperado c=3, obtido {c_ok}"

        # Replay do mesmo código
        ok, msg, c_replay = auth.verify_and_advance(valid_otp, caller_info=caller)
        assert not ok
        assert c_replay == 4
        print("  -> PASSOU: Contador avança estritamente a cada tentativa!")

        print("[*] 6. Testando Disjuntor Fail-Safe (Lockdown após 3 falhas consecutivas)...")
        auth.verify_and_advance("111111", caller_info=caller)  # Falha 2
        ok_fail3, msg_fail3, _ = auth.verify_and_advance("222222", caller_info=caller)  # Falha 3 -> Lockdown
        assert not ok_fail3
        assert "FAIL_SAFE_LOCKDOWN" in msg_fail3 or auth.is_lockdown()
        print("  -> PASSOU: Fail-Safe acionado após 3 falhas consecutivas!")

        print("[*] 7. Testando Reset com Destruição de Privilégios (Autodestruição)...")
        # Falha: Presença física errada
        try:
            auth.reset_and_destroy_privileges("SenhaSegura@2026", "PHYS-ERRADO", "PHYS-123456", caller)
            assert False, "Deveria ter falhado na presença física"
        except PermissionError:
            pass

        # Falha: Senha errada
        try:
            auth.reset_and_destroy_privileges("SenhaInvalida", "PHYS-123456", "PHYS-123456", caller)
            assert False, "Deveria ter falhado com senha errada"
        except PermissionError:
            pass

        # Sucesso: Ambas corretas
        destroy_res = auth.reset_and_destroy_privileges(
            recovery_password="SenhaSegura@2026",
            physical_challenge_response="PHYS-123456",
            expected_challenge="PHYS-123456",
            caller_info=caller
        )
        assert destroy_res["status"] == "destroyed"
        assert not auth.is_provisioned()
        print("  -> PASSOU: Chave destruída e privilégios revogados com sucesso!")

        print("[*] 8. Testando Bloqueio de Origem Não Autorizada...")
        bad_caller = {"pid": 9999, "exe": "C:\\Malicious\\hacker.exe", "script": "evil.py"}
        # Reprovisiona para testar caller
        auth.provision("NovaSenhaSegura@2026", caller_info=caller)
        ok, msg, _ = auth.verify_and_advance("123456", caller_info=bad_caller)
        assert not ok
        assert "Origem" in msg
        print("  -> PASSOU: Origem suspeita bloqueada com sucesso!")

        print("[*] 9. Testando Canal de Pré-Autorização (Ticket de até 45 Minutos)...")
        res_pre = auth.provision("SenhaSegura@2026", force=True, caller_info=caller)
        secret_b32_pre = urllib.parse.parse_qs(urllib.parse.urlparse(res_pre["uri"]).query)["secret"][0]
        secret_bytes_pre = base64.b32decode(secret_b32_pre)
        valid_otp_pre = HOTPAuth._compute_hotp_internal(bytearray(secret_bytes_pre), 0, 6)

        # 1. Cria ticket de pré-autorização de 45 minutos (2700s)
        ok_pre, msg_pre, data_pre = auth.create_preauth_ticket(valid_otp_pre, caller, lifetime_seconds=2700)
        assert ok_pre
        assert "token" in data_pre
        assert data_pre["expires_in"] == 2700

        # 2. Consome o ticket com sucesso
        ok_consume, msg_consume = auth.consume_preauth_ticket(data_pre["token"], caller.get("user"))
        assert ok_consume, f"Falha ao consumir ticket: {msg_consume}"

        # 3. Tentativa de reuso do mesmo ticket deve falhar (uso estritamente único)
        ok_reuse, _ = auth.consume_preauth_ticket(data_pre["token"], caller.get("user"))
        assert not ok_reuse
        print("  -> PASSOU: Pré-autorização e consumo atômico de ticket funcionam com sucesso!")

        # -------------------------------------------------------------
        # TESTE 10: Diagnóstico Passivo de Sincronia sem Avançar Contador
        # -------------------------------------------------------------
        print("[*] 10. Testando Diagnóstico Passivo de Sincronia (Sync Probe)...")
        c_before_sync = auth.get_counter_status()["counter"]
        secret_ba_test = bytearray(secret_bytes_pre)
        current_sync_otp = auth._compute_hotp_internal(secret_ba_test, c_before_sync, 6)
        future_sync_otp = auth._compute_hotp_internal(secret_ba_test, c_before_sync + 5, 6)

        # 1. Código exato do contador atual: deve reportar 'synchronized'
        diag_cur = auth.diagnose_otp_sync(current_sync_otp)
        assert diag_cur["success"]
        assert diag_cur["status"] == "synchronized"
        assert diag_cur["matched_counter"] == c_before_sync
        assert diag_cur["diff"] == 0

        # 2. Código 5 posições à frente: deve reportar 'ahead'
        diag_ahead = auth.diagnose_otp_sync(future_sync_otp)
        assert diag_ahead["success"]
        assert diag_ahead["status"] == "ahead"
        assert diag_ahead["matched_counter"] == c_before_sync + 5
        assert diag_ahead["diff"] == 5

        # 3. Código inexistente / errado: deve reportar 'not_found'
        diag_none = auth.diagnose_otp_sync("000000" if current_sync_otp != "000000" else "999999")
        assert not diag_none["success"] or diag_none["status"] == "not_found"

        # 4. CRÍTICO: Garantir que o contador NÃO se moveu após os 3 diagnósticos
        c_after_sync = auth.get_counter_status()["counter"]
        assert c_before_sync == c_after_sync, f"Contador alterado indevidamente durante probe passivo! ({c_before_sync} != {c_after_sync})"
        print("  -> PASSOU: Diagnóstico passivo detecta índices sem mover o contador!")

    print("\n=======================================================")
    print("TODOS OS REQUISITOS DE SEGURANÇA FORAM TESTADOS E APROVADOS!")
    print("=======================================================")

if __name__ == "__main__":
    test_all_security_rules()
