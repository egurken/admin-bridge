import base64 as b64_mod
import ctypes
import hashlib
import json
import tempfile
import time
import urllib.parse
from pathlib import Path
from hotp_auth import HOTPAuth, SecurityError
from hotp_crypto import (
    verify_owner_anchor,
    verify_owner_password,
    generate_mutual_confirmation_code,
    protect_transit_token,
    unprotect_transit_token,
)
from app import is_self_targeting_command


def test_all_security_rules():
    with tempfile.TemporaryDirectory() as tmpdir:
        cfg_path = Path(tmpdir) / "hotp_test_config.json"
        auth = HOTPAuth(config_file=cfg_path)
        caller = {"pid": 1234, "exe": "C:\\Python\\python.exe", "script": "C:\\Utilitario\\client.py"}

        print("[*] 1. Testando Provisionamento Inicial e Proteção Modular DPAPI...")
        res = auth.provision(recovery_password="SenhaSegura@2026", caller_info=caller)
        assert res["counter"] == 0
        assert "uri" in res
        parsed = urllib.parse.urlparse(res["uri"])
        params = urllib.parse.parse_qs(parsed.query)
        secret_b32 = params["secret"][0]
        assert secret_b32
        assert auth.is_provisioned()
        print("  -> PASSOU: Chave provisionada e protegida com DPAPI!")

        print("[*] 2. Testando Bloqueio de Geração Duplicada - Flag=1...")
        try:
            auth.provision(recovery_password="OutraSenha123", caller_info=caller)
            assert False, "Deveria ter lançado PermissionError!"
        except PermissionError as e:
            print(f"  -> PASSOU: Bloqueado conforme esperado! - {e}")

        print("[*] 3. Testando Assinatura de Integridade - Detecção de Adulteração Manual...")
        if hasattr(ctypes, "windll"):
            try:
                ctypes.windll.kernel32.SetFileAttributesW(str(cfg_path), 0x80)
            except Exception:
                pass
        with open(cfg_path, "r", encoding="utf-8") as f:
            tampered_data = json.load(f)
        tampered_data["counter"] = 999
        with open(cfg_path, "w", encoding="utf-8") as f:
            json.dump(tampered_data, f, indent=2)

        try:
            auth._load_config_raw()
            assert False, "Deveria ter detectado adulteração e lançado SecurityError!"
        except SecurityError as e:
            print(f"  -> PASSOU: Adulteração externa detectada com sucesso! - {e}")

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
        ok, msg, c_err1 = auth.verify_and_advance("000000", caller_info=caller)
        assert not ok
        assert c_err1 == 1

        ok, msg, c_err2 = auth.verify_and_advance("999999", caller_info=caller)
        assert not ok
        assert c_err2 == 2

        secret_bytes = b64_mod.b32decode(secret_b32)
        valid_otp = HOTPAuth._compute_hotp_internal(bytearray(secret_bytes), 2, 6)

        ok, msg, c_ok = auth.verify_and_advance(valid_otp, caller_info=caller)
        assert ok
        assert c_ok == 3, f"Esperado c=3, obtido {c_ok}"

        ok, msg, c_replay = auth.verify_and_advance(valid_otp, caller_info=caller)
        assert not ok
        assert c_replay == 4
        print("  -> PASSOU: Contador avança estritamente a cada tentativa!")

        print("[*] 6. Testando Disjuntor Fail-Safe (Lockdown após 3 falhas consecutivas)...")
        auth.verify_and_advance("111111", caller_info=caller)
        ok_fail3, msg_fail3, _ = auth.verify_and_advance("222222", caller_info=caller)
        assert not ok_fail3
        assert "FAIL_SAFE_LOCKDOWN" in msg_fail3 or auth.is_lockdown()
        print("  -> PASSOU: Fail-Safe acionado após 3 falhas consecutivas!")

        print("[*] 7. Testando Reset com Destruição de Privilégios (Autodestruição)...")
        try:
            auth.reset_and_destroy_privileges("SenhaSegura@2026", "PHYS-ERRADO", "PHYS-123456", caller)
            assert False, "Deveria ter falhado na presença física"
        except PermissionError:
            pass

        try:
            auth.reset_and_destroy_privileges("SenhaInvalida", "PHYS-123456", "PHYS-123456", caller)
            assert False, "Deveria ter falhado com senha errada"
        except PermissionError:
            pass

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
        auth.provision("NovaSenhaSegura@2026", caller_info=caller)
        ok, msg, _ = auth.verify_and_advance("123456", caller_info=bad_caller)
        assert not ok
        assert "Origem" in msg
        print("  -> PASSOU: Origem suspeita bloqueada com sucesso!")

        print("[*] 9. Testando Canal de Pré-Autorização (Ticket de até 45 Minutos)...")
        res_pre = auth.provision("SenhaSegura@2026", force=True, caller_info=caller)
        secret_b32_pre = urllib.parse.parse_qs(urllib.parse.urlparse(res_pre["uri"]).query)["secret"][0]
        secret_bytes_pre = b64_mod.b32decode(secret_b32_pre)
        valid_otp_pre = HOTPAuth._compute_hotp_internal(bytearray(secret_bytes_pre), 0, 6)

        ok_pre, msg_pre, data_pre = auth.create_preauth_ticket(valid_otp_pre, caller, lifetime_seconds=2700)
        assert ok_pre
        assert "token" in data_pre
        assert data_pre["expires_in"] == 2700

        ok_consume, msg_consume = auth.consume_preauth_ticket(data_pre["token"], caller.get("user"))
        assert ok_consume, f"Falha ao consumir ticket: {msg_consume}"

        ok_reuse, _ = auth.consume_preauth_ticket(data_pre["token"], caller.get("user"))
        assert ok_reuse, "Falha ao reutilizar ticket valido dentro dos 45 minutos"

        ok_bad_user, _ = auth.consume_preauth_ticket(data_pre["token"], "hacker_user")
        assert not ok_bad_user

        ok_rev, _ = auth.revoke_preauth_ticket()
        assert ok_rev
        ok_after_rev, _ = auth.consume_preauth_ticket(data_pre["token"], caller.get("user"))
        assert not ok_after_rev
        print("  -> PASSOU: Modo Auth de 45 minutos com multi-execucao e revogacao imediata validado com sucesso!")

        print("[*] 10. Testando Sincronização HOTP com Atualização Estrita do Contador...")
        res_sync = auth.provision("SenhaSync@2026", force=True, caller_info=caller)
        secret_b32_s = urllib.parse.parse_qs(urllib.parse.urlparse(res_sync["uri"]).query)["secret"][0]
        secret_ba_s = bytearray(b64_mod.b32decode(secret_b32_s))

        assert auth.get_counter_status()["counter"] == 0

        otp_0 = auth._compute_hotp_internal(secret_ba_s, 0, 6)
        diag_0 = auth.diagnose_otp_sync(otp_0)
        assert diag_0["success"]
        assert diag_0["status"] == "synchronized"
        assert diag_0["matched_counter"] == 0
        assert diag_0["next_counter"] == 1
        assert auth.get_counter_status()["counter"] == 1
        print("  -> Subteste 10.1 PASSOU: Código no atual (0) avança contador para 1!")

        otp_6 = auth._compute_hotp_internal(secret_ba_s, 6, 6)
        diag_req = auth.diagnose_otp_sync(otp_6, allow_lookahead=False)
        assert not diag_req["success"]
        assert diag_req["status"] == "prompt_lookahead"
        assert auth.get_counter_status()["counter"] == 1

        diag_ahead = auth.diagnose_otp_sync(otp_6, allow_lookahead=True)
        assert diag_ahead["success"]
        assert diag_ahead["status"] == "ahead"
        assert diag_ahead["matched_counter"] == 6
        assert diag_ahead["next_counter"] == 7
        assert auth.get_counter_status()["counter"] == 7
        print("  -> Subteste 10.2 PASSOU: Código à frente (6) exige autorização e avança após confirmação!")

        otp_2 = auth._compute_hotp_internal(secret_ba_s, 2, 6)
        diag_past = auth.diagnose_otp_sync(otp_2)
        assert diag_past["success"]
        assert diag_past["status"] == "behind"
        assert diag_past["matched_counter"] == 2
        assert diag_past["next_counter"] == 7
        assert auth.get_counter_status()["counter"] == 7
        print("  -> Subteste 10.3 PASSOU: Código anterior (2) detectado sem recuar o computador!")

        diag_denied = auth.diagnose_otp_sync("000000", allow_lookahead=False)
        assert not diag_denied["success"]
        assert diag_denied["status"] == "prompt_lookahead"
        assert auth.get_counter_status()["counter"] == 7

        diag_exhausted = auth.diagnose_otp_sync("000000", allow_lookahead=True)
        assert not diag_exhausted["success"]
        assert diag_exhausted["status"] == "not_found"
        assert diag_exhausted["next_counter"] == 17
        assert auth.get_counter_status()["counter"] == 17
        print("  -> Subteste 10.4 PASSOU: Esgotamento das 10 posições salta contador 10 posições para 17!")

        print("[*] 11. Testando Validação Obrigatória de OTP no Pareamento Inicial...")
        res_init = auth.provision("SenhaMestra@2026", force=True, caller_info=caller)
        secret_b32_init = urllib.parse.parse_qs(urllib.parse.urlparse(res_init["uri"]).query)["secret"][0]
        secret_ba_init = bytearray(b64_mod.b32decode(secret_b32_init))
        valid_otp_0 = auth._compute_hotp_internal(secret_ba_init, 0, 6)

        ok_bad, _ = auth.verify_and_finalize_initial_otp("000000" if valid_otp_0 != "000000" else "111111")
        assert not ok_bad

        ok_good, _ = auth.verify_and_finalize_initial_otp(valid_otp_0)
        assert ok_good
        assert auth.get_counter_status()["counter"] == 1
        print("  -> PASSOU: Pareamento inicial exige e valida OTP com sucesso!")

        print("[*] 12. Testando Reparo de Adulteração Protegido por Senha Mestra...")
        if hasattr(ctypes, "windll"):
            try:
                ctypes.windll.kernel32.SetFileAttributesW(str(cfg_path), 0x80)
            except Exception:
                pass
        with open(cfg_path, "r", encoding="utf-8") as f:
            tampered_data2 = json.load(f)
        tampered_data2["counter"] = 777
        with open(cfg_path, "w", encoding="utf-8") as f:
            json.dump(tampered_data2, f, indent=2)

        st_tampered = auth.get_counter_status()
        assert st_tampered["status_text"] == "Bloqueado por adulteração"

        ok_rep_bad, _ = auth.repair_corrupted_installation("SenhaErrada123")
        assert not ok_rep_bad

        ok_rep_good, _ = auth.repair_corrupted_installation("SenhaMestra@2026")
        assert ok_rep_good
        print("  -> PASSOU: Status Bloqueado por adulteração limpo e reparo protegido por senha mestra!")

        print("[*] 13. Testando Bloqueio de Comandos Auto-Direcionados (Incluindo Evasões Avançadas)...")
        assert is_self_targeting_command(r"dir C:\Utilitario")
        assert is_self_targeting_command(r"cat c:/utilitario/config/hotp_config.json")
        assert is_self_targeting_command(r"cd UTILIT~1")
        assert is_self_targeting_command(r"schtasks /delete /tn AdminBridge /f")
        assert is_self_targeting_command(r"powershell -ExecutionPolicy Bypass -File C:\Utilitario\AdminBridge.exe")
        # Novas evasões bloqueadas:
        assert is_self_targeting_command(r'dir C:\Util"i"tario')
        assert is_self_targeting_command(r"dir C:\Util^itario")
        assert is_self_targeting_command(r"Get-ChildItem C:\Uti*\config")
        assert is_self_targeting_command(r"type config\*.json")
        assert is_self_targeting_command(r"del queue\requests\*.json")
        b64_evil = b64_mod.b64encode(r"Get-ChildItem C:\Utilitario".encode("utf-16le")).decode("ascii")
        assert is_self_targeting_command(f"powershell.exe -enc {b64_evil}")
        assert is_self_targeting_command(f"powershell.exe -e {b64_evil}")
        assert not is_self_targeting_command("ipconfig /all")
        assert not is_self_targeting_command("netstat -ano")
        print("  -> PASSOU: Comandos auto-direcionados, curingas, caminhos relativos e ofuscações bloqueados!")

        print("[*] 14. Testando Âncora Soberana Ed25519 e Detecção de Adulteração de Binário...")
        fake_exe = Path(tmpdir) / "AdminBridge.exe"
        fake_exe.write_bytes(b"MZ_ORIGINAL_SIGNED_BINARY_V1")

        res_anchor = auth.provision("SenhaSoberana@2026", force=True, caller_info=caller)
        anchor_file = auth.config_dir / "owner_anchor.json"
        assert anchor_file.exists()

        ok_anc, msg_anc = verify_owner_anchor(anchor_file, auth.config_dir)
        assert ok_anc, f"Falha na verificacao da ancora: {msg_anc}"
        assert verify_owner_password("SenhaSoberana@2026", anchor_file, auth.config_dir)
        assert not verify_owner_password("SenhaIncorreta@123", anchor_file, auth.config_dir)

        # Simula um Administrador alterando o executável AdminBridge.exe na pasta
        fake_exe.write_bytes(b"MZ_MODIFIED_MALICIOUS_BINARY_V2")
        ok_anc_tampered, msg_anc_tampered = verify_owner_anchor(anchor_file, auth.config_dir)
        assert not ok_anc_tampered, "Deveria detectar modificação do executável AdminBridge.exe!"
        assert "static_mesh_tampered" in msg_anc_tampered

        # _load_config_raw também deve bloquear imediatamente a execução
        try:
            auth._load_config_raw()
            assert False, "Deveria bloquear carregamento após modificação do AdminBridge.exe!"
        except SecurityError:
            pass

        # Restaura o binário original e verifica que volta a ser aceito
        fake_exe.write_bytes(b"MZ_ORIGINAL_SIGNED_BINARY_V1")
        ok_anc_restored, _ = verify_owner_anchor(anchor_file, auth.config_dir)
        assert ok_anc_restored
        print("  -> PASSOU: Substituição do executável AdminBridge.exe detectada e bloqueada pela âncora Ed25519!")

        print("[*] 15. Testando Ciclo de 14 Dias e Renovação de Senha Mestra...")
        ok_14d_init, elapsed_init = auth.check_owner_password_status()
        assert ok_14d_init
        assert elapsed_init < 60

        with open(cfg_path, "r", encoding="utf-8") as f:
            cfg_14d = json.load(f)
        cfg_14d["last_owner_password_verified_at"] = time.time() - (15 * 86400)
        auth._save_config_raw(cfg_14d)

        ok_14d_exp, elapsed_exp = auth.check_owner_password_status()
        assert not ok_14d_exp, "Ciclo de 14 dias deveria constar como expirado"
        assert elapsed_exp >= 15 * 86400

        ok_renew_bad = auth.refresh_owner_password_verification("SenhaErrada")
        assert not ok_renew_bad

        ok_renew_good = auth.refresh_owner_password_verification("SenhaSoberana@2026")
        assert ok_renew_good

        ok_14d_renewed, _ = auth.check_owner_password_status()
        assert ok_14d_renewed
        print("  -> PASSOU: Ciclo de 14 dias detecta expiração e renova com Senha Mestra!")

        print("[*] 16. Testando Contra-Senha de Confirmação Mútua no Modo Auth...")
        secret_b32_16 = urllib.parse.parse_qs(urllib.parse.urlparse(res_anchor["uri"]).query)["secret"][0]
        secret_ba_16 = bytearray(b64_mod.b32decode(secret_b32_16))
        valid_otp_16 = auth._compute_hotp_internal(secret_ba_16, 0, 6)

        ok_ticket_16, msg_ticket_16, data_ticket_16 = auth.create_preauth_ticket(valid_otp_16, caller)
        assert ok_ticket_16
        assert "mutual_confirmation_code" in data_ticket_16
        m_code = data_ticket_16["mutual_confirmation_code"]
        assert len(m_code) == 6
        expected_m_code = generate_mutual_confirmation_code(bytes(secret_ba_16), valid_otp_16)
        assert m_code == expected_m_code
        print("  -> PASSOU: Contra-senha mútua gerada e validada matematicamente no modo auth!")

        print("[*] 17. Testando Proteção DPAPI de OTP em Trânsito e Anti-TOCTOU na Fila...")
        req_id = "req-12345"
        legit_code = "ipconfig /flushdns"
        legit_hash = hashlib.sha256(legit_code.encode("utf-8")).hexdigest()
        enc_otp = protect_transit_token("654321", req_id, legit_hash)
        assert enc_otp and "654321" not in enc_otp

        # Descriptografia legítima com mesmo req_id e code_hash funciona
        dec_otp = unprotect_transit_token(enc_otp, req_id, legit_hash)
        assert dec_otp == "654321"

        # Se um atacante na fila alterar o comando (code_hash diferente), a descriptografia falha!
        evil_hash = hashlib.sha256(b"net localgroup administrators attacker /add").hexdigest()
        assert unprotect_transit_token(enc_otp, req_id, evil_hash) is None
        print("  -> PASSOU: OTP protegido em trânsito e vinculado criptograficamente ao comando!")

    print("\n=======================================================")
    print("TODOS OS 17 REQUISITOS DE SEGURANÇA FORAM TESTADOS E APROVADOS!")
    print("=======================================================")


if __name__ == "__main__":
    test_all_security_rules()
