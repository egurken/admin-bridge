import json
import tempfile
import time
from pathlib import Path
from hotp_auth import HOTPAuth, SecurityError
from hotp_crypto import (
    verify_owner_anchor, verify_owner_password, generate_mutual_confirmation_code
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
        import urllib.parse
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
        # Simula edição manual externa em Bloco de Notas adulterando o contador de 0 para 999
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
        # TESTE 10: Sincronização Inteligente com Avanço Ativo e Salto do Contador
        # -------------------------------------------------------------
        print("[*] 10. Testando Sincronização HOTP com Atualização Estrita do Contador...")
        # Reprovisiona para iniciar em c=0
        res_sync = auth.provision("SenhaSync@2026", force=True, caller_info=caller)
        secret_b32_s = urllib.parse.parse_qs(urllib.parse.urlparse(res_sync["uri"]).query)["secret"][0]
        secret_ba_s = bytearray(base64.b32decode(secret_b32_s))

        assert auth.get_counter_status()["counter"] == 0

        # Caso 1: Código coincide no contador atual (0). Contador avança obrigatoriamente para 1 (+1).
        otp_0 = auth._compute_hotp_internal(secret_ba_s, 0, 6)
        diag_0 = auth.diagnose_otp_sync(otp_0)
        assert diag_0["success"]
        assert diag_0["status"] == "synchronized"
        assert diag_0["matched_counter"] == 0
        assert diag_0["next_counter"] == 1
        assert "(" not in diag_0["message"] and ")" not in diag_0["message"]
        assert auth.get_counter_status()["counter"] == 1, "Contador em disco deve ter avançado para 1"
        print("  -> Subteste 10.1 PASSOU: Código no atual (0) avança contador para 1!")

        # Caso 2: Celular está à frente (por exemplo celular na posição 6, computador em 1).
        # Deve buscar de 2 até 11, encontrar em 6, interromper a busca e pular para 6 + 1 = 7.
        # Caso 2: Codigo a frente exige allow_lookahead=True.
        # Sem autorizacao previa [allow_lookahead=False], o sistema recusa saltar e solicita confirmacao.
        otp_6 = auth._compute_hotp_internal(secret_ba_s, 6, 6)
        diag_req = auth.diagnose_otp_sync(otp_6, allow_lookahead=False)
        assert not diag_req["success"]
        assert diag_req["status"] == "prompt_lookahead"
        assert auth.get_counter_status()["counter"] == 1, "Contador deve permanecer intacto em 1"

        # Com autorizacao expressa [allow_lookahead=True], pesquisa e avanca para 7
        diag_ahead = auth.diagnose_otp_sync(otp_6, allow_lookahead=True)
        assert diag_ahead["success"]
        assert diag_ahead["status"] == "ahead"
        assert diag_ahead["matched_counter"] == 6
        assert diag_ahead["next_counter"] == 7
        assert "(" not in diag_ahead["message"] and ")" not in diag_ahead["message"]
        assert auth.get_counter_status()["counter"] == 7, "Contador em disco deve ter saltado para 7"
        print("  -> Subteste 10.2 PASSOU: Código à frente (6) exige autorização e avança após confirmação!")

        # Caso 3: Codigo do passado [posicao 2 enquanto computador esta em 7].
        # A busca sequencial reversa detecta a posicao 2.
        # Nao recua o contador do computador e reporta codigo expirado.
        otp_2 = auth._compute_hotp_internal(secret_ba_s, 2, 6)
        diag_past = auth.diagnose_otp_sync(otp_2)
        assert diag_past["success"]
        assert diag_past["status"] == "behind"
        assert diag_past["matched_counter"] == 2
        assert diag_past["next_counter"] == 7
        assert "(" not in diag_past["message"] and ")" not in diag_past["message"]
        assert auth.get_counter_status()["counter"] == 7, "Contador em disco deve permanecer em 7"
        print("  -> Subteste 10.3 PASSOU: Código anterior (2) detectado sem recuar o computador!")

        # Caso 4: Codigo nao encontrado e usuario recusa busca a frente
        diag_denied = auth.diagnose_otp_sync("000000", allow_lookahead=False)
        assert not diag_denied["success"]
        assert diag_denied["status"] == "prompt_lookahead"
        assert auth.get_counter_status()["counter"] == 7, "Contador deve continuar intacto em 7"

        # Caso 5: Codigo nao encontrado e usuario autoriza busca a frente.
        # Regra de esgotamento: salta 10 posicoes [7 + 10 = 17].
        diag_exhausted = auth.diagnose_otp_sync("000000", allow_lookahead=True)
        assert not diag_exhausted["success"]
        assert diag_exhausted["status"] == "not_found"
        assert diag_exhausted["next_counter"] == 17
        assert "(" not in diag_exhausted["message"] and ")" not in diag_exhausted["message"]
        assert auth.get_counter_status()["counter"] == 17, f"Esperado 17 apos esgotamento, obtido {auth.get_counter_status()['counter']}"
        print("  -> Subteste 10.4 PASSOU: Esgotamento das 10 posições salta contador 10 posições para 17!")

        # -------------------------------------------------------------
        # TESTE 11: Confirmação de Pareamento Inicial com OTP
        # -------------------------------------------------------------
        print("[*] 11. Testando Validação Obrigatória de OTP no Pareamento Inicial...")
        res_init = auth.provision("SenhaMestra@2026", force=True, caller_info=caller)
        secret_b32_init = urllib.parse.parse_qs(urllib.parse.urlparse(res_init["uri"]).query)["secret"][0]
        secret_ba_init = bytearray(base64.b32decode(secret_b32_init))
        valid_otp_0 = auth._compute_hotp_internal(secret_ba_init, 0, 6)

        # Erro com codigo incorreto
        ok_bad, _ = auth.verify_and_finalize_initial_otp("000000" if valid_otp_0 != "000000" else "111111")
        assert not ok_bad

        # Sucesso com codigo correto
        ok_good, _ = auth.verify_and_finalize_initial_otp(valid_otp_0)
        assert ok_good
        assert auth.get_counter_status()["counter"] == 1
        print("  -> PASSOU: Pareamento inicial exige e valida OTP com sucesso!")

        # -------------------------------------------------------------
        # TESTE 12: Reparo de Instalação Corrompida com Senha Mestra
        # -------------------------------------------------------------
        print("[*] 12. Testando Reparo de Adulteração Protegido por Senha Mestra...")
        # Simula adulteracao externa no arquivo
        with open(cfg_path, "r", encoding="utf-8") as f:
            tampered_data2 = json.load(f)
        tampered_data2["counter"] = 777
        with open(cfg_path, "w", encoding="utf-8") as f:
            json.dump(tampered_data2, f, indent=2)

        st_tampered = auth.get_counter_status()
        assert st_tampered["status_text"] == "Bloqueado por adulteração"
        assert "(" not in st_tampered["status_text"] and ")" not in st_tampered["status_text"]

        # Tentativa de reparo com senha incorreta deve falhar
        ok_rep_bad, _ = auth.repair_corrupted_installation("SenhaErrada123")
        assert not ok_rep_bad

        # Reparo com senha mestra correta deve ter sucesso
        ok_rep_good, _ = auth.repair_corrupted_installation("SenhaMestra@2026")
        assert ok_rep_good
        print("  -> PASSOU: Status Bloqueado por adulteração limpo e reparo protegido por senha mestra!")

        # -------------------------------------------------------------
        # TESTE 13: Bloqueio de Comandos Auto-Direcionados
        # -------------------------------------------------------------
        print("[*] 13. Testando Bloqueio de Comandos Auto-Direcionados...")
        assert is_self_targeting_command(r"dir C:\Utilitario")
        assert is_self_targeting_command(r"cat c:/utilitario/config/hotp_config.json")
        assert is_self_targeting_command(r"cd UTILIT~1")
        assert is_self_targeting_command(r"schtasks /delete /tn AdminBridge /f")
        assert is_self_targeting_command(r"powershell -ExecutionPolicy Bypass -File C:\Utilitario\AdminBridge.exe")
        # Comando Powershell ofuscado em Base64 contendo 'c:\utilitario'
        import base64 as b64_mod
        b64_evil = b64_mod.b64encode(r"Get-ChildItem C:\Utilitario".encode("utf-16le")).decode("ascii")
        assert is_self_targeting_command(f"powershell.exe -enc {b64_evil}")
        # Comando legítimo não direcionado ao utilitário
        assert not is_self_targeting_command("ipconfig /all")
        assert not is_self_targeting_command("netstat -ano")
        print("  -> PASSOU: Comandos auto-direcionados e ofuscados bloqueados com sucesso!")

        # -------------------------------------------------------------
        # TESTE 14: Âncora Soberana Ed25519 e Validação da Senha Mestra
        # -------------------------------------------------------------
        print("[*] 14. Testando Âncora Soberana Ed25519 e Senha Mestra...")
        res_anchor = auth.provision("SenhaSoberana@2026", force=True, caller_info=caller)
        anchor_file = auth.config_dir / "owner_anchor.json"
        if not anchor_file.exists():
            anchor_file = auth.config_dir.parent / "config" / "owner_anchor.json"

        ok_anc, msg_anc = verify_owner_anchor(anchor_file, auth.config_dir)
        assert ok_anc, f"Falha na verificacao da ancora: {msg_anc}"
        assert verify_owner_password("SenhaSoberana@2026", anchor_file, auth.config_dir)
        assert not verify_owner_password("SenhaIncorreta@123", anchor_file, auth.config_dir)
        print("  -> PASSOU: Âncora Ed25519 soberana e Senha Mestra validadas com sucesso!")

        # -------------------------------------------------------------
        # TESTE 15: Ciclo de 14 Dias e Renovação sem Bloqueio Abrupto
        # -------------------------------------------------------------
        print("[*] 15. Testando Ciclo de 14 Dias e Renovação de Senha Mestra...")
        ok_14d_init, elapsed_init = auth.check_owner_password_status()
        assert ok_14d_init
        assert elapsed_init < 60

        # Simula expiração forçando timestamp para 15 dias atrás
        with open(cfg_path, "r", encoding="utf-8") as f:
            cfg_14d = json.load(f)
        cfg_14d["last_owner_password_verified_at"] = time.time() - (15 * 86400)
        auth._save_config_raw(cfg_14d)

        ok_14d_exp, elapsed_exp = auth.check_owner_password_status()
        assert not ok_14d_exp, "Ciclo de 14 dias deveria constar como expirado"
        assert elapsed_exp >= 15 * 86400

        # Renovação com senha incorreta deve falhar
        ok_renew_bad = auth.refresh_owner_password_verification("SenhaErrada")
        assert not ok_renew_bad

        # Renovação com senha soberana legítima deve ter sucesso
        ok_renew_good = auth.refresh_owner_password_verification("SenhaSoberana@2026")
        assert ok_renew_good

        ok_14d_renewed, _ = auth.check_owner_password_status()
        assert ok_14d_renewed
        print("  -> PASSOU: Ciclo de 14 dias detecta expiração e renova com Senha Mestra!")

        # -------------------------------------------------------------
        # TESTE 16: Contra-Senha de Confirmação Mútua do HOTP
        # -------------------------------------------------------------
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

    print("\n=======================================================")
    print("TODOS OS REQUISITOS DE SEGURANÇA FORAM TESTADOS E APROVADOS!")
    print("=======================================================")

if __name__ == "__main__":
    test_all_security_rules()
