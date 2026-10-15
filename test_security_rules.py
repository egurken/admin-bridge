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
    ensure_transit_keypair,
    verify_scheduled_task_integrity,
)
from app import is_self_targeting_command
from hotp_crypto import inspect_script_3_layers


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
        with open(cfg_path, "r", encoding="utf-8") as f:
            tampered_data = json.load(f)
        tampered_data["counter"] = 999
        if hasattr(ctypes, "windll"):
            try:
                ctypes.windll.kernel32.SetFileAttributesW(str(cfg_path), 0x80)
            except Exception:
                pass
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
        with open(cfg_path, "r", encoding="utf-8") as f:
            tampered_data2 = json.load(f)
        tampered_data2["counter"] = 777
        if hasattr(ctypes, "windll"):
            try:
                ctypes.windll.kernel32.SetFileAttributesW(str(cfg_path), 0x80)
            except Exception:
                pass
        with open(cfg_path, "w", encoding="utf-8") as f:
            json.dump(tampered_data2, f, indent=2)

        st_tampered = auth.get_counter_status()
        assert st_tampered["status_text"] == "Bloqueado por adulteração"

        ok_rep_bad, _ = auth.repair_corrupted_installation("SenhaErrada123")
        assert not ok_rep_bad

        ok_rep_good, _ = auth.repair_corrupted_installation("SenhaMestra@2026")
        assert ok_rep_good
        print("  -> PASSOU: Status Bloqueado por adulteração limpo e reparo protegido por senha mestra!")

        print("[*] 13. Testando Bloqueio de Comandos Auto-Direcionados (16/16 Variações de Auditoria SEC-04)...")
        evasion_vectors = [
            r"dir C:\Utilitario",
            r"cat c:/utilitario/config/hotp_config.json",
            r"cd UTILIT~1",
            r"schtasks /delete /tn AdminBridge /f",
            r"schtasks /delete /tn Admin* /f",
            r"taskkill /f /im Admin* /t",
            r'powershell -Command "Get-Process Admin* | Stop-Process -Force"',
            r"dir C:\U* /s",
            r'cmd.exe /c "cd \ && cd Ut* && cd con* && dir"',
            r'cmd.exe /c "set X=Utilitario" && cmd.exe /c "dir C:\%X%"',
            r"""powershell -Command \"$p = 'C:\\' + 'Utili' + 'tario'; Get-ChildItem $p\"""",
            r"icacls C:\U* /grant Everyone:F",
            r'reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\Admin*" /f',
            r"""wmic process where \"name like 'Admin%'\" delete""",
            r"powershell -enc RwBlAHQALQBQAHIAbwBjAGUAcwBzACAALQBOAGEAbQBlACAAQQBkAG0AaQBuACoA",
            r"powershell -e RwBlAHQALQBDAGgAaQBsAGQASQB0AGUAbQAgACIASgBvAGkAbgAtAFAAYQB0AGgAIgA=",
            r"""powershell -Command \"Get-Content (Join-Path 'C:\\' ('Uti'+'litario\\config\\hotp_config.json'))\"""",
            r"type \\?\C:\Utilitario\config\hotp_config.json",
            r"""powershell -Command \"Get-Content -LiteralPath '\\\\?\\C:\\Utilitario\\config\\hotp_config.json'\"""",
            r'reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\AdminBridge.exe"',
            r'dir C:\Util"i"tario',
            r"dir C:\Util^itario",
            r"type config\*.json",
            r"del queue\requests\*.json",
        ]
        for vec in evasion_vectors:
            assert is_self_targeting_command(vec), f"Falha ao bloquear vetor de evasao SEC-04: {vec}"
        assert not is_self_targeting_command("ipconfig /all")
        assert not is_self_targeting_command("netstat -ano")
        print(f"  -> PASSOU: {len(evasion_vectors)}/{len(evasion_vectors)} (100%) variações de auto-ataque e evasão bloqueadas!")

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
        if hasattr(ctypes, "windll"):
            try:
                ctypes.windll.kernel32.SetFileAttributesW(str(fake_exe), 0x80)
            except Exception:
                pass
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
        if hasattr(ctypes, "windll"):
            try:
                ctypes.windll.kernel32.SetFileAttributesW(str(fake_exe), 0x80)
            except Exception:
                pass
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
        tmp_cfg_dir = Path(tmpdir) / "config"
        tmp_q_dir = Path(tmpdir) / "queue"
        tmp_cfg_dir.mkdir(parents=True, exist_ok=True)
        tmp_q_dir.mkdir(parents=True, exist_ok=True)
        ensure_transit_keypair(tmp_cfg_dir, tmp_q_dir)

        req_id = "req-12345"
        legit_code = "ipconfig /flushdns"
        legit_hash = hashlib.sha256(legit_code.encode("utf-8")).hexdigest()
        enc_otp = protect_transit_token("654321", req_id, legit_hash, config_dir=tmp_cfg_dir, queue_dir=tmp_q_dir)
        assert enc_otp and "654321" not in enc_otp

        # Descriptografia legítima com mesmo req_id e code_hash funciona
        dec_otp = unprotect_transit_token(enc_otp, req_id, legit_hash, config_dir=tmp_cfg_dir)
        assert dec_otp == "654321"

        # Se um atacante na fila alterar o comando (code_hash diferente), a descriptografia falha!
        evil_hash = hashlib.sha256(b"net localgroup administrators attacker /add").hexdigest()
        assert unprotect_transit_token(enc_otp, req_id, evil_hash, config_dir=tmp_cfg_dir) is None
        print("  -> PASSOU: OTP protegido em trânsito e vinculado criptograficamente ao comando!")


        print("[*] 18. Testando Bloqueio de Desinstalação sem Senha e Autorização com Senha Mestra...")
        # Sem senha deve bloquear
        ok_uninst_empty, _ = auth.authorize_and_prepare_uninstall("", caller_info=caller)
        assert not ok_uninst_empty, "Desinstalacao sem senha deveria ser bloqueada!"

        # Com senha errada deve bloquear
        ok_uninst_bad, _ = auth.authorize_and_prepare_uninstall("SenhaErrada999", caller_info=caller)
        assert not ok_uninst_bad, "Desinstalacao com senha incorreta deveria ser bloqueada!"

        # Com a Senha Mestra legítima deve autorizar e destravar os arquivos
        ok_uninst_good, msg_uninst_good = auth.authorize_and_prepare_uninstall("SenhaSoberana@2026", caller_info=caller)
        assert ok_uninst_good, f"Desinstalacao com senha correta deveria passar: {msg_uninst_good}"
        print("  -> PASSOU: Desinstalação exige Senha de Recuperação e destrava arquivos somente para o proprietário!")

        print("[*] 19. Testando Auditoria Anti-Mascaramento da Tarefa Agendada (verify_scheduled_task_integrity)...")
        legit_task_xml = Path(tmpdir) / "AdminBridge_LegitTask.xml"
        legit_task_xml.write_text(
            '<?xml version="1.0" encoding="UTF-16"?>\n'
            '<Task><Actions><Exec>\n'
            '  <Command>"C:\\Utilitario\\AdminBridge.exe"</Command>\n'
            '  <Arguments>--daemon</Arguments>\n'
            '</Exec></Actions></Task>',
            encoding="utf-16"
        )
        ok_task_legit, msg_task_legit = verify_scheduled_task_integrity(Path("C:/Utilitario"), [legit_task_xml])
        assert ok_task_legit, f"Tarefa legitima deveria passar: {msg_task_legit}"

        # Simula um invasor alterando a tarefa AdminBridge para mascarar um script malicioso
        masquerade_task_xml = Path(tmpdir) / "AdminBridge_EvilTask.xml"
        masquerade_task_xml.write_text(
            '<?xml version="1.0" encoding="UTF-16"?>\n'
            '<Task><Actions><Exec>\n'
            '  <Command>powershell.exe</Command>\n'
            '  <Arguments>-ExecutionPolicy Bypass -File C:\\Temp\\backdoor.ps1</Arguments>\n'
            '</Exec></Actions></Task>',
            encoding="utf-16"
        )
        ok_task_evil, msg_task_evil = verify_scheduled_task_integrity(Path("C:/Utilitario"), [masquerade_task_xml])
        assert not ok_task_evil, "Tarefa mascarando script externo deveria ser bloqueada!"
        assert "Mascaramento" in msg_task_evil
        print("  -> PASSOU: Tentativa de mascarar script malicioso na Tarefa Agendada detectada e bloqueada!")

        print("[*] 20. Testando Cofre Dividido (hw_salt.bin) e Armadilha Forense contra Leitura Offline...")
        salt_path = auth.config_dir / "hw_salt.bin"
        assert salt_path.exists() and salt_path.stat().st_size == 32
        orig_salt = salt_path.read_bytes()

        # Simula um Administrador tentando tocar/substituir hw_salt.bin enquanto o software está desligado
        salt_path.write_bytes(b"A" * 32)
        try:
            auth._load_config_raw()
            assert False, "Deveria detectar violacao do hw_salt.bin!"
        except SecurityError:
            pass

        # Restaura os bytes originais, mas como o mtime/USN de hw_salt.bin mudou pelo toque, o sistema ainda detecta!
        time.sleep(0.01)
        salt_path.write_bytes(orig_salt)
        try:
            auth._load_config_raw()
            assert False, "Deveria detectar mudanca de USN/mtime em hw_salt.bin mesmo restaurando os bytes!"
        except SecurityError:
            pass

        # Somente o proprietário com a Senha Mestra consegue re-ancorar a instalação após o alerta
        ok_rep_salt, _ = auth.repair_corrupted_installation("SenhaSoberana@2026")
        assert ok_rep_salt
        print("  -> PASSOU: Qualquer toque ou alteração de permissão/USN em hw_salt.bin bloqueia o sistema até reparo com Senha Mestra!")

        print("[*] 21. Testando Inspetor de Scripts em 3 Camadas (AMSI + Classificador + Explicador IA)...")
        # Script benigno -> Risco baixo, sem step-up
        rep_safe = inspect_script_3_layers("ipconfig /flushdns")
        assert not rep_safe["requires_step_up"]
        assert rep_safe["risk_level"] == "low"

        # Script tentando criar serviço eterno + desativar Windows Defender -> Alto/Crítico, exige step-up e gera explicação em português!
        evil_script = "sc create MeuServicoEterno binPath= C:\\Temp\\backdoor.exe start= auto && powershell Set-MpPreference -DisableRealtimeMonitoring $true"
        rep_risk = inspect_script_3_layers(evil_script)
        assert rep_risk["requires_step_up"], "Script que cria serviço eterno e desativa Defender deveria exigir Step-Up!"
        assert rep_risk["risk_score"] >= 75
        assert "Serviço" in rep_risk["explanation"] and "Antivírus" in rep_risk["explanation"]
        print("  -> PASSOU: Inspetor de 3 Camadas identifica risco, pausa execução e explica o que o script faz em português!")

        print("[*] 22. Testando Desenrolamento Recursivo de Scripts Externos (Script que chama outro Script)...")
        ext_self_attack = Path(tmpdir) / "inocente_por_fora.ps1"
        ext_self_attack.write_text("Get-Content C:\\Utilitario\\config\\hotp_config.json", encoding="utf-8")
        cmd_calling_ext_attack = f"powershell.exe -ExecutionPolicy Bypass -File \"{ext_self_attack}\""
        assert is_self_targeting_command(cmd_calling_ext_attack), "Deveria ler dentro do .ps1 externo e bloquear o ataque a C:\\Utilitario!"

        nivel2_ps1 = Path(tmpdir) / "nivel2_oculto.ps1"
        nivel2_ps1.write_text("sc.exe create ServicoEscondido binPath= C:\\Temp\\malware.exe start= auto", encoding="utf-8")
        nivel1_bat = Path(tmpdir) / "nivel1_wrapper.bat"
        nivel1_bat.write_text(f"powershell -File \"{nivel2_ps1}\"", encoding="utf-8")

        rep_nested = inspect_script_3_layers(f"call \"{nivel1_bat}\"")
        assert rep_nested["requires_step_up"], "Deveria desenrolar nivel1.bat -> nivel2.ps1 e detectar criação de serviço eterno!"
        assert rep_nested["risk_score"] >= 65
        assert len(rep_nested.get("referenced_files", [])) == 2
        assert "Serviço Permanente" in rep_nested["explanation"]
        assert "sc.exe create ServicoEscondido" in rep_nested["unrolled_code"]
        print("  -> PASSOU: Scripts externos aninhados (.bat -> .ps1) são abertos e inspecionados recursivamente!")

    print("\n=======================================================")
    print("TODOS OS 22 REQUISITOS DE SEGURANÇA FORAM TESTADOS E APROVADOS!")
    print("=======================================================")


if __name__ == "__main__":
    test_all_security_rules()
