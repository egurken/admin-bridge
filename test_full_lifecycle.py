# -*- coding: utf-8 -*-
"""Teste Ativo do Ciclo de Vida Completo do Admin Bridge
Cobre todas as etapas: instalacao, provisionamento, erros de OTP, sincronia,
disjuntor fail-safe, pre-autorizacao, fila de execucao, inspecao de scripts,
IA local headless e preparo de desinstalacao.
"""

import base64
import hashlib
import hmac
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from hotp_auth import HOTPAuth, SecurityError, DEFAULT_DIGITS
from hotp_crypto import (
    AtomicLock,
    inspect_script_3_layers,
    suppress_ollama_tray_autostart,
    get_local_ai_status,
    protect_transit_token,
    unprotect_transit_token,
    ensure_transit_keypair,
    create_owner_anchor,
    verify_owner_anchor,
    verify_owner_password,
    read_passive_metadata
)
from app import is_self_targeting_command


def log_test(step_num: int, title: str):
    print(f"\n[ETAPA {step_num}] {title}")


def log_pass(msg: str):
    print(f"  -> PASSOU: {msg}")


def log_fail(msg: str):
    print(f"  -> FALHOU: {msg}")
    raise AssertionError(msg)


def run_full_lifecycle_test():
    print("=" * 65)
    print("INICIANDO TESTE ATIVO DO CICLO DE VIDA COMPLETO DO ADMIN BRIDGE")
    print("=" * 65)

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        cfg_file = tmp_path / "config" / "hotp_config.json"
        auth = HOTPAuth(config_file=cfg_file)
        master_password = "SenhaMestraSoberana@2026"
        caller_client = {
            "pid": os.getpid(),
            "exe": sys.executable,
            "script": "test_full_lifecycle.py",
            "user": os.getenv("USERNAME", "test_user")
        }

        # -------------------------------------------------------------
        # ETAPA 1: Provisionamento Inicial e Blindagem de Segredo
        # -------------------------------------------------------------
        log_test(1, "Provisionamento Inicial com DPAPI e Ancora Ed25519")
        res_prov = auth.provision(master_password, caller_info=caller_client)
        assert res_prov["counter"] == 0
        assert "uri" in res_prov
        assert auth.is_provisioned()
        log_pass("Chave mestra provisionada com DPAPI, salt de hardware e flag=1.")

        # -------------------------------------------------------------
        # ETAPA 2: Tratamento de Erros e Formatos Invalidos de OTP
        # -------------------------------------------------------------
        log_test(2, "Validacao de Formatos Invalidos e Rejeicao Precoce")
        invalid_otps = ["", "123", "abc123", "1234567", "abcdef", "12 456"]
        for bad_otp in invalid_otps:
            ok, err_msg = auth.verify_and_finalize_initial_otp(bad_otp)
            assert not ok, f"Deveria rejeitar OTP invalido: {bad_otp}"
            assert "digitos" in err_msg.lower() or "invalido" in err_msg.lower()

        # Verifica que o contador nao foi consumido com entradas malformadas
        meta_after_bad = read_passive_metadata(cfg_file)
        assert meta_after_bad.get("counter") == 0
        log_pass("Todas as entradas malformadas rejeitadas sem degradar ou queimar o contador.")

        # -------------------------------------------------------------
        # ETAPA 3: Confirmacao de Pareamento com OTP Valido
        # -------------------------------------------------------------
        log_test(3, "Pareamento Inicial Obrigatorio com Celular")
        # Computa o OTP correto no indice 0
        with AtomicLock():
            raw_cfg = auth._load_config_raw()
            sec_dp = base64.b64decode(raw_cfg["secret_dpapi"])
            secret_ba = auth._unprotect_secret(sec_dp)
            correct_otp_0 = auth._compute_hotp_internal(secret_ba, 0, DEFAULT_DIGITS)
            correct_otp_1 = auth._compute_hotp_internal(secret_ba, 1, DEFAULT_DIGITS)
            correct_otp_2 = auth._compute_hotp_internal(secret_ba, 2, DEFAULT_DIGITS)
            correct_otp_3 = auth._compute_hotp_internal(secret_ba, 3, DEFAULT_DIGITS)

        # OTP errado no pareamento deve falhar
        ok_wrong, msg_wrong = auth.verify_and_finalize_initial_otp("000000" if correct_otp_0 != "000000" else "111111")
        assert not ok_wrong
        log_pass("Codigo incorreto bloqueado no pareamento inicial.")

        # OTP correto confirma o pareamento
        ok_pair, msg_pair = auth.verify_and_finalize_initial_otp(correct_otp_0)
        assert ok_pair, f"Falha no pareamento com codigo correto: {msg_pair}"

        meta_paired = read_passive_metadata(cfg_file)
        assert meta_paired.get("counter") == 1
        assert meta_paired.get("provisioned_flag") == 1
        log_pass("Pareamento inicial confirmado com sucesso no indice #0. Proximo contador: 1.")

        # -------------------------------------------------------------
        # ETAPA 4: Diagnostico de Sincronia (Sync Diagnostics)
        # -------------------------------------------------------------
        log_test(4, "Diagnostico Inteligente de Sincronia (Sync Test)")
        # 4.1 Codigo sincronizado na posicao atual (1)
        diag_sync = auth.diagnose_otp_sync(correct_otp_1)
        assert diag_sync["success"]
        assert diag_sync["status"] == "synchronized"
        log_pass("Sincronia exata detectada e contador avancado para 2.")

        # 4.2 Codigo atrasado (reuso do codigo 0 ja utilizado)
        diag_stale = auth.diagnose_otp_sync(correct_otp_0)
        assert diag_stale["success"]
        assert diag_stale["status"] == "behind"
        assert diag_stale["diff"] < 0
        log_pass("Tentativa de reuso de codigo atrasado detectada com status 'behind' sem recuar o sistema.")

        # 4.3 Codigo adiantado no celular (posicao 3 enquanto PC esta na 2)
        diag_ahead_prompt = auth.diagnose_otp_sync(correct_otp_3, allow_lookahead=False)
        assert diag_ahead_prompt["status"] == "prompt_lookahead"
        log_pass("Deslocamento futuro identificado com solicitacao de autorizacao.")

        diag_ahead_ok = auth.diagnose_otp_sync(correct_otp_3, allow_lookahead=True)
        assert diag_ahead_ok["success"]
        assert diag_ahead_ok["status"] == "ahead"
        log_pass("Busca futura confirmada: contador avancado com sucesso para indice 4.")

        # -------------------------------------------------------------
        # ETAPA 5: Disjuntor Fail-Safe e Reparo com Senha Mestra
        # -------------------------------------------------------------
        log_test(5, "Disjuntor de Forca Bruta (Lockdown apos 3 falhas e Reparo)")
        # Injeta 3 falhas consecutivas com codigos falsos
        dummy_code = "999999"
        for i in range(1, 4):
            ok_f, msg_f, _ = auth.verify_and_advance(dummy_code, caller_info=caller_client)
            assert not ok_f

        meta_lockdown = read_passive_metadata(cfg_file)
        assert meta_lockdown.get("lockdown") is True or auth.is_lockdown()
        log_pass("Disjuntor Fail-Safe disparado apos 3 falhas. Sistema em LOCKDOWN.")

        # Novas tentativas durante o lockdown devem ser sumariamente rejeitadas
        ok_blocked, msg_blocked, _ = auth.verify_and_advance(correct_otp_3, caller_info=caller_client)
        assert not ok_blocked
        assert "lockdown" in msg_blocked.lower()
        log_pass("Novas tentativas durante lockdown rejeitadas imediatamente.")

        # Reparo soberano com Senha Mestra
        ok_repair, msg_repair = auth.repair_corrupted_installation(master_password)
        assert ok_repair, f"Reparo deveria ter sucesso com senha correta: {msg_repair}"
        meta_unlocked = read_passive_metadata(cfg_file)
        assert meta_unlocked.get("lockdown") is False
        assert len(meta_unlocked.get("failures", [])) == 0
        log_pass("Sistema restaurado e desbloqueado com sucesso apos validacao da Senha Mestra.")

        # -------------------------------------------------------------
        # ETAPA 6: Sessao de Pre-Autorizacao (Ticket de 45 Minutos)
        # -------------------------------------------------------------
        log_test(6, "Sessao de Pre-Autorizacao e Revogacao Imediata")
        # Le contador atual para gerar proximo OTP
        cur_c = read_passive_metadata(cfg_file).get("counter", 0)
        with AtomicLock():
            sec_dp = base64.b64decode(auth._load_config_raw()["secret_dpapi"])
            secret_ba = auth._unprotect_secret(sec_dp)
            otp_preauth = auth._compute_hotp_internal(secret_ba, cur_c, DEFAULT_DIGITS)

        ok_ticket, msg_ticket, ticket_data = auth.create_preauth_ticket(otp_preauth, caller_client, lifetime_seconds=2700)
        assert ok_ticket, f"Falha ao criar ticket de pre-autorizacao: {msg_ticket}"
        assert "token" in ticket_data and ticket_data.get("expires_in") == 2700
        assert "mutual_confirmation_code" in ticket_data

        # Valida consumo e multi-reuso do ticket ativo
        ok_consume, msg_consume = auth.consume_preauth_ticket(ticket_data["token"], caller_client.get("user"))
        assert ok_consume, f"Falha ao consumir ticket: {msg_consume}"

        ok_reuse, _ = auth.consume_preauth_ticket(ticket_data["token"], caller_client.get("user"))
        assert ok_reuse, "Falha ao reutilizar ticket valido dentro dos 45 minutos"

        ok_bad_user, _ = auth.consume_preauth_ticket(ticket_data["token"], "hacker_user")
        assert not ok_bad_user
        log_pass("Modo Auth ativado para 45 minutos com multi-execucao e contra-senha validada.")

        # Revogacao manual
        ok_rev, msg_rev = auth.revoke_preauth_ticket()
        assert ok_rev
        ok_after_rev, _ = auth.consume_preauth_ticket(ticket_data["token"], caller_client.get("user"))
        assert not ok_after_rev
        log_pass("Ticket revogado imediatamente e novas solicitacoes com token revogado bloqueadas.")

        # -------------------------------------------------------------
        # ETAPA 7: Fila de Requisicoes e Criptografia DPAPI em Transito
        # -------------------------------------------------------------
        log_test(7, "Fila de Comandos (Requests/Responses) e Protecao DPAPI")
        queue_dir = tmp_path / "queue"
        req_dir = queue_dir / "requests"
        resp_dir = queue_dir / "responses"
        req_dir.mkdir(parents=True, exist_ok=True)
        resp_dir.mkdir(parents=True, exist_ok=True)
        ensure_transit_keypair(cfg_file.parent, queue_dir)

        req_id = "test-cmd-001"
        action_name = "whoami /priv"
        action_hash = hashlib.sha256(action_name.encode("utf-8")).hexdigest()

        # Protege o token em transito simulando o cliente
        transit_tok = protect_transit_token("123456", req_id, action_hash, config_dir=cfg_file.parent, queue_dir=queue_dir)
        unprot = unprotect_transit_token(transit_tok, req_id, action_hash, config_dir=cfg_file.parent)
        assert unprot == "123456"
        log_pass("Token em transito protegido e desembrulhado com sucesso via DPAPI.")

        # -------------------------------------------------------------
        # ETAPA 8: Inspecao de Scripts em 3 Camadas (AMSI + Classificador)
        # -------------------------------------------------------------
        log_test(8, "Inspecao em 3 Camadas e Bloqueio de Comandos Auto-Direcionados")
        # Comando seguro
        safe_res = inspect_script_3_layers("net start spooler")
        assert safe_res["risk_level"] == "low"
        assert not safe_res["requires_step_up"]
        log_pass("Comando de baixa periculosidade aprovado sem step-up.")

        # Comando malicioso
        evil_cmd = "powershell -enc JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0AA=="
        evil_res = inspect_script_3_layers(evil_cmd)
        assert evil_res["requires_step_up"]
        assert evil_res["risk_level"] in ("high", "critical")
        log_pass("Comando ofuscado identificado e retido para aprovacao com step-up.")

        # Tentativa de auto-ataque contra C:\Utilitario
        assert is_self_targeting_command("rd /s /q C:\\Utilitario")
        assert is_self_targeting_command("takeown /f C:\\Utilitario\\config")
        assert is_self_targeting_command("icacls \"C:\\Utilitario\\queue\" /grant:r Everyone:F")
        log_pass("100% das tentativas de auto-ataque e violacao de integridade foram neutralizadas.")

        # -------------------------------------------------------------
        # ETAPA 9: Mini-IA Local Headless (Sem Tray Icon)
        # -------------------------------------------------------------
        log_test(9, "IA Local On-Device 100% Headless (Sem Icone de Bandeja)")
        ok_suppress = suppress_ollama_tray_autostart()
        assert ok_suppress
        ai_st = get_local_ai_status()
        assert isinstance(ai_st, dict)
        assert "badge_text" in ai_st
        log_pass(f"Motor Ollama higienizado para headless. Status: {ai_st['badge_text']}.")

        # -------------------------------------------------------------
        # ETAPA 10: Bloqueio e Autorizacao de Desinstalacao
        # -------------------------------------------------------------
        log_test(10, "Autorizacao Segura de Desinstalacao com Senha Mestra")
        # Desinstalacao sem senha deve ser negada
        ok_uninst_bad, _ = auth.authorize_and_prepare_uninstall("SenhaErrada", caller_client)
        assert not ok_uninst_bad
        log_pass("Tentativa de desinstalacao com senha errada bloqueada.")

        # Desinstalacao com a Senha Mestra correta
        ok_uninst_good, uninst_msg = auth.authorize_and_prepare_uninstall(master_password, caller_client)
        assert ok_uninst_good, f"Falha ao autorizar desinstalacao: {uninst_msg}"
        log_pass("Desinstalacao autorizada com sucesso pelo proprietario autenticado.")

    print("\n" + "=" * 65)
    print("TODAS AS 10 ETAPAS DO CICLO DE VIDA FORAM TESTADAS E APROVADAS!")
    print("=" * 65)
    return True


if __name__ == "__main__":
    success = run_full_lifecycle_test()
    sys.exit(0 if success else 1)
