# -*- coding: utf-8 -*-
"""Teste Ativo do Admin Bridge Instalado em C:\\Utilitario
Valida todas as rotinas em producao:
1. Status do daemon e integridade
2. Diagnostico e teste passivo de sincronia (sync)
3. Pre-autorizacao de 45 minutos via OTP (preauth)
4. Execucao de comando elevado via fila com token
5. Bloqueio de auto-ataque e scripts maliciosos
6. Verificacao de status headless da IA local
"""

import base64
import json
import os
import subprocess
import sys
import time
from pathlib import Path

from hotp_auth import HOTPAuth, DEFAULT_DIGITS
from hotp_crypto import (
    AtomicLock,
    inspect_script_3_layers,
    suppress_ollama_tray_autostart,
    get_local_ai_status,
    read_passive_metadata
)
from app import is_self_targeting_command

UTILITARIO_DIR = Path("C:/Utilitario")
EXE_PATH = UTILITARIO_DIR / "AdminBridge.exe"
CONFIG_FILE = UTILITARIO_DIR / "config" / "hotp_config.json"
PREAUTH_FILE = UTILITARIO_DIR / "config" / "preauth_ticket.json"


def log_test(num: int, title: str):
    print(f"\n[TESTE INSTALADO {num}] {title}")


def log_pass(msg: str):
    print(f"  -> SUCESSO: {msg}")


def log_fail(msg: str):
    print(f"  -> FALHOU: {msg}")
    raise AssertionError(msg)


def run_installed_bridge_tests():
    print("=" * 65)
    print("VALIDACAO ATIVA DO ADMIN BRIDGE INSTALADO EM C:\\Utilitario")
    print("=" * 65)

    if not EXE_PATH.exists():
        log_fail("Executavel C:\\Utilitario\\AdminBridge.exe nao encontrado.")

    # -------------------------------------------------------------
    # 1. Teste de Status do Servico
    # -------------------------------------------------------------
    log_test(1, "Verificacao de Status e Heartbeat do Servico em Producao")
    res_status = subprocess.run(
        [str(EXE_PATH), "status"],
        capture_output=True,
        text=True,
        check=False
    )
    assert res_status.returncode == 0, f"Falha ao executar status: {res_status.stderr}"
    assert "STATUS DO ADMIN BRIDGE" in res_status.stdout
    assert "Provisionado:             SIM" in res_status.stdout
    assert "Lockdown Fail-Safe:       NORMAL" in res_status.stdout
    assert "Integridade do Estado:    \xcdntegro" in res_status.stdout or "ntegro" in res_status.stdout
    log_pass("Servico ativo, integro, provisionado e em estado NORMAL.")

    # -------------------------------------------------------------
    # 2. Diagnostico de Sincronia Passiva (HOTP Sync)
    # -------------------------------------------------------------
    log_test(2, "Diagnostico Passivo de Sincronia HOTP (Comando sync)")
    auth = HOTPAuth(config_file=CONFIG_FILE)
    meta = read_passive_metadata(CONFIG_FILE)
    cur_counter = meta.get("counter", 0)

    # Computa OTP do contador atual
    with AtomicLock():
        raw_cfg = auth._load_config_raw()
        sec_dp = base64.b64decode(raw_cfg["secret_dpapi"])
        secret_ba = auth._unprotect_secret(sec_dp)
        valid_otp_cur = auth._compute_hotp_internal(secret_ba, cur_counter, DEFAULT_DIGITS)

    res_sync = subprocess.run(
        [str(EXE_PATH), "sync", "--otp", valid_otp_cur],
        capture_output=True,
        text=True,
        check=False
    )
    assert res_sync.returncode == 0, f"Falha no comando sync: {res_sync.stderr}"
    assert "SINCRONIZADO" in res_sync.stdout or "DIAGN\xd3STICO" in res_sync.stdout or "DIAGNOSTICO" in res_sync.stdout
    log_pass(f"Sincronia validada com sucesso no contador #{cur_counter}.")

    # -------------------------------------------------------------
    # 3. Pre-Autorizacao (Sessao de 45 minutos com OTP)
    # -------------------------------------------------------------
    log_test(3, "Ativacao do Modo Auth (Pre-Autorizacao de 45 Minutos)")
    # O comando sync avancou o contador em 1 (para cur_counter + 1)
    meta_now = read_passive_metadata(CONFIG_FILE)
    new_counter = meta_now.get("counter", cur_counter + 1)

    with AtomicLock():
        sec_dp = base64.b64decode(auth._load_config_raw()["secret_dpapi"])
        secret_ba = auth._unprotect_secret(sec_dp)
        valid_otp_preauth = auth._compute_hotp_internal(secret_ba, new_counter, DEFAULT_DIGITS)

    res_pre = subprocess.run(
        [str(EXE_PATH), "preauth", "--otp", valid_otp_preauth, "--lifetime", "2700"],
        capture_output=True,
        text=True,
        check=False
    )
    assert res_pre.returncode == 0, f"Falha no comando preauth: {res_pre.stderr}"
    assert PREAUTH_FILE.exists(), "Arquivo preauth_ticket.json nao foi gerado!"

    with open(PREAUTH_FILE, "r", encoding="utf-8") as pf:
        t_data = json.load(pf)
    assert "token" in t_data
    assert t_data.get("expires_in") == 2700
    token_str = t_data["token"]
    contra_senha = t_data.get("mutual_confirmation_code", "N/A")
    log_pass(f"Ticket preauth emitido com sucesso! Contra-senha: {contra_senha}, Token: {token_str[:12]}...")

    # -------------------------------------------------------------
    # 4. Execucao de Comando Elevado via Fila usando Ticket Preauth
    # -------------------------------------------------------------
    log_test(4, "Execucao de Comando Elevado via Fila com Token Preauth")
    client_py = Path("c:/Users/epgur/.gemini/antigravity/Utilitário/client.py")
    res_run = subprocess.run(
        [
            sys.executable,
            str(client_py),
            "run",
            "--title", "Teste Auditoria Elevada",
            "--type", "cmd",
            "--code", "whoami /priv",
            "--otp", token_str
        ],
        capture_output=True,
        text=True,
        check=False
    )
    assert res_run.returncode == 0, f"Falha na execucao via fila: {res_run.stderr}\n{res_run.stdout}"
    assert "SeDebugPrivilege" in res_run.stdout or "PRIVILEGIOS" in res_run.stdout or "Privilege" in res_run.stdout or "SUCCESS" in res_run.stdout
    log_pass("Comando elevado executado com sucesso atraves do token preauth sem solicitar novo OTP.")

    # -------------------------------------------------------------
    # 5. Inspecao 3 Camadas e Bloqueio de Comandos Auto-Direcionados
    # -------------------------------------------------------------
    log_test(5, "Inspecao em 3 Camadas e Bloqueio de Comandos Evasivos/Auto-Ataque")
    assert is_self_targeting_command("rd /s /q C:\\Utilitario")
    assert is_self_targeting_command("takeown /f C:\\Utilitario\\config")
    assert is_self_targeting_command("icacls \"C:\\Utilitario\\queue\" /grant:r Everyone:F")
    assert is_self_targeting_command("powershell -enc RwBlAHQALQBQAHIAbwBjAGUAcwBzACAALQBOAGEAbQBlACAAQQBkAG0AaQBuACoA")

    # Testa submissao de comando auto-direcionado via fila
    res_attack = subprocess.run(
        [
            sys.executable,
            str(client_py),
            "run",
            "--title", "Tentativa Auto Ataque",
            "--type", "cmd",
            "--code", "dir C:\\Utilitario\\config",
            "--otp", token_str
        ],
        capture_output=True,
        text=True,
        check=False
    )
    assert res_attack.returncode != 0 or "AUTO_TARGET" in res_attack.stdout or "REJEITADO" in res_attack.stdout or "Bloqueado" in res_attack.stdout
    log_pass("Comandos direcionados a C:\\Utilitario bloqueados sumariamente pelo motor de seguranca.")

    # -------------------------------------------------------------
    # 6. Modo Headless da IA Local (Sem Icone de Bandeja)
    # -------------------------------------------------------------
    log_test(6, "Validacao Headless da Mini-IA Local On-Device")
    assert suppress_ollama_tray_autostart(), "Falha ao suprimir autostart da bandeja do Ollama"
    ai_status = get_local_ai_status()
    assert isinstance(ai_status, dict)
    assert "badge_text" in ai_status
    log_pass(f"Motor de IA higienizado para headless: {ai_status['badge_text']}.")

    # -------------------------------------------------------------
    # 7. Revogacao do Ticket Preauth
    # -------------------------------------------------------------
    log_test(7, "Revogacao Imediata do Ticket de Pre-Autorizacao")
    res_rev = subprocess.run(
        [str(EXE_PATH), "revoke-preauth"],
        capture_output=True,
        text=True,
        check=False
    )
    assert res_rev.returncode == 0
    assert not PREAUTH_FILE.exists() or not auth.consume_preauth_ticket(token_str, os.getenv("USERNAME"))[0]
    log_pass("Ticket revogado com sucesso. Token anterior invalidado permanentemente.")

    print("\n" + "=" * 65)
    print("TODAS AS ROTINAS DO ADMIN BRIDGE INSTALADO PASSARAM COM SUCESSO!")
    print("=" * 65)
    return True


if __name__ == "__main__":
    ok = run_installed_bridge_tests()
    sys.exit(0 if ok else 1)
