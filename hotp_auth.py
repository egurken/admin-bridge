import base64
import gc
import hashlib
import hmac
import json
import logging
import os
import secrets
import struct
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Tuple

import qrcode

from hotp_crypto import (
    dpapi_protect, dpapi_unprotect, wipe_buffer,
    hash_recovery_password, verify_recovery_password,
    apply_strict_acls, AtomicLock, verify_caller_origin
)

BASE_DIR = Path("C:/Utilitario")
CONFIG_DIR = BASE_DIR / "config"
LOGS_DIR = BASE_DIR / "logs"
CONFIG_FILE = CONFIG_DIR / "hotp_config.json"
AUTH_LOG_FILE = LOGS_DIR / "auth.log"

DEFAULT_DIGITS = 6
DEFAULT_LOOK_AHEAD_WINDOW = 5
FAIL_SAFE_MAX_FAILURES = 3
FAIL_SAFE_WINDOW_SECONDS = 300  # 5 minutos


class HOTPAuth:
    """Implementação do sistema de autenticação HOTP (RFC 4226) com modelo de validação cega,

    higiene estrita de memória, controle de hardware (DPAPI/TPM), isolamento e mecanismo fail-safe.
    """

    def __init__(self, config_file: Path = CONFIG_FILE):
        self.config_file = config_file
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        LOGS_DIR.mkdir(parents=True, exist_ok=True)

    def _load_config_raw(self) -> dict:
        """Carrega a configuração do disco."""
        if not self.config_file.exists():
            return {}
        with open(self.config_file, "r", encoding="utf-8") as f:
            return json.load(f)

    def _save_config_raw(self, config_data: dict):
        """Salva a configuração atomicamente e aplica permissões ACL restritas."""
        tmp_file = self.config_file.with_suffix(".tmp")
        with open(tmp_file, "w", encoding="utf-8") as f:
            json.dump(config_data, f, indent=2, ensure_ascii=False)
        tmp_file.replace(self.config_file)
        # Aplica permissões ACL restritas (apenas SYSTEM e Administradores)
        apply_strict_acls(self.config_file)

    def _log_audit(
        self,
        action: str,
        counter_before: int,
        counter_after: int,
        success: bool,
        details: str,
        otp_provided: str = "",
        caller_info: Optional[dict] = None
    ):
        """Registra logs estruturados de auditoria de todas as operações."""
        timestamp = datetime.now(timezone.utc).isoformat()
        status_str = "SUCCESS" if success else "FAIL"
        masked_otp = (otp_provided[:2] + "****" + otp_provided[-1:]) if len(otp_provided) >= 4 else "****"
        caller_str = (
            f"PID:{caller_info.get('pid', '?')} | "
            f"Exe:{Path(caller_info.get('exe', '?')).name} | "
            f"User:{caller_info.get('user', '?')}"
        ) if caller_info else "N/A"

        entry = (
            f"[{timestamp}] [{status_str}] Action: {action} | "
            f"Counter: {counter_before}->{counter_after} | "
            f"OTP: {masked_otp} | Caller: {caller_str} | Details: {details}\n"
        )

        try:
            with open(AUTH_LOG_FILE, "a", encoding="utf-8") as f:
                f.write(entry)
        except Exception:
            pass

    @staticmethod
    def _compute_hotp_internal(secret_ba: bytearray, counter: int, digits: int = 6) -> str:
        """Calcula o valor HOTP de forma isolada sem vazamento de memória."""
        counter_bytes = struct.pack(">Q", counter)
        h = hmac.new(bytes(secret_ba), counter_bytes, hashlib.sha1).digest()
        offset = h[19] & 0x0F
        bin_code = (
            ((h[offset] & 0x7F) << 24)
            | ((h[offset + 1] & 0xFF) << 16)
            | ((h[offset + 2] & 0xFF) << 8)
            | (h[offset + 3] & 0xFF)
        )
        otp = bin_code % (10**digits)
        return str(otp).zfill(digits)

    # -------------------------------------------------------------------------
    # PROVISIONAMENTO INICIAL (UMA ÚNICA VEZ)
    # -------------------------------------------------------------------------
    def is_provisioned(self) -> bool:
        """Verifica se a chave já foi provisionada e o flag está em 1."""
        cfg = self._load_config_raw()
        return cfg.get("provisioned_flag", 0) == 1

    def is_lockdown(self) -> bool:
        """Verifica se o sistema está em estado de lockdown de segurança."""
        cfg = self._load_config_raw()
        return cfg.get("lockdown", False) is True

    def provision(self, recovery_password: str, force: bool = False, caller_info: Optional[dict] = None) -> dict:
        """Gera a chave secreta inicial, protege com DPAPI, gera QR code e trava o flag em 1.

        Permitido estritamente uma única vez (ou durante reset autenticado).
        """
        with AtomicLock():
            cfg = self._load_config_raw()
            if cfg.get("provisioned_flag", 0) == 1 and not force:
                self._log_audit("PROVISION_DENIED", cfg.get("counter", 1), cfg.get("counter", 1), False, "Tentativa não autorizada de gerar nova chave com flag=1", caller_info=caller_info)
                raise PermissionError(
                    "Operação Bloqueada: A chave HOTP já foi provisionada e está travada (flag=1). "
                    "Geração de nova chave proibida sem procedimento de reset autenticado."
                )

            if not recovery_password or len(recovery_password) < 8:
                raise ValueError("A palavra-passe de recuperação deve conter pelo menos 8 caracteres.")

            # 1. Gera segredo criptográfico de 160 bits (20 bytes)
            raw_secret = secrets.token_bytes(20)
            secret_b32 = base64.b32encode(raw_secret).decode("ascii")

            # 2. Criptografa o segredo via DPAPI
            secret_dpapi = dpapi_protect(raw_secret)
            secret_dpapi_b64 = base64.b64encode(secret_dpapi).decode("ascii")

            # Limpa imediatamente os bytes do segredo em texto claro
            raw_secret_ba = bytearray(raw_secret)
            wipe_buffer(raw_secret_ba)
            del raw_secret, raw_secret_ba
            gc.collect()

            # 3. Gera hash seguro para a senha de recuperação (PBKDF2 600.000 iterações) e protege com DPAPI
            pw_hash_b64, salt_b64 = hash_recovery_password(recovery_password)
            pw_hash_dpapi = dpapi_protect(pw_hash_b64.encode("ascii"))
            pw_hash_dpapi_b64 = base64.b64encode(pw_hash_dpapi).decode("ascii")

            # 4. Gera a URI para o autenticador do celular (com counter=0)
            uri = f"otpauth://hotp/AntigravityBridge:Admin?secret={secret_b32}&counter=0&digits={DEFAULT_DIGITS}"

            # 5. Salva configuração protegida com flag = 1 e counter = 0
            new_config = {
                "provisioned_flag": 1,
                "lockdown": False,
                "secret_dpapi": secret_dpapi_b64,
                "recovery_hash_dpapi": pw_hash_dpapi_b64,
                "recovery_salt": salt_b64,
                "counter": 0,
                "digits": DEFAULT_DIGITS,
                "look_ahead_window": DEFAULT_LOOK_AHEAD_WINDOW,
                "failures": [],
                "created_at": datetime.now(timezone.utc).isoformat(),
                "last_used_at": None,
                "last_success_counter": 0,
            }
            self._save_config_raw(new_config)

            self._log_audit("PROVISION", 0, 0, True, "Chave provisionada com sucesso e protegida via DPAPI. Flag travado em 1 e counter=0.", caller_info=caller_info)

            # Retorna URI e segredo temporariamente APENAS em memória RAM para o assistente de interface local
            return {
                "uri": uri,
                "secret_base32": secret_b32,
                "counter": 0,
                "provisioned_flag": 1
            }

    # -------------------------------------------------------------------------
    # PROCEDIMENTO DE RESET (SENHA DE RECUPERAÇÃO + PRESENÇA FÍSICA)
    # -------------------------------------------------------------------------
    def reset_and_reprovision(
        self,
        recovery_password: str,
        physical_challenge_response: str,
        expected_challenge: str,
        new_recovery_password: str,
        caller_info: Optional[dict] = None
    ) -> dict:
        """Executa o reset estrito com desafio de presença física local e senha digitada pelo usuário.

        Nenhuma credencial estática é permitida.
        """
        with AtomicLock():
            cfg = self._load_config_raw()
            c_before = cfg.get("counter", 1)

            # 1. Validação de Presença Física
            if not physical_challenge_response or physical_challenge_response.strip().upper() != expected_challenge.strip().upper():
                self._log_audit("RESET_FAIL", c_before, c_before, False, "Falha na confirmação de presença física.", caller_info=caller_info)
                raise PermissionError("Validação de presença física falhou: código de verificação incorreto.")

            # 2. Validação da Senha de Recuperação
            if "recovery_hash_dpapi" not in cfg or "recovery_salt" not in cfg:
                raise ValueError("Configuração corrompida: dados de recuperação ausentes.")

            try:
                enc_hash = base64.b64decode(cfg["recovery_hash_dpapi"])
                expected_hash_ba = dpapi_unprotect(enc_hash)
                expected_hash_b64 = expected_hash_ba.decode("ascii")
                wipe_buffer(expected_hash_ba)
                del expected_hash_ba
            except Exception as e:
                raise RuntimeError(f"Erro ao descriptografar hash com DPAPI: {e}")

            if not verify_recovery_password(recovery_password, expected_hash_b64, cfg["recovery_salt"]):
                self._log_audit("RESET_FAIL", c_before, c_before, False, "Senha de recuperação incorreta.", caller_info=caller_info)
                raise PermissionError("Senha de recuperação incorreta.")

            # Ambas as condições cumpridas!
            # Reseta flag para 0 e limpa segredo anterior
            cfg["provisioned_flag"] = 0
            cfg["lockdown"] = False
            cfg["failures"] = []
            cfg["secret_dpapi"] = ""
            self._save_config_raw(cfg)
            self._log_audit("RESET_UNLOCKED", c_before, c_before, True, "Senha e presença física verificadas. Flag resetado para 0.", caller_info=caller_info)

            # Re-provisiona e retorna para 1
            result = self.provision(new_recovery_password, force=True, caller_info=caller_info)

            # Tenta reativar a tarefa agendada
            try:
                subprocess.run(
                    ["schtasks", "/change", "/tn", "AntigravityAdminBridge", "/enable"],
                    capture_output=True,
                    check=False,
                    creationflags=0x08000000
                )
            except Exception:
                pass

            self._log_audit("RESET_COMPLETED", c_before, 0, True, "Nova chave provisionada com sucesso. Flag restaurado para 1 e counter=0.", caller_info=caller_info)
            return result

    # -------------------------------------------------------------------------
    # VALIDAÇÃO CEGA COM ISOLAMENTO DE MEMÓRIA E FAIL-SAFE
    # -------------------------------------------------------------------------
    def verify_and_advance(self, provided_otp: Optional[str], caller_info: Optional[dict] = None) -> Tuple[bool, str, int]:
        """Validação cega atômica do token HOTP:

        - O computador NUNCA calcula nem expõe o OTP para a interface.
        - Memória desencriptada no milissegundo exato e sobrescrita com zeros.
        - Comparação em tempo constante (hmac.compare_digest).
        - Contador avança obrigatoriamente tanto em SUCESSO quanto em ERRO.
        - Fail-Safe: 3 falhas em 5 minutos desativam a tarefa elevada e encerram o utilitário.
        """
        with AtomicLock():
            cfg = self._load_config_raw()

            if cfg.get("provisioned_flag", 0) != 1:
                return False, "Utilitário não provisionado. Provisione a chave antes de executar.", 0

            current_counter = cfg["counter"]
            digits = cfg.get("digits", DEFAULT_DIGITS)
            look_ahead = cfg.get("look_ahead_window", DEFAULT_LOOK_AHEAD_WINDOW)

            # Verifica se já está em estado de lockdown fail-safe
            if cfg.get("lockdown", False):
                self._log_audit("LOCKDOWN_BLOCKED", current_counter, current_counter, False, "Requisição rejeitada: utilitário em lockdown de segurança.", provided_otp or "", caller_info)
                return False, "FAIL_SAFE_LOCKDOWN: O utilitário foi desativado por excesso de falhas. Exige UAC manual.", current_counter

            # Valida origem do processo chamador
            valid_caller, caller_msg = verify_caller_origin(caller_info)
            if not valid_caller:
                new_counter = current_counter + 1
                cfg["counter"] = new_counter
                self._save_config_raw(cfg)
                self._log_audit("VERIFY_REJECTED", current_counter, new_counter, False, f"Origem não autorizada: {caller_msg}", provided_otp or "", caller_info)
                return False, f"Origem da requisição não autorizada: {caller_msg}", new_counter

            # Validação do formato do código fornecido
            if not provided_otp or not str(provided_otp).strip().isdigit() or len(str(provided_otp).strip()) not in (6, 8):
                new_counter = current_counter + 1
                cfg["counter"] = new_counter
                self._record_failure_and_check_lockdown(cfg, current_counter, new_counter, provided_otp or "", caller_info, "Formato do OTP inválido ou ausente")
                return False, "Código OTP não fornecido ou formato numérico inválido.", new_counter

            provided_otp = str(provided_otp).strip()

            # Desencripta a chave estritamente no milissegundo da validação
            secret_ba = None
            match_counter = None
            try:
                secret_raw = base64.b64decode(cfg["secret_dpapi"])
                secret_ba = dpapi_unprotect(secret_raw)

                # Compara candidatos na janela de look-ahead usando tempo constante
                for test_counter in range(current_counter, current_counter + look_ahead + 1):
                    expected = self._compute_hotp_internal(secret_ba, test_counter, digits)
                    if hmac.compare_digest(expected, provided_otp):
                        match_counter = test_counter
                        break
            except Exception as e:
                new_counter = current_counter + 1
                cfg["counter"] = new_counter
                self._record_failure_and_check_lockdown(cfg, current_counter, new_counter, provided_otp, caller_info, f"Erro ao acessar chave DPAPI: {e}")
                return False, f"Erro ao acessar chave de hardware: {e}", new_counter
            finally:
                # Higiene estrita de memória: sobrescreve buffers com zeros e invoca gc.collect()
                if secret_ba is not None:
                    wipe_buffer(secret_ba)
                    del secret_ba
                gc.collect()

            if match_counter is not None:
                # SUCESSO!
                new_counter = match_counter + 1
                cfg["counter"] = new_counter
                cfg["last_success_counter"] = match_counter
                cfg["last_used_at"] = datetime.now(timezone.utc).isoformat()
                cfg["failures"] = []  # Limpa histórico de falhas consecutivas
                self._save_config_raw(cfg)

                self._log_audit(
                    "VERIFY",
                    current_counter,
                    new_counter,
                    True,
                    f"Código validado com sucesso no índice #{match_counter}. Contador avançou para {new_counter}.",
                    provided_otp,
                    caller_info
                )
                return True, "Autenticação HOTP aprovada.", new_counter
            else:
                # ERRO! REGRA 3: O contador AVANÇA OBRIGATORIAMENTE mesmo com código errado!
                new_counter = current_counter + 1
                cfg["counter"] = new_counter
                is_lockdown = self._record_failure_and_check_lockdown(
                    cfg, current_counter, new_counter, provided_otp, caller_info, "Código incorreto ou expirado"
                )
                if is_lockdown:
                    return False, "FAIL_SAFE_LOCKDOWN: 3 falhas consecutivas detectadas em menos de 5 minutos. Central desativada.", new_counter
                return False, "Código OTP incorreto ou expirado.", new_counter

    def _record_failure_and_check_lockdown(
        self,
        cfg: dict,
        counter_before: int,
        counter_after: int,
        provided_otp: str,
        caller_info: Optional[dict],
        reason: str
    ) -> bool:
        """Registra falha consecutiva e aciona o mecanismo fail-safe se atingir o limiar."""
        now = time.time()
        # Filtra falhas ocorridas na janela de 5 minutos
        failures = [t for t in cfg.get("failures", []) if (now - t) <= FAIL_SAFE_WINDOW_SECONDS]
        failures.append(now)
        cfg["failures"] = failures

        if len(failures) >= FAIL_SAFE_MAX_FAILURES:
            cfg["lockdown"] = True
            cfg["lockdown_at"] = datetime.now(timezone.utc).isoformat()
            self._save_config_raw(cfg)

            # Aciona desativação imediata da tarefa agendada
            try:
                subprocess.run(
                    ["schtasks", "/change", "/tn", "AntigravityAdminBridge", "/disable"],
                    capture_output=True,
                    check=False,
                    creationflags=0x08000000
                )
            except Exception:
                pass

            self._log_audit(
                "FAIL_SAFE_LOCKDOWN",
                counter_before,
                counter_after,
                False,
                f"3 falhas consecutivas em < 5 minutos! Tarefa agendada desativada. Motivo: {reason}",
                provided_otp,
                caller_info
            )
            return True
        else:
            self._save_config_raw(cfg)
            self._log_audit(
                "VERIFY_FAIL",
                counter_before,
                counter_after,
                False,
                f"{reason}. Falha {len(failures)}/{FAIL_SAFE_MAX_FAILURES} na janela de 5m.",
                provided_otp,
                caller_info
            )
            return False

    # -------------------------------------------------------------------------
    # CONSULTA PASSIVA DE METADADOS SEM AVANÇO (REGRA 1 & 8)
    # -------------------------------------------------------------------------
    def get_counter_status(self) -> dict:
        """Consulta metadados do contador e estado de segurança.

        O computador NUNCA calcula nem retorna tokens nesta função.
        """
        with AtomicLock():
            cfg = self._load_config_raw()
            return {
                "counter": cfg.get("counter", 1),
                "provisioned_flag": cfg.get("provisioned_flag", 0),
                "lockdown": cfg.get("lockdown", False),
                "failures_in_window": len([t for t in cfg.get("failures", []) if (time.time() - t) <= FAIL_SAFE_WINDOW_SECONDS]),
                "created_at": cfg.get("created_at"),
                "last_used_at": cfg.get("last_used_at"),
                "last_success_counter": cfg.get("last_success_counter", 0)
            }
