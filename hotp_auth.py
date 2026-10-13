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
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Tuple

from hotp_crypto import (
    AtomicLock,
    apply_isolated_bridge_ntfs_acls,
    apply_system_only_ntfs_acls,
    check_integrity_mac,
    compute_integrity_mac,
    dpapi_protect,
    dpapi_unprotect,
    generate_physical_challenge,
    hash_recovery_password,
    read_passive_metadata,
    restore_ntfs_acls_for_removal,
    verify_caller_origin,
    verify_integrity_mac,
    verify_recovery_password,
    wipe_buffer,
    DPAPI_ENTROPY,
)

BASE_DIR = Path("C:/Utilitario")
CONFIG_DIR = BASE_DIR / "config"
QUEUE_DIR = BASE_DIR / "queue"
LOGS_DIR = BASE_DIR / "logs"
CONFIG_FILE = CONFIG_DIR / "hotp_config.json"
STATUS_FILE = QUEUE_DIR / "status.json"
AUTH_LOG_FILE = LOGS_DIR / "auth.log"
PREAUTH_TICKET_FILE = CONFIG_DIR / "preauth_ticket.json"

DEFAULT_DIGITS = 6
DEFAULT_LOOK_AHEAD_WINDOW = 5
FAIL_SAFE_MAX_FAILURES = 3
FAIL_SAFE_WINDOW_SECONDS = 300  # 5 minutos
DEFAULT_PREAUTH_LIFETIME = 2700  # 45 minutos de validade máxima para pré-autorização


class SecurityError(RuntimeError):
    """Exceção levantada quando violação de integridade ou segurança é detectada."""
    pass


class HOTPAuth:
    """Módulo de autenticação HOTP (RFC 4226) blind-validation, isolamento de memória e integridade."""

    def __init__(self, config_file: Path = CONFIG_FILE):
        self.config_file = Path(config_file)
        self.config_dir = self.config_file.parent
        self.ticket_file = self.config_dir / "preauth_ticket.json"
        try:
            self.config_dir.mkdir(parents=True, exist_ok=True)
            QUEUE_DIR.mkdir(parents=True, exist_ok=True)
            LOGS_DIR.mkdir(parents=True, exist_ok=True)
        except Exception:
            pass

    # -------------------------------------------------------------------------
    # OPERAÇÕES DE ARQUIVO E INTEGRIDADE (DPAPI MAC)
    # -------------------------------------------------------------------------
    def _load_config_raw(self) -> dict:
        """Carrega a configuração bruta e valida a assinatura de integridade HMAC/DPAPI."""
        try:
            if not self.config_file.exists():
                return {}
            with open(self.config_file, "r", encoding="utf-8") as f:
                cfg = json.load(f)
        except (PermissionError, OSError):
            raise

        if not cfg:
            return {}

        # Validação estrita da assinatura de integridade
        is_valid, reason = check_integrity_mac(cfg)
        if not is_valid:
            if reason == "decrypt_error":
                # Tenta auto-migração se a chave foi protegida sob a conta de usuário legada
                try:
                    if self.migrate_config_to_machine_dpapi():
                        with open(self.config_file, "r", encoding="utf-8") as f:
                            cfg = json.load(f)
                        if verify_integrity_mac(cfg):
                            return cfg
                except Exception:
                    pass

            self._log_audit(
                "TAMPER_DETECTED",
                cfg.get("counter", 0),
                cfg.get("counter", 0),
                False,
                f"Assinatura de integridade invalida: {reason}. O arquivo foi modificado externamente."
            )
            raise SecurityError(
                "VIOLAÇÃO DE SEGURANÇA: A assinatura de integridade do arquivo hotp_config.json falhou. "
                "O arquivo foi modificado externamente. Execução bloqueada."
            )

        return cfg

    def migrate_config_to_machine_dpapi(self) -> bool:
        """Migra de forma transparente o arquivo hotp_config.json legado para DPAPI de máquina.

        Permite que o serviço SYSTEM e o usuário autentiquem sem violações de integridade.
        """
        with AtomicLock():
            if not self.config_file.exists():
                return False
            try:
                with open(self.config_file, "r", encoding="utf-8") as f:
                    cfg = json.load(f)
                if not cfg.get("secret_dpapi"):
                    return False

                sec_raw = base64.b64decode(cfg["secret_dpapi"])
                sec_plain = dpapi_unprotect(sec_raw, DPAPI_ENTROPY)
                new_sec_dpapi = dpapi_protect(bytes(sec_plain), DPAPI_ENTROPY)
                wipe_buffer(sec_plain)

                rec_raw = base64.b64decode(cfg["recovery_hash_dpapi"])
                rec_plain = dpapi_unprotect(rec_raw, DPAPI_ENTROPY)
                new_rec_dpapi = dpapi_protect(bytes(rec_plain), DPAPI_ENTROPY)
                wipe_buffer(rec_plain)

                cfg["secret_dpapi"] = base64.b64encode(new_sec_dpapi).decode("ascii")
                cfg["recovery_hash_dpapi"] = base64.b64encode(new_rec_dpapi).decode("ascii")
                cfg["integrity_mac"] = compute_integrity_mac(cfg)

                # Gravação atômica
                tmp_file = self.config_file.with_suffix(".tmp")
                with open(tmp_file, "w", encoding="utf-8") as f:
                    json.dump(cfg, f, indent=2, ensure_ascii=False)
                tmp_file.replace(self.config_file)

                apply_isolated_bridge_ntfs_acls(BASE_DIR)
                self._update_public_status(cfg)
                logging.info("[MIGRAÇÃO] hotp_config.json migrado para DPAPI de máquina com sucesso.")
                return True
            except Exception as e:
                logging.warning(f"[MIGRAÇÃO] Falha ao migrar hotp_config.json: {e}")
                return False

    def _save_config_raw(self, config_data: dict):
        """Salva a configuração atomicamente com assinatura de integridade e permissões SYSTEM."""
        # 1. Calcula a assinatura de integridade protegida por DPAPI
        config_data["integrity_mac"] = compute_integrity_mac(config_data)

        # 2. Gravação atômica
        tmp_file = self.config_file.with_suffix(".tmp")
        with open(tmp_file, "w", encoding="utf-8") as f:
            json.dump(config_data, f, indent=2, ensure_ascii=False)
        tmp_file.replace(self.config_file)

        # 3. Aplica permissões restritas exclusivas a SYSTEM e Administradores
        apply_isolated_bridge_ntfs_acls(BASE_DIR)

        # 4. Atualiza o snapshot público para o Dashboard
        self._update_public_status(config_data)

    def _update_public_status(self, cfg: dict):
        """Atualiza o arquivo público queue/status.json sem vazar nenhuma chave ou senha."""
        now = time.time()
        failures = [t for t in cfg.get("failures", []) if (now - t) <= FAIL_SAFE_WINDOW_SECONDS]
        lockdown = cfg.get("lockdown", False)
        provisioned = cfg.get("provisioned_flag", 0) == 1

        status_text = "Ativo"
        if lockdown:
            status_text = "Bloqueado (Lockdown)"
        elif not provisioned:
            status_text = "Aguardando Provisionamento"

        status_payload = {
            "counter": cfg.get("counter", 0),
            "provisioned_flag": cfg.get("provisioned_flag", 0),
            "lockdown": lockdown,
            "recent_failures": len(failures),
            "max_failures": FAIL_SAFE_MAX_FAILURES,
            "status_text": status_text,
            "last_used_at": cfg.get("last_used_at"),
            "created_at": cfg.get("created_at"),
            "updated_at": datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S")
        }

        try:
            tmp_status = STATUS_FILE.with_suffix(".tmp")
            with open(tmp_status, "w", encoding="utf-8") as f:
                json.dump(status_payload, f, indent=2, ensure_ascii=False)
            tmp_status.replace(STATUS_FILE)
        except Exception:
            pass

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
        """Registra logs estruturados de auditoria de todas as operações no fuso horário local do usuário."""
        timestamp = datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S")
        status_str = "SUCCESS" if success else "FAIL"
        # Mantém estritamente apenas os 2 primeiros dígitos visíveis
        clean_otp = str(otp_provided).strip()
        masked_otp = (clean_otp[:2] + "****") if len(clean_otp) >= 2 else "******"

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
    # PROVISIONAMENTO INICIAL
    # -------------------------------------------------------------------------
    def is_provisioned(self) -> bool:
        """Verifica se a chave já foi provisionada e o flag está em 1."""
        try:
            cfg = self._load_config_raw()
            if cfg:
                return cfg.get("provisioned_flag", 0) == 1
        except Exception:
            pass

        # Fallback para snapshot público de status se o processo for de usuário
        if STATUS_FILE.exists():
            try:
                with open(STATUS_FILE, "r", encoding="utf-8") as f:
                    pub = json.load(f)
                    return pub.get("provisioned_flag", 0) == 1
            except Exception:
                pass

        return False

    def is_lockdown(self) -> bool:
        """Verifica se o sistema está em estado de lockdown de segurança."""
        try:
            cfg = self._load_config_raw()
            if cfg:
                return cfg.get("lockdown", False) is True
        except Exception:
            pass

        if STATUS_FILE.exists():
            try:
                with open(STATUS_FILE, "r", encoding="utf-8") as f:
                    pub = json.load(f)
                    return pub.get("lockdown", False) is True
            except Exception:
                pass

        return False

    def provision(self, recovery_password: str, force: bool = False, caller_info: Optional[dict] = None) -> dict:
        """Gera a chave secreta inicial em memória, protege com DPAPI e trava o flag em 1.

        Permitido estritamente uma única vez (ou durante reset autenticado).
        """
        with AtomicLock():
            cfg = {}
            try:
                if self.config_file.exists():
                    cfg = self._load_config_raw()
            except SecurityError:
                if not force:
                    raise
            except (PermissionError, OSError):
                pass

            if cfg.get("provisioned_flag", 0) == 1 and not force:
                self._log_audit(
                    "PROVISION_DENIED",
                    cfg.get("counter", 0),
                    cfg.get("counter", 0),
                    False,
                    "Tentativa não autorizada de gerar nova chave com flag=1",
                    caller_info=caller_info
                )
                raise PermissionError(
                    "Operação Bloqueada: A chave HOTP já foi provisionada e está travada em flag=1. "
                    "Geração de nova chave proibida sem procedimento de reset autenticado."
                )

            if not recovery_password or len(recovery_password) < 8:
                raise ValueError("A palavra-passe de recuperação deve conter pelo menos 8 caracteres.")

            # 1. Gera segredo criptográfico de 160 bits - 20 bytes
            raw_secret = secrets.token_bytes(20)
            secret_b32 = base64.b32encode(raw_secret).decode("ascii")

            # 2. Criptografa o segredo via DPAPI
            secret_dpapi = dpapi_protect(raw_secret)
            secret_dpapi_b64 = base64.b64encode(secret_dpapi).decode("ascii")

            # Limpa imediatamente os bytes do segredo em texto claro da RAM
            raw_secret_ba = bytearray(raw_secret)
            wipe_buffer(raw_secret_ba)
            del raw_secret, raw_secret_ba
            gc.collect()

            # 3. Hash da senha de recuperação PBKDF2 600.000 iterações e proteção DPAPI
            pw_hash_b64, salt_b64 = hash_recovery_password(recovery_password)
            pw_hash_dpapi = dpapi_protect(pw_hash_b64.encode("ascii"))
            pw_hash_dpapi_b64 = base64.b64encode(pw_hash_dpapi).decode("ascii")

            # 4. Gera a URI para o autenticador do celular com counter=0
            uri = f"otpauth://hotp/AdminBridge:Admin?secret={secret_b32}&counter=0&digits={DEFAULT_DIGITS}&issuer=AdminBridge"

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
                "created_at": datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S"),
                "last_used_at": None,
                "last_success_counter": 0,
            }
            self._save_config_raw(new_config)

            self._log_audit(
                "PROVISION",
                0,
                0,
                True,
                "Chave provisionada com sucesso e protegida via DPAPI. Flag travado em 1 e counter=0.",
                caller_info=caller_info
            )

            return {
                "uri": uri,
                "secret_base32": secret_b32,
                "digits": DEFAULT_DIGITS,
                "counter": 0
            }

    def verify_and_finalize_initial_otp(self, otp: str) -> Tuple[bool, str]:
        """Valida o primeiro codigo gerado no celular para confirmar o pareamento e trava a configuracao."""
        clean_otp = str(otp).strip()
        if not clean_otp.isdigit() or len(clean_otp) != DEFAULT_DIGITS:
            return False, f"O codigo OTP deve conter exatamente {DEFAULT_DIGITS} digitos numericos."

        with AtomicLock():
            cfg = self._load_config_raw()
            if not cfg:
                return False, "Configuracao nao encontrada para validacao inicial."

            secret_dpapi_b64 = cfg.get("secret_dpapi")
            secret_enc = base64.b64decode(secret_dpapi_b64)
            secret_ba = dpapi_unprotect(secret_enc)
            try:
                # Compara nas posicoes 0 a 2 para tolerar cliques iniciais no celular
                matched = None
                for test_c in range(0, 3):
                    expected = self._compute_hotp_internal(secret_ba, test_c, DEFAULT_DIGITS)
                    if hmac.compare_digest(expected, clean_otp):
                        matched = test_c
                        break

                if matched is None:
                    return False, "Codigo incorreto. Digite os 6 digitos exibidos no aplicativo do seu celular."

                # Avanco estrito: proximo sera matched + 1
                new_c = matched + 1
                cfg["counter"] = new_c
                cfg["provisioned_flag"] = 1
                cfg["last_success_counter"] = matched
                cfg["last_used_at"] = datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S")
                self._save_config_raw(cfg)

                self._log_audit(
                    "INITIAL_PAIRING_VERIFIED",
                    0,
                    new_c,
                    True,
                    f"Pareamento inicial confirmado com sucesso no indice #{matched}. Proximo contador: {new_c}."
                )
                return True, "Pareamento inicial validado com sucesso."
            finally:
                wipe_buffer(secret_ba)
                del secret_ba
                gc.collect()

    def repair_corrupted_installation(self, recovery_password: str) -> Tuple[bool, str]:
        """Restaura pastas e arquivos apos deteccao de adulteracao exigindo a palavra-passe do proprietario."""
        if not recovery_password or len(recovery_password) < 8:
            return False, "A palavra-passe deve conter pelo menos 8 caracteres."

        with AtomicLock():
            # Tenta validar a palavra-passe contra o hash existente se disponivel
            if self.config_file.exists():
                try:
                    with open(self.config_file, "r", encoding="utf-8") as f:
                        raw_data = json.load(f)
                    salt_b64 = raw_data.get("recovery_salt")
                    hash_dpapi_b64 = raw_data.get("recovery_hash_dpapi")
                    if salt_b64 and hash_dpapi_b64:
                        hash_raw = base64.b64decode(hash_dpapi_b64)
                        expected_hash_ba = dpapi_unprotect(hash_raw)
                        expected_hash = bytes(expected_hash_ba).decode("ascii")
                        wipe_buffer(expected_hash_ba)
                        if not verify_recovery_password(recovery_password, expected_hash, salt_b64):
                            return False, "Palavra-passe de recuperacao incorreta. Apenas o proprietario pode reparar o sistema."
                except Exception:
                    pass

            # Executa a restauracao das pastas e remocao de arquivos adulterados
            try:
                self.config_file.unlink(missing_ok=True)
                if self.ticket_file.exists():
                    self.ticket_file.unlink(missing_ok=True)
                if STATUS_FILE.exists():
                    STATUS_FILE.unlink(missing_ok=True)

                self.config_dir.mkdir(parents=True, exist_ok=True)
                QUEUE_DIR.mkdir(parents=True, exist_ok=True)
                LOGS_DIR.mkdir(parents=True, exist_ok=True)
                (BASE_DIR / "scripts").mkdir(parents=True, exist_ok=True)

                apply_isolated_bridge_ntfs_acls(BASE_DIR)
                self._log_audit("REPAIR_SUCCESS", 0, 0, True, "Reparo do sistema executado pelo proprietario com sucesso.")
                return True, "Estrutura do sistema reparada com sucesso. Pronto para reinicializacao."
            except Exception as e:
                return False, f"Falha ao executar reparo de pastas: {e}"

    # -------------------------------------------------------------------------
    # RESET E AUTODESTRUIÇÃO DE PRIVILÉGIOS (REQUISITO 3)
    # -------------------------------------------------------------------------
    def reset_and_destroy_privileges(
        self,
        recovery_password: str,
        physical_challenge_response: str,
        expected_challenge: str,
        caller_info: Optional[dict] = None
    ) -> dict:
        """Executa a revogação estrita de privilégios e destruição de chaves:

        1. Exige palavra-passe de recuperação correta e desafio de presença física.
        2. Destrói imediatamente a chave secreta da memória e do disco.
        3. Remove a tarefa agendada do Windows (schtasks /delete /f).
        4. O utilitário perde todas as permissões administrativas permanentes.
        """
        with AtomicLock():
            cfg = self._load_config_raw()
            c_before = cfg.get("counter", 0)

            # 1. Validação de Presença Física
            if not physical_challenge_response or physical_challenge_response.strip().upper() != expected_challenge.strip().upper():
                self._log_audit("RESET_FAIL", c_before, c_before, False, "Falha na confirmação de presença física.", caller_info=caller_info)
                raise PermissionError("Validação de presença física falhou: o código digitado não confere.")

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

            # 3. CONDIÇÕES CUMPRIDAS: AUTODESTRUIÇÃO DE PRIVILÉGIOS E SEGREDO
            # Destrói a chave do disco
            cfg["provisioned_flag"] = 0
            cfg["lockdown"] = False
            cfg["secret_dpapi"] = ""
            cfg["counter"] = 0
            cfg["failures"] = []
            self._save_config_raw(cfg)

            # Remove a tarefa agendada do Windows
            try:
                for tn in ("AdminBridge", "AntigravityAdminBridge"):
                    subprocess.run(["schtasks", "/delete", "/tn", tn, "/f"], capture_output=True, check=False, creationflags=0x08000000)
            except Exception:
                pass

            self._log_audit(
                "RESET_PRIVILEGES_DESTROYED",
                c_before,
                0,
                True,
                "Chave destruída. Tarefa elevada removida do Windows. Privilégios revogados com sucesso.",
                caller_info=caller_info
            )

            return {
                "status": "destroyed",
                "message": "Chave HOTP revogada e destruída. Tarefa agendada removida. Privilégios elevados encerrados com sucesso."
            }

    # -------------------------------------------------------------------------
    # VALIDAÇÃO CEGA COM ISOLAMENTO DE MEMÓRIA E FAIL-SAFE
    # -------------------------------------------------------------------------
    def verify_and_advance(self, provided_otp: Optional[str], caller_info: Optional[dict] = None) -> Tuple[bool, str, int]:
        """Validação cega atômica do token HOTP:

        - O computador NUNCA calcula nem expõe o OTP para a interface.
        - Memória desencriptada no milissegundo exato e sobrescrita com zeros.
        - Comparação em tempo constante (hmac.compare_digest).
        - Contador avança obrigatoriamente tanto em SUCESSO quanto em ERRO (+1).
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
                self._log_audit(
                    "LOCKDOWN_BLOCKED",
                    current_counter,
                    current_counter,
                    False,
                    "Requisição rejeitada: utilitário em lockdown de segurança.",
                    provided_otp or "",
                    caller_info
                )
                return False, "FAIL_SAFE_LOCKDOWN: O utilitário foi desativado por excesso de falhas. Exige UAC manual.", current_counter

            # Valida origem do processo chamador
            valid_caller, caller_msg = verify_caller_origin(caller_info)
            if not valid_caller:
                new_counter = current_counter + 1
                cfg["counter"] = new_counter
                self._save_config_raw(cfg)
                self._log_audit(
                    "VERIFY_REJECTED",
                    current_counter,
                    new_counter,
                    False,
                    f"Origem não autorizada: {caller_msg}",
                    provided_otp or "",
                    caller_info
                )
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
                cfg["last_used_at"] = datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S")
                cfg["failures"] = []  # Limpa falhas anteriores
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
                # ERRO: Avança contador obrigatoriamente
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
        failures = [t for t in cfg.get("failures", []) if (now - t) <= FAIL_SAFE_WINDOW_SECONDS]
        failures.append(now)
        cfg["failures"] = failures

        if len(failures) >= FAIL_SAFE_MAX_FAILURES:
            cfg["lockdown"] = True
            cfg["lockdown_at"] = datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S")
            self._save_config_raw(cfg)

            # Aciona desativação/remoção imediata da tarefa agendada
            try:
                for tn in ("AdminBridge", "AntigravityAdminBridge"):
                    subprocess.run(["schtasks", "/delete", "/tn", tn, "/f"], capture_output=True, check=False, creationflags=0x08000000)
            except Exception:
                pass

            self._log_audit(
                "FAIL_SAFE_LOCKDOWN",
                counter_before,
                counter_after,
                False,
                f"3 falhas consecutivas em < 5 minutos! Tarefa elevada removida. Motivo: {reason}",
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
        """Consulta metadados passivos (contador, estado, falhas).

        Pode ser executado com leitura direta ou via snapshot público.
        O computador NUNCA calcula nem retorna tokens nesta função.
        """
        # Se puder ler o arquivo config direto (ex: como SYSTEM), usa read_passive_metadata
        try:
            return read_passive_metadata(self.config_file)
        except Exception:
            pass

        # Fallback: lê do snapshot público queue/status.json
        if STATUS_FILE.exists():
            try:
                with open(STATUS_FILE, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                pass

        return {
            "counter": 0,
            "provisioned_flag": 0,
            "lockdown": False,
            "recent_failures": 0,
            "max_failures": FAIL_SAFE_MAX_FAILURES,
            "status_text": "Aguardando Provisionamento",
            "tampered": False
        }

    # -------------------------------------------------------------------------
    # CANAL DE PRÉ-AUTORIZAÇÃO (TICKET TEMPORÁRIO DE ATÉ 45 MINUTOS)
    # -------------------------------------------------------------------------
    def create_preauth_ticket(
        self,
        otp: str,
        caller_info: Optional[dict] = None,
        lifetime_seconds: int = DEFAULT_PREAUTH_LIFETIME
    ) -> Tuple[bool, str, dict]:
        """Consome o OTP imediatamente no início da interação, avança o contador (+1)

        e gera um ticket de autorização temporário válido por até 45 minutos.
        Garante que o código não expire enquanto o assistente pesquisa e monta os scripts.
        """
        caller = caller_info or {"pid": os.getpid(), "user": os.getenv("USERNAME", "unknown")}
        is_valid, auth_msg, used_counter = self.verify_and_advance(otp, caller)
        if not is_valid:
            return False, auth_msg, {}

        token = secrets.token_hex(24)
        token_hash = hashlib.sha256(token.encode("ascii")).hexdigest()
        ticket_data = {
            "token_hash": token_hash,
            "caller_user": caller.get("user", os.getenv("USERNAME", "unknown")),
            "caller_pid": caller.get("pid", 0),
            "counter_used": used_counter - 1,
            "created_at": time.time(),
            "expires_at": time.time() + lifetime_seconds,
            "lifetime_seconds": lifetime_seconds,
            "used": False
        }

        with AtomicLock():
            self.config_dir.mkdir(parents=True, exist_ok=True)
            tmp_t = self.ticket_file.with_suffix(".tmp")
            with open(tmp_t, "w", encoding="utf-8") as f:
                json.dump(ticket_data, f, indent=2)
            tmp_t.replace(self.ticket_file)

        self._log_audit(
            "PREAUTH_TICKET_CREATED",
            used_counter - 1,
            used_counter,
            True,
            f"Ticket de pre-autorizacao gerado com sucesso para validade de {lifetime_seconds // 60} minutos.",
            otp,
            caller
        )

        return True, f"Pre-autorizacao confirmada com sucesso! Valida por ate {lifetime_seconds // 60} minutos.", {
            "token": token,
            "expires_in": lifetime_seconds,
            "counter": used_counter - 1
        }

    def consume_preauth_ticket(
        self,
        token: Optional[str] = None,
        caller_user: Optional[str] = None
    ) -> Tuple[bool, str]:
        """Valida e consome atomicamente o ticket de pre-autorizacao para execucao de comando."""
        with AtomicLock():
            if not self.ticket_file.exists():
                return False, "Nenhum ticket de pre-autorizacao ativo encontrado."

            try:
                with open(self.ticket_file, "r", encoding="utf-8") as f:
                    ticket = json.load(f)
            except Exception as e:
                return False, f"Falha ao ler ticket de pre-autorizacao: {e}"

            now = time.time()
            if now > ticket.get("expires_at", 0):
                self.ticket_file.unlink(missing_ok=True)
                return False, "Ticket de pre-autorizacao expirado por limite de 45 minutos."

            # Exige estritamente o token Bearer secreto
            if not token or not str(token).strip():
                return False, "Token secreto de pre-autorizacao e estritamente obrigatorio."

            expected_hash = hashlib.sha256(token.strip().encode("ascii")).hexdigest()
            if not hmac.compare_digest(expected_hash, ticket.get("token_hash", "")):
                return False, "Token de pre-autorizacao fornecido e incorreto."

            # Consumo estritamente unico
            try:
                self.ticket_file.unlink(missing_ok=True)
            except Exception:
                pass

            self._log_audit(
                "PREAUTH_TICKET_CONSUMED",
                ticket.get("counter_used", 0),
                ticket.get("counter_used", 0) + 1,
                True,
                "Ticket de pre-autorizacao validado e consumido com sucesso para execucao imediata."
            )
            return True, "Ticket de pre-autorizacao validado e consumido com sucesso."

    def diagnose_otp_sync(
        self,
        provided_otp: str,
        max_lookahead: int = 10,
        max_lookback: Optional[int] = None
    ) -> dict:
        """
        Modo de diagnóstico e teste de sincronia HOTP RFC 4226.
        Aplica a máquina de estados estrita em duas fases no próprio processo.
        """
        clean_otp = str(provided_otp).strip()
        if not clean_otp.isdigit() or len(clean_otp) != DEFAULT_DIGITS:
            return {
                "success": False,
                "error": f"O código OTP deve conter exatamente {DEFAULT_DIGITS} dígitos numéricos."
            }

        with AtomicLock():
            cfg = self._load_config_raw()

            if not cfg or cfg.get("provisioned_flag") != 1:
                return {
                    "success": False,
                    "error": "O utilitário ainda não está provisionado."
                }

            current_counter = cfg.get("counter", 0)

            # Recupera segredo em memória de forma segura
            secret_dpapi_b64 = cfg.get("secret_dpapi")
            secret_enc = base64.b64decode(secret_dpapi_b64)
            secret_ba = dpapi_unprotect(secret_enc)

            try:
                # 1. Fase 1: Busca sequencial de tras para frente - de current_counter ate 0
                for c in range(current_counter, -1, -1):
                    code = self._compute_hotp_internal(secret_ba, c, DEFAULT_DIGITS)
                    if hmac.compare_digest(clean_otp, code):
                        if c == current_counter:
                            new_c = current_counter + 1
                            cfg["counter"] = new_c
                            self._save_config_raw(cfg)
                            self._log_audit(
                                "SYNC_MATCH_CURRENT",
                                current_counter,
                                new_c,
                                True,
                                f"Sincronizacao confirmada no indice atual #{c}. Contador avancou para {new_c}.",
                                clean_otp
                            )
                            return {
                                "success": True,
                                "matched_counter": c,
                                "current_counter": current_counter,
                                "next_counter": new_c,
                                "diff": 0,
                                "status": "synchronized",
                                "status_label": "100% Sincronizado",
                                "summary": "Seu celular esta perfeitamente sincronizado com o computador.",
                                "action_instruction": f"O proximo codigo gerado no seu celular OTP #{new_c} sera o aceito para o proximo comando.",
                                "message": f"Seu autenticador esta no OTP #{c} e esta sincronizado com o computador. O proximo OTP necessario agora e o #{new_c}."
                            }
                        else:
                            diff = c - current_counter
                            return {
                                "success": True,
                                "matched_counter": c,
                                "current_counter": current_counter,
                                "next_counter": current_counter,
                                "diff": diff,
                                "status": "behind",
                                "status_label": "Codigo Antigo - Atrasado",
                                "summary": "Este codigo ja expirou e nao sera aceito.",
                                "action_instruction": f"O celular gerou o codigo antigo #{c}, mas o computador ja espera o OTP #{current_counter}. Gere novos codigos no aplicativo ate alcancar o computador.",
                                "message": f"Seu autenticador esta no OTP #{c}, abaixo do contador do computador que esta no #{current_counter}. O proximo OTP necessario no computador continua sendo o #{current_counter}."
                            }

                # 2. Fase 2: Busca sequencial para frente - estritamente ate 10 posicoes acima
                max_c = current_counter + 10
                for c in range(current_counter + 1, max_c + 1):
                    code = self._compute_hotp_internal(secret_ba, c, DEFAULT_DIGITS)
                    if hmac.compare_digest(clean_otp, code):
                        # Interrompe imediatamente sem calcular seguintes
                        new_c = c + 1
                        cfg["counter"] = new_c
                        self._save_config_raw(cfg)
                        self._log_audit(
                            "SYNC_JUMP_AHEAD",
                            current_counter,
                            new_c,
                            True,
                            f"Sincronizacao identificada a frente no OTP #{c}. Contador saltou para {new_c}.",
                            clean_otp
                        )
                        diff = c - current_counter
                        return {
                            "success": True,
                            "matched_counter": c,
                            "current_counter": current_counter,
                            "next_counter": new_c,
                            "diff": diff,
                            "status": "ahead",
                            "status_label": "Compativel - A Frente",
                            "summary": "Seu aplicativo avancou e o computador sincronizou com o salto!",
                            "action_instruction": f"Seu celular esta no OTP #{c}. O computador avancou o contador e agora aguarda o OTP #{new_c}.",
                            "message": f"Seu autenticador esta no OTP #{c}. O contador do computador pulou para #{new_c} e este sera o proximo aceito."
                        }

                # 3. Esgotamento das 10 posicoes acima sem correspondencia: o contador salta para current_counter + 11
                exhausted_c = current_counter + 11
                cfg["counter"] = exhausted_c
                self._save_config_raw(cfg)
                self._log_audit(
                    "SYNC_EXHAUSTED_JUMP",
                    current_counter,
                    exhausted_c,
                    False,
                    f"10 posicoes acima testadas sem correspondencia. Contador saltou para {exhausted_c}.",
                    clean_otp
                )
                return {
                    "success": False,
                    "matched_counter": None,
                    "current_counter": current_counter,
                    "next_counter": exhausted_c,
                    "diff": None,
                    "status": "not_found",
                    "status_label": "Nao Reconhecido",
                    "summary": "O codigo digitado nao correspondeu as 10 posicoes testadas.",
                    "action_instruction": f"Foram testadas 10 posicoes acima do computador #{current_counter} e o contador agora saltou para aguardar o OTP #{exhausted_c}.",
                    "message": f"Codigo OTP nao encontrado apos testar 10 posicoes acima. O contador do sistema agora saltou para #{exhausted_c}."
                }

            finally:
                wipe_buffer(secret_ba)
                del secret_ba
                gc.collect()
