import base64
import ctypes
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

from hotp_crypto import (
    AtomicLock,
    append_ledger_block,
    apply_isolated_bridge_ntfs_acls,
    apply_system_only_ntfs_acls,
    check_config_acl_isolation,
    check_integrity_mac,
    compute_integrity_mac,
    create_detached_signature_file,
    create_owner_anchor,
    clear_external_system_vault,
    dpapi_protect,
    KernelFileGuard,
    protect_transit_token,
    unprotect_transit_token,
    verify_scheduled_task_integrity,
    dpapi_unprotect,
    ensure_hw_salt,
    get_composite_entropy,
    generate_mutual_confirmation_code,
    generate_physical_challenge,
    get_file_usn,
    hash_recovery_password,
    lock_memory_page,
    read_passive_metadata,
    restore_ntfs_acls_for_removal,
    verify_caller_origin,
    verify_integrity_mac,
    verify_ledger_integrity,
    verify_owner_anchor,
    verify_owner_password,
    verify_recovery_password,
    wipe_buffer,
    DPAPI_ENTROPY,
    DPAPI_MAC_ENTROPY,
    _canonical_payload,
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
    # OPERAÇÕES DE ARQUIVO E INTEGRIDADE (DPAPI MAC + OWNER ANCHOR)
    # -------------------------------------------------------------------------
    def _protect_secret(self, plaintext: bytes) -> bytes:
        """Criptografa segredo via DPAPI combinando entropia da aplicação + MachineGuid + hw_salt.bin."""
        ensure_hw_salt(self.config_dir)
        comp_ent = get_composite_entropy(DPAPI_ENTROPY, self.config_dir)
        return dpapi_protect(plaintext, entropy=comp_ent)

    def _unprotect_secret(self, ciphertext: bytes) -> bytearray:
        """Descriptografa segredo via DPAPI exigindo o hw_salt.bin íntegro (com fallback para migração)."""
        comp_ent = get_composite_entropy(DPAPI_ENTROPY, self.config_dir)
        try:
            return dpapi_unprotect(ciphertext, entropy=comp_ent)
        except Exception:
            return dpapi_unprotect(ciphertext, entropy=DPAPI_ENTROPY)

    def _load_config_raw(self) -> dict:
        """Carrega a configuração bruta e valida a assinatura de integridade HMAC/DPAPI, USN e Âncora Ed25519."""
        try:
            if not self.config_file.exists():
                return {}
            with open(self.config_file, "r", encoding="utf-8") as f:
                cfg = json.load(f)
        except (PermissionError, OSError):
            raise

        if not cfg:
            return {}

        # 1. Validação estrita da assinatura de integridade, USN e static_mesh_hash
        is_valid, reason = check_integrity_mac(cfg, self.config_file)
        if not is_valid:
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

        # 2. Validação da âncora criptográfica Ed25519 do proprietário contra modificação de executável/pasta
        if cfg.get("provisioned_flag", 0) == 1:
            anchor_file = self.config_dir / "owner_anchor.json"
            if anchor_file.exists() or self.config_file == CONFIG_FILE:
                ok_anc, anc_reason = verify_owner_anchor(anchor_file, self.config_dir)
                if not ok_anc:
                    self._log_audit(
                        "TAMPER_DETECTED",
                        cfg.get("counter", 0),
                        cfg.get("counter", 0),
                        False,
                        f"Violacao da ancora soberana Ed25519: {anc_reason}."
                    )
                    raise SecurityError(
                        f"VIOLAÇÃO DE SEGURANÇA: A âncora do proprietário ou o executável foram adulterados ({anc_reason})."
                    )

        return cfg

    def migrate_config_to_machine_dpapi(self) -> bool:
        """Migra o arquivo hotp_config.json para DPAPI de máquina apenas se o arquivo for autêntico."""
        with AtomicLock():
            if not self.config_file.exists():
                return False
            try:
                with open(self.config_file, "r", encoding="utf-8") as f:
                    cfg = json.load(f)
                if not cfg.get("secret_dpapi"):
                    return False

                is_valid, _ = check_integrity_mac(cfg, self.config_file)
                if not is_valid:
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

                tmp_file = self.config_file.with_suffix(".tmp")
                with open(tmp_file, "w", encoding="utf-8") as f:
                    json.dump(cfg, f, indent=2, ensure_ascii=False)
                tmp_file.replace(self.config_file)

                apply_isolated_bridge_ntfs_acls(BASE_DIR)
                create_detached_signature_file(self.config_file, cfg)
                self._update_public_status(cfg)
                logging.info("[MIGRAÇÃO] hotp_config.json migrado para DPAPI de maquina com sucesso.")
                return True
            except Exception as e:
                logging.warning(f"[MIGRAÇÃO] Falha ao migrar hotp_config.json: {e}")
                return False

    def _save_config_raw(self, config_data: dict):
        """Salva a configuração atomicamente com assinatura de integridade e permissões restritas."""
        # 1. Calcula a assinatura de integridade protegida por DPAPI
        config_data["integrity_mac"] = compute_integrity_mac(config_data)

        # 2. Desbloqueia atributo somente leitura se o arquivo já existir
        if self.config_file.exists() and hasattr(ctypes, "windll"):
            try:
                ctypes.windll.kernel32.SetFileAttributesW(str(self.config_file), 0x80)
            except Exception:
                pass

        # 3. Gravação atômica
        tmp_file = self.config_file.with_suffix(".tmp")
        with open(tmp_file, "w", encoding="utf-8") as f:
            json.dump(config_data, f, indent=2, ensure_ascii=False)
        tmp_file.replace(self.config_file)

        # 4. Gera assinatura digital desanexada imediatamente em sincronia
        create_detached_signature_file(self.config_file, config_data)

        # 5. Restaura atributo somente-leitura para dificultar edições acidentais
        if hasattr(ctypes, "windll"):
            try:
                ctypes.windll.kernel32.SetFileAttributesW(str(self.config_file), 0x01)
            except Exception:
                pass

        # 6. Atualiza o snapshot público para o Dashboard
        self._update_public_status(config_data)

    def _update_public_status(self, cfg: dict):
        """Atualiza o arquivo público queue/status.json sem vazar nenhuma chave ou senha."""
        now = time.time()
        failures = [t for t in cfg.get("failures", []) if (now - t) <= FAIL_SAFE_WINDOW_SECONDS]
        lockdown = cfg.get("lockdown", False)
        provisioned = cfg.get("provisioned_flag", 0) == 1

        status_text = "Ativo"
        if lockdown:
            status_text = "Bloqueado [Lockdown]"
        elif not provisioned:
            status_text = "Aguardando Provisionamento"

        auth_mode_active = False
        auth_expires_in = 0
        if self.ticket_file.exists():
            try:
                with open(self.ticket_file, "r", encoding="utf-8") as tf:
                    tdata = json.load(tf)
                exp = tdata.get("expires_at", 0)
                if now < exp:
                    auth_mode_active = True
                    auth_expires_in = int(exp - now)
            except Exception:
                pass

        status_payload = {
            "counter": cfg.get("counter", 0),
            "provisioned_flag": cfg.get("provisioned_flag", 0),
            "lockdown": lockdown,
            "recent_failures": len(failures),
            "max_failures": FAIL_SAFE_MAX_FAILURES,
            "status_text": status_text,
            "auth_mode_active": auth_mode_active,
            "auth_expires_in": auth_expires_in,
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
        """Registra logs estruturados de auditoria e blocos encadeados no ledger imutável."""
        timestamp = datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S")
        status_str = "SUCCESS" if success else "FAIL"
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

        try:
            code_hash = hashlib.sha256(details.encode("utf-8")).hexdigest()[:16]
            append_ledger_block(action, counter_after, code_hash, caller_info, status_str, details)
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

    @staticmethod
    def compute_hotp(secret: bytes, counter: int, digits: int = 6) -> str:
        """Alias para compatibilidade retroativa de cálculo do HOTP RFC 4226."""
        sec_ba = bytearray(secret)
        try:
            return HOTPAuth._compute_hotp_internal(sec_ba, counter, digits)
        finally:
            wipe_buffer(sec_ba)

    # -------------------------------------------------------------------------
    # PROVISIONAMENTO INICIAL (COM BLINDAGEM PRÉ-GRAVAÇÃO)
    # -------------------------------------------------------------------------
    def is_provisioned(self) -> bool:
        """Verifica se a chave já foi provisionada e o flag está em 1."""
        try:
            cfg = self._load_config_raw()
            if cfg:
                return cfg.get("provisioned_flag", 0) == 1
        except SecurityError:
            return True
        except Exception:
            pass

        if STATUS_FILE.exists():
            try:
                with open(STATUS_FILE, "r", encoding="utf-8") as f:
                    pub = json.load(f)
                    return pub.get("provisioned_flag", 0) == 1
            except Exception:
                pass

        if self.config_file.exists():
            return True

        return False

    def is_lockdown(self) -> bool:
        """Verifica se o sistema está em estado de lockdown de segurança."""
        try:
            cfg = self._load_config_raw()
            if cfg:
                return cfg.get("lockdown", False) is True
        except SecurityError:
            return True
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

    def force_lockdown(self, reason: str = "Bloqueio forçado"):
        """Força o estado de lockdown de segurança no arquivo de configuração."""
        with AtomicLock():
            try:
                if self.config_file.exists():
                    try:
                        with open(self.config_file, "r", encoding="utf-8") as f:
                            cfg = json.load(f)
                    except Exception:
                        cfg = {}
                    cfg["lockdown"] = True
                    cfg["lockdown_reason"] = reason
                    self._save_config_raw(cfg)
                else:
                    self._update_public_status({"lockdown": True, "lockdown_reason": reason, "provisioned_flag": 0})
            except Exception:
                pass

    def check_owner_password_status(self) -> Tuple[bool, float]:
        """Verifica se o ciclo de 14 dias para confirmação da Senha Mestra expirou."""
        try:
            cfg = self._load_config_raw()
            last_v = cfg.get("last_owner_password_verified_at")
            if not last_v:
                return True, 0.0
            elapsed = time.time() - float(last_v)
            is_valid = elapsed <= 1209600.0
            return is_valid, elapsed
        except Exception:
            return True, 0.0

    def refresh_owner_password_verification(self, password: str) -> bool:
        """Renova o ciclo de 14 dias mediante confirmação da Senha Mestra legítima."""
        with AtomicLock():
            try:
                anchor_file = self.config_dir / "owner_anchor.json"
                if anchor_file.exists():
                    if not verify_owner_password(password, anchor_file, self.config_dir):
                        return False
                else:
                    cfg = self._load_config_raw()
                    salt_b64 = cfg.get("recovery_salt")
                    hash_dpapi_b64 = cfg.get("recovery_hash_dpapi")
                    if not salt_b64 or not hash_dpapi_b64:
                        return False
                    hash_raw = base64.b64decode(hash_dpapi_b64)
                    expected_hash_ba = self._unprotect_secret(hash_raw)
                    expected_hash = bytes(expected_hash_ba).decode("ascii")
                    wipe_buffer(expected_hash_ba)
                    if not verify_recovery_password(password, expected_hash, salt_b64):
                        return False

                cfg = self._load_config_raw()
                cfg["last_owner_password_verified_at"] = time.time()
                self._save_config_raw(cfg)
                self._log_audit(
                    "OWNER_PASSWORD_REFRESHED",
                    cfg.get("counter", 0),
                    cfg.get("counter", 0),
                    True,
                    "Ciclo de 14 dias da Senha Mestra renovado com sucesso pelo proprietario."
                )
                return True
            except Exception as e:
                logging.warning(f"Falha ao renovar ciclo de 14 dias: {e}")
                return False

    def provision(self, recovery_password: str, force: bool = False, caller_info: Optional[dict] = None) -> dict:
        """Gera a chave secreta inicial em memória, aplica ACL NTFS ANTES de gravar, protege com DPAPI e trava flag=1."""
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

            # 0. Blindagem NTFS prévia ANTES de gravar qualquer segredo no disco (elimina Race Condition TOCTOU)
            try:
                self.config_dir.mkdir(parents=True, exist_ok=True)
                ensure_hw_salt(self.config_dir)
                base_root = self.config_dir.parent if self.config_dir.name == "config" else self.config_dir
                apply_isolated_bridge_ntfs_acls(base_root)
            except Exception:
                pass

            # 1. Cria a âncora Ed25519 do proprietário diretamente em self.config_dir
            anchor_target = self.config_dir / "owner_anchor.json"
            try:
                create_owner_anchor(recovery_password, self.config_dir, anchor_path=anchor_target)
            except Exception as e:
                logging.warning(f"Aviso ao gerar ancora do proprietario: {e}")

            # 2. Gera segredo criptográfico de 160 bits (20 bytes) em buffer mutável travado na RAM
            raw_secret_ba = bytearray(secrets.token_bytes(20))
            lock_memory_page(raw_secret_ba)
            try:
                secret_b32 = base64.b32encode(bytes(raw_secret_ba)).decode("ascii")
                secret_dpapi = self._protect_secret(bytes(raw_secret_ba))
                secret_dpapi_b64 = base64.b64encode(secret_dpapi).decode("ascii")
            finally:
                wipe_buffer(raw_secret_ba)
                del raw_secret_ba
                gc.collect()

            # 3. Hash da senha de recuperação PBKDF2 (600.000 iterações) e proteção DPAPI
            pw_hash_b64, salt_b64 = hash_recovery_password(recovery_password)
            pw_hash_dpapi = self._protect_secret(pw_hash_b64.encode("ascii"))
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
                "last_owner_password_verified_at": time.time(),
            }
            self._save_config_raw(new_config)

            try:
                base_root = self.config_dir.parent if self.config_dir.name == "config" else self.config_dir
                apply_isolated_bridge_ntfs_acls(base_root)
            except Exception:
                pass

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
        """Valida o primeiro código gerado no celular para confirmar o pareamento e trava a configuração."""
        clean_otp = str(otp).strip()
        if not clean_otp.isdigit() or len(clean_otp) != DEFAULT_DIGITS:
            return False, f"O codigo OTP deve conter exatamente {DEFAULT_DIGITS} digitos numericos."

        if self._is_daemon_alive_other_process():
            rpc_res = self._delegate_rpc_to_daemon(
                "sync",
                {"otp": clean_otp, "allow_lookahead": allow_lookahead, "max_lookahead": max_lookahead, "max_lookback": max_lookback},
                timeout=12.0
            )
            if rpc_res is not None and "result" in rpc_res:
                return rpc_res["result"]

        with AtomicLock():
            try:
                cfg = self._load_config_raw()
            except PermissionError:
                rpc_res = self._delegate_rpc_to_daemon(
                    "sync",
                    {"otp": clean_otp, "allow_lookahead": allow_lookahead, "max_lookahead": max_lookahead, "max_lookback": max_lookback},
                    timeout=12.0
                )
                if rpc_res is not None and "result" in rpc_res:
                    return rpc_res["result"]
                raise
            if not cfg:
                return False, "Configuracao nao encontrada para validacao inicial."

            secret_dpapi_b64 = cfg.get("secret_dpapi")
            secret_enc = base64.b64decode(secret_dpapi_b64)
            secret_ba = self._unprotect_secret(secret_enc)
            try:
                matched = None
                for test_c in range(0, 3):
                    expected = self._compute_hotp_internal(secret_ba, test_c, DEFAULT_DIGITS)
                    if hmac.compare_digest(expected, clean_otp):
                        matched = test_c
                        break

                if matched is None:
                    return False, "Codigo incorreto. Digite os 6 digitos exibidos no aplicativo do seu celular."

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
        """Restaura pastas e arquivos após detecção de adulteração exigindo estritamente a palavra-passe do proprietário."""
        if not recovery_password or len(recovery_password) < 8:
            return False, "A palavra-passe deve conter pelo menos 8 caracteres."

        with AtomicLock():
            raw_data = None
            password_verified = False

            # 1. Valida contra owner_anchor.json se presente
            anchor_file = self.config_dir / "owner_anchor.json"
            if anchor_file.exists():
                if verify_owner_password(recovery_password, anchor_file, self.config_dir):
                    password_verified = True
                else:
                    return False, "Palavra-passe de recuperacao incorreta. Apenas o proprietario pode reparar o sistema."

            # 2. Valida contra o hash PBKDF2 protegido por DPAPI no hotp_config.json
            if self.config_file.exists():
                try:
                    with open(self.config_file, "r", encoding="utf-8") as f:
                        raw_data = json.load(f)
                    salt_b64 = raw_data.get("recovery_salt")
                    hash_dpapi_b64 = raw_data.get("recovery_hash_dpapi")
                    if salt_b64 and hash_dpapi_b64:
                        hash_raw = base64.b64decode(hash_dpapi_b64)
                        expected_hash_ba = self._unprotect_secret(hash_raw)
                        expected_hash = bytes(expected_hash_ba).decode("ascii")
                        wipe_buffer(expected_hash_ba)
                        if not verify_recovery_password(recovery_password, expected_hash, salt_b64):
                            return False, "Palavra-passe de recuperacao incorreta. Apenas o proprietario pode reparar o sistema."
                        password_verified = True
                except Exception:
                    if not password_verified:
                        return False, "Nao foi possivel validar a palavra-passe de recuperacao."

            # Se os dados internos do hotp_config.json forem autênticos, re-ancora a assinatura
            if raw_data and isinstance(raw_data, dict):
                mac_b64 = raw_data.get("integrity_mac")
                if mac_b64:
                    try:
                        raw_mac = base64.b64decode(mac_b64)
                        expected_digest_ba = dpapi_unprotect(raw_mac, entropy=DPAPI_MAC_ENTROPY)
                        expected_digest = bytes(expected_digest_ba)
                        wipe_buffer(expected_digest_ba)
                        test_cfg = dict(raw_data)
                        test_cfg["lockdown"] = False
                        actual_digest = hashlib.sha256(_canonical_payload(test_cfg)).digest()
                        if hmac.compare_digest(actual_digest, expected_digest):
                            raw_data["lockdown"] = False
                            raw_data["failures"] = []
                            create_owner_anchor(recovery_password, self.config_dir, anchor_path=anchor_file)
                            self._save_config_raw(raw_data)
                            self._log_audit("REPAIR_SUCCESS", raw_data.get("counter", 0), raw_data.get("counter", 0), True, "Assinatura digital e integridade re-ancoradas com sucesso pelo proprietario.")
                            return True, "Integridade revalidada com sucesso pelo proprietario. Configuracao e sincronia mantidas intactas."
                    except Exception:
                        pass

            # Caso esteja corrompido, limpa os arquivos para permitir novo provisionamento seguro
            try:
                for f in [self.config_file, self.config_file.with_name(self.config_file.name + ".sig"), anchor_file, self.ticket_file, STATUS_FILE]:
                    if f.exists():
                        if hasattr(ctypes, "windll"):
                            try:
                                ctypes.windll.kernel32.SetFileAttributesW(str(f), 0x80)
                            except Exception:
                                pass
                        try:
                            f.unlink(missing_ok=True)
                        except Exception:
                            pass

                self.config_dir.mkdir(parents=True, exist_ok=True)
                QUEUE_DIR.mkdir(parents=True, exist_ok=True)
                LOGS_DIR.mkdir(parents=True, exist_ok=True)
                (BASE_DIR / "scripts").mkdir(parents=True, exist_ok=True)

                clear_external_system_vault()
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
        """Executa a revogação estrita de privilégios e destruição de chaves."""
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
                expected_hash_ba = self._unprotect_secret(enc_hash)
                expected_hash_b64 = expected_hash_ba.decode("ascii")
                wipe_buffer(expected_hash_ba)
                del expected_hash_ba
            except Exception as e:
                raise RuntimeError(f"Erro ao descriptografar hash com DPAPI: {e}")

            if not verify_recovery_password(recovery_password, expected_hash_b64, cfg["recovery_salt"]):
                self._log_audit("RESET_FAIL", c_before, c_before, False, "Senha de recuperação incorreta.", caller_info=caller_info)
                raise PermissionError("Senha de recuperação incorreta.")

            # 3. CONDIÇÕES CUMPRIDAS: AUTODESTRUIÇÃO DE PRIVILÉGIOS E SEGREDO
            cfg["provisioned_flag"] = 0
            cfg["lockdown"] = False
            cfg["secret_dpapi"] = ""
            cfg["counter"] = 0
            cfg["failures"] = []
            KernelFileGuard.release_all_locks()
            clear_external_system_vault()
            self._save_config_raw(cfg)

            if sys.platform == "win32":
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

    # -------------------------------------------------------------------------
    # DELEGAÇÃO RPC SEGURA PARA O DAEMON SYSTEM (EVITA CONFLITO DE LOCK / ACL)
    # -------------------------------------------------------------------------
    def _is_daemon_alive_other_process(self) -> bool:
        """Verifica se o daemon SYSTEM está ativo em outro processo."""
        if self.config_file != CONFIG_FILE:
            return False
        hb_file = QUEUE_DIR / "heartbeat.json"
        if not hb_file.exists():
            return False
        try:
            with open(hb_file, "r", encoding="utf-8") as f:
                hb = json.load(f)
            if hb.get("mode") == "daemon" and hb.get("pid") != os.getpid():
                return (time.time() - float(hb.get("timestamp", 0))) <= 10.0
        except Exception:
            pass
        return False

    def _delegate_rpc_to_daemon(self, rpc_action: str, params: dict, timeout: float = 15.0) -> Optional[dict]:
        """Envia operação administrativa/HOTP criptografada via DPAPI para o daemon SYSTEM processar em memória."""
        req_dir = QUEUE_DIR / "requests"
        resp_dir = QUEUE_DIR / "responses"
        try:
            req_dir.mkdir(parents=True, exist_ok=True)
            resp_dir.mkdir(parents=True, exist_ok=True)
            req_id = f"rpc-{secrets.token_hex(12)}"
            action_hash = hashlib.sha256(rpc_action.encode("utf-8")).hexdigest()

            safe_params = dict(params)
            if "otp" in safe_params and safe_params["otp"]:
                safe_params["otp_dpapi"] = protect_transit_token(str(safe_params.pop("otp")), req_id, action_hash)
            if "password" in safe_params and safe_params["password"]:
                safe_params["password_dpapi"] = protect_transit_token(str(safe_params.pop("password")), req_id, action_hash)

            payload = {
                "id": req_id,
                "script_type": "control_rpc",
                "rpc_action": rpc_action,
                "code_hash": action_hash,
                "params": safe_params,
                "created_at": datetime.now().astimezone().isoformat(),
                "caller": {
                    "pid": os.getpid(),
                    "exe": sys.executable,
                    "user": os.getenv("USERNAME") or os.getenv("USER") or "unknown"
                }
            }
            req_file = req_dir / f"{req_id}.json"
            tmp_req = req_file.with_suffix(".tmp")
            with open(tmp_req, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2, ensure_ascii=False)
            tmp_req.replace(req_file)

            res_file = resp_dir / f"{req_id}.json"
            start_t = time.time()
            while (time.time() - start_t) < timeout:
                if res_file.exists():
                    try:
                        with open(res_file, "r", encoding="utf-8") as rf:
                            resp = json.load(rf)
                        res_file.unlink(missing_ok=True)
                        return resp
                    except Exception:
                        time.sleep(0.1)
                        continue
                time.sleep(0.15)
            req_file.unlink(missing_ok=True)
        except Exception:
            pass
        return None

    # -------------------------------------------------------------------------
    # AUTORIZAÇÃO DE DESINSTALAÇÃO COM SENHA MESTRA E DESTRAVAMENTO DE KERNEL
    # -------------------------------------------------------------------------
    def authorize_and_prepare_uninstall(
        self,
        recovery_password: str,
        caller_info: Optional[dict] = None
    ) -> Tuple[bool, str]:
        """Exige a Palavra-passe de Recuperação (Senha Mestra) para autorizar a desinstalação.

        1. Se a senha estiver incorreta ou ausente, bloqueia a desinstalação e mantém os arquivos travados.
        2. Se a senha estiver correta, instrui o daemon SYSTEM a soltar todos os locks de kernel (KernelFileGuard),
           limpa o cofre externo (HKLM\\SECURITY e System Volume Information) e libera as ACLs para remoção limpa.
        """
        anchor_file = self.config_dir / "owner_anchor.json"
        has_active_install = self.config_file.exists() or anchor_file.exists()

        if not has_active_install:
            KernelFileGuard.release_all_locks()
            clear_external_system_vault()
            return True, "Utilitario nao provisionado. Pronto para remocao."

        if not recovery_password or len(str(recovery_password).strip()) < 8:
            self._log_audit("UNINSTALL_DENIED", 0, 0, False, "Tentativa de desinstalacao sem fornecer a Senha de Recuperacao.", caller_info=caller_info)
            return False, "A Palavra-passe de Recuperacao (minimo 8 caracteres) e obrigatoria para desinstalar."

        pw = str(recovery_password).strip()

        # Se o daemon SYSTEM estiver ativo em outro processo e segurando os locks de arquivo, delega a validação e o destravamento a ele
        if self._is_daemon_alive_other_process():
            rpc_res = self._delegate_rpc_to_daemon("uninstall_unlock", {"password": pw}, timeout=10.0)
            if rpc_res is not None:
                return bool(rpc_res.get("ok")), str(rpc_res.get("message", ""))

        with AtomicLock():
            verified = False
            # 1. Verifica contra a âncora Ed25519 do proprietário
            if anchor_file.exists():
                if verify_owner_password(pw, anchor_file, self.config_dir):
                    verified = True
                else:
                    self._log_audit("UNINSTALL_DENIED", 0, 0, False, "Tentativa de desinstalacao com Senha Mestra incorreta (ancora).", caller_info=caller_info)
                    return False, "Palavra-passe de Recuperacao incorreta. Desinstalacao bloqueada."

            # 2. Verifica contra o hash PBKDF2 protegido por DPAPI no hotp_config.json
            if self.config_file.exists():
                try:
                    with open(self.config_file, "r", encoding="utf-8") as f:
                        cfg = json.load(f)
                    salt_b64 = cfg.get("recovery_salt")
                    hash_dpapi_b64 = cfg.get("recovery_hash_dpapi")
                    if salt_b64 and hash_dpapi_b64:
                        enc_hash = base64.b64decode(hash_dpapi_b64)
                        expected_hash_ba = self._unprotect_secret(enc_hash)
                        expected_hash_b64 = expected_hash_ba.decode("ascii")
                        wipe_buffer(expected_hash_ba)
                        if not verify_recovery_password(pw, expected_hash_b64, salt_b64):
                            self._log_audit("UNINSTALL_DENIED", cfg.get("counter", 0), cfg.get("counter", 0), False, "Tentativa de desinstalacao com Senha de Recuperacao incorreta.", caller_info=caller_info)
                            return False, "Palavra-passe de Recuperacao incorreta. Desinstalacao bloqueada."
                        verified = True
                except PermissionError:
                    # Se o arquivo estiver travado pelo daemon SYSTEM, tenta via RPC
                    rpc_res = self._delegate_rpc_to_daemon("uninstall_unlock", {"password": pw}, timeout=10.0)
                    if rpc_res is not None:
                        return bool(rpc_res.get("ok")), str(rpc_res.get("message", ""))
                    if not verified:
                        return False, "Arquivo de configuracao bloqueado pelo servico SYSTEM. Tente novamente."
                except Exception as e:
                    if not verified:
                        return False, f"Erro ao validar credenciais para desinstalacao: {e}"

            if not verified:
                return False, "Nao foi possivel validar a Palavra-passe de Recuperacao."

            # SENHA VALIDADA: Destrava todos os handles de kernel, limpa cofre externo e restaura ACLs
            KernelFileGuard.release_all_locks()
            clear_external_system_vault()
            base_root = self.config_dir.parent if self.config_dir.name == "config" else self.config_dir
            restore_ntfs_acls_for_removal(base_root)

            for f in (self.config_file, self.config_file.with_name(self.config_file.name + ".sig"), anchor_file, self.ticket_file):
                if f.exists() and hasattr(ctypes, "windll"):
                    try:
                        ctypes.windll.kernel32.SetFileAttributesW(str(f), 0x80)
                    except Exception:
                        pass

            self._log_audit(
                "UNINSTALL_AUTHORIZED",
                0,
                0,
                True,
                "Desinstalacao autenticada pelo proprietario. Travas de kernel e cofres externos liberados.",
                caller_info=caller_info
            )
            return True, "Desinstalacao autorizada com sucesso. Travas de seguranca liberadas."

    def verify_and_advance(self, provided_otp: Optional[str], caller_info: Optional[dict] = None) -> Tuple[bool, str, int]:
        """Validação cega atômica do token HOTP com higiene estrita de memória e Fail-Safe."""
        with AtomicLock():
            cfg = self._load_config_raw()

            if cfg.get("provisioned_flag", 0) != 1:
                return False, "Utilitário não provisionado. Provisione a chave antes de executar.", 0

            current_counter = cfg["counter"]
            digits = cfg.get("digits", DEFAULT_DIGITS)
            look_ahead = cfg.get("look_ahead_window", DEFAULT_LOOK_AHEAD_WINDOW)

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

            if not provided_otp or not str(provided_otp).strip().isdigit() or len(str(provided_otp).strip()) not in (6, 8):
                new_counter = current_counter + 1
                cfg["counter"] = new_counter
                self._record_failure_and_check_lockdown(cfg, current_counter, new_counter, provided_otp or "", caller_info, "Formato do OTP inválido ou ausente")
                return False, "Código OTP não fornecido ou formato numérico inválido.", new_counter

            provided_otp = str(provided_otp).strip()

            secret_ba = None
            match_counter = None
            try:
                secret_raw = base64.b64decode(cfg["secret_dpapi"])
                secret_ba = self._unprotect_secret(secret_raw)

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
                if secret_ba is not None:
                    wipe_buffer(secret_ba)
                    del secret_ba
                gc.collect()

            if match_counter is not None:
                new_counter = match_counter + 1
                cfg["counter"] = new_counter
                cfg["last_success_counter"] = match_counter
                cfg["last_used_at"] = datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S")
                cfg["failures"] = []
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

            if sys.platform == "win32":
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
        """Consulta metadados passivos (contador, estado, falhas). O computador NUNCA calcula tokens aqui."""
        try:
            return read_passive_metadata(self.config_file)
        except Exception:
            pass

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
        """Consome o OTP imediatamente, avança o contador (+1) e gera ticket temporário válido por até 45 minutos."""
        caller = caller_info or {"pid": os.getpid(), "user": os.getenv("USERNAME") or os.getenv("USER") or "unknown"}
        if self._is_daemon_alive_other_process():
            rpc_res = self._delegate_rpc_to_daemon("preauth", {"otp": otp, "lifetime": lifetime_seconds}, timeout=12.0)
            if rpc_res is not None:
                return bool(rpc_res.get("ok")), str(rpc_res.get("message", "")), rpc_res.get("data", {})
        try:
            is_valid, auth_msg, used_counter = self.verify_and_advance(otp, caller)
        except PermissionError:
            rpc_res = self._delegate_rpc_to_daemon("preauth", {"otp": otp, "lifetime": lifetime_seconds}, timeout=12.0)
            if rpc_res is not None:
                return bool(rpc_res.get("ok")), str(rpc_res.get("message", "")), rpc_res.get("data", {})
            raise
        if not is_valid:
            return False, auth_msg, {}

        mutual_code = ""
        sec_ba = None
        try:
            cfg = self._load_config_raw()
            sec_raw = base64.b64decode(cfg["secret_dpapi"])
            sec_ba = self._unprotect_secret(sec_raw)
            mutual_code = generate_mutual_confirmation_code(bytes(sec_ba), otp)
        except Exception:
            pass
        finally:
            if sec_ba is not None:
                wipe_buffer(sec_ba)

        token = secrets.token_hex(24)
        token_hash = hashlib.sha256(token.encode("ascii")).hexdigest()
        ticket_data = {
            "token_hash": token_hash,
            "mutual_confirmation_code": mutual_code,
            "caller_user": caller.get("user", os.getenv("USERNAME") or os.getenv("USER") or "unknown"),
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
            "mutual_confirmation_code": mutual_code,
            "expires_in": lifetime_seconds,
            "counter": used_counter - 1
        }

    def consume_preauth_ticket(
        self,
        token: Optional[str] = None,
        caller_user: Optional[str] = None
    ) -> Tuple[bool, str]:
        """Valida o ticket de pré-autorização para execução dentro da janela de até 45 minutos."""
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

            if not token or not str(token).strip():
                return False, "Token secreto de pre-autorizacao e estritamente obrigatorio."

            expected_hash = hashlib.sha256(token.strip().encode("ascii")).hexdigest()
            if not hmac.compare_digest(expected_hash, ticket.get("token_hash", "")):
                return False, "Token de pre-autorizacao fornecido e incorreto."

            expected_user = ticket.get("caller_user")
            if expected_user and caller_user and str(expected_user).lower() != str(caller_user).lower():
                return False, f"Ticket de pre-autorizacao pertence a '{expected_user}', nao a '{caller_user}'."

            cmds = ticket.get("commands_executed", 0) + 1
            ticket["commands_executed"] = cmds
            ticket["last_used_at"] = now
            try:
                tmp_t = self.ticket_file.with_suffix(".tmp")
                with open(tmp_t, "w", encoding="utf-8") as f:
                    json.dump(ticket, f, indent=2)
                tmp_t.replace(self.ticket_file)
            except Exception:
                pass

            self._log_audit(
                "PREAUTH_TICKET_USED",
                ticket.get("counter_used", 0),
                ticket.get("counter_used", 0),
                True,
                f"Comando executado via Modo Auth [Uso #{cmds}]. Valido ate {int((ticket.get('expires_at', 0) - now) // 60)}m restantes."
            )
            return True, "Ticket de pre-autorizacao validado com sucesso."

    def revoke_preauth_ticket(self) -> Tuple[bool, str]:
        """Revoga e encerra imediatamente o Modo Auth ativo [fecha a porta de 45 minutos]."""
        if self._is_daemon_alive_other_process():
            rpc_res = self._delegate_rpc_to_daemon("revoke_preauth", {}, timeout=8.0)
            if rpc_res is not None:
                return bool(rpc_res.get("ok")), str(rpc_res.get("message", ""))
        with AtomicLock():
            if not self.ticket_file.exists():
                return True, "Nenhum Modo Auth ativo para revogar."
            try:
                self.ticket_file.unlink(missing_ok=True)
                self._update_public_status(self.get_counter_status())
                self._log_audit(
                    "PREAUTH_TICKET_REVOKED",
                    0,
                    0,
                    True,
                    "Modo Auth de 45 minutos revogado e encerrado imediatamente pelo usuario."
                )
                return True, "Modo Auth encerrado com sucesso."
            except Exception as e:
                return False, f"Falha ao revogar Modo Auth: {e}"

    def diagnose_otp_sync(
        self,
        provided_otp: str,
        allow_lookahead: bool = False,
        max_lookahead: int = 10,
        max_lookback: Optional[int] = 50
    ) -> dict:
        """Modo de diagnóstico e sincronia HOTP RFC 4226 protegido contra lockdown bypass e força bruta."""
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

            if cfg.get("lockdown", False):
                return {
                    "success": False,
                    "error": "FAIL_SAFE_LOCKDOWN: O utilitário está em lockdown de segurança."
                }

            current_counter = cfg.get("counter", 0)
            lower_bound = 0 if max_lookback is None else max(0, current_counter - int(max_lookback))

            secret_dpapi_b64 = cfg.get("secret_dpapi")
            secret_enc = base64.b64decode(secret_dpapi_b64)
            secret_ba = self._unprotect_secret(secret_enc)

            try:
                # 1. Fase 1: Busca sequencial de trás para frente dentro do limite seguro
                for c in range(current_counter, lower_bound - 1, -1):
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

                if not allow_lookahead:
                    return {
                        "success": False,
                        "matched_counter": None,
                        "current_counter": current_counter,
                        "next_counter": current_counter,
                        "diff": None,
                        "status": "prompt_lookahead",
                        "status_label": "Busca a Frente Necessaria",
                        "summary": "Codigo nao localizado no contador atual nem nos anteriores.",
                        "action_instruction": "Deseja pesquisar as proximas 10 posicoes futuras? Se nao encontrar, o contador saltara 10 posicoes para alinhar.",
                        "message": "Codigo nao coincide com a posicao atual. Confirmacao necessaria para buscar a frente."
                    }

                # 2. Fase 2: Busca sequencial para frente sob autorização expressa - até 10 posições
                step_limit = min(int(max_lookahead), 10)
                max_c = current_counter + step_limit
                for c in range(current_counter + 1, max_c + 1):
                    code = self._compute_hotp_internal(secret_ba, c, DEFAULT_DIGITS)
                    if hmac.compare_digest(clean_otp, code):
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

                # 3. Esgotamento das 10 posições acima sem correspondência: salta 10 posições e contabiliza falha
                exhausted_c = current_counter + 10
                cfg["counter"] = exhausted_c
                self._record_failure_and_check_lockdown(
                    cfg,
                    current_counter,
                    exhausted_c,
                    clean_otp,
                    None,
                    "10 posicoes acima testadas sem correspondencia em diagnose_otp_sync"
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
                    "action_instruction": f"Foram testadas 10 posicoes acima do computador #{current_counter} e o contador saltou para o OTP #{exhausted_c}.",
                    "message": f"Codigo OTP nao encontrado apos testar 10 posicoes acima. O contador do sistema saltou para #{exhausted_c}."
                }

            finally:
                wipe_buffer(secret_ba)
                del secret_ba
                gc.collect()
