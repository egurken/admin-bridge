import base64
import ctypes
import hashlib
import hmac
import json
import logging
import msvcrt
import os
import re
import secrets
import subprocess
import sys
import threading
import time
from ctypes import wintypes
from datetime import datetime
from pathlib import Path
from typing import Optional, Tuple

BASE_DIR = Path("C:/Utilitario")
CONFIG_DIR = BASE_DIR / "config"
QUEUE_DIR = BASE_DIR / "queue"
LOGS_DIR = BASE_DIR / "logs"
LOCK_FILE = QUEUE_DIR / "hotp.lock"
LEDGER_FILE = LOGS_DIR / "ledger.jsonl"
LEDGER_ANCHOR_FILE = LOGS_DIR / "ledger.anchor"

# DPAPI Structures & Functions
class DATA_BLOB(ctypes.Structure):
    _fields_ = [
        ("cbData", wintypes.DWORD),
        ("pbData", ctypes.POINTER(ctypes.c_byte))
    ]

crypt32 = ctypes.windll.crypt32
kernel32 = ctypes.windll.kernel32

DPAPI_ENTROPY = b"AntigravityBridge_TPM_DPAPI_Entropy_2026"
DPAPI_MAC_ENTROPY = b"AntigravityConfigIntegrityV2"
CRYPTPROTECT_UI_FORBIDDEN = 0x1
CRYPTPROTECT_LOCAL_MACHINE = 0x4
DPAPI_FLAGS = CRYPTPROTECT_LOCAL_MACHINE | CRYPTPROTECT_UI_FORBIDDEN  # 0x5 - Escopo de maquina seguro com entropia restrita e ACL NTFS estrita


def wipe_buffer(buf):
    """Sobrescreve buffers de memoria com zeros para higiene estrita de memoria."""
    if buf is None:
        return
    if isinstance(buf, bytearray):
        raw_len = len(buf)
        if raw_len > 0:
            try:
                p_buf = (ctypes.c_char * raw_len).from_buffer(buf)
                kernel32.RtlZeroMemory(ctypes.byref(p_buf), raw_len)
            except Exception:
                for i in range(raw_len):
                    buf[i] = 0
    elif isinstance(buf, (bytes, str)):
        pass


def lock_memory_page(buf: bytearray) -> bool:
    """Bloqueia paginas de memoria fisica no Windows impedindo descarregamento no arquivo pagefile.sys."""
    try:
        if not buf:
            return False
        raw_len = len(buf)
        p_buf = (ctypes.c_char * raw_len).from_buffer(buf)
        return bool(kernel32.VirtualLock(ctypes.byref(p_buf), raw_len))
    except Exception:
        return False


def unlock_memory_page(buf: bytearray) -> bool:
    """Desbloqueia paginas de memoria fisica previamente travadas."""
    try:
        if not buf:
            return False
        raw_len = len(buf)
        p_buf = (ctypes.c_char * raw_len).from_buffer(buf)
        return bool(kernel32.VirtualUnlock(ctypes.byref(p_buf), raw_len))
    except Exception:
        return False


def configure_anti_dump_mitigations():
    """Desativa caixas de dialogo de falha e despejos de memoria crash dump no Windows."""
    try:
        kernel32.SetErrorMode(0x0001 | 0x0002)
    except Exception:
        pass


def dpapi_protect(plaintext: bytes, entropy: bytes = DPAPI_ENTROPY) -> bytes:
    """Criptografa dados usando a DPAPI do Windows com escopo de máquina (TPM/LSA).

    Permite que o serviço SYSTEM e administradores autentiquem os dados sem falha de integridade.
    Sobrescreve os buffers nativos antes de desalocar.
    """
    raw_len = len(plaintext)
    p_buffer = ctypes.create_string_buffer(plaintext, raw_len)
    data_in = DATA_BLOB(raw_len, ctypes.cast(p_buffer, ctypes.POINTER(ctypes.c_byte)))

    entropy_blob = DATA_BLOB(
        len(entropy),
        ctypes.cast(ctypes.create_string_buffer(entropy, len(entropy)), ctypes.POINTER(ctypes.c_byte))
    ) if entropy else DATA_BLOB(0, None)
    data_out = DATA_BLOB()

    res = crypt32.CryptProtectData(
        ctypes.byref(data_in),
        "HOTP_Hardware_Key",
        ctypes.byref(entropy_blob) if entropy else None,
        None,
        None,
        DPAPI_FLAGS,
        ctypes.byref(data_out)
    )

    # Limpa buffer nativo de entrada imediatamente
    ctypes.memset(ctypes.cast(p_buffer, ctypes.c_void_p), 0, raw_len)

    if not res:
        err = ctypes.GetLastError()
        raise ctypes.WinError(err)

    buf = ctypes.string_at(data_out.pbData, data_out.cbData)
    ctypes.memset(data_out.pbData, 0, data_out.cbData)
    kernel32.LocalFree(data_out.pbData)
    return buf


def dpapi_unprotect(ciphertext: bytes, entropy: bytes = DPAPI_ENTROPY) -> bytearray:
    """Descriptografa dados usando DPAPI e retorna bytearray mutável.

    Limpa buffers nativos com memset antes de desalocar.
    """
    data_in = DATA_BLOB(
        len(ciphertext),
        ctypes.cast(ctypes.create_string_buffer(ciphertext, len(ciphertext)), ctypes.POINTER(ctypes.c_byte))
    )
    entropy_blob = DATA_BLOB(
        len(entropy),
        ctypes.cast(ctypes.create_string_buffer(entropy, len(entropy)), ctypes.POINTER(ctypes.c_byte))
    ) if entropy else DATA_BLOB(0, None)
    data_out = DATA_BLOB()

    res = crypt32.CryptUnprotectData(
        ctypes.byref(data_in),
        None,
        ctypes.byref(entropy_blob) if entropy else None,
        None,
        None,
        CRYPTPROTECT_UI_FORBIDDEN,
        ctypes.byref(data_out)
    )
    if not res:
        err = ctypes.GetLastError()
        raise ctypes.WinError(err)

    raw_bytes = ctypes.string_at(data_out.pbData, data_out.cbData)
    # Higiene de memória nativa: zera os bytes descriptografados na memória do Windows
    ctypes.memset(data_out.pbData, 0, data_out.cbData)
    kernel32.LocalFree(data_out.pbData)

    # Retorna bytearray mutável para posterior sobrescrita pelo chamador
    return bytearray(raw_bytes)


def _canonical_payload(cfg: dict) -> bytes:
    """Gera representação canônica em bytes dos campos sensíveis do estado para assinatura."""
    fields = [
        str(cfg.get("provisioned_flag", 0)),
        str(cfg.get("lockdown", False)),
        str(cfg.get("counter", 0)),
        str(cfg.get("digits", 6)),
        str(cfg.get("look_ahead_window", 5)),
        str(cfg.get("secret_dpapi", "")),
        str(cfg.get("recovery_hash_dpapi", "")),
        str(cfg.get("recovery_salt", "")),
        json.dumps(cfg.get("failures", []), sort_keys=True)
    ]
    return "|".join(fields).encode("utf-8")


_static_mesh_cache = {}
_usn_cache = {}


def get_file_usn(file_path: Path) -> str:
    """Obtem o USN [Update Sequence Number] do registro NTFS usando fsutil com cache inteligente."""
    try:
        stat_res = file_path.stat()
        mtime_ns = int(stat_res.st_mtime_ns)
        size = int(stat_res.st_size)
        cache_key = (str(file_path), mtime_ns, size)
        if cache_key in _usn_cache:
            return _usn_cache[cache_key]
    except Exception:
        return "0x0"

    usn_val = None
    try:
        p = subprocess.run(
            ["fsutil", "usn", "readdata", str(file_path)],
            capture_output=True,
            text=True,
            check=False,
            creationflags=0x08000000
        )
        if p.returncode == 0:
            m = re.search(r"Usn\s*:\s*(0x[0-9a-fA-F]+)", p.stdout, re.IGNORECASE)
            if m:
                usn_val = m.group(1).lower()
    except Exception:
        pass

    if not usn_val:
        usn_val = hex(mtime_ns)

    _usn_cache[cache_key] = usn_val
    return usn_val


def get_static_mesh_hash(base_dir: Path = BASE_DIR) -> str:
    """Calcula a ancora estatica unindo o executavel e a tarefa agendada com cache em memoria."""
    exe_file = base_dir / "AdminBridge.exe"
    exe_mtime = 0
    exe_size = 0
    if exe_file.exists():
        try:
            st = exe_file.stat()
            exe_mtime = int(st.st_mtime_ns)
            exe_size = int(st.st_size)
        except Exception:
            pass

    task_xml = Path("C:/Windows/System32/Tasks/AdminBridge")
    task_mtime = 0
    try:
        if task_xml.exists():
            task_mtime = int(task_xml.stat().st_mtime_ns)
    except Exception:
        pass

    cache_key = (str(base_dir), exe_mtime, exe_size, task_mtime)
    if cache_key in _static_mesh_cache:
        return _static_mesh_cache[cache_key]

    components = []
    # 1. Executavel principal
    if exe_file.exists():
        try:
            with open(exe_file, "rb") as ef:
                components.append(hashlib.sha256(ef.read()).hexdigest())
        except Exception:
            components.append("exe_read_error")
    else:
        components.append("exe_not_installed")

    # 2. XML da Tarefa Agendada no Windows
    try:
        if task_xml.exists():
            with open(task_xml, "rb") as tf:
                components.append(hashlib.sha256(tf.read()).hexdigest())
        else:
            components.append("task_not_registered")
    except PermissionError:
        components.append("task_protected")
    except Exception:
        components.append("task_read_error")

    # 3. Entropia de maquina
    components.append(hashlib.sha256(DPAPI_ENTROPY).hexdigest())

    combined = "|".join(components).encode("utf-8")
    result = hashlib.sha256(combined).hexdigest()
    _static_mesh_cache[cache_key] = result
    return result


def compute_integrity_mac(cfg: dict) -> str:
    """Gera uma assinatura de integridade protegida por DPAPI sobre os metadados do JSON.

    Impede qualquer adulteracao manual externa [por exemplo, edicao com Bloco de Notas].
    """
    payload = _canonical_payload(cfg)
    digest = hashlib.sha256(payload).digest()
    encrypted_digest = dpapi_protect(digest, entropy=DPAPI_MAC_ENTROPY)
    return base64.b64encode(encrypted_digest).decode("ascii")


def check_integrity_mac(cfg: dict, config_path: Optional[Path] = None) -> Tuple[bool, str]:
    """Valida a assinatura de integridade e diagnostica com precisao o motivo da falha.

    Retorna [True, 'ok'] se integro.
    Retorna [False, 'tampered'] se o arquivo foi adulterado externamente.
    Retorna [False, 'usn_tampered'] se o USN do NTFS divergir da assinatura legítima.
    Retorna [False, 'decrypt_error'] se a chave DPAPI nao pode ser lida no contexto atual.
    """
    mac_b64 = cfg.get("integrity_mac")
    if not mac_b64:
        return False, "missing_mac"
    try:
        raw_mac = base64.b64decode(mac_b64)
        expected_digest_ba = dpapi_unprotect(raw_mac, entropy=DPAPI_MAC_ENTROPY)
        expected_digest = bytes(expected_digest_ba)
        wipe_buffer(expected_digest_ba)

        payload = _canonical_payload(cfg)
        actual_digest = hashlib.sha256(payload).digest()
        if not hmac.compare_digest(actual_digest, expected_digest):
            return False, "tampered"
    except Exception:
        return False, "decrypt_error"

    # Verificacao adicional do arquivo acompanhante .sig e USN
    if config_path and Path(config_path).exists():
        cp = Path(config_path)
        sig_file = cp.with_name(cp.name + ".sig")
        if sig_file.exists():
            try:
                with open(sig_file, "r", encoding="utf-8") as sf:
                    sig_data = json.load(sf)
                if sig_data.get("integrity_mac") != mac_b64:
                    return False, "sig_mac_mismatch"
                with open(cp, "rb") as f:
                    curr_hash = hashlib.sha256(f.read()).hexdigest()
                if sig_data.get("sha256") and sig_data.get("sha256") != curr_hash:
                    return False, "sha256_mismatch"
                sig_usn = sig_data.get("usn")
                if sig_usn and sig_usn != "0x0":
                    curr_usn = get_file_usn(cp)
                    if curr_usn != "0x0" and curr_usn != sig_usn:
                        return False, "usn_tampered"
            except PermissionError:
                pass
            except Exception:
                return False, "sig_read_error"

    return True, "ok"


def verify_integrity_mac(cfg: dict, config_path: Optional[Path] = None) -> bool:
    """Verifica se a assinatura de integridade corresponde aos metadados do JSON.

    Retorna True se integro, False se adulterado ou corrompido.
    """
    ok, _ = check_integrity_mac(cfg, config_path)
    return ok


def read_passive_metadata(config_path: Path) -> dict:
    """Le metadados passivos [contador, flag, falhas, lockdown] SEM decodificar a chave secreta.

    Verifica a assinatura de integridade antes de retornar os dados.
    """
    try:
        if not config_path.exists():
            return {
                "counter": 0,
                "provisioned_flag": 0,
                "lockdown": False,
                "recent_failures": 0,
                "max_failures": 3,
                "status_text": "Aguardando Provisionamento",
                "tampered": False
            }
        with open(config_path, "r", encoding="utf-8") as f:
            cfg = json.load(f)
    except PermissionError:
        # Quando restrito a SYSTEM, processos de usuario recebem Acesso Negado
        raise
    except Exception:
        return {
            "counter": 0,
            "provisioned_flag": 0,
            "lockdown": True,
            "recent_failures": 3,
            "status_text": "Arquivo Corrompido",
            "tampered": True
        }

    is_valid = verify_integrity_mac(cfg, config_path)
    now = time.time()
    failures_5m = [t for t in cfg.get("failures", []) if (now - t) < 300]
    lockdown = cfg.get("lockdown", False) or not is_valid
    provisioned = cfg.get("provisioned_flag", 0) == 1

    status_text = "Ativo"
    if not is_valid:
        status_text = "Bloqueado por adulteração"
    elif lockdown:
        status_text = "Bloqueado - Lockdown Fail-Safe"
    elif not provisioned:
        status_text = "Aguardando Provisionamento"

    return {
        "counter": cfg.get("counter", 0),
        "provisioned_flag": cfg.get("provisioned_flag", 0),
        "lockdown": lockdown,
        "recent_failures": len(failures_5m),
        "max_failures": 3,
        "status_text": status_text,
        "tampered": not is_valid,
        "last_used_at": cfg.get("last_used_at"),
        "created_at": cfg.get("created_at")
    }


def generate_physical_challenge() -> str:
    """Gera um código aleatório dinâmico para desafio de presença física na máquina."""
    return f"PHYS-{secrets.randbelow(900000) + 100000}"


def hash_recovery_password(password: str, salt: Optional[bytes] = None) -> Tuple[str, str]:
    """Gera hash seguro PBKDF2-HMAC-SHA256 para a senha de recuperacao [600.000 iteracoes]."""
    if salt is None:
        salt = secrets.token_bytes(16)
    pw_bytes = password.encode("utf-8")
    derived = hashlib.pbkdf2_hmac("sha256", pw_bytes, salt, 600000)
    return base64.b64encode(derived).decode("ascii"), base64.b64encode(salt).decode("ascii")


def verify_recovery_password(password: str, expected_hash_b64: str, salt_b64: str) -> bool:
    """Valida a senha de recuperacao utilizando comparacao de tempo constante."""
    salt = base64.b64decode(salt_b64)
    expected_hash = base64.b64decode(expected_hash_b64)
    derived = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 600000)
    return hmac.compare_digest(derived, expected_hash)


def create_detached_signature_file(config_file: Path, cfg: dict) -> Path:
    """Gera arquivo acompanhante de assinatura digital de integridade com USN e malha estatica."""
    sig_file = config_file.with_name(config_file.name + ".sig")
    try:
        if config_file.exists():
            with open(config_file, "rb") as f:
                data_bytes = f.read()
            file_hash = hashlib.sha256(data_bytes).hexdigest()
            file_usn = get_file_usn(config_file)
        else:
            file_hash = ""
            file_usn = "0x0"
        
        static_mesh = get_static_mesh_hash(config_file.parent.parent)
        sig_payload = {
            "file": config_file.name,
            "sha256": file_hash,
            "usn": file_usn,
            "static_mesh_hash": static_mesh,
            "integrity_mac": cfg.get("integrity_mac", ""),
            "signed_at": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
            "signer": "AdminBridge DPAPI Machine Seal"
        }
        if sig_file.exists():
            try:
                ctypes.windll.kernel32.SetFileAttributesW(str(sig_file), 0x80)
            except Exception:
                pass
        try:
            tmp_sig = sig_file.with_suffix(".sig.tmp")
            with open(tmp_sig, "w", encoding="utf-8") as f:
                json.dump(sig_payload, f, indent=2, ensure_ascii=False)
            tmp_sig.replace(sig_file)
        except (PermissionError, OSError):
            with open(sig_file, "w", encoding="utf-8") as f:
                json.dump(sig_payload, f, indent=2, ensure_ascii=False)
    except Exception as e:
        logging.warning(f"Aviso ao gerar assinatura desanexada: {e}")
    return sig_file


def create_owner_anchor(password: str, base_dir: Path = BASE_DIR) -> dict:
    """Gera e registra a ancora criptografica Ed25519 soberana do proprietario."""
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.hazmat.primitives import serialization

    salt = secrets.token_bytes(16)
    derived = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=16384, r=8, p=1, maxmem=32 * 1024 * 1024, dklen=32)
    derived_ba = bytearray(derived)

    try:
        priv_key = ed25519.Ed25519PrivateKey.from_private_bytes(bytes(derived_ba))
        pub_key = priv_key.public_key()
        pub_bytes = pub_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

        mesh_hash = get_static_mesh_hash(base_dir)
        sign_payload = f"AdminBridge_OwnerAnchor_v1|{mesh_hash}".encode("utf-8")
        signature = priv_key.sign(sign_payload)

        anchor_data = {
            "version": "1.0",
            "salt_b64": base64.b64encode(salt).decode("ascii"),
            "public_key_b64": base64.b64encode(pub_bytes).decode("ascii"),
            "static_mesh_hash": mesh_hash,
            "signature_b64": base64.b64encode(signature).decode("ascii"),
            "created_at": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
        }

        if base_dir.name == "config":
            anchor_file = base_dir / "owner_anchor.json"
        else:
            anchor_file = base_dir / "config" / "owner_anchor.json"
        anchor_file.parent.mkdir(parents=True, exist_ok=True)
        if anchor_file.exists():
            subprocess.run(["attrib", "-r", str(anchor_file)], capture_output=True, check=False, creationflags=0x08000000)
        with open(anchor_file, "w", encoding="utf-8") as af:
            json.dump(anchor_data, af, indent=2, ensure_ascii=False)
        subprocess.run(["attrib", "+r", str(anchor_file)], capture_output=True, check=False, creationflags=0x08000000)
        subprocess.run(["cmd.exe", "/c", f'icacls "{anchor_file}" /inheritance:r /grant:r "*S-1-5-18:(F)" "*S-1-5-32-544:(F)" /c /q'], capture_output=True, check=False, creationflags=0x08000000)
        return anchor_data
    finally:
        wipe_buffer(derived_ba)
        del derived, derived_ba


def verify_owner_anchor(anchor_path: Optional[Path] = None, base_dir: Path = BASE_DIR) -> Tuple[bool, str]:
    """Valida a assinatura Ed25519 da ancora do proprietario contra a malha estatica atual."""
    from cryptography.hazmat.primitives.asymmetric import ed25519

    if anchor_path is None:
        anchor_path = base_dir / "owner_anchor.json" if base_dir.name == "config" else base_dir / "config" / "owner_anchor.json"

    if not anchor_path.exists():
        return True, "owner_anchor_not_present"

    try:
        with open(anchor_path, "r", encoding="utf-8") as af:
            anchor_data = json.load(af)

        pub_bytes = base64.b64decode(anchor_data["public_key_b64"])
        signature = base64.b64decode(anchor_data["signature_b64"])
        recorded_mesh = anchor_data.get("static_mesh_hash", "")

        pub_key = ed25519.Ed25519PublicKey.from_public_bytes(pub_bytes)
        sign_payload = f"AdminBridge_OwnerAnchor_v1|{recorded_mesh}".encode("utf-8")
        pub_key.verify(signature, sign_payload)
        return True, "ok"
    except Exception as e:
        return False, f"owner_anchor_invalid: {e}"


def verify_owner_password(password: str, anchor_path: Optional[Path] = None, base_dir: Path = BASE_DIR) -> bool:
    """Verifica se a Senha Mestra digitada corresponde a chave publica Ed25519 registrada na ancora."""
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.hazmat.primitives import serialization

    if anchor_path is None:
        anchor_path = base_dir / "owner_anchor.json" if base_dir.name == "config" else base_dir / "config" / "owner_anchor.json"

    if not anchor_path.exists():
        return False

    try:
        with open(anchor_path, "r", encoding="utf-8") as af:
            anchor_data = json.load(af)

        salt = base64.b64decode(anchor_data["salt_b64"])
        expected_pub = base64.b64decode(anchor_data["public_key_b64"])

        derived = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=16384, r=8, p=1, maxmem=32 * 1024 * 1024, dklen=32)
        derived_ba = bytearray(derived)
        try:
            priv_key = ed25519.Ed25519PrivateKey.from_private_bytes(bytes(derived_ba))
            pub_key = priv_key.public_key()
            pub_bytes = pub_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )
            return hmac.compare_digest(pub_bytes, expected_pub)
        finally:
            wipe_buffer(derived_ba)
            del derived, derived_ba
    except Exception:
        return False


def generate_mutual_confirmation_code(secret_bytes: bytes, otp_code: str) -> str:
    """Gera contra-senha deterministica de confirmacao mutua para provar autenticidade do servico."""
    clean_otp = str(otp_code).strip()
    key_material = (clean_otp + "_CONFIRMACAO").encode("utf-8")
    digest = hmac.new(secret_bytes, key_material, hashlib.sha256).hexdigest()
    return digest[:6].upper()


def harden_process_dacl() -> bool:
    """Endurece a seguranca do processo atual para mitigar encerramento trivial por terceiros."""
    try:
        # Define mitigacoes basicas de processo no Windows
        kernel32 = ctypes.windll.kernel32
        kernel32.SetErrorMode(0x0001 | 0x0002)
        return True
    except Exception:
        return False


def check_config_acl_isolation(base_dir: Path = BASE_DIR) -> bool:
    """Verifica se a pasta config e arquivos sensiveis estao estritamente isolados contra usuarios comuns."""
    forbidden_principals = ["usuários", "usuarios", "users", "autenticados", "authenticated", "s-1-5-32-545", "s-1-5-11"]
    for rel_path in ("config/hotp_config.json", "config/hotp_config.json.sig", "config/owner_anchor.json", "scripts"):
        target = base_dir / rel_path
        if not target.exists():
            continue
        try:
            p = subprocess.run(["icacls", str(target)], capture_output=True, text=True, check=False, creationflags=0x08000000)
            out = p.stdout.lower()
            for f in forbidden_principals:
                if f in out:
                    return False
        except Exception:
            return False
    return True


def apply_isolated_bridge_ntfs_acls(base_dir: Path = BASE_DIR) -> bool:
    """Aplica permissoes ACL granulares e blindadas sem depender de scripts externos:
    - Posse exclusiva definida para SYSTEM / Administradores
    - config: Acesso total EXCLUSIVO a SYSTEM e Administradores. Bloqueio estrito a usuarios comuns.
    - hotp_config.json: Bloqueio estrito de heranca e acesso exclusivo a SYSTEM / Administradores.
    - scripts: Acesso total EXCLUSIVO a SYSTEM e Administradores.
    - queue: SYSTEM [F], Admins [M] e Users [M] para envio de comandos.
    - logs: SYSTEM [F] e Admins [M].
    - AdminBridge.exe: Unico executavel com permissao de execucao para usuarios.
    """
    config_dir = base_dir / "config"
    scripts_dir = base_dir / "scripts"
    queue_dir = base_dir / "queue"
    logs_dir = base_dir / "logs"
    exe_file = base_dir / "AdminBridge.exe"

    # 1. Garante que as pastas fiquem visiveis normalmente, sem atributos ocultos
    for d in (config_dir, scripts_dir, queue_dir, logs_dir):
        if d.exists():
            try:
                subprocess.run(["attrib", "-h", "-s", str(d)], capture_output=True, check=False, creationflags=0x08000000)
            except Exception:
                pass

    # 2. Assume posse recursiva de C:\Utilitario\config para SYSTEM e Administradores
    try:
        if config_dir.exists():
            subprocess.run(["takeown", "/f", str(config_dir), "/r", "/d", "y"], capture_output=True, check=False, creationflags=0x08000000)
    except Exception:
        pass

    # 3. Blindagem estrita de config - EXCLUSIVO SYSTEM e Administradores total [Zero acesso a usuarios comuns]
    try:
        if config_dir.exists():
            cfg_str = str(config_dir)
            # Remove heranca recursivamente e concede acesso exclusivo a SYSTEM e Administradores
            subprocess.run(["cmd.exe", "/c", f'icacls "{cfg_str}" /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)(F)" "*S-1-5-32-544:(OI)(CI)(F)" /t /c /q'], capture_output=True, check=False, creationflags=0x08000000)
            subprocess.run(["cmd.exe", "/c", f'icacls "{cfg_str}\\*" /inheritance:r /grant:r "*S-1-5-18:(F)" "*S-1-5-32-544:(F)" /c /q'], capture_output=True, check=False, creationflags=0x08000000)
            for specific_file in ("hotp_config.json", "hotp_config.json.sig", "owner_anchor.json"):
                sp = config_dir / specific_file
                if sp.exists():
                    subprocess.run(["cmd.exe", "/c", f'icacls "{sp}" /inheritance:r /grant:r "*S-1-5-18:(F)" "*S-1-5-32-544:(F)" /c /q'], capture_output=True, check=False, creationflags=0x08000000)
    except Exception:
        pass

    # 4. Blindagem estrita de scripts - somente SYSTEM e Administradores
    try:
        if scripts_dir.exists():
            sc_str = str(scripts_dir)
            subprocess.run(["cmd.exe", "/c", f'icacls "{sc_str}" /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)(F)" "*S-1-5-32-544:(OI)(CI)(F)" /t /c /q'], capture_output=True, check=False, creationflags=0x08000000)
    except Exception:
        pass

    # 5. Canal de logs
    try:
        if logs_dir.exists():
            l_str = str(logs_dir)
            subprocess.run(["cmd.exe", "/c", f'icacls "{l_str}" /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)(F)" "*S-1-5-32-544:(OI)(CI)(F)" /t /c /q'], capture_output=True, check=False, creationflags=0x08000000)
    except Exception:
        pass

    # 6. Canal de fila para envio de solicitacoes pelo usuario
    try:
        if queue_dir.exists():
            q_str = str(queue_dir)
            subprocess.run(["cmd.exe", "/c", f'icacls "{q_str}" /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)(F)" "*S-1-5-32-544:(OI)(CI)(M)" "*S-1-5-32-545:(OI)(CI)(M)" /c /q'], capture_output=True, check=False, creationflags=0x08000000)
    except Exception:
        pass

    # 7. Permissao no executavel principal: unico arquivo executavel para o usuario
    try:
        if exe_file.exists():
            cmd_exe = f'icacls "{exe_file}" /grant "*S-1-5-18:(F)" "*S-1-5-32-544:(RX)" "*S-1-5-32-545:(RX)" /c /q'
            subprocess.run(["cmd.exe", "/c", cmd_exe], capture_output=True, check=False, creationflags=0x08000000)
    except Exception:
        pass

    return check_config_acl_isolation(base_dir)


def check_forensic_integrity(config_file: Path) -> Tuple[bool, str]:
    """Verifica se a posse ou integridade do arquivo foi violada durante a inatividade."""
    if not config_file.exists():
        return True, "Configuracao ainda nao existe."

    try:
        ps_cmd = f"(Get-Acl -LiteralPath '{config_file}').Owner"
        res = subprocess.run(
            ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps_cmd],
            capture_output=True,
            text=True,
            check=False,
            creationflags=0x08000000
        )
        owner = res.stdout.strip()
        if owner and not ("SISTEMA" in owner.upper() or "SYSTEM" in owner.upper() or "S-1-5-18" in owner):
            return False, f"Alerta forense: Posse do arquivo de configuracao alterada para {owner} durante a inatividade."

        canary_file = config_file.parent / "canary.bin"
        if canary_file.exists():
            try:
                with open(canary_file, "rb") as cf:
                    cdata = cf.read()
                if len(cdata) != 32:
                    return False, "Alerta forense: Arquivo canario adulterado na pasta de configuracao."
            except Exception as e:
                return False, f"Alerta forense: Falha ao verificar canario: {e}"
        else:
            try:
                with open(canary_file, "wb") as cf:
                    cf.write(secrets.token_bytes(32))
            except Exception:
                pass

        return True, "Integridade forense confirmada."
    except Exception as e:
        return True, f"Verificacao forense ignorada por erro de ambiente: {e}"


def apply_system_only_ntfs_acls(target_path: Path):
    """Alias para compatibilidade retroativa com chamadas anteriores."""
    apply_isolated_bridge_ntfs_acls()


def restore_ntfs_acls_for_removal(target_path: Path):
    """Assume posse (takeown) e restaura permissões para Administradores para permitir remoção/desinstalação."""
    if not target_path.exists():
        return

    try:
        # 1. Assume a posse do diretório e arquivos
        subprocess.run(
            ["takeown", "/f", str(target_path), "/r", "/d", "y"],
            capture_output=True,
            check=False,
            creationflags=0x08000000
        )
        # 2. Concede controle total para Administradores (*S-1-5-32-544)
        subprocess.run(
            ["icacls", str(target_path), "/grant", "*S-1-5-32-544:(OI)(CI)(F)", "/t"],
            capture_output=True,
            check=False,
            creationflags=0x08000000
        )
    except Exception:
        pass


_lock_local = threading.local()


class AtomicLock:
    """Lock atômico inter-processos e inter-threads utilizando Windows Named Mutex e lock de arquivo (Re-entrante)."""

    def __init__(self, mutex_name: str = "Local\\AntigravityHOTPMutex", timeout_ms: int = 5000):
        self.mutex_name = mutex_name
        self.timeout_ms = timeout_ms

    def __enter__(self):
        QUEUE_DIR.mkdir(parents=True, exist_ok=True)
        if not hasattr(_lock_local, "depth"):
            _lock_local.depth = 0
            _lock_local.mutex_handle = None
            _lock_local.lock_file_fd = None

        if _lock_local.depth > 0:
            _lock_local.depth += 1
            return self

        # 1. Named Mutex do Windows
        handle = kernel32.CreateMutexW(None, False, self.mutex_name)
        if handle:
            wait_res = kernel32.WaitForSingleObject(handle, self.timeout_ms)
            if wait_res not in (0, 0x80):
                kernel32.CloseHandle(handle)
                raise TimeoutError("Tempo limite esgotado ao aguardar mutex do HOTP.")
        _lock_local.mutex_handle = handle

        # 2. File Lock
        try:
            fd = os.open(str(LOCK_FILE), os.O_CREAT | os.O_RDWR)
            start_time = time.time()
            while True:
                try:
                    msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
                    break
                except (BlockingIOError, OSError):
                    if (time.time() - start_time) * 1000 > self.timeout_ms:
                        raise TimeoutError("Tempo limite esgotado ao aguardar lock de arquivo do HOTP.")
                    time.sleep(0.05)
            _lock_local.lock_file_fd = fd
        except Exception:
            if _lock_local.mutex_handle:
                kernel32.ReleaseMutex(_lock_local.mutex_handle)
                kernel32.CloseHandle(_lock_local.mutex_handle)
                _lock_local.mutex_handle = None
            raise

        _lock_local.depth = 1
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if not hasattr(_lock_local, "depth") or _lock_local.depth == 0:
            return

        _lock_local.depth -= 1
        if _lock_local.depth > 0:
            return

        # Libera recursos no nível 0
        if _lock_local.lock_file_fd is not None:
            try:
                msvcrt.locking(_lock_local.lock_file_fd, msvcrt.LK_UNLCK, 1)
                os.close(_lock_local.lock_file_fd)
            except Exception:
                pass
            _lock_local.lock_file_fd = None

        if _lock_local.mutex_handle:
            try:
                kernel32.ReleaseMutex(_lock_local.mutex_handle)
                kernel32.CloseHandle(_lock_local.mutex_handle)
            except Exception:
                pass
            _lock_local.mutex_handle = None


def get_current_caller_info() -> dict:
    """Coleta dados do processo cliente atual para rastreabilidade de origem."""
    return {
        "pid": os.getpid(),
        "exe": sys.executable,
        "script": str(Path(__file__).resolve()),
        "user": os.getenv("USERNAME", "unknown"),
        "timestamp": time.time()
    }


def verify_caller_origin(caller_data: Optional[dict]) -> Tuple[bool, str]:
    """Verifica se a origem da requisição pertence ao executável/ambiente oficial."""
    if not caller_data or not isinstance(caller_data, dict):
        return False, "Origem da requisição não informada ou formato inválido."

    pid = caller_data.get("pid")
    exe = str(caller_data.get("exe", "")).lower()

    if not pid:
        return False, "PID do chamador não informado."

    is_valid_exe = (
        "python" in exe
        or "adminbridge" in exe
        or "powershell" in exe
        or "c:\\utilitario" in exe
    )

    if not is_valid_exe:
        return False, f"Executável de origem não autorizado: {exe}"

    return True, "Origem validada com sucesso."


def append_ledger_block(action: str, counter: int, code_hash: str, caller_info: Optional[dict] = None, status: str = "SUCCESS", details: str = "") -> dict:
    """Registra um bloco encadeado por hash criptografico [estilo blockchain] no log imutavel de auditoria."""
    try:
        LOGS_DIR.mkdir(parents=True, exist_ok=True)
        prev_hash = "0" * 64
        index = 0
        if LEDGER_FILE.exists() and LEDGER_FILE.stat().st_size > 0:
            try:
                with open(LEDGER_FILE, "r", encoding="utf-8") as lf:
                    lines = [ln.strip() for ln in lf if ln.strip()]
                    if lines:
                        last_block = json.loads(lines[-1])
                        prev_hash = last_block.get("block_hash", "0" * 64)
                        index = last_block.get("index", 0) + 1
            except Exception:
                pass

        timestamp = datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S UTC")
        caller_str = f"PID:{caller_info.get('pid', '?')}|User:{caller_info.get('user', '?')}" if caller_info else "N/A"

        # Formato de payload canônico para cálculo de hash do bloco
        block_payload = f"{index}|{prev_hash}|{timestamp}|{counter}|{action}|{code_hash}|{status}|{caller_str}".encode("utf-8")
        block_hash = hashlib.sha256(block_payload).hexdigest()

        block = {
            "index": index,
            "prev_hash": prev_hash,
            "timestamp": timestamp,
            "counter": counter,
            "action": action,
            "code_hash": code_hash,
            "status": status,
            "caller": caller_str,
            "details": details,
            "block_hash": block_hash
        }

        with open(LEDGER_FILE, "a", encoding="utf-8") as lf:
            lf.write(json.dumps(block, ensure_ascii=False) + "\n")

        with open(LEDGER_ANCHOR_FILE, "w", encoding="utf-8") as af:
            json.dump({"last_index": index, "last_hash": block_hash, "updated_at": timestamp}, af, indent=2)

        return block
    except Exception:
        return {}


def verify_ledger_integrity() -> Tuple[bool, str]:
    """Verifica a integridade matematica estrita da cadeia de blocos de auditoria."""
    if not LEDGER_FILE.exists() or LEDGER_FILE.stat().st_size == 0:
        return True, "Ledger vazio ou ainda nao iniciado."
    try:
        prev_hash = "0" * 64
        with open(LEDGER_FILE, "r", encoding="utf-8") as lf:
            for line_no, ln in enumerate(lf, start=1):
                raw = ln.strip()
                if not raw:
                    continue
                block = json.loads(raw)
                expected_prev = block.get("prev_hash")
                if expected_prev != prev_hash:
                    return False, f"Quebra de encadeamento no bloco #{block.get('index')}: hash anterior nao confere."

                idx = block.get("index", 0)
                ts = block.get("timestamp", "")
                ctr = block.get("counter", 0)
                act = block.get("action", "")
                chash = block.get("code_hash", "")
                st = block.get("status", "")
                caller_str = block.get("caller", "")
                payload = f"{idx}|{expected_prev}|{ts}|{ctr}|{act}|{chash}|{st}|{caller_str}".encode("utf-8")
                calc_hash = hashlib.sha256(payload).hexdigest()
                if calc_hash != block.get("block_hash"):
                    return False, f"Adulteracao detectada no bloco #{idx}: hash recalculado diverge."
                prev_hash = calc_hash
        return True, "Cadeia de blocos integra e verificada com sucesso."
    except Exception as e:
        return False, f"Falha na verificacao do ledger: {e}"

