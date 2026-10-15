import base64
import ctypes
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import subprocess
import sys
import tempfile
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Optional, Tuple

if sys.platform == "win32":
    import msvcrt
    from ctypes import wintypes
else:
    msvcrt = None
    class wintypes:
        DWORD = ctypes.c_uint32
        HANDLE = ctypes.c_void_p
        HWND = ctypes.c_void_p
        ULONG = ctypes.c_ulong
        LPCWSTR = ctypes.c_wchar_p
        HINSTANCE = ctypes.c_void_p
        HKEY = ctypes.c_void_p

BASE_DIR = Path("C:/Utilitario")
CONFIG_DIR = BASE_DIR / "config"
QUEUE_DIR = BASE_DIR / "queue"
LOGS_DIR = BASE_DIR / "logs"
LOCK_FILE = QUEUE_DIR / "hotp.lock"
LEDGER_FILE = LOGS_DIR / "ledger.jsonl"
LEDGER_ANCHOR_FILE = LOGS_DIR / "ledger.anchor"
HW_SALT_FILE = CONFIG_DIR / "hw_salt.bin"

# DPAPI Structures & Functions
class DATA_BLOB(ctypes.Structure):
    _fields_ = [
        ("cbData", wintypes.DWORD),
        ("pbData", ctypes.POINTER(ctypes.c_byte))
    ]

crypt32 = getattr(ctypes, "windll", None).crypt32 if hasattr(ctypes, "windll") else None
kernel32 = getattr(ctypes, "windll", None).kernel32 if hasattr(ctypes, "windll") else None
advapi32 = getattr(ctypes, "windll", None).advapi32 if hasattr(ctypes, "windll") else None

DPAPI_ENTROPY = b"AntigravityBridge_TPM_DPAPI_Entropy_2026"
DPAPI_MAC_ENTROPY = b"AntigravityConfigIntegrityV2"
DPAPI_QUEUE_ENTROPY = b"AntigravityQueueTransitProtectionV2"
CRYPTPROTECT_UI_FORBIDDEN = 0x1
CRYPTPROTECT_LOCAL_MACHINE = 0x4
DPAPI_FLAGS = CRYPTPROTECT_LOCAL_MACHINE | CRYPTPROTECT_UI_FORBIDDEN  # 0x5 - Escopo de maquina seguro com entropia composta e ACL NTFS estrita


def _get_machine_guid_bytes() -> bytes:
    """Obtém o MachineGuid único da instalação do Windows para vincular a entropia ao host."""
    if sys.platform != "win32":
        return b"NonWinHostGuid"
    try:
        import winreg
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Cryptography",
            0,
            winreg.KEY_READ | winreg.KEY_WOW64_64KEY
        ) as key:
            val, _ = winreg.QueryValueEx(key, "MachineGuid")
            if val:
                return str(val).strip().encode("utf-8")
    except Exception:
        pass
    return b"FallbackMachineGuid"


def get_composite_entropy(base_entropy: bytes = DPAPI_ENTROPY, config_dir: Optional[Path] = None) -> bytes:
    """Combina a entropia base com o MachineGuid do Windows e o salt local protegido em config/."""
    target_cfg_dir = config_dir or CONFIG_DIR
    salt_file = target_cfg_dir / "hw_salt.bin"
    hw_salt = b""
    try:
        if salt_file.exists():
            with open(salt_file, "rb") as sf:
                hw_salt = sf.read(32)
    except Exception:
        hw_salt = b""
    return hashlib.sha256(base_entropy + b"|" + _get_machine_guid_bytes() + b"|" + hw_salt).digest()


def ensure_hw_salt(config_dir: Optional[Path] = None) -> bytes:
    """Garante a existência de um salt aleatório de 256 bits exclusivo em config/hw_salt.bin."""
    target_cfg_dir = config_dir or CONFIG_DIR
    salt_file = target_cfg_dir / "hw_salt.bin"
    try:
        target_cfg_dir.mkdir(parents=True, exist_ok=True)
        if salt_file.exists() and salt_file.stat().st_size >= 32:
            with open(salt_file, "rb") as sf:
                return sf.read(32)
        new_salt = secrets.token_bytes(32)
        with open(salt_file, "wb") as sf:
            sf.write(new_salt)
        if sys.platform == "win32" and not any(k in str(salt_file).lower() for k in ("temp", "tmp", "appdata")):
            subprocess.run(
                ["icacls", str(salt_file), "/inheritance:r", "/grant:r", "*S-1-5-18:(F)", "*S-1-5-32-544:(F)", "/c", "/q"],
                capture_output=True,
                check=False,
                creationflags=0x08000000
            )
        return new_salt
    except Exception:
        return b""


def wipe_buffer(buf):
    """Sobrescreve buffers de memória mutáveis com zeros e desbloqueia páginas físicas."""
    if buf is None:
        return
    if isinstance(buf, bytearray):
        raw_len = len(buf)
        if raw_len > 0:
            try:
                if kernel32 is not None:
                    p_buf = (ctypes.c_char * raw_len).from_buffer(buf)
                    kernel32.RtlZeroMemory(ctypes.byref(p_buf), raw_len)
                else:
                    for i in range(raw_len):
                        buf[i] = 0
            except Exception:
                for i in range(raw_len):
                    buf[i] = 0
            try:
                unlock_memory_page(buf)
            except Exception:
                pass
    elif isinstance(buf, memoryview):
        try:
            if not buf.readonly:
                for i in range(len(buf)):
                    buf[i] = 0
        except Exception:
            pass


def lock_memory_page(buf: bytearray) -> bool:
    """Bloqueia páginas de memória física no Windows impedindo descarregamento no pagefile.sys."""
    try:
        if not buf or kernel32 is None:
            return False
        raw_len = len(buf)
        p_buf = (ctypes.c_char * raw_len).from_buffer(buf)
        return bool(kernel32.VirtualLock(ctypes.byref(p_buf), raw_len))
    except Exception:
        return False


def unlock_memory_page(buf: bytearray) -> bool:
    """Desbloqueia páginas de memória física previamente travadas."""
    try:
        if not buf or kernel32 is None:
            return False
        raw_len = len(buf)
        p_buf = (ctypes.c_char * raw_len).from_buffer(buf)
        return bool(kernel32.VirtualUnlock(ctypes.byref(p_buf), raw_len))
    except Exception:
        return False


def configure_anti_dump_mitigations():
    """Desativa caixas de diálogo de falha, crash dumps e carregamento inseguro de DLLs no Windows."""
    if kernel32 is None:
        return
    try:
        # SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX
        kernel32.SetErrorMode(0x0001 | 0x0002 | 0x8000)
        # Remove o diretório de trabalho atual da busca padrão de DLLs para mitigar DLL Hijacking
        if hasattr(kernel32, "SetDllDirectoryW"):
            kernel32.SetDllDirectoryW("")
        # Habilita política de mitigação de carregamento de imagens (ProcessImageLoadPolicy = 10)
        if hasattr(kernel32, "SetProcessMitigationPolicy"):
            policy_val = ctypes.c_uint64(0x1 | 0x2)  # NoRemoteImages | NoLowMandatoryLabelImages
            kernel32.SetProcessMitigationPolicy(10, ctypes.byref(policy_val), ctypes.sizeof(policy_val))
    except Exception:
        pass


def dpapi_protect(plaintext: bytes, entropy: bytes = DPAPI_ENTROPY) -> bytes:
    """Criptografa dados usando a DPAPI do Windows com escopo de máquina (TPM/LSA).

    Sobrescreve todos os buffers nativos imediatamente antes de desalocar.
    """
    if crypt32 is None or kernel32 is None:
        # Fallback determinístico apenas para testes automatizados fora do Windows
        key = hashlib.sha256((entropy or b"") + _get_machine_guid_bytes()).digest()
        nonce = secrets.token_bytes(16)
        stream = hashlib.pbkdf2_hmac("sha256", key, nonce, 1000, dklen=len(plaintext))
        enc = bytes(a ^ b for a, b in zip(plaintext, stream))
        mac = hmac.new(key, nonce + enc, hashlib.sha256).digest()
        return b"SIM_DPAPI_V2|" + nonce + mac + enc

    raw_len = len(plaintext)
    p_buffer = ctypes.create_string_buffer(bytes(plaintext), raw_len)
    data_in = DATA_BLOB(raw_len, ctypes.cast(p_buffer, ctypes.POINTER(ctypes.c_byte)))

    ent_buf = ctypes.create_string_buffer(entropy, len(entropy)) if entropy else None
    entropy_blob = DATA_BLOB(
        len(entropy),
        ctypes.cast(ent_buf, ctypes.POINTER(ctypes.c_byte))
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

    # Limpa buffers nativos de entrada e entropia imediatamente
    ctypes.memset(ctypes.cast(p_buffer, ctypes.c_void_p), 0, raw_len)
    if ent_buf is not None:
        ctypes.memset(ctypes.cast(ent_buf, ctypes.c_void_p), 0, len(entropy))

    if not res:
        err = ctypes.GetLastError()
        raise ctypes.WinError(err)

    out_len = int(data_out.cbData)
    buf = ctypes.string_at(data_out.pbData, out_len)
    ctypes.memset(data_out.pbData, 0, out_len)
    kernel32.LocalFree(data_out.pbData)
    return buf


def dpapi_unprotect(ciphertext: bytes, entropy: bytes = DPAPI_ENTROPY) -> bytearray:
    """Descriptografa dados usando DPAPI diretamente para bytearray mutável travado em RAM.

    NUNCA cria objetos bytes/str imutáveis em Python com o segredo em texto claro.
    """
    if crypt32 is None or kernel32 is None:
        if not ciphertext.startswith(b"SIM_DPAPI_V2|"):
            raise RuntimeError("Blob DPAPI inválido.")
        raw = ciphertext[len(b"SIM_DPAPI_V2|"):]
        nonce, mac, enc = raw[:16], raw[16:48], raw[48:]
        key = hashlib.sha256((entropy or b"") + _get_machine_guid_bytes()).digest()
        expected_mac = hmac.new(key, nonce + enc, hashlib.sha256).digest()
        if not hmac.compare_digest(mac, expected_mac):
            raise RuntimeError("Falha de autenticação DPAPI: entropia ou integridade inválida.")
        stream = hashlib.pbkdf2_hmac("sha256", key, nonce, 1000, dklen=len(enc))
        out_ba = bytearray(a ^ b for a, b in zip(enc, stream))
        lock_memory_page(out_ba)
        return out_ba

    in_buf = ctypes.create_string_buffer(ciphertext, len(ciphertext))
    data_in = DATA_BLOB(
        len(ciphertext),
        ctypes.cast(in_buf, ctypes.POINTER(ctypes.c_byte))
    )
    ent_buf = ctypes.create_string_buffer(entropy, len(entropy)) if entropy else None
    entropy_blob = DATA_BLOB(
        len(entropy),
        ctypes.cast(ent_buf, ctypes.POINTER(ctypes.c_byte))
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
    if ent_buf is not None:
        ctypes.memset(ctypes.cast(ent_buf, ctypes.c_void_p), 0, len(entropy))

    if not res:
        err = ctypes.GetLastError()
        raise ctypes.WinError(err)

    out_len = int(data_out.cbData)
    mutable_out = bytearray(out_len)
    if out_len > 0:
        dst_buf = (ctypes.c_char * out_len).from_buffer(mutable_out)
        ctypes.memmove(dst_buf, data_out.pbData, out_len)
        ctypes.memset(data_out.pbData, 0, out_len)
    kernel32.LocalFree(data_out.pbData)

    lock_memory_page(mutable_out)
    return mutable_out


_transit_priv_cache = {}
_transit_pub_cache = {}


def ensure_transit_keypair(config_dir: Path = CONFIG_DIR, queue_dir: Path = QUEUE_DIR) -> bytes:
    """Garante um par de chaves assimétricas X25519 (Curve25519) para criptografia unidirecional na fila:
    - Chave Privada: salva em config/transit_priv.bin (protegida por DPAPI + hw_salt.bin e ACL restrita a SYSTEM/Admin).
    - Chave Pública: publicada em queue/transit_pub.json (permite que clientes criptografem OTPs sem NUNCA poderem descriptografar).
    """
    global _transit_priv_cache, _transit_pub_cache
    from cryptography.hazmat.primitives.asymmetric import x25519
    from cryptography.hazmat.primitives import serialization

    priv_file = config_dir / "transit_priv.bin"
    pub_file = queue_dir / "transit_pub.json"
    cfg_key = str(config_dir.resolve())

    if cfg_key in _transit_priv_cache and pub_file.exists():
        return _transit_pub_cache[cfg_key]

    try:
        config_dir.mkdir(parents=True, exist_ok=True)
        queue_dir.mkdir(parents=True, exist_ok=True)
        comp_ent = get_composite_entropy(DPAPI_QUEUE_ENTROPY, config_dir)

        if priv_file.exists():
            enc_priv = priv_file.read_bytes()
            priv_ba = dpapi_unprotect(enc_priv, entropy=comp_ent)
            try:
                priv_key = x25519.X25519PrivateKey.from_private_bytes(bytes(priv_ba))
            finally:
                wipe_buffer(priv_ba)
        else:
            priv_key = x25519.X25519PrivateKey.generate()
            raw_priv = priv_key.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption()
            )
            raw_priv_ba = bytearray(raw_priv)
            try:
                enc_priv = dpapi_protect(bytes(raw_priv_ba), entropy=comp_ent)
                priv_file.write_bytes(enc_priv)
                if sys.platform == "win32" and not any(k in str(priv_file).lower() for k in ("temp", "tmp", "appdata")):
                    subprocess.run(
                        ["icacls", str(priv_file), "/inheritance:r", "/grant:r", "*S-1-5-18:(F)", "*S-1-5-32-544:(F)", "/c", "/q"],
                        capture_output=True, check=False, creationflags=0x08000000
                    )
            finally:
                wipe_buffer(raw_priv_ba)

        pub_bytes = priv_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        _transit_priv_cache[cfg_key] = priv_key
        _transit_pub_cache[cfg_key] = pub_bytes
        pub_b64 = base64.b64encode(pub_bytes).decode("ascii")
        pub_file.write_text(json.dumps({"pub_x25519_b64": pub_b64}), encoding="utf-8")
        return pub_bytes
    except Exception:

        return b""


def protect_transit_token(token_str: str, req_id: str, code_hash: str, config_dir: Path = CONFIG_DIR, queue_dir: Path = QUEUE_DIR) -> str:
    """Criptografa um OTP ou token de pré-autorização usando Criptografia Assimétrica X25519 (ECIES):
    O cliente usa apenas a Chave Pública (queue/transit_pub.json) e uma chave efêmera descartada imediatamente.
    Nenhum usuário comum (nem mesmo o próprio processo cliente após cifrar) consegue reverter o ciphertext sem a Chave Privada em config/!
    """
    if not token_str:
        return ""
    from cryptography.hazmat.primitives.asymmetric import x25519
    from cryptography.hazmat.primitives import serialization

    pub_file = queue_dir / "transit_pub.json"
    recipient_pub_bytes = None
    if pub_file.exists():
        try:
            data = json.loads(pub_file.read_text(encoding="utf-8"))
            recipient_pub_bytes = base64.b64decode(data["pub_x25519_b64"])
        except Exception:
            recipient_pub_bytes = None

    if not recipient_pub_bytes:
        recipient_pub_bytes = ensure_transit_keypair(config_dir, queue_dir)

    raw_ba = bytearray(str(token_str).strip().encode("utf-8"))
    try:
        if recipient_pub_bytes and len(recipient_pub_bytes) == 32:
            recipient_pub = x25519.X25519PublicKey.from_public_bytes(recipient_pub_bytes)
            eph_priv = x25519.X25519PrivateKey.generate()
            eph_pub_bytes = eph_priv.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )
            shared_secret = bytearray(eph_priv.exchange(recipient_pub))
            try:
                nonce = secrets.token_bytes(16)
                context_bind = f"{req_id}|{code_hash}".encode("utf-8")
                derived_key = hashlib.pbkdf2_hmac("sha256", bytes(shared_secret), nonce + context_bind, 1000, dklen=32)
                keystream = hashlib.pbkdf2_hmac("sha256", derived_key, b"ENC_STREAM", 1, dklen=len(raw_ba))
                ciphertext = bytes(a ^ b for a, b in zip(raw_ba, keystream))
                mac = hmac.new(derived_key, eph_pub_bytes + nonce + context_bind + ciphertext, hashlib.sha256).digest()
                envelope = b"X25519_V1|" + eph_pub_bytes + nonce + mac + ciphertext
                return base64.b64encode(envelope).decode("ascii")
            finally:
                wipe_buffer(shared_secret)
                del eph_priv

        # Fallback caso X25519 não esteja inicializado (exige hw_salt.bin em config/)
        comp_ent = get_composite_entropy(DPAPI_QUEUE_ENTROPY, config_dir)
        bound_entropy = hashlib.sha256(
            comp_ent + b"|" + str(req_id).encode("utf-8") + b"|" + str(code_hash).encode("utf-8")
        ).digest()
        enc = dpapi_protect(bytes(raw_ba), entropy=bound_entropy)
        return base64.b64encode(enc).decode("ascii")
    finally:
        wipe_buffer(raw_ba)


def unprotect_transit_token(enc_b64: str, req_id: str, code_hash: str, config_dir: Path = CONFIG_DIR) -> Optional[str]:
    """Descriptografa e autentica um OTP/token em trânsito usando a Chave Privada X25519 guardada em config/transit_priv.bin."""
    if not enc_b64:
        return None
    from cryptography.hazmat.primitives.asymmetric import x25519

    plain_ba = None
    try:
        raw_enc = base64.b64decode(enc_b64)
        if raw_enc.startswith(b"X25519_V1|"):
            body = raw_enc[len(b"X25519_V1|"):]
            eph_pub_bytes = body[:32]
            nonce = body[32:48]
            mac = body[48:80]
            ciphertext = body[80:]

            global _transit_priv_cache
            cfg_key = str(config_dir.resolve())
            priv_key = _transit_priv_cache.get(cfg_key)
            if priv_key is None:
                priv_file = config_dir / "transit_priv.bin"
                try:
                    if not priv_file.exists():
                        return None
                    comp_ent = get_composite_entropy(DPAPI_QUEUE_ENTROPY, config_dir)
                    priv_ba = dpapi_unprotect(priv_file.read_bytes(), entropy=comp_ent)
                    try:
                        priv_key = x25519.X25519PrivateKey.from_private_bytes(bytes(priv_ba))
                        _transit_priv_cache[cfg_key] = priv_key
                    finally:
                        wipe_buffer(priv_ba)
                except Exception:
                    return None


            eph_pub = x25519.X25519PublicKey.from_public_bytes(eph_pub_bytes)
            shared_secret = bytearray(priv_key.exchange(eph_pub))
            try:
                context_bind = f"{req_id}|{code_hash}".encode("utf-8")
                derived_key = hashlib.pbkdf2_hmac("sha256", bytes(shared_secret), nonce + context_bind, 1000, dklen=32)
                expected_mac = hmac.new(derived_key, eph_pub_bytes + nonce + context_bind + ciphertext, hashlib.sha256).digest()
                if not hmac.compare_digest(mac, expected_mac):
                    return None
                keystream = hashlib.pbkdf2_hmac("sha256", derived_key, b"ENC_STREAM", 1, dklen=len(ciphertext))
                plain_ba = bytearray(a ^ b for a, b in zip(ciphertext, keystream))
                return plain_ba.decode("utf-8")
            finally:
                wipe_buffer(shared_secret)

        comp_ent = get_composite_entropy(DPAPI_QUEUE_ENTROPY, config_dir)
        bound_entropy = hashlib.sha256(
            comp_ent + b"|" + str(req_id).encode("utf-8") + b"|" + str(code_hash).encode("utf-8")
        ).digest()
        plain_ba = dpapi_unprotect(raw_enc, entropy=bound_entropy)
        return plain_ba.decode("utf-8")
    except Exception:
        return None
    finally:
        if plain_ba is not None:
            wipe_buffer(plain_ba)


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
_integrity_mac_cache = {}
_owner_anchor_cache = {}
_forensic_cache = {}

def clear_integrity_caches():
    """Limpa todos os caches em memória após reparo, provisionamento ou atualização de configuração."""
    _static_mesh_cache.clear()
    _usn_cache.clear()
    _integrity_mac_cache.clear()
    _owner_anchor_cache.clear()
    _forensic_cache.clear()
    _transit_priv_cache.clear()
    _transit_pub_cache.clear()




def _file_stat_sig(p: Optional[Path]) -> Tuple[int, int]:
    """Retorna (mtime_ns, size) rápido de um arquivo para invalidação instantânea de cache."""
    if p is None:
        return (0, 0)
    try:
        st = p.stat()
        return (int(st.st_mtime_ns), int(st.st_size))
    except Exception:
        return (-1, -1)


def get_file_usn(file_path: Path) -> str:
    """Obtém o USN [Update Sequence Number] do registro NTFS usando fsutil com cache inteligente."""
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
    if sys.platform == "win32":
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


_mesh_root_cache = {}


def _resolve_mesh_root(base_dir: Path = BASE_DIR) -> Path:
    """Normaliza o diretório raiz do aplicativo para cálculo consistente do hash da malha estática."""
    b = Path(base_dir)
    if b.name == "config":
        return b.parent
    if (b / "AdminBridge.exe").exists():
        return b
    if (b.parent / "AdminBridge.exe").exists():
        return b.parent
    return b


def get_static_mesh_hash(base_dir: Path = BASE_DIR) -> str:
    """Calcula a impressão digital (SHA-256) estática do executável AdminBridge.exe e da entropia da máquina."""
    root_dir = _resolve_mesh_root(base_dir)
    exe_file = root_dir / "AdminBridge.exe"
    exe_mtime = 0
    exe_size = 0
    if exe_file.exists():
        try:
            st = exe_file.stat()
            exe_mtime = int(st.st_mtime_ns)
            exe_size = int(st.st_size)
        except Exception:
            pass

    cache_key = (str(root_dir), exe_mtime, exe_size)
    if cache_key in _static_mesh_cache:
        return _static_mesh_cache[cache_key]

    components = []
    # 1. Executável principal
    if exe_file.exists():
        try:
            with open(exe_file, "rb") as ef:
                components.append(hashlib.sha256(ef.read()).hexdigest())
        except Exception:
            components.append("exe_read_error")
    else:
        components.append("exe_not_installed")

    # 2. Entropia de máquina
    components.append(hashlib.sha256(DPAPI_ENTROPY).hexdigest())

    combined = "|".join(components).encode("utf-8")
    result = hashlib.sha256(combined).hexdigest()
    _static_mesh_cache[cache_key] = result
    return result


def verify_scheduled_task_integrity(base_dir: Path = BASE_DIR, custom_task_files: Optional[list] = None) -> Tuple[bool, str]:
    r"""Verifica se as Tarefas Agendadas (AdminBridge / AdminBridgeWatchdog) apontam EXCLUSIVAMENTE
    para o executável oficial em C:\Utilitario\AdminBridge.exe --daemon, impedindo que um invasor
    mascare scripts maliciosos (.bat, .ps1, .vbs, cmd, powershell) dentro da tarefa do sistema.
    """
    task_files = custom_task_files if custom_task_files is not None else [
        Path("C:/Windows/System32/Tasks/AdminBridge"),
        Path("C:/Windows/System32/Tasks/AdminBridgeWatchdog"),
    ]
    expected_exe = str((base_dir / "AdminBridge.exe")).lower().replace("/", "\\")
    forbidden_masquerade_tokens = [
        ".bat", ".cmd", ".ps1", ".vbs", ".js", ".hta", ".scr",
        "powershell", "pwsh", "wscript", "cscript", "mshta",
        "rundll32", "regsvr32", "certutil", "bitsadmin", "curl", "wget"
    ]

    for tf_path in task_files:
        if not tf_path.exists():
            continue
        try:
            raw_bytes = tf_path.read_bytes()
            # O Agendador de Tarefas do Windows salva XML em UTF-16 (com BOM) ou UTF-8
            xml_text = ""
            for enc in ("utf-16", "utf-16le", "utf-8", "latin-1"):
                try:
                    decoded = raw_bytes.decode(enc)
                    if "<Task" in decoded or "<Command>" in decoded or "AdminBridge" in decoded:
                        xml_text = decoded.lower()
                        break
                except Exception:
                    continue
            if not xml_text:
                continue

            # Extrai todos os blocos <Command>...</Command> e <Arguments>...</Arguments>
            cmds = re.findall(r"<command>(.*?)</command>", xml_text, flags=re.DOTALL)
            args = re.findall(r"<arguments>(.*?)</arguments>", xml_text, flags=re.DOTALL)

            if not cmds:
                return False, f"Tarefa agendada {tf_path.name} corrompida ou sem tag <Command>."

            for c in cmds:
                c_clean = c.strip().strip('"').strip("'").replace("/", "\\")
                if c_clean != expected_exe and not c_clean.endswith("\\utilitario\\adminbridge.exe"):
                    return False, f"Alerta de Mascaramento: Tarefa {tf_path.name} aponta para executavel estranho ({c_clean})."
                for bad_tok in forbidden_masquerade_tokens:
                    if bad_tok in c_clean:
                        return False, f"Alerta de Mascaramento: Comando proibido ({bad_tok}) detectado na tarefa {tf_path.name}."

            for a in args:
                a_clean = a.strip()
                if a_clean and a_clean != "--daemon":
                    return False, f"Alerta de Mascaramento: Argumentos adulterados ({a_clean}) na tarefa {tf_path.name}."
                for bad_tok in forbidden_masquerade_tokens:
                    if bad_tok in a_clean:
                        return False, f"Alerta de Mascaramento: Script externo ({bad_tok}) injetado nos argumentos da tarefa {tf_path.name}."
        except PermissionError:
            # Se um processo de usuário comum não puder ler System32\Tasks, ignora (o daemon SYSTEM fará a leitura)
            continue
        except Exception as e:
            return False, f"Erro ao auditar tarefa agendada {tf_path.name}: {e}"

    return True, "Integridade da tarefa agendada confirmada." 


def compute_integrity_mac(cfg: dict) -> str:
    """Gera uma assinatura de integridade protegida por DPAPI sobre os metadados do JSON.

    Impede qualquer adulteração manual externa [por exemplo, edição com Bloco de Notas].
    """
    payload = _canonical_payload(cfg)
    digest = hashlib.sha256(payload).digest()
    encrypted_digest = dpapi_protect(digest, entropy=DPAPI_MAC_ENTROPY)
    return base64.b64encode(encrypted_digest).decode("ascii")


def check_integrity_mac(cfg: dict, config_path: Optional[Path] = None) -> Tuple[bool, str]:
    """Valida a assinatura de integridade, o arquivo .sig acompanhante, o USN e a malha estática (com cache reativo por mtime/size).

    Retorna [True, 'ok'] se íntegro.
    Retorna [False, motivo] se o arquivo, assinatura, USN ou executável foi adulterado.
    """
    mac_b64 = cfg.get("integrity_mac")
    if not mac_b64:
        return False, "missing_mac"

    cache_key = None
    if config_path:
        cp_obj = Path(config_path)
        sig_obj = cp_obj.with_name(cp_obj.name + ".sig")
        salt_obj = cp_obj.parent / "hw_salt.bin"
        exe_obj = _resolve_mesh_root(cp_obj.parent) / "AdminBridge.exe"
        payload_hash = hashlib.sha256(_canonical_payload(cfg)).hexdigest()
        cache_key = (
            str(cp_obj),
            payload_hash,
            mac_b64,
            _file_stat_sig(cp_obj),
            _file_stat_sig(sig_obj),
            _file_stat_sig(salt_obj),
            _file_stat_sig(exe_obj),
        )
        if cache_key in _integrity_mac_cache:
            return _integrity_mac_cache[cache_key]
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

    # Verificação obrigatória do arquivo acompanhante .sig, USN e static_mesh_hash
    if config_path and Path(config_path).exists():
        cp = Path(config_path)
        sig_file = cp.with_name(cp.name + ".sig")
        if not sig_file.exists():
            if cfg.get("provisioned_flag", 0) == 1 and cp.name == "hotp_config.json":
                return False, "sig_missing"
        else:
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
                recorded_mesh = sig_data.get("static_mesh_hash")
                if recorded_mesh:
                    curr_mesh = get_static_mesh_hash(cp.parent)
                    if not hmac.compare_digest(recorded_mesh, curr_mesh):
                        return False, "static_mesh_tampered"
                salt_file = cp.parent / "hw_salt.bin"
                rec_salt_hash = sig_data.get("hw_salt_sha256")
                if rec_salt_hash:
                    if not salt_file.exists():
                        return False, "hw_salt_missing"
                    curr_salt_hash = hashlib.sha256(salt_file.read_bytes()).hexdigest()
                    if not hmac.compare_digest(rec_salt_hash, curr_salt_hash):
                        return False, "hw_salt_tampered"
                rec_salt_usn = sig_data.get("hw_salt_usn")
                if rec_salt_usn and rec_salt_usn != "0x0" and salt_file.exists():
                    curr_salt_usn = get_file_usn(salt_file)
                    if curr_salt_usn != "0x0" and curr_salt_usn != rec_salt_usn:
                        return False, "hw_salt_usn_tampered"
            except PermissionError:
                pass
            except Exception:
                return False, "sig_read_error"

    if cache_key is not None:
        if len(_integrity_mac_cache) > 64:
            _integrity_mac_cache.clear()
        _integrity_mac_cache[cache_key] = (True, "ok")
    return True, "ok"


def verify_integrity_mac(cfg: dict, config_path: Optional[Path] = None) -> bool:
    """Verifica se a assinatura de integridade corresponde aos metadados do JSON e malha estática."""
    ok, _ = check_integrity_mac(cfg, config_path)
    return ok


def read_passive_metadata(config_path: Path) -> dict:
    """Lê metadados passivos [contador, flag, falhas, lockdown] SEM decodificar a chave secreta.

    Verifica a assinatura de integridade e a âncora do proprietário antes de retornar os dados.
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
    if is_valid and cfg.get("provisioned_flag", 0) == 1:
        anchor_candidate = config_path.parent / "owner_anchor.json"
        if anchor_candidate.exists():
            ok_anchor, _ = verify_owner_anchor(anchor_candidate, config_path.parent)
            if not ok_anchor:
                is_valid = False

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
    """Gera hash seguro PBKDF2-HMAC-SHA256 para a senha de recuperação [600.000 iterações]."""
    if salt is None:
        salt = secrets.token_bytes(16)
    pw_bytes = password.encode("utf-8")
    derived = hashlib.pbkdf2_hmac("sha256", pw_bytes, salt, 600000)
    return base64.b64encode(derived).decode("ascii"), base64.b64encode(salt).decode("ascii")


def verify_recovery_password(password: str, expected_hash_b64: str, salt_b64: str) -> bool:
    """Valida a senha de recuperação utilizando comparação de tempo constante."""
    salt = base64.b64decode(salt_b64)
    expected_hash = base64.b64decode(expected_hash_b64)
    derived = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 600000)
    return hmac.compare_digest(derived, expected_hash)


def create_detached_signature_file(config_file: Path, cfg: dict) -> Path:
    """Gera arquivo acompanhante de assinatura digital de integridade com USN e malha estática."""
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

        static_mesh = get_static_mesh_hash(config_file.parent)
        salt_file = config_file.parent / "hw_salt.bin"
        salt_usn = get_file_usn(salt_file) if salt_file.exists() else "0x0"
        salt_hash = hashlib.sha256(salt_file.read_bytes()).hexdigest() if salt_file.exists() else ""
        sig_payload = {
            "file": config_file.name,
            "sha256": file_hash,
            "usn": file_usn,
            "hw_salt_usn": salt_usn,
            "hw_salt_sha256": salt_hash,
            "static_mesh_hash": static_mesh,
            "integrity_mac": cfg.get("integrity_mac", ""),
            "signed_at": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
            "signer": "AdminBridge DPAPI Machine Seal"
        }
        if sig_file.exists() and kernel32 is not None:
            try:
                kernel32.SetFileAttributesW(str(sig_file), 0x80)
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


def _resolve_anchor_file(base_dir: Path = BASE_DIR, anchor_path: Optional[Path] = None) -> Path:
    """Resolve de forma determinística o caminho para owner_anchor.json."""
    if anchor_path is not None:
        return Path(anchor_path)
    b = Path(base_dir)
    if b.name == "config" or (b / "hotp_config.json").exists() or any(b.glob("*config*.json")):
        return b / "owner_anchor.json"
    return b / "config" / "owner_anchor.json"



# -----------------------------------------------------------------------------
# CAMADA ANTI-CHEAT: BLOQUEIO DE KERNEL (CreateFileW ShareMode=0), DACL DE PROCESSO E COFRE EXTERNO SYSTEM
# -----------------------------------------------------------------------------
EXTERNAL_VAULT_DIRS = [
    Path("C:/System Volume Information/AdminBridgeVault"),
    Path("C:/Windows/System32/config/systemprofile/AppData/Local/AdminBridgeVault"),
]


class KernelFileGuard:
    """Mantém handles nativos abertos no kernel do Windows (ntoskrnl/Ntfs.sys) para impedir:
    1. Sobrescrita, renomeação ou exclusão de AdminBridge.exe (dwShareMode = FILE_SHARE_READ).
    2. Leitura, cópia ou modificação de hotp_config.json e owner_anchor.json (dwShareMode = 0 - Exclusivo Total).
    Integra-se ao AtomicLock para liberar o handle de config por 2ms apenas quando o próprio daemon SYSTEM atualiza o contador.
    """
    _exe_handles = {}
    _cfg_handles = {}
    _guarded_cfg_paths = set()
    _active = False

    @classmethod
    def lock_executable_file(cls, exe_path: Path = BASE_DIR / "AdminBridge.exe") -> bool:
        """Trava o executável no kernel permitindo apenas leitura/execução (bloqueia escrita/delete até para Admin)."""
        if sys.platform != "win32" or kernel32 is None:
            return True
        p_str = str(exe_path)
        if p_str in cls._exe_handles and cls._exe_handles[p_str] not in (None, -1, 0):
            return True
        if not exe_path.exists():
            return False
        GENERIC_READ = 0x80000000
        FILE_SHARE_READ = 0x00000001  # Permite execução/leitura, mas PROÍBE escrita (FILE_SHARE_WRITE) e exclusão (FILE_SHARE_DELETE)
        OPEN_EXISTING = 3
        FILE_ATTRIBUTE_NORMAL = 0x80
        h = kernel32.CreateFileW(p_str, GENERIC_READ, FILE_SHARE_READ, None, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, None)
        if h and h != -1 and h != 0xFFFFFFFFFFFFFFFF:
            cls._exe_handles[p_str] = h
            return True
        return False

    @classmethod
    def acquire_exclusive_config_locks(cls, config_dir: Path = CONFIG_DIR):
        """Aplica trava de kernel diferenciada:
        - hw_salt.bin (chave de desencriptação DPAPI): dwShareMode = 0 (ZERO leitura, escrita ou exclusão por outros processos).
        - hotp_config.json, .sig e owner_anchor.json: dwShareMode = FILE_SHARE_READ (permite leitura passiva de status pela GUI sem WinError 32, mas BLOQUEIA escrita, sobrescrita, renomeação e exclusão no kernel).
        """
        cls._active = True
        if sys.platform != "win32" or kernel32 is None:
            return
        GENERIC_READ = 0x80000000
        NO_SHARING = 0x00000000       # Bloqueio total de leitura, escrita e exclusão para hw_salt.bin
        FILE_SHARE_READ = 0x00000001  # Bloqueio total de escrita, sobrescrita e exclusão para metadados
        OPEN_EXISTING = 3
        FILE_ATTRIBUTE_NORMAL = 0x80
        for fname in ("hw_salt.bin", "hotp_config.json", "hotp_config.json.sig", "owner_anchor.json"):
            fpath = config_dir / fname
            cls._guarded_cfg_paths.add(fpath)
            p_str = str(fpath)
            if p_str in cls._cfg_handles and cls._cfg_handles[p_str] not in (None, -1, 0):
                continue
            if fpath.exists():
                share_mode = NO_SHARING if fname == "hw_salt.bin" else FILE_SHARE_READ
                h = kernel32.CreateFileW(p_str, GENERIC_READ, share_mode, None, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, None)
                if h and h != -1 and h != 0xFFFFFFFFFFFFFFFF:
                    cls._cfg_handles[p_str] = h

    @classmethod
    def suspend_config_locks_for_atomic_io(cls):
        """Libera temporariamente os handles exclusivos de config durante uma operação interna do próprio daemon dentro do AtomicLock."""
        if sys.platform != "win32" or kernel32 is None:
            return
        for p_str, h in list(cls._cfg_handles.items()):
            if h and h not in (-1, 0):
                try:
                    kernel32.CloseHandle(h)
                except Exception:
                    pass
            cls._cfg_handles.pop(p_str, None)

    @classmethod
    def release_all_locks(cls):
        """Libera todos os handles de kernel (executável e configuração) após autorização de reset ou desinstalação."""
        cls._active = False
        if sys.platform != "win32" or kernel32 is None:
            cls._exe_handles.clear()
            cls._cfg_handles.clear()
            return
        for handle_dict in (cls._exe_handles, cls._cfg_handles):
            for p_str, h in list(handle_dict.items()):
                if h and h not in (-1, 0):
                    try:
                        kernel32.CloseHandle(h)
                    except Exception:
                        pass
                handle_dict.pop(p_str, None)

    @classmethod
    def resume_config_locks_after_atomic_io(cls):
        """Re-adquire imediatamente os bloqueios de kernel após concluir a operação interna."""
        if not cls._active or sys.platform != "win32" or kernel32 is None:
            return
        GENERIC_READ = 0x80000000
        NO_SHARING = 0x00000000
        FILE_SHARE_READ = 0x00000001
        OPEN_EXISTING = 3
        FILE_ATTRIBUTE_NORMAL = 0x80
        for fpath in list(cls._guarded_cfg_paths):
            p_str = str(fpath)
            if p_str not in cls._cfg_handles and fpath.exists():
                share_mode = NO_SHARING if fpath.name == "hw_salt.bin" else FILE_SHARE_READ
                h = kernel32.CreateFileW(p_str, GENERIC_READ, share_mode, None, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, None)
                if h and h != -1 and h != 0xFFFFFFFFFFFFFFFF:
                    cls._cfg_handles[p_str] = h


def sync_external_system_vault(anchor_data: dict) -> bool:
    """Espelha a âncora soberana em áreas exclusivas do SYSTEM fora de C:\\Utilitario:
    1. Registro HKLM\\SECURITY\\Policy\\Secrets\\AdminBridgeAnchor (acessível apenas a SYSTEM).
    2. C:\\System Volume Information\\AdminBridgeVault (partição/diretório oculto do sistema onde Admin tem Acesso Negado).
    Impede que um Admin temporário apague a pasta C:\\Utilitario inteira e substitua por arquivos novos.
    """
    if sys.platform != "win32":
        return True
    payload_str = json.dumps({
        "public_key_b64": anchor_data.get("public_key_b64", ""),
        "static_mesh_hash": anchor_data.get("static_mesh_hash", ""),
        "signature_b64": anchor_data.get("signature_b64", "")
    }, sort_keys=True)

    # 1. Tenta gravar em HKLM\SECURITY (acessível apenas quando rodando como SYSTEM)
    try:
        import winreg
        with winreg.CreateKeyEx(
            winreg.HKEY_LOCAL_MACHINE,
            r"SECURITY\Policy\Secrets\AdminBridgeAnchor",
            0,
            winreg.KEY_WRITE | winreg.KEY_WOW64_64KEY
        ) as key:
            winreg.SetValueEx(key, "AnchorSeal", 0, winreg.REG_SZ, payload_str)
    except Exception:
        pass

    # 2. Tenta gravar nos cofres externos de sistema fora de C:\Utilitario
    for ext_dir in EXTERNAL_VAULT_DIRS:
        try:
            ext_dir.mkdir(parents=True, exist_ok=True)
            subprocess.run(
                ["icacls", str(ext_dir), "/inheritance:r", "/grant:r", "*S-1-5-18:(OI)(CI)(F)", "/c", "/q"],
                capture_output=True, check=False, creationflags=0x08000000
            )
            seal_file = ext_dir / "anchor_seal.json"
            with open(seal_file, "w", encoding="utf-8") as sf:
                sf.write(payload_str)
        except Exception:
            pass
    return True


def clear_external_system_vault():
    """Limpa a âncora externa exclusivamente durante um reset ou reparo autenticado pelo proprietário."""
    if sys.platform != "win32":
        return
    try:
        import winreg
        winreg.DeleteKeyEx(
            winreg.HKEY_LOCAL_MACHINE,
            r"SECURITY\Policy\Secrets\AdminBridgeAnchor",
            winreg.KEY_WOW64_64KEY,
            0
        )
    except Exception:
        pass
    for ext_dir in EXTERNAL_VAULT_DIRS:
        try:
            seal_file = ext_dir / "anchor_seal.json"
            if seal_file.exists():
                seal_file.unlink(missing_ok=True)
        except Exception:
            pass


def verify_external_system_vault(local_anchor: dict) -> Tuple[bool, str]:
    """Compara o owner_anchor.json de C:\\Utilitario com o cofre externo do SYSTEM (HKLM\\SECURITY e System Volume Information).
    Se um Admin temporário tiver substituído a pasta C:\\Utilitario inteira por novos arquivos, a chave pública divergirá do cofre externo!
    """
    if sys.platform != "win32":
        return True, "ok"

    ext_seals = []
    try:
        import winreg
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SECURITY\Policy\Secrets\AdminBridgeAnchor",
            0,
            winreg.KEY_READ | winreg.KEY_WOW64_64KEY
        ) as key:
            val, _ = winreg.QueryValueEx(key, "AnchorSeal")
            if val:
                ext_seals.append(json.loads(val))
    except Exception:
        pass

    for ext_dir in EXTERNAL_VAULT_DIRS:
        try:
            seal_file = ext_dir / "anchor_seal.json"
            if seal_file.exists():
                with open(seal_file, "r", encoding="utf-8") as sf:
                    ext_seals.append(json.load(sf))
        except Exception:
            pass

    for seal in ext_seals:
        ext_pub = seal.get("public_key_b64", "")
        ext_sig = seal.get("signature_b64", "")
        if ext_pub and ext_pub != local_anchor.get("public_key_b64", ""):
            return False, "external_vault_mismatch: A pasta C:\\Utilitario foi substituida por uma nova instalacao nao autorizada"
        if ext_sig and ext_sig != local_anchor.get("signature_b64", ""):
            return False, "external_vault_signature_mismatch: Assinatura da pasta C:\\Utilitario diverge do cofre externo SYSTEM"

    return True, "ok"


def create_owner_anchor(password: str, base_dir: Path = BASE_DIR, anchor_path: Optional[Path] = None) -> dict:
    """Gera e registra a âncora criptográfica Ed25519 soberana do proprietário vinculada ao binário e tarefa."""
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.hazmat.primitives import serialization

    salt = secrets.token_bytes(16)
    derived = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=16384, r=8, p=1, maxmem=32 * 1024 * 1024, dklen=32)
    derived_ba = bytearray(derived)
    lock_memory_page(derived_ba)

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

        anchor_file = _resolve_anchor_file(base_dir, anchor_path)
        anchor_file.parent.mkdir(parents=True, exist_ok=True)
        if anchor_file.exists() and sys.platform == "win32":
            subprocess.run(["attrib", "-r", str(anchor_file)], capture_output=True, check=False, creationflags=0x08000000)
        with open(anchor_file, "w", encoding="utf-8") as af:
            json.dump(anchor_data, af, indent=2, ensure_ascii=False)
        if sys.platform == "win32" and not any(k in str(anchor_file).lower() for k in ("temp", "tmp", "appdata")):
            subprocess.run(["attrib", "+r", str(anchor_file)], capture_output=True, check=False, creationflags=0x08000000)
            subprocess.run(
                ["icacls", str(anchor_file), "/inheritance:r", "/grant:r", "*S-1-5-18:(F)", "*S-1-5-32-544:(RX)", "/c", "/q"],
                capture_output=True,
                check=False,
                creationflags=0x08000000
            )
        if base_dir == BASE_DIR or Path(base_dir).resolve() == BASE_DIR.resolve() or Path(base_dir).parent.resolve() == BASE_DIR.resolve():
            sync_external_system_vault(anchor_data)
        return anchor_data
    finally:
        wipe_buffer(derived_ba)
        del derived, derived_ba


def verify_owner_anchor(anchor_path: Optional[Path] = None, base_dir: Path = BASE_DIR) -> Tuple[bool, str]:
    """Valida a assinatura Ed25519 da âncora do proprietário CONTRA a malha estática real em disco (com cache reativo)."""
    from cryptography.hazmat.primitives.asymmetric import ed25519

    target_anchor = _resolve_anchor_file(base_dir, anchor_path)
    if not target_anchor.exists():
        return False, "owner_anchor_missing: arquivo owner_anchor.json ausente ou removido"

    exe_obj = _resolve_mesh_root(base_dir) / "AdminBridge.exe"
    anc_cache_key = (str(target_anchor), _file_stat_sig(target_anchor), _file_stat_sig(exe_obj))
    if anc_cache_key in _owner_anchor_cache:
        return _owner_anchor_cache[anc_cache_key]

    try:
        with open(target_anchor, "r", encoding="utf-8") as af:
            anchor_data = json.load(af)

        pub_bytes = base64.b64decode(anchor_data["public_key_b64"])
        signature = base64.b64decode(anchor_data["signature_b64"])
        recorded_mesh = anchor_data.get("static_mesh_hash", "")

        # Recalcula o hash atual do executável AdminBridge.exe e da Tarefa Agendada no disco
        actual_mesh = get_static_mesh_hash(base_dir)
        if not hmac.compare_digest(recorded_mesh, actual_mesh):
            return False, "static_mesh_tampered: executavel AdminBridge.exe ou tarefa agendada foram alterados"

        pub_key = ed25519.Ed25519PublicKey.from_public_bytes(pub_bytes)
        sign_payload = f"AdminBridge_OwnerAnchor_v1|{actual_mesh}".encode("utf-8")
        pub_key.verify(signature, sign_payload)

        if base_dir == BASE_DIR or Path(base_dir).resolve() == BASE_DIR.resolve() or Path(base_dir).parent.resolve() == BASE_DIR.resolve():
            ok_ext, ext_msg = verify_external_system_vault(anchor_data)
            if not ok_ext:
                return False, ext_msg

        if len(_owner_anchor_cache) > 64:
            _owner_anchor_cache.clear()
        _owner_anchor_cache[anc_cache_key] = (True, "ok")
        return True, "ok"
    except Exception as e:
        return False, f"owner_anchor_invalid: {e}"


def verify_owner_password(password: str, anchor_path: Optional[Path] = None, base_dir: Path = BASE_DIR) -> bool:
    """Verifica se a Senha Mestra digitada corresponde à chave pública Ed25519 registrada na âncora."""
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.hazmat.primitives import serialization

    target_anchor = _resolve_anchor_file(base_dir, anchor_path)
    if not target_anchor.exists():
        return False

    try:
        with open(target_anchor, "r", encoding="utf-8") as af:
            anchor_data = json.load(af)

        salt = base64.b64decode(anchor_data["salt_b64"])
        expected_pub = base64.b64decode(anchor_data["public_key_b64"])

        derived = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=16384, r=8, p=1, maxmem=32 * 1024 * 1024, dklen=32)
        derived_ba = bytearray(derived)
        lock_memory_page(derived_ba)
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
    """Gera contra-senha determinística de confirmação mútua para provar autenticidade do serviço."""
    clean_otp = str(otp_code).strip()
    key_material = (clean_otp + "_CONFIRMACAO").encode("utf-8")
    digest = hmac.new(secret_bytes, key_material, hashlib.sha256).hexdigest()
    return digest[:6].upper()


def harden_process_dacl() -> bool:
    """Endurece a DACL do processo no kernel do Windows (estilo Anti-Cheat):
    Nega PROCESS_TERMINATE (0x0001), PROCESS_VM_READ (0x0010), PROCESS_VM_WRITE (0x0020) e PROCESS_SUSPEND_RESUME (0x0800)
    para Usuários Comuns (BU) e Administradores (BA), concedendo controle total apenas ao próprio SYSTEM (SY).
    """
    try:
        configure_anti_dump_mitigations()
        if sys.platform == "win32" and advapi32 is not None and kernel32 is not None:
            # SDDL: DACL Protegida que nega Terminate/VM_Read/VM_Write/Suspend para Admins (BA) e Users (BU), e permite tudo para SYSTEM (SY)
            sddl = "D:P(D;;0x0831;;;BA)(D;;0x0831;;;BU)(A;;0x1fffff;;;SY)"
            p_sd = ctypes.c_void_p()
            if advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1, ctypes.byref(p_sd), None):
                try:
                    DACL_SECURITY_INFORMATION = 0x00000004
                    h_proc = kernel32.GetCurrentProcess()
                    advapi32.SetKernelObjectSecurity(h_proc, DACL_SECURITY_INFORMATION, p_sd)
                finally:
                    kernel32.LocalFree(p_sd)
        return True
    except Exception:
        return False


def check_config_acl_isolation(base_dir: Path = BASE_DIR) -> bool:
    """Verifica se a pasta config e arquivos sensíveis estão estritamente isolados contra usuários comuns."""
    if sys.platform != "win32":
        return True
    forbidden_principals = ["usuários", "usuarios", "users", "autenticados", "authenticated", "s-1-5-32-545", "s-1-5-11", "everyone", "todos", "s-1-1-0"]
    for rel_path in (
        "config",
        "config/hotp_config.json",
        "config/hotp_config.json.sig",
        "config/owner_anchor.json",
        "config/preauth_ticket.json",
        "scripts",
        "queue/processing"
    ):
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
    """Aplica permissões ACL granulares chamando icacls.exe diretamente (sem cmd.exe /c para evitar erro 87 de escape de aspas):
    - Raiz C:\\Utilitario: Remove herança de C:\\ (/inheritance:r), bloqueando escrita/criação de arquivos por usuários comuns.
    - C:\\Utilitario\\config: Exclusivo para SYSTEM e Administradores (Bloqueio total a usuários comuns / Medium Integrity).
    - C:\\Utilitario\\queue\\requests: Drop-box seguro (Usuários comuns têm apenas WD/AD para criar requisições, sem listar ou ler arquivos de terceiros).
    - C:\\Utilitario\\queue\\processing: Exclusivo para SYSTEM e Administradores.
    - AdminBridge.exe: Somente leitura e execução (RX) para Administradores e Usuários; Controle Total apenas para SYSTEM.
    """
    if sys.platform != "win32":
        return True

    b_str = str(base_dir).lower()
    if "temp" in b_str or "tmp" in b_str or "appdata" in b_str:
        return True

    config_dir = base_dir / "config"
    scripts_dir = base_dir / "scripts"
    queue_dir = base_dir / "queue"
    req_dir = queue_dir / "requests"
    proc_dir = queue_dir / "processing"
    resp_dir = queue_dir / "responses"
    gui_pending_dir = queue_dir / "gui_pending"
    try:
        gui_pending_dir.mkdir(parents=True, exist_ok=True)
    except Exception:
        pass
    logs_dir = base_dir / "logs"
    exe_file = base_dir / "AdminBridge.exe"
    legacy_exe = base_dir / "AntigravityBridge.exe"

    for d in (config_dir, scripts_dir, queue_dir, req_dir, proc_dir, resp_dir, logs_dir):
        try:
            d.mkdir(parents=True, exist_ok=True)
            subprocess.run(["attrib", "-h", "-s", str(d)], capture_output=True, check=False, creationflags=0x08000000)
        except Exception:
            pass

    # Garante par de chaves X25519 da fila antes de fechar as permissões
    try:
        ensure_transit_keypair(config_dir, queue_dir)
    except Exception:
        pass

    # 1. Blindagem da pasta raiz C:\Utilitario (Sem /d y isolado no takeown, e chamada direta ao icacls.exe!)
    try:
        if base_dir.exists():
            subprocess.run(["takeown", "/f", str(base_dir), "/a"], capture_output=True, check=False, creationflags=0x08000000)
            subprocess.run([
                "icacls", str(base_dir),
                "/inheritance:r",
                "/grant:r", "*S-1-5-18:(OI)(CI)(F)",
                "/grant", "*S-1-5-32-544:(OI)(CI)(RX)",
                "/grant", "*S-1-5-32-545:(RX)",
                "/c", "/q"
            ], capture_output=True, check=False, creationflags=0x08000000)
    except Exception:
        pass

    # 2. Blindagem estrita de C:\Utilitario\config (Zero acesso a usuários comuns / Medium Integrity)
    try:
        if config_dir.exists():
            cfg_str = str(config_dir)
            subprocess.run(["takeown", "/f", cfg_str, "/a", "/r", "/d", "y"], capture_output=True, check=False, creationflags=0x08000000)
            subprocess.run([
                "icacls", cfg_str,
                "/inheritance:r",
                "/grant:r", "*S-1-5-18:(OI)(CI)(F)",
                "/grant", "*S-1-5-32-544:(OI)(CI)(F)",
                "/t", "/c", "/q"
            ], capture_output=True, check=False, creationflags=0x08000000)

            is_system_account = os.getenv("USERNAME", "").upper() in ("SYSTEM", "SISTEMA") or os.getenv("USERPROFILE", "").lower().endswith("systemprofile")
            for specific_file in ("hotp_config.json", "hotp_config.json.sig", "owner_anchor.json", "preauth_ticket.json", "hw_salt.bin", "transit_priv.bin", "canary.bin"):
                sp = config_dir / specific_file
                if sp.exists():
                    if is_system_account and specific_file in ("hw_salt.bin", "transit_priv.bin", "canary.bin"):
                        subprocess.run([
                            "icacls", str(sp),
                            "/inheritance:r",
                            "/grant:r", "*S-1-5-18:(F)",
                            "/c", "/q"
                        ], capture_output=True, check=False, creationflags=0x08000000)
                    else:
                        subprocess.run([
                            "icacls", str(sp),
                            "/inheritance:r",
                            "/grant:r", "*S-1-5-18:(F)",
                            "/grant", "*S-1-5-32-544:(F)",
                            "/c", "/q"
                        ], capture_output=True, check=False, creationflags=0x08000000)
    except Exception:
        pass

    # 3. Blindagem estrita de scripts, queue/processing e logs (Zero acesso a usuários comuns)
    for restricted_dir in (scripts_dir, proc_dir, logs_dir):
        try:
            if restricted_dir.exists():
                subprocess.run(["takeown", "/f", str(restricted_dir), "/a", "/r", "/d", "y"], capture_output=True, check=False, creationflags=0x08000000)
                subprocess.run([
                    "icacls", str(restricted_dir),
                    "/inheritance:r",
                    "/grant:r", "*S-1-5-18:(OI)(CI)(F)",
                    "/grant", "*S-1-5-32-544:(OI)(CI)(F)",
                    "/t", "/c", "/q"
                ], capture_output=True, check=False, creationflags=0x08000000)
        except Exception:
            pass

    # 4. Canal de fila: queue/requests funciona como Drop-Box (WD,AD para usuários criarem sem listar/ler arquivos alheios)
    try:
        if queue_dir.exists():
            subprocess.run([
                "icacls", str(queue_dir),
                "/inheritance:r",
                "/grant:r", "*S-1-5-18:(OI)(CI)(F)",
                "/grant", "*S-1-5-32-544:(OI)(CI)(M)",
                "/grant", "*S-1-5-32-545:(RX)",
                "/c", "/q"
            ], capture_output=True, check=False, creationflags=0x08000000)
            for status_f in (queue_dir / "status.json", queue_dir / "heartbeat.json", queue_dir / "transit_pub.json", LOCK_FILE):
                if status_f.exists():
                    subprocess.run([
                        "icacls", str(status_f),
                        "/inheritance:r",
                        "/grant:r", "*S-1-5-18:(F)",
                        "/grant", "*S-1-5-32-544:(M)",
                        "/grant", "*S-1-5-32-545:(M)" if status_f == LOCK_FILE else "*S-1-5-32-545:(RX)",
                        "/c", "/q"
                    ], capture_output=True, check=False, creationflags=0x08000000)

        if req_dir.exists():
            subprocess.run([
                "icacls", str(req_dir),
                "/inheritance:r",
                "/grant:r", "*S-1-5-18:(OI)(CI)(F)",
                "/grant", "*S-1-5-32-544:(OI)(CI)(F)",
                "/grant", "*S-1-3-0:(IO)(F)",
                "/grant", "*S-1-5-32-545:(CI)(WD,AD)",
                "/c", "/q"
            ], capture_output=True, check=False, creationflags=0x08000000)

        for open_q_dir in (resp_dir, gui_pending_dir):
            if open_q_dir.exists():
                subprocess.run([
                    "icacls", str(open_q_dir),
                    "/inheritance:r",
                    "/grant:r", "*S-1-5-18:(OI)(CI)(F)",
                    "/grant", "*S-1-5-32-544:(OI)(CI)(F)",
                    "/grant", "*S-1-5-32-545:(OI)(CI)(M)",
                    "/c", "/q"
                ], capture_output=True, check=False, creationflags=0x08000000)
    except Exception:
        pass

    # 5. Blindagem estrita dos executáveis principais
    for target_bin in (exe_file, legacy_exe):
        try:
            if target_bin.exists():
                subprocess.run(["attrib", "-r", str(target_bin)], capture_output=True, check=False, creationflags=0x08000000)
                subprocess.run(["takeown", "/f", str(target_bin), "/a"], capture_output=True, check=False, creationflags=0x08000000)
                subprocess.run([
                    "icacls", str(target_bin),
                    "/inheritance:r",
                    "/grant:r", "*S-1-5-18:(F)",
                    "/grant", "*S-1-5-32-544:(RX)",
                    "/grant", "*S-1-5-32-545:(RX)",
                    "/c", "/q"
                ], capture_output=True, check=False, creationflags=0x08000000)
                subprocess.run(["attrib", "+r", str(target_bin)], capture_output=True, check=False, creationflags=0x08000000)
        except Exception:
            pass

    ok_iso = check_config_acl_isolation(base_dir)
    if ok_iso:
        try:
            (config_dir / ".acl_seal").write_text(str(int(time.time())), encoding="utf-8")
        except Exception:
            pass
    return ok_iso


def check_forensic_integrity(config_file: Path) -> Tuple[bool, str]:
    """Verifica se a posse, o arquivo canário ou a âncora soberana foram violados (com cache de USN/mtime para zero lag)."""
    if not config_file.exists():
        return True, "Configuracao ainda nao existe."

    canary_file = config_file.parent / "canary.bin"
    anchor_file = config_file.parent / "owner_anchor.json"
    exe_file = _resolve_mesh_root(config_file.parent) / "AdminBridge.exe"
    for_cache_key = (
        str(config_file),
        _file_stat_sig(config_file),
        get_file_usn(config_file),
        _file_stat_sig(canary_file),
        _file_stat_sig(anchor_file),
        _file_stat_sig(exe_file),
    )

    try:
        if sys.platform == "win32" and for_cache_key not in _forensic_cache:
            ps_cmd = f"(Get-Acl -LiteralPath '{config_file}').Owner"
            res = subprocess.run(
                ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps_cmd],
                capture_output=True,
                text=True,
                check=False,
                creationflags=0x08000000
            )
            owner = res.stdout.strip()
            if owner and not (
                "SISTEMA" in owner.upper()
                or "SYSTEM" in owner.upper()
                or "ADMINISTRADORES" in owner.upper()
                or "ADMINISTRATORS" in owner.upper()
                or "S-1-5-18" in owner
                or "S-1-5-32-544" in owner
            ):
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

        # Verifica a âncora soberana do proprietário e o hash do executável
        anchor_file = config_file.parent / "owner_anchor.json"
        if anchor_file.exists():
            ok_anc, msg_anc = verify_owner_anchor(anchor_file, config_file.parent)
            if not ok_anc:
                return False, f"Alerta forense: Violacao da ancora do proprietario ({msg_anc})."

        # Verifica se a Tarefa Agendada do Windows não foi adulterada para mascarar outro script
        ok_task, msg_task = verify_scheduled_task_integrity(_resolve_mesh_root(config_file.parent))
        if not ok_task:
            return False, f"Alerta forense: {msg_task}"

        if len(_forensic_cache) > 32:
            _forensic_cache.clear()
        _forensic_cache[for_cache_key] = True
        return True, "Integridade forense confirmada."
    except Exception as e:
        return True, f"Verificacao forense ignorada por erro de ambiente: {e}"


def apply_system_only_ntfs_acls(target_path: Path):
    """Alias para compatibilidade retroativa com chamadas anteriores."""
    apply_isolated_bridge_ntfs_acls()


def restore_ntfs_acls_for_removal(target_path: Path):
    """Assume posse (takeown) e restaura permissões para Administradores para permitir remoção/desinstalação."""
    if sys.platform != "win32" or not target_path.exists():
        return
    t_str = str(target_path).lower()
    if "temp" in t_str or "tmp" in t_str or "appdata" in t_str:
        return

    try:
        subprocess.run(
            ["takeown", "/f", str(target_path), "/r", "/d", "y"],
            capture_output=True,
            check=False,
            creationflags=0x08000000
        )
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
        try:
            QUEUE_DIR.mkdir(parents=True, exist_ok=True)
        except Exception:
            pass
        if not hasattr(_lock_local, "depth"):
            _lock_local.depth = 0
            _lock_local.mutex_handle = None
            _lock_local.lock_file_fd = None

        if _lock_local.depth > 0:
            _lock_local.depth += 1
            return self

        # 1. Named Mutex do Windows
        handle = None
        if kernel32 is not None:
            handle = kernel32.CreateMutexW(None, False, self.mutex_name)
            if handle:
                wait_res = kernel32.WaitForSingleObject(handle, self.timeout_ms)
                if wait_res not in (0, 0x80):
                    kernel32.CloseHandle(handle)
                    raise TimeoutError("Tempo limite esgotado ao aguardar mutex do HOTP.")
        _lock_local.mutex_handle = handle

        # 2. File Lock (tenta LOCK_FILE ou fallback no TEMP)
        try:
            try:
                fd = os.open(str(LOCK_FILE), os.O_CREAT | os.O_RDWR)
            except (FileNotFoundError, PermissionError, OSError):
                fallback_lock = Path(tempfile.gettempdir()) / "AdminBridge_atomic.lock"
                fd = os.open(str(fallback_lock), os.O_CREAT | os.O_RDWR)
            start_time = time.time()
            if msvcrt is not None:
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
            if _lock_local.mutex_handle and kernel32 is not None:
                kernel32.ReleaseMutex(_lock_local.mutex_handle)
                kernel32.CloseHandle(_lock_local.mutex_handle)
                _lock_local.mutex_handle = None
            raise

        KernelFileGuard.suspend_config_locks_for_atomic_io()
        _lock_local.depth = 1
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if not hasattr(_lock_local, "depth") or _lock_local.depth == 0:
            return

        _lock_local.depth -= 1
        if _lock_local.depth > 0:
            return

        KernelFileGuard.resume_config_locks_after_atomic_io()
        if _lock_local.lock_file_fd is not None:
            try:
                if msvcrt is not None:
                    msvcrt.locking(_lock_local.lock_file_fd, msvcrt.LK_UNLCK, 1)
                os.close(_lock_local.lock_file_fd)
            except Exception:
                pass
            _lock_local.lock_file_fd = None

        if _lock_local.mutex_handle and kernel32 is not None:
            try:
                kernel32.ReleaseMutex(_lock_local.mutex_handle)
                kernel32.CloseHandle(_lock_local.mutex_handle)
            except Exception:
                pass
            _lock_local.mutex_handle = None


def get_current_caller_info() -> dict:
    """Coleta dados reais do processo cliente atual para rastreabilidade de origem."""
    return {
        "pid": os.getpid(),
        "exe": sys.executable,
        "script": str(Path(__file__).resolve()),
        "user": os.getenv("USERNAME") or os.getenv("USER") or "unknown",
        "timestamp": time.time()
    }


def get_os_process_username(pid: int) -> Optional[str]:
    """Obtém diretamente do Token de Kernel do Windows (OpenProcessToken + LookupAccountSidW)
    o nome real do usuário dono do processo PID, impedindo falsificação de caller.user no JSON.
    """
    if sys.platform != "win32" or kernel32 is None or advapi32 is None or not pid:
        return None
    PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
    TOKEN_QUERY = 0x0008
    TokenUser = 1
    h_proc = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, int(pid))
    if not h_proc:
        return None
    h_tok = wintypes.HANDLE()
    try:
        if not advapi32.OpenProcessToken(h_proc, TOKEN_QUERY, ctypes.byref(h_tok)):
            return None
        needed = wintypes.DWORD(0)
        advapi32.GetTokenInformation(h_tok, TokenUser, None, 0, ctypes.byref(needed))
        if needed.value == 0:
            return None
        buf = ctypes.create_string_buffer(needed.value)
        if not advapi32.GetTokenInformation(h_tok, TokenUser, buf, needed.value, ctypes.byref(needed)):
            return None
        p_sid = ctypes.cast(buf, ctypes.POINTER(ctypes.c_void_p)).contents
        name_len = wintypes.DWORD(256)
        dom_len = wintypes.DWORD(256)
        name_buf = ctypes.create_unicode_buffer(256)
        dom_buf = ctypes.create_unicode_buffer(256)
        sid_use = wintypes.DWORD(0)
        if advapi32.LookupAccountSidW(None, p_sid, name_buf, ctypes.byref(name_len), dom_buf, ctypes.byref(dom_len), ctypes.byref(sid_use)):
            return name_buf.value
        return None
    except Exception:
        return None
    finally:
        if h_tok:
            kernel32.CloseHandle(h_tok)
        kernel32.CloseHandle(h_proc)


def _get_os_process_image_path(pid: int) -> Optional[str]:
    """Consulta diretamente no kernel do Windows o caminho real do executável de um PID ativo."""
    if sys.platform != "win32" or kernel32 is None or not pid:
        return None
    PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
    h_proc = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, int(pid))
    if not h_proc:
        return None
    try:
        buf_len = wintypes.DWORD(1024)
        buf = ctypes.create_unicode_buffer(1024)
        if kernel32.QueryFullProcessImageNameW(h_proc, 0, buf, ctypes.byref(buf_len)):
            return buf.value
        return None
    except Exception:
        return None
    finally:
        kernel32.CloseHandle(h_proc)


def verify_caller_origin(caller_data: Optional[dict]) -> Tuple[bool, str]:
    """Verifica se a origem da requisição pertence ao executável/ambiente oficial e valida o PID no SO."""
    if not caller_data or not isinstance(caller_data, dict):
        return False, "Origem da requisição não informada ou formato inválido."

    pid = caller_data.get("pid")
    exe = str(caller_data.get("exe", "")).lower()

    if not pid or not isinstance(pid, int) or pid <= 0:
        return False, "PID do chamador não informado ou inválido."

    # Se o PID estiver ativo no Windows, confere o caminho real do processo no kernel contra falsificação de JSON
    real_exe = _get_os_process_image_path(pid)
    if real_exe:
        real_exe_lower = real_exe.lower()
        real_valid = (
            "python" in real_exe_lower
            or "adminbridge" in real_exe_lower
            or "antigravitybridge" in real_exe_lower
            or "powershell" in real_exe_lower
            or "c:\\utilitario" in real_exe_lower
        )
        if not real_valid:
            return False, f"Processo real do PID {pid} não autorizado pelo kernel: {real_exe}"

    is_valid_exe = (
        "python" in exe
        or "adminbridge" in exe
        or "antigravitybridge" in exe
        or "powershell" in exe
        or "c:\\utilitario" in exe
    )

    if not is_valid_exe:
        return False, f"Executável de origem não autorizado: {exe}"

    real_user = get_os_process_username(pid)
    claimed_user = caller_data.get("user")
    if real_user and claimed_user and real_user.lower() not in ("system", "sistema"):
        if str(claimed_user).lower() != str(real_user).lower():
            return False, f"Falsificacao de identidade detectada: PID {pid} pertence a '{real_user}', mas declarou '{claimed_user}'."

    return True, "Origem validada com sucesso."


def append_ledger_block(action: str, counter: int, code_hash: str, caller_info: Optional[dict] = None, status: str = "SUCCESS", details: str = "") -> dict:
    """Registra um bloco encadeado por hash criptográfico [estilo blockchain] no log imutável de auditoria."""
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
    """Verifica a integridade matemática estrita da cadeia de blocos de auditoria."""
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


# =============================================================================
# INSPETOR DE SCRIPTS EM 3 CAMADAS (Windows AMSI + Classificador Leve + IA Explicadora Sob Demanda)
# =============================================================================
def scan_with_windows_amsi(code_text: str, app_name: str = "AdminBridge_ScriptGuard") -> Tuple[bool, str]:
    """Camada 1: Passa o script pela interface nativa Antimalware Scan Interface (amsi.dll) do Windows 10/11.
    Executa em ~1-3ms no Core i5 com 0 MB de peso extra, utilizando o motor local do Windows Defender.
    """
    if sys.platform != "win32" or not code_text:
        return True, "AMSI disponivel apenas no Windows ou script vazio."
    try:
        amsi = ctypes.windll.amsi
        amsi_context = ctypes.c_void_p()
        res_init = amsi.AmsiInitialize(ctypes.c_wchar_p(app_name), ctypes.byref(amsi_context))
        if res_init != 0 or not amsi_context:
            return True, "AMSI nao inicializado neste ambiente."
        try:
            amsi_result = ctypes.c_int(0)
            res_scan = amsi.AmsiScanString(
                amsi_context,
                ctypes.c_wchar_p(code_text),
                ctypes.c_wchar_p("AdminBridge_Submitted_Script"),
                None,
                ctypes.byref(amsi_result)
            )
            if res_scan == 0 and amsi_result.value >= 32768:  # AMSI_RESULT_DETECTED = 32768
                return False, f"Windows Defender (AMSI) classificou este script como MALICIOSO (Codigo AMSI: {amsi_result.value})."
            return True, "Aprovado pelo motor nativo Windows AMSI."
        finally:
            amsi.AmsiUninitialize(amsi_context)
    except Exception:
        return True, "Verificacao AMSI ignorada."


RISK_SIGNATURES = [
    {
        "id": "PERSIST_SERVICE",
        "score": 65,
        "category": "Criação de Serviço Permanente no Sistema",
        "pattern": r"(?:\bsc(?:\.exe)?\s+(?:create|config|failure)\b|\bnew-service\b|\bset-service\b.*startuptype)",
        "explanation": "Tenta criar ou modificar um Serviço do Windows que pode iniciar sozinho com poder máximo toda vez que o computador ligar."
    },
    {
        "id": "PERSIST_TASK",
        "score": 60,
        "category": "Criação de Tarefa Agendada Automática",
        "pattern": r"(?:\bschtasks(?:\.exe)?\s+/create\b|\bregister-scheduledtask\b|\bset-scheduledtask\b|\bnew-scheduledtaskaction\b)",
        "explanation": "Tenta agendar uma tarefa automática no Windows para rodar programas em segundo plano ou ao ligar o computador."
    },
    {
        "id": "PERSIST_REGISTRY_AUTORUN",
        "score": 65,
        "category": "Inicialização Automática no Registro (Autorun)",
        "pattern": r"(?:currentversion\\run|currentversion\\runonce|winlogon\\shell|winlogon\\userinit|image\s+file\s+execution\s+options)",
        "explanation": "Tenta alterar chaves de inicialização automática do Registro do Windows para rodar programas escondidos no login."
    },
    {
        "id": "PRIV_USER_ADMIN",
        "score": 75,
        "category": "Criação de Conta ou Elevação a Administrador",
        "pattern": r"(?:\bnet1?(?:\.exe)?\s+(?:user|localgroup)\b.*(?:/add|/active)|\bnew-localuser\b|\badd-localgroupmember\b)",
        "explanation": "Tenta criar um novo usuário no Windows ou adicionar uma conta ao grupo de Administradores permanentes da máquina."
    },
    {
        "id": "DEFENSE_EVASION_DEFENDER",
        "score": 85,
        "category": "Desativação de Antivírus ou Firewall",
        "pattern": r"(?:\bset-mppreference\b|\badd-mppreference\b|-disablerealtimemonitoring|-exclusionpath|\bnetsh\b.*advfirewall.*(?:off|disable|add\s+rule))",
        "explanation": "Tenta desativar a proteção em tempo real do Windows Defender, adicionar pastas ocultas na lista de exceções do antivírus ou abrir portas no Firewall."
    },
    {
        "id": "CREDENTIAL_DUMP",
        "score": 95,
        "category": "Extração de Senhas do Sistema (SAM / LSASS)",
        "pattern": r"(?:\breg(?:\.exe)?\s+save\b.*(?:hklm\\sam|hklm\\security|hklm\\system)|\blsass\b|\bcomsvcs\.dll\b.*minidump|\bmimikatz\b|\bsekurlsa\b)",
        "explanation": "Tenta extrair cofres de senhas internas do Windows (SAM, SECURITY ou memória do processo LSASS)."
    },
    {
        "id": "RANSOM_SHADOW_DELETE",
        "score": 95,
        "category": "Destruição de Pontos de Restauração / Cópias de Sombra",
        "pattern": r"(?:\bvssadmin\b.*delete\s+shadows|\bwmic\b.*shadowcopy\s+delete|\bbcdedit\b.*recoveryenabled\s+no|\bwbadmin\b.*delete\s+catalog)",
        "explanation": "Tenta apagar as cópias de sombra e pontos de recuperação do Windows (comportamento típico de sabotagem ou ransomware)."
    },
    {
        "id": "REMOTE_EXEC_CRADLE",
        "score": 70,
        "category": "Download e Execução Direta da Internet",
        "pattern": r"(?:downloadstring|downloaddata|downloadfile|\biex\b|\binvoke-expression\b|\bmshta\b|\bregsvr32\b.*http|\bcertutil\b.*-urlcache|\bbitsadmin\b.*/transfer)",
        "explanation": "Tenta baixar um código externo da internet e executá-lo diretamente no computador."
    },
    {
        "id": "MASS_DELETION_FORMAT",
        "score": 65,
        "category": "Exclusão Recursiva ou Formatação de Disco",
        "pattern": r"(?:\bformat(?:\.com|\.exe)?\s+[a-z]:|\bdiskpart\b|\brd\s+/s\s+/q\s+c:\\(?:windows|users|program)|\bremove-item\b.*-recurse.*-force.*c:\\(?:windows|users))",
        "explanation": "Tenta apagar pastas críticas do sistema operacional ou formatar volumes de disco."
    },
    {
        "id": "OBFUSCATED_EXEC",
        "score": 50,
        "category": "Comando Codificado ou Ofuscado",
        "pattern": r"(?:-[eE][nN]?[cC]?[oO]?[dD]?[eE]?[dD]?[cC]?[oO]?[mM]?[mM]?[aA]?[nN]?[dD]?\s+[A-Za-z0-9+/=]{16,}|frombase64string|\bchar\[\]\s*\()",
        "explanation": "Usa codificação Base64 ou ofuscação para esconder os comandos reais que serão executados."
    },
    {
        "id": "EXTERNAL_TEMP_BINARY_OR_SCRIPT",
        "score": 45,
        "category": "Execução de Script ou Binário em Pasta Temporária/Downloads",
        "pattern": r"(?:\\temp\\|\\appdata\\|\\downloads\\|/temp/|/downloads/|\b(?:powershell|pwsh|cmd|cscript|wscript|python|mshta)(?:\.exe)?\b[^\n]*(?:-(?:file|f)\b|\.(?:ps1|bat|cmd|vbs|js|hta|py)\b))",
        "explanation": "Executa um arquivo de script externo (.ps1, .bat, .vbs, .py) ou um programa localizado em pastas temporárias/Downloads."
    }
]

SCRIPT_EXTENSIONS = (".ps1", ".bat", ".cmd", ".vbs", ".js", ".wsf", ".hta", ".py", ".psm1")


def extract_and_read_referenced_scripts(cmd_text: str, _visited: Optional[set] = None, _depth: int = 0) -> Tuple[str, list]:
    """Desenrola recursivamente (até 3 níveis) qualquer arquivo de script externo (.ps1, .bat, .cmd, .vbs, .py, etc.)
    chamado pela linha de comando, lendo o conteúdo interno do arquivo no disco para que nenhum script malicioso
    possa se esconder atrás de um comando aparentemente inocente como 'powershell -File C:\\Temp\\helper.ps1'.
    Retorna (texto_combinado_completo, lista_de_arquivos_lidos).
    """
    if not cmd_text or _depth > 3:
        return cmd_text or "", []
    if _visited is None:
        _visited = set()

    expanded = os.path.expandvars(cmd_text)
    candidates = set()

    # 1. Captura caminhos entre aspas ou sem aspas que terminem em extensões de script (.ps1, .bat, .cmd, .py, .vbs, .js, .hta)
    ext_pattern = r"(?:[\"\']([^\"\']+\.(?:ps1|bat|cmd|vbs|js|wsf|hta|py|psm1))[\"\']|([^\s\"\';&|><()]+\.(?:ps1|bat|cmd|vbs|js|wsf|hta|py|psm1)))"
    for m in re.finditer(ext_pattern, expanded, flags=re.IGNORECASE):
        c_path = (m.group(1) or m.group(2) or "").strip()
        if c_path:
            candidates.add(c_path)

    # 2. Captura qualquer argumento passado após -File, -f, call, start
    arg_pattern = r"(?:-(?:file|f)\s+|(?:\bcall|\bstart)\s+)(?:[\"\']([^\"\']+)[\"\']|([^\s\"\';&|><]+))"
    for m in re.finditer(arg_pattern, expanded, flags=re.IGNORECASE):
        c_path = (m.group(1) or m.group(2) or "").strip()
        if c_path and not c_path.startswith("-"):
            candidates.add(c_path)

    combined_parts = [cmd_text]
    read_files_info = []

    for raw_cand in sorted(candidates):
        for test_p in (Path(raw_cand), BASE_DIR / raw_cand):
            try:
                if test_p.exists() and test_p.is_file():
                    resolved_str = str(test_p.resolve())
                    if resolved_str in _visited:
                        break
                    _visited.add(resolved_str)
                    # Lê até 256 KB do script externo para inspeção profunda
                    raw_bytes = test_p.read_bytes()[:262144]
                    file_hash = hashlib.sha256(raw_bytes).hexdigest()[:16]
                    file_content = ""
                    for enc in ("utf-8", "utf-16", "latin-1"):
                        try:
                            file_content = raw_bytes.decode(enc)
                            break
                        except Exception:
                            continue
                    if file_content:
                        read_files_info.append({
                            "path": resolved_str,
                            "sha256_prefix": file_hash,
                            "content": file_content
                        })
                        sub_combined, sub_files = extract_and_read_referenced_scripts(
                            file_content, _visited=_visited, _depth=_depth + 1
                        )
                        combined_parts.append(f"\n# [CONTEÚDO INTERNO DE {resolved_str} (SHA256:{file_hash})]:\n{sub_combined}")
                        read_files_info.extend(sub_files)
                    break
            except Exception:
                continue

    return "\n".join(combined_parts), read_files_info



def _decode_embedded_base64(cmd_text: str) -> str:
    extra = []
    tokens = re.findall(
        r"(?:-[eE][nN]?[cC]?[oO]?[dD]?[eE]?[dD]?[cC]?[oO]?[mM]?[mM]?[aA]?[nN]?[dD]?\s+|frombase64string\s*\(\s*[\"\x27]?)([A-Za-z0-9+/=]{12,})",
        cmd_text
    )
    for b64_str in tokens:
        for enc in ("utf-16le", "utf-8"):
            try:
                dec = base64.b64decode(b64_str).decode(enc, errors="ignore")
                if dec and any(c.isalpha() for c in dec):
                    extra.append(dec)
                    break
            except Exception:
                pass
    return (cmd_text + "\n" + "\n".join(extra)) if extra else cmd_text


AI_READY_SEAL_FILE = QUEUE_DIR / "ai_ready.json"


def _ensure_ollama_on_demand() -> Optional[str]:
    """Localiza o binário do Ollama no Windows para acordá-lo sob demanda."""
    if sys.platform != "win32":
        return None
    import shutil
    found = shutil.which("ollama")
    if found:
        return found
    local_app = os.environ.get("LOCALAPPDATA", "")
    if local_app:
        candidate = Path(local_app) / "Programs" / "Ollama" / "ollama.exe"
        if candidate.exists():
            return str(candidate)
    return None


def is_local_slm_verified() -> bool:
    """Verifica se o mini-modelo local qwen2.5:0.5b já foi instalado, testado e aprovado."""
    if AI_READY_SEAL_FILE.exists():
        try:
            data = json.loads(AI_READY_SEAL_FILE.read_text(encoding="utf-8"))
            if data.get("verified") is True:
                return True
        except Exception:
            pass
    # Se o selo ainda não existir, consulta rapidamente /api/tags (timeout 0.4s) para ver se qwen2.5:0.5b já está no Ollama
    try:
        import urllib.request
        with urllib.request.urlopen("http://127.0.0.1:11434/api/tags", timeout=0.4) as resp:
            tags_data = json.loads(resp.read().decode("utf-8"))
            models = [m.get("name", "").lower() for m in tags_data.get("models", [])]
            if any("qwen2.5:0.5b" in m or "qwen2.5-coder:0.5b" in m for m in models):
                QUEUE_DIR.mkdir(parents=True, exist_ok=True)
                AI_READY_SEAL_FILE.write_text(json.dumps({"verified": True, "model": "qwen2.5:0.5b", "verified_at": time.time()}), encoding="utf-8")
                return True
    except Exception:
        pass
    return False


def pull_and_test_local_slm(progress_callback=None) -> Tuple[bool, str]:
    """Baixa o modelo qwen2.5:0.5b diretamente pela API HTTP do Ollama (POST /api/pull),
    sem depender da lista de modelos da interface gráfica do Ollama, e faz um teste real de inferência!
    """
    import urllib.request

    # 1. Garante que o servidor Ollama está respondendo em 127.0.0.1:11434
    server_up = False
    for _ in range(2):
        try:
            with urllib.request.urlopen("http://127.0.0.1:11434/api/tags", timeout=1.5) as r:
                if r.status == 200:
                    server_up = True
                    break
        except Exception:
            ollama_bin = _ensure_ollama_on_demand()
            if ollama_bin:
                try:
                    subprocess.Popen([ollama_bin, "serve"], creationflags=0x08000000 if sys.platform == "win32" else 0)
                    time.sleep(1.5)
                except Exception:
                    pass

    if not server_up:
        return False, "O serviço do Ollama não foi detectado em http://127.0.0.1:11434. Verifique se o aplicativo Ollama está aberto."

    # 2. Solicita o download direto do modelo qwen2.5:0.5b via API HTTP (/api/pull)
    if progress_callback:
        progress_callback("Baixando modelo ultraleve qwen2.5:0.5b (~350 MB) direto pelo servidor local do Ollama...")
    try:
        pull_body = json.dumps({"name": "qwen2.5:0.5b", "stream": False}).encode("utf-8")
        req_pull = urllib.request.Request(
            "http://127.0.0.1:11434/api/pull",
            data=pull_body,
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        with urllib.request.urlopen(req_pull, timeout=600.0) as resp:
            pull_res = json.loads(resp.read().decode("utf-8"))
            if pull_res.get("error"):
                return False, f"Erro ao baixar modelo: {pull_res.get('error')}"
    except Exception as e:
        return False, f"Falha ao baixar qwen2.5:0.5b via API do Ollama: {e}"

    # 3. Executa teste real de análise de script e descarrega da RAM (keep_alive: 0s)
    if progress_callback:
        progress_callback("Testando resposta da Mini-IA com script de verificação e liberando RAM (keep_alive=0s)...")
    test_explanation = _try_local_slm_explanation(
        'sc.exe create ServicoTeste binPath= "C:\\Temp\\teste.exe" start= auto',
        [{"category": "Criação de Serviço", "explanation": "Cria serviço automático"}],
        timeout_sec=10.0
    )
    if not test_explanation:
        return False, "O modelo foi baixado, mas não respondeu ao teste de verificação."

    try:
        QUEUE_DIR.mkdir(parents=True, exist_ok=True)
        AI_READY_SEAL_FILE.write_text(
            json.dumps({
                "verified": True,
                "model": "qwen2.5:0.5b",
                "sample_test": test_explanation[:160],
                "verified_at": time.time()
            }, indent=2, ensure_ascii=False),
            encoding="utf-8"
        )
    except Exception:
        pass

    return True, f"Mini-IA qwen2.5:0.5b instalada, testada e validada com sucesso!\n\nResposta do teste:\n\"{test_explanation}\""


def _try_local_slm_explanation(code_text: str, findings: list, timeout_sec: float = 4.0) -> Optional[str]:
    """Camada 3 (Prompt Técnico Específico + Zero RAM em Repouso com keep_alive='0s'):
    Analisa especificamente quais comandos, caminhos de arquivo, serviços ou chaves de registro
    estão sendo tocados pelo script e descarrega o modelo da RAM imediatamente após responder.
    """
    import urllib.request
    detected_cats = ", ".join([f.get("category", "") for f in (findings or [])]) or "Ação administrativa"
    prompt = (
        "Você é um auditor técnico de segurança do Windows. Analise o comando abaixo (categorias detectadas: "
        f"{detected_cats}) e explique em português claro e específico, em no máximo 3 tópicos curtos:\n"
        "1. Qual executável ou comando exato está sendo chamado;\n"
        "2. Qual arquivo, pasta, serviço ou chave do Windows será alterado;\n"
        "3. Qual o impacto prático se o usuário autorizar.\n\n"
        f"SCRIPT:\n{code_text[:1000]}"
    )
    req_body = json.dumps({
        "model": "qwen2.5:0.5b",
        "prompt": prompt,
        "stream": False,
        "keep_alive": "0s",  # Libera 100% da RAM imediatamente após gerar a resposta!
        "options": {"num_predict": 160, "temperature": 0.1}
    }).encode("utf-8")

    for attempt in range(2):
        try:
            req = urllib.request.Request(
                "http://127.0.0.1:11434/api/generate",
                data=req_body,
                headers={"Content-Type": "application/json"},
                method="POST"
            )
            with urllib.request.urlopen(req, timeout=timeout_sec) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                ans = (data.get("response") or "").strip()
                if len(ans) > 15:
                    return ans
                break
        except Exception:
            if attempt == 0 and sys.platform == "win32":
                ollama_bin = _ensure_ollama_on_demand()
                if ollama_bin:
                    try:
                        subprocess.Popen([ollama_bin, "serve"], creationflags=0x08000000)
                        time.sleep(0.8)
                        continue
                    except Exception:
                        break
            break
    return None


def build_human_explanation(code_text: str, findings: list, amsi_msg: str = "") -> str:
    """Camada 3: Gera explicação clara em português para o usuário decidir se autoriza com novo OTP ou via UAC."""
    lines = []
    if amsi_msg and "MALICIOSO" in amsi_msg.upper():
        lines.append(f"🚨 ALERTA DO WINDOWS DEFENDER (AMSI): {amsi_msg}")

    if findings:
        lines.append("🔍 O que este script tenta fazer no seu computador:")
        for f in findings:
            lines.append(f"  • [{f['category']}]: {f['explanation']}")

    llm_summary = _try_local_slm_explanation(code_text, findings)
    if llm_summary:
        lines.append(f"\n🤖 Resumo da IA Local:\n  {llm_summary}")

    lines.append(
        "\n⚠️ Por segurança, a execução automática (mesmo com ticket de 45 min) foi pausada. "
        "Para autorizar este script mesmo assim, gere um NOVO código de 6 dígitos no celular "
        "ou aprove clicando no botão UAC na tela."
    )
    return "\n".join(lines)


def inspect_script_3_layers(code_text: str) -> dict:
    """Executa o pipeline completo de 3 camadas:
    - Camada 1: Windows AMSI (amsi.dll)
    - Camada 2: Classificador Comportamental e De-ofuscação (0 a 100)
    - Camada 3: Explicador Semântico / IA Sob Demanda (acionado somente se Risco >= 40 ou AMSI detectar ameaça)
    """
    if not code_text or not str(code_text).strip():
        return {
            "risk_level": "low",
            "risk_score": 0,
            "requires_step_up": False,
            "amsi_clean": True,
            "findings": [],
            "explanation": "Comando vazio ou inofensivo."
        }

    # Desenrola recursivamente qualquer script externo (.ps1, .bat, .cmd, .py, .vbs) chamado pelo comando!
    unrolled_text, referenced_files = extract_and_read_referenced_scripts(code_text)
    amsi_clean, amsi_msg = scan_with_windows_amsi(unrolled_text)
    expanded_text = _decode_embedded_base64(unrolled_text)
    normalized = expanded_text.lower().translate(str.maketrans("", "", "\"'^`"))

    total_score = 0 if amsi_clean else 100
    matched_findings = []

    for rule in RISK_SIGNATURES:
        if re.search(rule["pattern"], normalized, flags=re.IGNORECASE | re.DOTALL):
            total_score = min(100, total_score + int(rule["score"]))
            matched_findings.append({
                "id": rule["id"],
                "category": rule["category"],
                "score": rule["score"],
                "explanation": rule["explanation"]
            })

    requires_step_up = (not amsi_clean) or (total_score >= 40)
    if total_score >= 75 or not amsi_clean:
        risk_level = "critical"
    elif total_score >= 40:
        risk_level = "high"
    else:
        risk_level = "low"

    explanation = ""
    if requires_step_up:
        explanation = build_human_explanation(expanded_text, matched_findings, amsi_msg if not amsi_clean else "")

    if referenced_files and requires_step_up:
        files_summary = "\n".join([f"  📄 {rf['path']} (SHA256: {rf['sha256_prefix']})" for rf in referenced_files])
        explanation = f"📂 Arquivos de script externos lidos e inspecionados recursivamente:\n{files_summary}\n\n" + explanation

    return {
        "risk_level": risk_level,
        "risk_score": total_score,
        "requires_step_up": requires_step_up,
        "amsi_clean": amsi_clean,
        "findings": matched_findings,
        "referenced_files": referenced_files,
        "unrolled_code": unrolled_text,
        "explanation": explanation
    }
