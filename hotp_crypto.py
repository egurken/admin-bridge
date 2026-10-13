import base64
import ctypes
import hashlib
import hmac
import msvcrt
import os
import secrets
import subprocess
import sys
import threading
import time
from ctypes import wintypes
from pathlib import Path
from typing import Optional, Tuple

BASE_DIR = Path("C:/Utilitario")
CONFIG_DIR = BASE_DIR / "config"
LOCK_FILE = CONFIG_DIR / "hotp.lock"

# DPAPI Structures & Functions
class DATA_BLOB(ctypes.Structure):
    _fields_ = [
        ("cbData", wintypes.DWORD),
        ("pbData", ctypes.POINTER(ctypes.c_byte))
    ]

crypt32 = ctypes.windll.crypt32
kernel32 = ctypes.windll.kernel32

DPAPI_ENTROPY = b"AntigravityBridge_TPM_DPAPI_Entropy_2026"
CRYPTPROTECT_UI_FORBIDDEN = 0x1


def wipe_buffer(buf):
    """Sobrescreve buffers de memória com zeros para higiene estrita de memória."""
    if buf is None:
        return
    if isinstance(buf, bytearray):
        for i in range(len(buf)):
            buf[i] = 0


def dpapi_protect(plaintext: bytes, entropy: bytes = DPAPI_ENTROPY) -> bytes:
    """Criptografa dados usando a DPAPI do Windows (vinculada ao usuário e TPM da máquina).

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
        CRYPTPROTECT_UI_FORBIDDEN,
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


def hash_recovery_password(password: str, salt: Optional[bytes] = None) -> Tuple[str, str]:
    """Gera hash seguro PBKDF2-HMAC-SHA256 para a senha de recuperação (600.000 iterações)."""
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


def apply_strict_acls(target_path: Path):
    """Aplica permissões ACL restritas no arquivo ou pasta via comando nativo icacls:

    Remove qualquer herança de permissões (/inheritance:r) e concede acesso exclusivo a
    SYSTEM (*S-1-5-18), grupo de Administradores locais (*S-1-5-32-544) e usuário ativo.
    """
    if not target_path.exists():
        return
    username = os.getenv("USERNAME", "")
    is_dir = target_path.is_dir()
    perm_system = "*S-1-5-18:(OI)(CI)(F)" if is_dir else "*S-1-5-18:(F)"
    perm_admin = "*S-1-5-32-544:(OI)(CI)(F)" if is_dir else "*S-1-5-32-544:(F)"
    perm_user = f'"{username}":(OI)(CI)(M)' if is_dir else f'"{username}":(M)'

    cmd = f'icacls "{target_path}" /inheritance:r /grant:r {perm_system} /grant:r {perm_admin} '
    if username:
        cmd += f'/grant:r {perm_user} '

    try:
        subprocess.run(
            ["cmd.exe", "/c", cmd],
            capture_output=True,
            check=False,
            creationflags=0x08000000  # CREATE_NO_WINDOW
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
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
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

    # Verifica se o executável do chamador é o Python oficial da máquina ou o binário do Utilitário
    is_valid_exe = (
        "python" in exe
        or "antigravity" in exe
        or "powershell" in exe
        or "c:\\utilitario" in exe
    )

    if not is_valid_exe:
        return False, f"Executável de origem não autorizado: {exe}"

    return True, "Origem validada com sucesso."
