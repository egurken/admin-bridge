import argparse
import base64
import ctypes
from ctypes import wintypes
import gc
import io
import json
import logging
import os
from pathlib import Path
import hashlib
import hmac
import secrets
import shutil
import subprocess
import sys
import threading
import time
import uuid
from datetime import datetime, timezone
from typing import Optional, Tuple, Callable, List, Dict, Any

import re
try:
    import qrcode
except ImportError:
    qrcode = None

try:
    from PyQt6.QtCore import Qt, QTimer, QThread, pyqtSignal
    from PyQt6.QtGui import QFont, QIcon, QColor, QPalette, QCursor, QAction, QPixmap
    from PyQt6.QtNetwork import QLocalServer, QLocalSocket
    from PyQt6.QtWidgets import (
        QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
        QLabel, QPushButton, QPlainTextEdit, QFrame, QSystemTrayIcon,
        QMenu, QMessageBox, QDialog, QLineEdit, QTableWidget, QTableWidgetItem,
        QHeaderView, QAbstractItemView, QInputDialog, QGridLayout, QLayout,
        QProgressBar, QSizePolicy
    )
    from app_icon import get_app_icon
except ImportError:
    Qt = QTimer = QFont = QIcon = QColor = QPalette = QCursor = QAction = QPixmap = None
    QLocalServer = QLocalSocket = None
    QApplication = QWidget = QVBoxLayout = QHBoxLayout = QLabel = QPushButton = None
    QPlainTextEdit = QFrame = QSystemTrayIcon = QMenu = QMessageBox = QLineEdit = None
    QTableWidget = QTableWidgetItem = QHeaderView = QAbstractItemView = QInputDialog = None
    QGridLayout = QLayout = QProgressBar = QSizePolicy = None
    class QThread:
        pass
    class QDialog:
        pass
    class QMainWindow:
        pass
    def pyqtSignal(*args, **kwargs):
        return None
    def get_app_icon():
        return None

from hotp_auth import HOTPAuth, SecurityError, PREAUTH_TICKET_FILE
from hotp_crypto import (
    wipe_buffer, apply_isolated_bridge_ntfs_acls, apply_system_only_ntfs_acls, restore_ntfs_acls_for_removal,
    verify_caller_origin, generate_physical_challenge, read_passive_metadata, check_forensic_integrity,
    configure_anti_dump_mitigations, harden_process_dacl, append_ledger_block, verify_ledger_integrity,
    check_config_acl_isolation, protect_transit_token, unprotect_transit_token, verify_owner_anchor,
    KernelFileGuard, verify_scheduled_task_integrity, get_os_process_username, ensure_transit_keypair,
    inspect_script_3_layers, extract_and_read_referenced_scripts,
    clear_integrity_caches, is_local_slm_verified, pull_and_test_local_slm,
    get_password_lockout_status, record_password_failure, reset_password_lockout, format_lockout_duration
)

LOCAL_SERVER_NAME = f"AdminBridge_GUI_{os.getenv('USERNAME', 'default')}"
BASE_DIR = Path("C:/Utilitario")
CONFIG_DIR = BASE_DIR / "config"
QUEUE_DIR = BASE_DIR / "queue"
REQUESTS_DIR = QUEUE_DIR / "requests"
PROCESSING_DIR = QUEUE_DIR / "processing"
GUI_PENDING_DIR = QUEUE_DIR / "gui_pending"
RESPONSES_DIR = QUEUE_DIR / "responses"
SCRIPTS_DIR = BASE_DIR / "scripts"
LOGS_DIR = BASE_DIR / "logs"
HEARTBEAT_FILE = QUEUE_DIR / "heartbeat.json"
STATUS_FILE = QUEUE_DIR / "status.json"
CONFIG_FILE = CONFIG_DIR / "hotp_config.json"
AUTH_LOG_FILE = LOGS_DIR / "auth.log"

root_logger = logging.getLogger()
root_logger.setLevel(logging.INFO)
try:
    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    file_handler = logging.FileHandler(str(LOGS_DIR / "app.log"), encoding="utf-8")
    file_handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
    root_logger.addHandler(file_handler)
except Exception:
    pass

debug_log_path = Path(os.environ.get("TEMP", ".")) / "adminbridge_debug.log"
def _debug_log(msg: str):
    try:
        with open(debug_log_path, "a", encoding="utf-8") as f:
            f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] [PID:{os.getpid()}] {msg}\n")
    except Exception:
        pass

def _global_excepthook(exc_type, exc_value, exc_tb):
    import traceback
    tb = "".join(traceback.format_exception(exc_type, exc_value, exc_tb))
    _debug_log(f"CRITICAL UNCAUGHT EXCEPTION:\n{tb}")
    if sys.__excepthook__:
        sys.__excepthook__(exc_type, exc_value, exc_tb)

sys.excepthook = _global_excepthook

if sys.stdout is not None:
    try:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
        root_logger.addHandler(console_handler)
    except Exception:
        pass



def is_admin() -> bool:
    """Verifica se o processo atual possui privilégios de Administrador."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def request_elevation():
    """Dispara elevação de privilégios nativa via prompt UAC do Windows (runas)."""
    executable = sys.executable
    args = " ".join([f'"{a}"' for a in sys.argv[1:]])
    ret = ctypes.windll.shell32.ShellExecuteW(
        None,
        "runas",
        executable,
        args,
        str(Path(executable).parent),
        1
    )
    if ret > 32:
        sys.exit(0)
    else:
        raise PermissionError("Elevação de privilégios UAC foi recusada pelo usuário.")


def request_elevation_with_args(extra_args: list):
    """Dispara elevação de privilégios nativa via prompt UAC com argumentos específicos."""
    executable = sys.executable
    args = " ".join([f'"{a}"' for a in extra_args])
    ret = ctypes.windll.shell32.ShellExecuteW(
        None,
        "runas",
        executable,
        args,
        str(Path(executable).parent),
        1
    )
    if ret > 32:
        sys.exit(0)
    else:
        raise PermissionError("Elevação de privilégios UAC foi recusada pelo usuário.")


def get_desktop_dir() -> Optional[Path]:
    """Obtém o diretório real da Área de Trabalho do usuário (suportando redirecionamentos do OneDrive)."""
    try:
        buf = ctypes.create_unicode_buffer(wintypes.MAX_PATH)
        if ctypes.windll.shell32.SHGetFolderPathW(None, 0, None, 0, buf) == 0 and buf.value:
            p = Path(buf.value)
            if p.exists():
                return p
    except Exception:
        pass
    userprofile = os.environ.get("USERPROFILE")
    if userprofile:
        p = Path(userprofile) / "Desktop"
        if p.exists():
            return p
    return None


def create_desktop_shortcut():
    """Remove atalhos legados .lnk sem lentidão de subprocessos PowerShell."""
    try:
        desktops_to_clean = []
        user_desktop = get_desktop_dir()
        if user_desktop:
            desktops_to_clean.append(user_desktop)
        pub_desktop = Path(os.environ.get("PUBLIC", "C:/Users/Public")) / "Desktop"
        if pub_desktop.exists() and pub_desktop not in desktops_to_clean:
            desktops_to_clean.append(pub_desktop)

        for d in desktops_to_clean:
            for old_lnk in ["Admin Bridge.lnk", "Antigravity Bridge.lnk", "Antigravity Admin Bridge.lnk", "Configurar Antigravity Bridge.lnk"]:
                try:
                    (d / old_lnk).unlink(missing_ok=True)
                except Exception:
                    pass
    except Exception:
        pass


def ensure_environment_installed():
    """Garante a estrutura de diretórios sem falhar quando executado por usuário padrão não-elevado."""
    if not is_admin():
        # Usuário comum não deve tentar criar/modificar pastas restritas para não sofrer PermissionError
        for pub_d in (RESPONSES_DIR, GUI_PENDING_DIR):
            try:
                pub_d.mkdir(parents=True, exist_ok=True)
            except Exception:
                pass
        create_desktop_shortcut()
        return

    for d in (BASE_DIR, CONFIG_DIR, LOGS_DIR, QUEUE_DIR, REQUESTS_DIR, PROCESSING_DIR, GUI_PENDING_DIR, RESPONSES_DIR, SCRIPTS_DIR):
        try:
            d.mkdir(parents=True, exist_ok=True)
        except Exception:
            pass

    try:
        (BASE_DIR / "runner.ps1").unlink(missing_ok=True)
    except Exception:
        pass

    target_exe = (BASE_DIR / "AdminBridge.exe").resolve()
    current_exe = Path(sys.executable).resolve()
    # Apenas permite instalar/copiar o executável se for Administrador E ainda não estiver provisionado/ancorado
    if getattr(sys, "frozen", False) and current_exe != target_exe and is_admin() and not CONFIG_FILE.exists():
        try:
            shutil.copy2(str(current_exe), str(target_exe))
        except Exception as e:
            logging.warning(f"Aviso ao copiar executavel para C:\\Utilitario: {e}")

    # Aplica permissoes restritas se .acl_seal nao existir ou se check_config_acl_isolation detectar heranca aberta
    if is_admin() and (not (CONFIG_DIR / ".acl_seal").exists() or not check_config_acl_isolation(BASE_DIR)):
        try:
            apply_isolated_bridge_ntfs_acls(BASE_DIR)
        except Exception:
            pass

    create_desktop_shortcut()


def is_self_targeting_command(cmd_text: str, _depth: int = 0) -> bool:
    r"""Verifica se uma linha de comando tenta inspecionar, alterar ou afetar a pasta C:\Utilitario, seus arquivos, tarefas ou processos.
    Inclui resolução de variáveis inline (%VAR% e $var), colapso de concatenação de strings (+ / Join-Path), curingas e Base64.
    """
    if not cmd_text or _depth > 3:
        return False

    raw = cmd_text.lower()

    # 1. Resolve variáveis definidas na própria linha de comando (ex: set X=Utilitario && dir C:\%X%)
    for m_var in re.finditer(r"\bset\s+([a-z0-9_]+)\s*=\s*([^\s&|;\"']+)", raw):
        v_name, v_val = m_var.group(1), m_var.group(2)
        raw = raw.replace(f"%{v_name}%", v_val).replace(f"!{v_name}!", v_val)

    # 2. Remove operadores de concatenação entre strings (ex: 'C:\' + 'Utili' + 'tario' -> 'c:\utilitario')
    collapsed = re.sub(r"[\"\']\s*\+\s*[\"\']", "", raw)
    deobfuscated = re.sub(r"[\"\'\^`+()]", "", collapsed)

    # 3. Alvos diretos, arquivos internos e nomes de tarefas/serviços
    forbidden_targets = [
        "c:\\utilitario",
        "c:/utilitario",
        "\\utilitario",
        "/utilitario",
        "utilit~1",
        "adminbridge.exe",
        "antigravitybridge.exe",
        "adminbridge",
        "antigravityadminbridge",
        "hotp_config",
        "owner_anchor",
        "preauth_ticket",
        "hw_salt",
        "transit_priv",
        "canary.bin",
        "ledger.jsonl",
        "ledger.anchor",
        "system32\\tasks\\admin",
        "system32/tasks/admin",
        "taskcache\\tree\\admin",
        "taskcache/tree/admin",
        "join-path",
    ]

    # 4. Padrões regex para curingas (C:\U*, cd Ut*, Admin*, WMI like 'Admin%', Stop-Process/taskkill/schtasks com Admin*)
    forbidden_regexes = [
        r"c:[\\/]+u[a-z0-9*?~]*",
        r"\bcd\s+ut[a-z0-9*?~]*",
        r"(?:^|[\s;&|><(])(config|queue|scripts)[\\/]",
        r"\b(?:schtasks|taskkill|get-process|stop-process|wmic)\b[^\n]*\badmin[a-z0-9*?%]*",
        r"\bname\s+like\s+[\"\'\s]*admin",
        r"taskcache[\\/]+tree[\\/]+admin",
    ]

    for candidate in (raw, collapsed, deobfuscated):
        for target in forbidden_targets:
            if target in candidate:
                return True
        for rx in forbidden_regexes:
            if re.search(rx, candidate):
                return True

    # 5. Desofuscação de comandos PowerShell codificados em Base64 (-e, -en, -enc, -encodedcommand, FromBase64String)
    b64_tokens = re.findall(
        r"(?:-[eE][nN]?[cC]?[oO]?[dD]?[eE]?[dD]?[cC]?[oO]?[mM]?[mM]?[aA]?[nN]?[dD]?\s+|frombase64string\s*\(\s*[\"\']?)([A-Za-z0-9+/=]{12,})",
        cmd_text
    )
    for b64_str in b64_tokens:
        for enc_name in ("utf-16le", "utf-8", "latin-1"):
            try:
                decoded_bytes = base64.b64decode(b64_str)
                decoded_str = decoded_bytes.decode(enc_name, errors="ignore")
                if is_self_targeting_command(decoded_str, _depth + 1):
                    return True
            except Exception:
                pass

    # 6. Se o comando chama um arquivo de script externo (.ps1, .bat, .cmd, .py, .vbs) que existe no disco,
    # abre o arquivo externo e verifica recursivamente se o conteúdo de dentro dele tenta atacar C:\Utilitario!
    if _depth == 0:
        try:
            _, ref_files = extract_and_read_referenced_scripts(cmd_text)
            for rf in ref_files:
                if is_self_targeting_command(rf.get("content", ""), _depth + 1):
                    return True
        except Exception:
            pass

    return False


def trigger_incident_lockdown(req_id: Optional[str] = None, reason: str = "Adulteração ou violação detectada"):
    """Dispara o Protocolo de Incidente com desarmamento imediato da tarefa agendada e registro."""
    logging.critical(f"[LOCKDOWN PROTOCOL] {reason}")

    # 1. Desarma a tarefa agendada imediatamente
    try:
        for tn in ("AdminBridge", "AdminBridgeWatchdog", "AntigravityAdminBridge"):
            subprocess.run(["schtasks", "/delete", "/tn", tn, "/f"], capture_output=True, check=False, creationflags=0x08000000)
    except Exception as e:
        logging.error(f"Erro ao desarmar tarefa agendada: {e}")

    # 2. Força o estado de lockdown no motor de autenticacao
    try:
        auth = HOTPAuth()
        auth.force_lockdown(reason)
    except Exception:
        pass

    # 3. Registra no log de auditoria
    timestamp = datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S")
    entry = f"[{timestamp}] [SECURITY_INCIDENT] Motivo: {reason}\n"
    try:
        with open(AUTH_LOG_FILE, "a", encoding="utf-8") as f:
            f.write(entry)
    except Exception:
        pass

    # 4. Grava resposta de recusa 403 na fila
    if req_id:
        try:
            RESPONSES_DIR.mkdir(parents=True, exist_ok=True)
            res_file = RESPONSES_DIR / f"{req_id}.json"
            response = {
                "id": req_id,
                "status": "security_lockdown",
                "reason": f"Incidente de Seguranca: {reason}",
                "exit_code": 403,
                "output": f"[ACESSO BLOQUEADO]: {reason}. A tarefa agendada foi desarmada e o sistema bloqueado.",
                "completed_at": datetime.now().astimezone().isoformat()
            }
            with open(res_file, "w", encoding="utf-8") as f:
                json.dump(response, f, indent=2, ensure_ascii=False)
        except Exception:
            pass


def register_scheduled_task() -> bool:
    """Registra o executável no Agendador de Tarefas do Windows como SYSTEM com privilégios HIGHEST."""
    exe_path = str(BASE_DIR / "AdminBridge.exe")
    cmd = [
        "schtasks", "/create",
        "/tn", "AdminBridge",
        "/tr", f'"{exe_path}" --daemon',
        "/rl", "HIGHEST",
        "/ru", "SYSTEM",
        "/sc", "ONSTART",
        "/f"
    ]
    res = subprocess.run(cmd, capture_output=True, text=True, check=False, creationflags=0x08000000)
    if res.returncode == 0:
        logging.info("Tarefa agendada registrada sob conta SYSTEM com sucesso.")
        # Registra tarefa Watchdog secundária (a cada 1 minuto) para manter o daemon e os locks de kernel sempre ativos
        cmd_wd = [
            "schtasks", "/create",
            "/tn", "AdminBridgeWatchdog",
            "/tr", f'"{exe_path}" --daemon',
            "/rl", "HIGHEST",
            "/ru", "SYSTEM",
            "/sc", "MINUTE",
            "/mo", "1",
            "/f"
        ]
        subprocess.run(cmd_wd, capture_output=True, text=True, check=False, creationflags=0x08000000)
        subprocess.run(["schtasks", "/run", "/tn", "AdminBridge"], capture_output=True, check=False, creationflags=0x08000000)
        return True
    else:
        # Fallback para ONLOGON se ONSTART exigir permissões adicionais
        cmd_fallback = [
            "schtasks", "/create",
            "/tn", "AdminBridge",
            "/tr", f'"{exe_path}" --daemon',
            "/rl", "HIGHEST",
            "/ru", "SYSTEM",
            "/sc", "ONLOGON",
            "/f"
        ]
        res2 = subprocess.run(cmd_fallback, capture_output=True, text=True, check=False, creationflags=0x08000000)
        return res2.returncode == 0


def unregister_scheduled_task() -> bool:
    """Remove a tarefa agendada do Windows."""
    ok = True
    for tn in ("AdminBridge", "AdminBridgeWatchdog", "AntigravityAdminBridge"):
        cmd = ["schtasks", "/delete", "/tn", tn, "/f"]
        res = subprocess.run(cmd, capture_output=True, check=False, creationflags=0x08000000)
        if res.returncode == 0:
            ok = True
    return ok


class UninstallProgressDialog(QDialog):
    """Diálogo interativo com progresso visual em tempo real para desinstalação completa."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Desinstalação • Admin Bridge")
        self.resize(520, 340)
        self.setMinimumSize(500, 320)
        self.setStyleSheet("""
            QDialog {
                background-color: #11111b;
                color: #cdd6f4;
                font-family: 'Segoe UI', system-ui, sans-serif;
            }
            QLabel {
                color: #cdd6f4;
            }
            QProgressBar {
                border: 1px solid #313244;
                border-radius: 6px;
                text-align: center;
                background-color: #181825;
                color: #cdd6f4;
                font-weight: bold;
                height: 22px;
            }
            QProgressBar::chunk {
                background-color: #a6e3a1;
                border-radius: 5px;
            }
            QPushButton {
                background-color: #313244;
                color: #cdd6f4;
                border: none;
                border-radius: 6px;
                padding: 10px 18px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #45475a;
            }
        """)
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(14)

        lbl_title = QLabel("Desinstalando Admin Bridge...")
        lbl_title.setStyleSheet("font-size: 16px; font-weight: bold; color: #f38ba8;")
        layout.addWidget(lbl_title)

        self.lbl_status = QLabel("Iniciando processo de remoção...")
        self.lbl_status.setStyleSheet("font-size: 13px; color: #a6adc8;")
        self.lbl_status.setWordWrap(True)
        layout.addWidget(self.lbl_status)

        self.progress = QProgressBar()
        self.progress.setRange(0, 100)
        self.progress.setValue(5)
        layout.addWidget(self.progress)

        self.log_area = QPlainTextEdit()
        self.log_area.setReadOnly(True)
        self.log_area.setStyleSheet("background-color: #181825; color: #bac2de; font-family: Consolas, monospace; font-size: 11px; border: 1px solid #313244; border-radius: 6px;")
        layout.addWidget(self.log_area)

        self.btn_close = QPushButton("Concluir e Sair")
        self.btn_close.setEnabled(False)
        self.btn_close.clicked.connect(self.accept)
        layout.addWidget(self.btn_close, alignment=Qt.AlignmentFlag.AlignRight)

    def log(self, text: str):
        self.log_area.appendPlainText(text)
        QApplication.processEvents()

    def set_step(self, val: int, msg: str):
        self.progress.setValue(val)
        self.lbl_status.setText(msg)
        self.log(f"[*] {msg}")
        QApplication.processEvents()

    def run_uninstall(self) -> bool:
        KernelFileGuard.release_all_locks()
        self.set_step(15, "1/5 Encerrando tarefas agendadas do Windows...")
        for tn in ("AdminBridge", "AdminBridgeWatchdog", "AntigravityAdminBridge"):
            subprocess.run(["schtasks", "/end", "/tn", tn], capture_output=True, check=False, creationflags=0x08000000)
            subprocess.run(["schtasks", "/delete", "/tn", tn, "/f"], capture_output=True, check=False, creationflags=0x08000000)
        time.sleep(0.5)

        self.set_step(35, "2/5 Finalizando processos em segundo plano...")
        subprocess.run(["taskkill", "/f", "/im", "AntigravityBridge.exe"], capture_output=True, check=False, creationflags=0x08000000)
        time.sleep(0.5)

        self.set_step(55, "3/5 Removendo atalhos da Área de Trabalho...")
        try:
            desktops = []
            ud = get_desktop_dir()
            if ud and ud.exists():
                desktops.append(ud)
            pub = Path(os.environ.get("PUBLIC", "C:/Users/Public")) / "Desktop"
            if pub.exists() and pub not in desktops:
                desktops.append(pub)
            for d in desktops:
                for pattern in ["*Admin*.lnk", "*Antigravity*.lnk", "*Admin Bridge*"]:
                    for item in d.glob(pattern):
                        try:
                            if item.is_file():
                                item.unlink(missing_ok=True)
                                self.log(f"  - Atalho removido: {item.name}")
                        except Exception:
                            pass
        except Exception as e:
            self.log(f"  Aviso ao remover atalhos: {e}")
        time.sleep(0.5)

        self.set_step(75, "4/5 Liberando permissões e travas de segurança...")
        try:
            restore_ntfs_acls_for_removal(BASE_DIR)
        except Exception as e:
            self.log(f"  Aviso ao restaurar permissões: {e}")
        time.sleep(0.5)

        self.set_step(90, "5/5 Disparando script de limpeza completa com repetições...")
        temp_dir = Path(os.environ.get("TEMP", "C:/Windows/Temp"))
        cleanup_bat = temp_dir / "adminbridge_cleanup.bat"
        bat_content = (
            "@echo off\r\n"
            "setlocal enabledelayedexpansion\r\n"
            "set RETRIES=0\r\n"
            ":WAIT_KILL\r\n"
            "timeout /t 1 /nobreak >nul\r\n"
            "taskkill /f /im AdminBridge.exe >nul 2>&1\r\n"
            "taskkill /f /im AntigravityBridge.exe >nul 2>&1\r\n"
            "takeown /f \"C:\\Utilitario\" /r /d y >nul 2>&1\r\n"
            "icacls \"C:\\Utilitario\" /grant \"*S-1-5-32-544:(OI)(CI)(F)\" /t >nul 2>&1\r\n"
            "attrib -r -h -s \"C:\\Utilitario\\*\" /s /d >nul 2>&1\r\n"
            "rd /s /q \"C:\\Utilitario\" >nul 2>&1\r\n"
            "if not exist \"C:\\Utilitario\" goto DONE\r\n"
            "set /a RETRIES+=1\r\n"
            "if !RETRIES! leq 10 goto WAIT_KILL\r\n"
            ":DONE\r\n"
            "del /f /q \"%~f0\" >nul 2>&1\r\n"
        )
        try:
            with open(cleanup_bat, "w", encoding="ascii") as f:
                f.write(bat_content)
            subprocess.Popen(["cmd.exe", "/c", str(cleanup_bat)], creationflags=0x08000000)
        except Exception as e:
            self.log(f"  Erro ao criar script de limpeza: {e}")

        self.set_step(100, "Desinstalação concluída com sucesso!")
        self.lbl_status.setStyleSheet("font-size: 13px; color: #a6e3a1; font-weight: bold;")
        self.btn_close.setEnabled(True)
        return True


def perform_full_uninstall(parent_widget=None) -> bool:
    """Executa o diálogo interativo de desinstalação completa."""
    dlg = UninstallProgressDialog(parent_widget)
    dlg.show()
    QApplication.processEvents()
    ok = dlg.run_uninstall()
    dlg.exec()
    return ok


def load_recent_history(max_items: int = 50) -> list:
    """Carrega o histórico recente de logs/auth.log ou, quando sem Admin, do snapshot público queue/status.json."""
    items = []
    try:
        if not AUTH_LOG_FILE.exists():
            raise FileNotFoundError()
    except Exception:
        if STATUS_FILE.exists():
            try:
                st = json.loads(STATUS_FILE.read_text(encoding="utf-8"))
                return (st.get("recent_history") or [])[:max_items]
            except Exception:
                pass
        return items

    try:
        with open(AUTH_LOG_FILE, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()

        for line in reversed(lines):
            line = line.strip()
            if not line or not line.startswith("["):
                continue

            parts = line.split("] [")
            if len(parts) >= 2:
                ts_raw = parts[0].lstrip("[")
                status_part = parts[1].split("]")[0]
                rest = line[line.find("Action: "):]

                action = "Comando"
                otp_masked = "******"
                details = ""
                for token in rest.split(" | "):
                    if token.startswith("Action:"):
                        action = token.split(":", 1)[1].strip()
                    elif token.startswith("OTP:"):
                        raw_otp = token.split(":", 1)[1].strip()
                        otp_masked = (raw_otp[:2] + "****") if len(raw_otp) >= 2 else "******"
                    elif token.startswith("Details:"):
                        details = token.split(":", 1)[1].strip()

                try:
                    if "T" in ts_raw:
                        dt = datetime.fromisoformat(ts_raw)
                        if dt.tzinfo is not None:
                            dt = dt.astimezone()
                        dt_str = dt.strftime("%d/%m/%Y %H:%M:%S")
                    else:
                        dt = datetime.strptime(ts_raw[:19], "%Y-%m-%d %H:%M:%S")
                        dt_str = dt.strftime("%d/%m/%Y %H:%M:%S")
                except Exception:
                    dt_str = ts_raw[:19]

                cmd_display = f"{action}: {details}" if details else action
                estado_str = "Aprovado" if status_part == "SUCCESS" else "Rejeitado"

                items.append({
                    "datetime": dt_str,
                    "command": cmd_display,
                    "status": estado_str,
                    "otp": otp_masked
                })
                if len(items) >= max_items:
                    break
    except Exception:
        if STATUS_FILE.exists():
            try:
                st = json.loads(STATUS_FILE.read_text(encoding="utf-8"))
                return (st.get("recent_history") or [])[:max_items]
            except Exception:
                pass

    return items


# -----------------------------------------------------------------------------
# RENDERIZAÇÃO EFÊMERA DE QR CODE EM MEMÓRIA
# -----------------------------------------------------------------------------
def render_qr_in_memory(uri: str) -> Tuple[QPixmap, bytearray]:
    """Gera o QR Code estritamente em memória RAM e retorna o QPixmap e o buffer mutável."""
    qr = qrcode.QRCode(
        version=None,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=8,
        border=2,
    )
    qr.add_data(uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")

    buf = io.BytesIO()
    img.save(buf, format="PNG")
    raw_bytes = bytearray(buf.getvalue())
    buf.close()

    pixmap = QPixmap()
    pixmap.loadFromData(raw_bytes)
    return pixmap, raw_bytes


# -----------------------------------------------------------------------------
# ASSISTENTE DE PROVISIONAMENTO INTERATIVO (ZERO-KNOWLEDGE)
# -----------------------------------------------------------------------------
class SetupWizardDialog(QDialog):
    """Janela de provisionamento interativo com zero exposição de segredos em disco."""

    def __init__(self, hotp_auth: HOTPAuth, parent=None):
        super().__init__(parent)
        self.hotp_auth = hotp_auth
        self.raw_qr_buffer: Optional[bytearray] = None

        self.setWindowTitle("Admin Bridge • Provisionamento de Seguranca")
        self.setMinimumSize(480, 580)
        self.setStyleSheet("""
            QDialog {
                background-color: #11111b;
                color: #cdd6f4;
                font-family: 'Segoe UI', system-ui, sans-serif;
            }
            QLabel {
                color: #cdd6f4;
            }
            QLineEdit {
                background-color: #1e1e2e;
                color: #cdd6f4;
                border: 1px solid #45475a;
                border-radius: 6px;
                padding: 10px 14px;
                font-size: 13px;
            }
            QLineEdit:focus {
                border: 1px solid #89b4fa;
            }
            QPushButton {
                background-color: #89b4fa;
                color: #11111b;
                font-weight: bold;
                border-radius: 6px;
                padding: 12px;
                font-size: 13px;
                border: none;
            }
            QPushButton:hover {
                background-color: #b4befe;
            }
            QPushButton#btnCancel {
                background-color: #313244;
                color: #a6adc8;
            }
            QPushButton#btnCancel:hover {
                background-color: #45475a;
            }
        """)

        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(28, 28, 28, 28)
        self.layout.setSpacing(16)
        self.init_password_step()

    def init_password_step(self):
        while self.layout.count():
            item = self.layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        lbl_title = QLabel("🔐 Assistente de Provisionamento HOTP")
        lbl_title.setStyleSheet("font-size: 18px; font-weight: bold; color: #a6e3a1;")
        self.layout.addWidget(lbl_title)

        lbl_desc = QLabel(
            "Defina sua Palavra-passe de Recuperação pessoal.\n"
            "Esta chave protegerá o segredo localmente via DPAPI e será necessária "
            "caso queira revogar ou redefinir o autenticador no futuro."
        )
        lbl_desc.setWordWrap(True)
        lbl_desc.setStyleSheet("font-size: 12px; color: #a6adc8; line-height: 1.4;")
        self.layout.addWidget(lbl_desc)

        lbl_p1 = QLabel("Palavra-passe de Recuperação - mínimo 8 caracteres:")
        lbl_p1.setStyleSheet("font-weight: 600; font-size: 12px; margin-top: 10px;")
        self.layout.addWidget(lbl_p1)

        self.txt_p1 = QLineEdit()
        self.txt_p1.setEchoMode(QLineEdit.EchoMode.Password)
        self.txt_p1.setPlaceholderText("Digite uma senha forte e memorize-a")
        self.layout.addWidget(self.txt_p1)

        lbl_p2 = QLabel("Confirmar Palavra-passe:")
        lbl_p2.setStyleSheet("font-weight: 600; font-size: 12px;")
        self.layout.addWidget(lbl_p2)

        self.txt_p2 = QLineEdit()
        self.txt_p2.setEchoMode(QLineEdit.EchoMode.Password)
        self.txt_p2.setPlaceholderText("Repita a mesma senha")
        self.layout.addWidget(self.txt_p2)

        self.btn_next = QPushButton("Gerar QR Code")
        self.btn_next.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.btn_next.clicked.connect(self.process_password_and_generate)
        self.layout.addWidget(self.btn_next)

        self.btn_cancel = QPushButton("Cancelar")
        self.btn_cancel.setObjectName("btnCancel")
        self.btn_cancel.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.btn_cancel.clicked.connect(self.reject)
        self.layout.addWidget(self.btn_cancel)

    def process_password_and_generate(self):
        p1 = self.txt_p1.text().strip()
        p2 = self.txt_p2.text().strip()

        if len(p1) < 8:
            QMessageBox.warning(self, "Aviso", "A palavra-passe deve conter pelo menos 8 caracteres.")
            return
        if p1 != p2:
            QMessageBox.warning(self, "Aviso", "As palavras-passe digitadas não coincidem.")
            return

        self.btn_next.setEnabled(False)
        self.btn_next.setText("Gerando chave segura...")
        QApplication.processEvents()
        try:
            caller_info = {
                "pid": os.getpid(),
                "exe": sys.executable,
                "script": "SetupWizardDialog",
                "user": os.getenv("USERNAME", "unknown")
            }
            # defer_acls=True exibe o QR Code na tela instantaneamente e aplica o icacls em background enquanto o usuário escaneia!
            res = self.hotp_auth.provision(p1, force=False, caller_info=caller_info, defer_acls=True)
            self.show_qr_step(res)
            threading.Thread(target=apply_isolated_bridge_ntfs_acls, args=(BASE_DIR,), daemon=True).start()
        except Exception as e:
            self.btn_next.setEnabled(True)
            self.btn_next.setText("Gerar QR Code")
            QMessageBox.critical(self, "Erro no Provisionamento", f"Falha ao gerar chave: {e}")

    def show_qr_step(self, res):
        # Aplica ambiente cego na tela impedindo captura ou visualizacao por softwares
        try:
            hwnd = int(self.winId())
            ret = ctypes.windll.user32.SetWindowDisplayAffinity(hwnd, 0x00000011)
            if not ret:
                ctypes.windll.user32.SetWindowDisplayAffinity(hwnd, 0x00000001)
        except Exception:
            pass

        self.resize(820, 520)
        self.setMinimumSize(800, 480)

        while self.layout.count():
            item = self.layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        lbl_header = QLabel("🔐 Pareamento e Ativação do Autenticador")
        lbl_header.setStyleSheet("font-size: 18px; font-weight: bold; color: #a6e3a1;")
        self.layout.addWidget(lbl_header)

        # Layout horizontal de duas colunas lado a lado
        columns_layout = QHBoxLayout()
        columns_layout.setSpacing(24)

        # Coluna Esquerda: QR Code e Chave Manual
        col_left = QVBoxLayout()
        col_left.setSpacing(10)

        lbl_qr_title = QLabel("1. Escaneie o QR Code no Celular")
        lbl_qr_title.setStyleSheet("font-size: 13px; font-weight: bold; color: #89b4fa;")
        col_left.addWidget(lbl_qr_title)

        lbl_sub = QLabel("Abra o Aegis, 2FAS ou Google Authenticator:")
        lbl_sub.setStyleSheet("font-size: 11px; color: #a6adc8;")
        col_left.addWidget(lbl_sub)

        pixmap, self.raw_qr_buffer = render_qr_in_memory(res["uri"])

        lbl_img = QLabel()
        lbl_img.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lbl_img.setPixmap(pixmap.scaled(220, 220, Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation))
        col_left.addWidget(lbl_img)

        lbl_manual = QLabel("Chave Secreta para Inserção Manual:")
        lbl_manual.setStyleSheet("font-size: 11px; font-weight: 600; color: #a6adc8;")
        col_left.addWidget(lbl_manual)

        txt_secret = QLineEdit(res.get("secret_base32", ""))
        txt_secret.setReadOnly(True)
        txt_secret.setStyleSheet("font-family: Consolas, monospace; font-size: 12px; background-color: #181825; color: #f9e2af;")
        col_left.addWidget(txt_secret)

        lbl_meta = QLabel("Padrão: HOTP RFC 4226 • Dígitos: 6 • HMAC-SHA1")
        lbl_meta.setStyleSheet("font-size: 10px; color: #6c7086;")
        col_left.addWidget(lbl_meta)
        col_left.addStretch()

        columns_layout.addLayout(col_left, stretch=1)

        # Coluna Direita: Validação do primeiro OTP e Conclusão
        col_right = QVBoxLayout()
        col_right.setSpacing(12)

        lbl_val_title = QLabel("2. Validação e Conclusão")
        lbl_val_title.setStyleSheet("font-size: 13px; font-weight: bold; color: #89b4fa;")
        col_right.addWidget(lbl_val_title)

        lbl_otp_input = QLabel("Digite o código de 6 dígitos que apareceu agora no celular para confirmar a sincronização:")
        lbl_otp_input.setWordWrap(True)
        lbl_otp_input.setStyleSheet("font-size: 12px; color: #cdd6f4; line-height: 1.4;")
        col_right.addWidget(lbl_otp_input)

        self.txt_verify_otp = QLineEdit()
        self.txt_verify_otp.setMaxLength(6)
        self.txt_verify_otp.setPlaceholderText("000000")
        self.txt_verify_otp.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.txt_verify_otp.setStyleSheet("font-family: Consolas, monospace; font-size: 26px; font-weight: bold; letter-spacing: 6px; color: #a6e3a1; padding: 12px;")
        self.txt_verify_otp.returnPressed.connect(self.verify_and_finalize_pairing)
        col_right.addWidget(self.txt_verify_otp)

        self.btn_finish = QPushButton("Validar Código e Concluir Pareamento")
        self.btn_finish.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.btn_finish.setStyleSheet("background-color: #a6e3a1; color: #11111b; font-weight: bold; padding: 12px;")
        self.btn_finish.clicked.connect(self.verify_and_finalize_pairing)
        col_right.addWidget(self.btn_finish)

        lbl_warn = QLabel("⚠️ ATENÇÃO: Esta é a ÚNICA vez que este código será exibido. A chave não será salva em disco.")
        lbl_warn.setWordWrap(True)
        lbl_warn.setStyleSheet("font-size: 11px; color: #f38ba8; font-weight: 600; line-height: 1.3;")
        col_right.addWidget(lbl_warn)

        btn_cancel_step = QPushButton("Cancelar")
        btn_cancel_step.setObjectName("btnCancel")
        btn_cancel_step.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        btn_cancel_step.clicked.connect(self.reject)
        col_right.addWidget(btn_cancel_step)
        col_right.addStretch()

        columns_layout.addLayout(col_right, stretch=1)
        self.layout.addLayout(columns_layout)

    def verify_and_finalize_pairing(self):
        otp = self.txt_verify_otp.text().strip()
        if len(otp) != 6 or not otp.isdigit():
            QMessageBox.warning(self, "Código Inválido", "Digite o código OTP de 6 dígitos exibido no seu celular.")
            return

        ok, msg = self.hotp_auth.verify_and_finalize_initial_otp(otp)
        if not ok:
            QMessageBox.critical(self, "Falha de Pareamento", msg)
            return

        try:
            hwnd = int(self.winId())
            ctypes.windll.user32.SetWindowDisplayAffinity(hwnd, 0x00000000)
        except Exception:
            pass

        if self.raw_qr_buffer is not None:
            wipe_buffer(self.raw_qr_buffer)
            self.raw_qr_buffer = None
        gc.collect()

        threading.Thread(target=register_scheduled_task, daemon=True).start()
        QMessageBox.information(self, "Pareamento Concluído", "Autenticador pareado e sincronizado com sucesso!")
        self.accept()

    def closeEvent(self, event):
        try:
            hwnd = int(self.winId())
            ctypes.windll.user32.SetWindowDisplayAffinity(hwnd, 0x00000000)
        except Exception:
            pass
        if self.raw_qr_buffer is not None:
            wipe_buffer(self.raw_qr_buffer)
            self.raw_qr_buffer = None
        gc.collect()
        super().closeEvent(event)


# -----------------------------------------------------------------------------
# ASSISTENTE DE RESET E AUTODESTRUIÇÃO DE PRIVILÉGIOS (REQUISITO 3)
# -----------------------------------------------------------------------------
class ResetWizardDialog(QDialog):
    """Diálogo de revogação de privilégios e destruição de chaves com confirmação física."""

    def __init__(self, hotp_auth: HOTPAuth, parent=None):
        super().__init__(parent)
        self.hotp_auth = hotp_auth
        self.challenge_code = generate_physical_challenge()

        self.setWindowTitle("Admin Bridge • Reiniciar Configuração")
        self.setMinimumSize(480, 520)
        self.setStyleSheet("""
            QDialog {
                background-color: #11111b;
                color: #cdd6f4;
                font-family: 'Segoe UI', system-ui, sans-serif;
            }
            QLabel {
                color: #cdd6f4;
            }
            QLineEdit {
                background-color: #1e1e2e;
                color: #cdd6f4;
                border: 1px solid #45475a;
                border-radius: 6px;
                padding: 10px 14px;
                font-size: 13px;
            }
            QLineEdit:focus {
                border: 1px solid #f38ba8;
            }
            QPushButton {
                background-color: #f38ba8;
                color: #11111b;
                font-weight: bold;
                border-radius: 6px;
                padding: 12px;
                font-size: 13px;
                border: none;
            }
            QPushButton:hover {
                background-color: #eba0ac;
            }
            QPushButton#btnCancel {
                background-color: #313244;
                color: #a6adc8;
            }
            QPushButton#btnCancel:hover {
                background-color: #45475a;
            }
        """)

        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(28, 28, 28, 28)
        self.layout.setSpacing(14)
        self.init_ui()

    def init_ui(self):
        lbl_title = QLabel("⚠️ Reiniciar Configuração")
        lbl_title.setStyleSheet("font-size: 18px; font-weight: bold; color: #f38ba8;")
        self.layout.addWidget(lbl_title)

        lbl_desc = QLabel(
            "Esta operação reinicia a configuração atual e remove as credenciais anteriores "
            "para que você possa definir uma nova palavra-passe e parear o autenticador novamente."
        )
        lbl_desc.setWordWrap(True)
        lbl_desc.setStyleSheet("font-size: 12px; color: #a6adc8; line-height: 1.4;")
        self.layout.addWidget(lbl_desc)

        lbl_ch_title = QLabel("Confirmação de Presença Física - digite o código abaixo:")
        lbl_ch_title.setStyleSheet("font-weight: 600; font-size: 12px; color: #fab387; margin-top: 10px;")
        self.layout.addWidget(lbl_ch_title)

        lbl_challenge_box = QLabel(self.challenge_code)
        lbl_challenge_box.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lbl_challenge_box.setStyleSheet(
            "font-family: Consolas, monospace; font-size: 18px; font-weight: bold; "
            "background-color: #181825; border: 1px dashed #fab387; color: #fab387; padding: 10px; border-radius: 6px;"
        )
        self.layout.addWidget(lbl_challenge_box)

        self.txt_challenge = QLineEdit()
        self.txt_challenge.setPlaceholderText("Digite o código exibido acima - ex: PHYS-123456")
        self.layout.addWidget(self.txt_challenge)

        lbl_curr_pw = QLabel("Palavra-passe de Recuperação:")
        lbl_curr_pw.setStyleSheet("font-weight: 600; font-size: 12px;")
        self.layout.addWidget(lbl_curr_pw)

        self.txt_curr_pw = QLineEdit()
        self.txt_curr_pw.setEchoMode(QLineEdit.EchoMode.Password)
        self.txt_curr_pw.setPlaceholderText("Digite sua palavra-passe de recuperação")
        self.layout.addWidget(self.txt_curr_pw)

        self.btn_submit = QPushButton("Confirmar e Reiniciar Configuração")
        self.btn_submit.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.btn_submit.clicked.connect(self.execute_reset)
        self.layout.addWidget(self.btn_submit)

        self.btn_cancel = QPushButton("Cancelar")
        self.btn_cancel.setObjectName("btnCancel")
        self.btn_cancel.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.btn_cancel.clicked.connect(self.reject)
        self.layout.addWidget(self.btn_cancel)

    def execute_reset(self):
        user_ch = self.txt_challenge.text().strip()
        if user_ch.upper() != self.challenge_code:
            QMessageBox.critical(self, "Falha de Presença Física", "O código de presença física digitado não confere.")
            return

        curr_pw = self.txt_curr_pw.text().strip()
        try:
            caller_info = {
                "pid": os.getpid(),
                "exe": sys.executable,
                "script": "ResetWizardDialog",
                "user": os.getenv("USERNAME", "unknown")
            }
            res = self.hotp_auth.reset_and_destroy_privileges(
                recovery_password=curr_pw,
                physical_challenge_response=user_ch,
                expected_challenge=self.challenge_code,
                caller_info=caller_info
            )
            QMessageBox.information(
                self,
                "Configuração Reiniciada",
                "Sucesso! A configuração foi reiniciada com êxito.\n"
                "Você pode agora configurar uma nova palavra-passe e parear o aplicativo."
            )
            self.accept()
        except Exception as e:
            QMessageBox.critical(self, "Erro na Reinicialização", f"Falha na reinicialização: {e}")


class SHELLEXECUTEINFO(ctypes.Structure):
    _fields_ = [
        ("cbSize", wintypes.DWORD),
        ("fMask", wintypes.ULONG),
        ("hwnd", wintypes.HWND),
        ("lpVerb", wintypes.LPCWSTR),
        ("lpFile", wintypes.LPCWSTR),
        ("lpParameters", wintypes.LPCWSTR),
        ("lpDirectory", wintypes.LPCWSTR),
        ("nShow", ctypes.c_int),
        ("hInstApp", wintypes.HINSTANCE),
        ("lpIDList", ctypes.c_void_p),
        ("lpClass", wintypes.LPCWSTR),
        ("hkeyClass", wintypes.HKEY),
        ("dwHotKey", wintypes.DWORD),
        ("hIcon", wintypes.HANDLE),
        ("hProcess", wintypes.HANDLE),
    ]


# -----------------------------------------------------------------------------
# THREAD DE EXECUÇÃO DE COMANDOS
# -----------------------------------------------------------------------------
class ExecutionThread(QThread):
    finished_signal = pyqtSignal(dict)

    def __init__(self, request_data, hwnd, force_uac: bool = False):
        super().__init__()
        self.request_data = request_data
        self.hwnd = hwnd
        self.force_uac = force_uac

    def run(self):
        req_id = self.request_data["id"]
        script_type = self.request_data.get("script_type", "bat").lower()
        code = self.request_data.get("code", "")

        SCRIPTS_DIR.mkdir(parents=True, exist_ok=True)
        RESPONSES_DIR.mkdir(parents=True, exist_ok=True)

        ext = "ps1" if script_type == "ps1" else "bat"
        script_file = SCRIPTS_DIR / f"{req_id}.{ext}"
        log_file = RESPONSES_DIR / f"{req_id}.log"
        exit_code = 0
        output_data = ""

        try:
            if self.force_uac:
                # Dispara via ShellExecuteEx com 'runas' para exigir UAC na tela
                if script_type in ("bat", "cmd"):
                    exe_target = "cmd.exe"
                    param_target = f'/c "{code}"'
                elif script_type == "ps1":
                    exe_target = "powershell.exe"
                    param_target = f'-NoProfile -ExecutionPolicy Bypass -Command "{code}"'
                else:
                    exe_target = "cmd.exe"
                    param_target = f'/c "{code}"'

                sei = SHELLEXECUTEINFO()
                sei.cbSize = ctypes.sizeof(SHELLEXECUTEINFO)
                sei.fMask = 0x00000040  # SEE_MASK_NOCLOSEPROCESS
                sei.hwnd = self.hwnd
                sei.lpVerb = "runas"
                sei.lpFile = exe_target
                sei.lpParameters = param_target
                sei.nShow = 0  # SW_HIDE

                res = ctypes.windll.shell32.ShellExecuteExW(ctypes.byref(sei))
                if not res or not sei.hProcess:
                    err = ctypes.GetLastError()
                    if err == 1223:  # ERROR_CANCELLED
                        response = {
                            "id": req_id,
                            "status": "rejected",
                            "exit_code": -1,
                            "output": "Operação cancelada pelo usuário no prompt UAC.",
                            "completed_at": datetime.now().astimezone().isoformat()
                        }
                        self.finished_signal.emit(response)
                        return
                    else:
                        raise ctypes.WinError(err)

                ctypes.windll.kernel32.WaitForSingleObject(sei.hProcess, 0xFFFFFFFF)
                exit_code_dw = wintypes.DWORD()
                ctypes.windll.kernel32.GetExitCodeProcess(sei.hProcess, ctypes.byref(exit_code_dw))
                exit_code = int(exit_code_dw.value)
                ctypes.windll.kernel32.CloseHandle(sei.hProcess)
                output_data = "Comando executado com sucesso via UAC elevado."
            else:
                # Execucao nativa direta em processo unico
                if script_type in ("bat", "cmd"):
                    cmd = ["cmd.exe", "/c", code]
                elif script_type == "ps1":
                    cmd = ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", code]
                else:
                    cmd = ["cmd.exe", "/c", code]

                safe_cwd = os.environ.get("SystemRoot", "C:\\Windows\\System32") if sys.platform == "win32" else None
                proc = subprocess.run(
                    cmd,
                    cwd=safe_cwd,
                    capture_output=True,
                    text=True,
                    check=False,
                    creationflags=0x08000000 if sys.platform == "win32" else 0
                )
                output_data = proc.stdout
                if proc.stderr:
                    output_data += ("\n[STDERR]:\n" if output_data else "") + proc.stderr
                exit_code = proc.returncode

        except Exception as e:
            exit_code = -1
            output_data = f"Falha na execução: {e}"

        response = {
            "id": req_id,
            "status": "approved",
            "exit_code": exit_code,
            "output": output_data,
            "completed_at": datetime.now().astimezone().isoformat()
        }
        self.finished_signal.emit(response)


# -----------------------------------------------------------------------------
# DIÁLOGO MODERNO DE TESTE E DIAGNÓSTICO DE SINCRONIA HOTP
# -----------------------------------------------------------------------------
class SyncTestDialog(QDialog):
    """Diálogo moderno e amigável para sincronização inteligente do aplicativo autenticador."""
    def __init__(self, hotp_auth: HOTPAuth, parent=None):
        super().__init__(parent)
        self.hotp_auth = hotp_auth
        self.setWindowTitle("Diagnóstico do Autenticador • Admin Bridge")
        self.resize(580, 560)
        self.setMinimumSize(560, 520)
        self.init_ui()

    def init_ui(self):
        self.setStyleSheet("""
            QDialog {
                background-color: #11111b;
                color: #cdd6f4;
                font-family: 'Segoe UI', system-ui, sans-serif;
            }
            QLabel {
                color: #cdd6f4;
            }
            QLineEdit {
                background-color: #181825;
                border: 2px solid #313244;
                border-radius: 8px;
                color: #89b4fa;
                font-family: 'Consolas', monospace;
                font-size: 24px;
                font-weight: bold;
                padding: 8px 12px;
                letter-spacing: 4px;
            }
            QLineEdit:focus {
                border: 2px solid #89b4fa;
            }
            QPushButton#btnVerify {
                background-color: #89b4fa;
                color: #11111b;
                border: none;
                border-radius: 8px;
                font-size: 14px;
                font-weight: bold;
                padding: 10px 20px;
            }
            QPushButton#btnVerify:hover {
                background-color: #b4befe;
            }
            QPushButton#btnVerify:disabled {
                background-color: #45475a;
                color: #a6adc8;
            }
            QPushButton#btnClose {
                background-color: #313244;
                color: #cdd6f4;
                border: none;
                border-radius: 8px;
                font-size: 13px;
                font-weight: bold;
                padding: 8px 20px;
            }
            QPushButton#btnClose:hover {
                background-color: #45475a;
            }
            QFrame#cardResult {
                background-color: #181825;
                border: 1px solid #313244;
                border-radius: 8px;
            }
        """)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(14)
        layout.setSizeConstraint(QLayout.SizeConstraint.SetMinimumSize)

        # Cabeçalho
        lbl_title = QLabel("Diagnóstico de Sincronia")
        lbl_title.setStyleSheet("font-size: 20px; font-weight: bold; color: #cdd6f4;")
        layout.addWidget(lbl_title)

        lbl_desc = QLabel(
            "Digite o código de 6 dígitos que está aparecendo agora na tela do seu celular "
            "Google Authenticator, Aegis, 2FAS ou compatível para verificar se ele está pronto para uso:"
        )
        lbl_desc.setWordWrap(True)
        lbl_desc.setStyleSheet("font-size: 13px; color: #a6adc8; line-height: 1.4;")
        layout.addWidget(lbl_desc)

        # Entrada de OTP
        input_box = QHBoxLayout()
        self.edit_otp = QLineEdit()
        self.edit_otp.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.edit_otp.setMaxLength(6)
        self.edit_otp.setPlaceholderText("000000")
        self.edit_otp.textChanged.connect(self.on_otp_text_changed)
        self.edit_otp.returnPressed.connect(self.run_verification)
        input_box.addWidget(self.edit_otp)

        self.btn_verify = QPushButton("Verificar")
        self.btn_verify.setObjectName("btnVerify")
        self.btn_verify.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_verify.clicked.connect(self.run_verification)
        input_box.addWidget(self.btn_verify)
        layout.addLayout(input_box)

        # Card de Resultado (dinâmico)
        self.card_result = QFrame()
        self.card_result.setObjectName("cardResult")
        res_layout = QVBoxLayout(self.card_result)
        res_layout.setContentsMargins(16, 16, 16, 16)
        res_layout.setSpacing(10)

        # Badge de Status
        self.badge_status = QLabel("AGUARDANDO CÓDIGO")
        self.badge_status.setStyleSheet("background-color: #313244; color: #a6adc8; padding: 4px 10px; border-radius: 4px; font-weight: bold; font-size: 11px;")
        res_layout.addWidget(self.badge_status, alignment=Qt.AlignmentFlag.AlignLeft)

        # Mensagem Principal (Humana)
        self.lbl_verdict = QLabel("Digite o código acima e clique em 'Verificar'.")
        self.lbl_verdict.setStyleSheet("font-size: 14px; font-weight: bold; color: #cdd6f4;")
        self.lbl_verdict.setWordWrap(True)
        res_layout.addWidget(self.lbl_verdict)

        # Próximo Passo / Instrução de Ação
        self.lbl_instruction = QLabel("Sincronização ativa: o contador do sistema avança automaticamente para alinhar com o seu aplicativo.")
        self.lbl_instruction.setStyleSheet("font-size: 12px; color: #bac2de; line-height: 1.4;")
        self.lbl_instruction.setWordWrap(True)
        res_layout.addWidget(self.lbl_instruction)

        # Detalhes do Diagnóstico
        self.frame_details = QFrame()
        self.frame_details.setStyleSheet("background-color: #11111b; border-radius: 6px;")
        det_layout = QGridLayout(self.frame_details)
        det_layout.setContentsMargins(14, 12, 14, 12)
        det_layout.setHorizontalSpacing(16)
        det_layout.setVerticalSpacing(8)

        lbl_hdr1 = QLabel("Código Testado:")
        lbl_hdr1.setMinimumHeight(24)
        det_layout.addWidget(lbl_hdr1, 0, 0)
        self.lbl_det_code = QLabel("-")
        self.lbl_det_code.setMinimumHeight(24)
        self.lbl_det_code.setStyleSheet("font-weight: bold; font-family: monospace;")
        det_layout.addWidget(self.lbl_det_code, 0, 1)

        lbl_hdr2 = QLabel("Posição no Celular:")
        lbl_hdr2.setMinimumHeight(24)
        det_layout.addWidget(lbl_hdr2, 1, 0)
        self.lbl_det_phone = QLabel("-")
        self.lbl_det_phone.setMinimumHeight(24)
        self.lbl_det_phone.setStyleSheet("font-weight: bold; font-family: monospace;")
        det_layout.addWidget(self.lbl_det_phone, 1, 1)

        lbl_hdr3 = QLabel("Próximo Código a Usar:")
        lbl_hdr3.setMinimumHeight(24)
        det_layout.addWidget(lbl_hdr3, 2, 0)
        self.lbl_det_next = QLabel("-")
        self.lbl_det_next.setMinimumHeight(24)
        self.lbl_det_next.setStyleSheet("font-weight: bold; font-family: monospace; color: #89b4fa;")
        det_layout.addWidget(self.lbl_det_next, 2, 1)

        res_layout.addWidget(self.frame_details)
        self.frame_details.hide()

        layout.addWidget(self.card_result)

        # Rodapé de segurança transparente
        lbl_security = QLabel("🔒 Sincronização inteligente: o contador avança automaticamente para alinhar com o seu aplicativo.")
        lbl_security.setStyleSheet("font-size: 11px; color: #6c7086;")
        layout.addWidget(lbl_security)

        # Botão Fechar
        btn_box = QHBoxLayout()
        btn_box.addStretch()
        btn_close = QPushButton("Fechar")
        btn_close.setObjectName("btnClose")
        btn_close.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_close.clicked.connect(self.accept)
        btn_box.addWidget(btn_close)
        layout.addLayout(btn_box)

    def on_otp_text_changed(self, text):
        clean = "".join([c for c in text if c.isdigit()])
        if clean != text:
            self.edit_otp.setText(clean)

    def run_verification(self):
        otp = self.edit_otp.text().strip()
        if len(otp) != 6 or not otp.isdigit():
            self.badge_status.setText("CÓDIGO INCOMPLETO")
            self.badge_status.setStyleSheet("background-color: #fab387; color: #11111b; padding: 4px 10px; border-radius: 4px; font-weight: bold; font-size: 11px;")
            self.lbl_verdict.setText("O código deve conter exatamente 6 números.")
            self.lbl_instruction.setText("Consulte os 6 dígitos exibidos no aplicativo do seu celular e tente novamente.")
            self.frame_details.hide()
            return

        self.btn_verify.setEnabled(False)
        self.btn_verify.setText("Verificando...")
        QApplication.processEvents()

        res = None
        try:
            res = self.hotp_auth.diagnose_otp_sync(otp, allow_lookahead=False)
            if res and not res.get("success") and res.get("status") == "prompt_lookahead":
                ask = QMessageBox.question(
                    self,
                    "Pesquisar Posições Futuras?",
                    "O código digitado não corresponde ao contador atual nem aos anteriores.\n\n"
                    "Deseja pesquisar nas próximas 10 posições futuras do seu autenticador?\n\n"
                    "Atenção: caso o código não seja localizado nessa janela à frente, "
                    "o contador do sistema saltará 10 posições para forçar o alinhamento com seu dispositivo.",
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                    QMessageBox.StandardButton.No
                )
                if ask == QMessageBox.StandardButton.Yes:
                    res = self.hotp_auth.diagnose_otp_sync(otp, allow_lookahead=True)
                else:
                    self.badge_status.setText("NÃO RECONHECIDO")
                    self.badge_status.setStyleSheet("background-color: #fab387; color: #11111b; padding: 4px 10px; border-radius: 4px; font-weight: bold; font-size: 11px;")
                    self.lbl_verdict.setText("Código não localizado no contador atual.")
                    self.lbl_instruction.setText("Verificação cancelada pelo usuário. O contador do sistema permaneceu inalterado.")
                    self.lbl_det_code.setText(otp)
                    self.lbl_det_phone.setText("Não localizado")
                    self.lbl_det_next.setText(f"OTP #{res.get('current_counter')}")
                    self.frame_details.show()
                    return
        except Exception as e:
            self.badge_status.setText("FALHA DE COMUNICAÇÃO")
            self.badge_status.setStyleSheet("background-color: #f38ba8; color: #11111b; padding: 4px 10px; border-radius: 4px; font-weight: bold; font-size: 11px;")
            self.lbl_verdict.setText("❌ Erro ao validar o código OTP.")
            self.lbl_instruction.setText(f"Detalhes: {e}. Verifique se o serviço em segundo plano está ativo.")
            self.lbl_det_code.setText(otp)
            self.lbl_det_phone.setText("Erro")
            self.lbl_det_next.setText("-")
            self.frame_details.show()
            return
        finally:
            self.btn_verify.setEnabled(True)
            self.btn_verify.setText("Verificar")

        if not res:
            return

        if res.get("success"):
            st = res.get("status")
            matched = res.get("matched_counter")
            next_c = res.get("next_counter")
            summary = res.get("summary", "")
            action = res.get("action_instruction", "")

            if st == "synchronized":
                self.badge_status.setText("100% SINCRONIZADO")
                self.badge_status.setStyleSheet("background-color: #a6e3a1; color: #11111b; padding: 4px 10px; border-radius: 4px; font-weight: bold; font-size: 11px;")
                self.lbl_verdict.setText(f"✅ {summary}")
                self.lbl_instruction.setText(action)
                self.lbl_det_phone.setText(f"OTP #{matched} - Atual")
                self.lbl_det_next.setText(f"OTP #{next_c}")
            elif st == "ahead":
                self.badge_status.setText("COMPATÍVEL - À FRENTE")
                self.badge_status.setStyleSheet("background-color: #89b4fa; color: #11111b; padding: 4px 10px; border-radius: 4px; font-weight: bold; font-size: 11px;")
                self.lbl_verdict.setText(f"ℹ️ {summary}")
                self.lbl_instruction.setText(action)
                self.lbl_det_phone.setText(f"OTP #{matched} - Celular avançado")
                self.lbl_det_next.setText(f"OTP #{next_c}")
            else:
                self.badge_status.setText("CÓDIGO ANTIGO - ATRASADO")
                self.badge_status.setStyleSheet("background-color: #fab387; color: #11111b; padding: 4px 10px; border-radius: 4px; font-weight: bold; font-size: 11px;")
                self.lbl_verdict.setText(f"⚠️ {summary}")
                self.lbl_instruction.setText(action)
                self.lbl_det_phone.setText(f"OTP #{matched} - Expirado")
                self.lbl_det_next.setText(f"OTP #{next_c} - Aguardando no PC")

            self.lbl_det_code.setText(otp)
            self.frame_details.show()
        else:
            self.badge_status.setText("NÃO RECONHECIDO")
            self.badge_status.setStyleSheet("background-color: #f38ba8; color: #11111b; padding: 4px 10px; border-radius: 4px; font-weight: bold; font-size: 11px;")
            self.lbl_verdict.setText("❌ " + res.get("summary", "Código não encontrado."))
            self.lbl_instruction.setText(res.get("action_instruction", res.get("error", "Verifique se o código foi digitado corretamente.")))
            self.lbl_det_code.setText(otp)
            self.lbl_det_phone.setText("Não localizado")
            self.lbl_det_next.setText(f"OTP #{res.get('next_counter', res.get('current_counter'))}")
            self.frame_details.show()


# -----------------------------------------------------------------------------
# DIÁLOGO RESPONSIVO DE AUTENTICAÇÃO POR SENHA (LOCKOUT & FEEDBACK IMEDIATO)
# -----------------------------------------------------------------------------
class ResponsivePasswordDialog(QDialog):
    """Diálogo responsivo moderno para validação de Palavra-passe de Recuperação / Senha Mestra.
    - Totalmente estilizado no tema escuro oficial (#11111b, #181825, #313244, #cdd6f4).
    - Campo de senha com botão de alternância de visualização [👁️ / 🔒].
    - Feedback imediato e claro inline sem fechar a caixa de diálogo em caso de erro.
    - Contador de tentativas restantes [5 tentativas] e cronômetro regressivo ativo em tempo real [bloqueio progressivo até 4h].
    - Totalmente não-bloqueante e responsivo para o usuário.
    """
    def __init__(
        self,
        title: str,
        prompt: str,
        verify_fn: Optional[Callable[[str], Tuple[bool, str]]] = None,
        parent=None,
        confirm_text: str = "Confirmar"
    ):
        super().__init__(parent)
        self.verify_fn = verify_fn
        self.verified_password = ""
        self._verifying = False
        self._has_error = False

        self.setWindowTitle(title)
        self.resize(480, 260)
        self.setMinimumWidth(420)
        self.setModal(True)

        app_icon = get_app_icon()
        if app_icon and not app_icon.isNull():
            self.setWindowIcon(app_icon)

        self.setStyleSheet("""
            QDialog {
                background-color: #181825;
                color: #cdd6f4;
                font-family: 'Segoe UI', system-ui, sans-serif;
            }
            QLabel {
                color: #cdd6f4;
            }
            QLineEdit {
                background-color: #11111b;
                color: #cdd6f4;
                border: 1px solid #313244;
                border-radius: 6px;
                padding: 10px;
                font-size: 13px;
                selection-background-color: #89b4fa;
            }
            QLineEdit:focus {
                border: 1px solid #89b4fa;
            }
            QLineEdit:disabled {
                background-color: #1e1e2e;
                color: #6c7086;
                border: 1px solid #313244;
            }
            QPushButton {
                font-weight: bold;
                border-radius: 6px;
                padding: 10px 16px;
                font-size: 13px;
                border: none;
            }
            QPushButton#btnConfirm {
                background-color: #89b4fa;
                color: #11111b;
            }
            QPushButton#btnConfirm:hover {
                background-color: #b4befe;
            }
            QPushButton#btnConfirm:disabled {
                background-color: #313244;
                color: #6c7086;
            }
            QPushButton#btnCancel {
                background-color: #313244;
                color: #cdd6f4;
            }
            QPushButton#btnCancel:hover {
                background-color: #45475a;
            }
            QPushButton#btnEye {
                background-color: #313244;
                color: #cdd6f4;
                padding: 10px 12px;
                font-size: 14px;
            }
            QPushButton#btnEye:hover {
                background-color: #45475a;
            }
        """)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(12)

        lbl_header = QLabel(f"<b>{title}</b>")
        lbl_header.setStyleSheet("font-size: 14px; color: #89b4fa;")
        layout.addWidget(lbl_header)

        self.lbl_prompt = QLabel(prompt)
        self.lbl_prompt.setWordWrap(True)
        self.lbl_prompt.setStyleSheet("font-size: 12px; color: #a6adc8; line-height: 1.4;")
        layout.addWidget(self.lbl_prompt)

        input_container = QHBoxLayout()
        input_container.setSpacing(6)

        self.edit_pwd = QLineEdit()
        self.edit_pwd.setEchoMode(QLineEdit.EchoMode.Password)
        self.edit_pwd.setPlaceholderText("Digite sua palavra-passe de recuperação...")
        self.edit_pwd.returnPressed.connect(self.on_confirm)
        input_container.addWidget(self.edit_pwd, stretch=1)

        self.btn_eye = QPushButton("👁️")
        self.btn_eye.setObjectName("btnEye")
        self.btn_eye.setToolTip("Alternar exibição da senha")
        self.btn_eye.clicked.connect(self.toggle_password_visibility)
        input_container.addWidget(self.btn_eye)
        layout.addLayout(input_container)

        self.lbl_status = QLabel("")
        self.lbl_status.setWordWrap(True)
        self.lbl_status.setStyleSheet("font-size: 12px; min-height: 22px;")
        layout.addWidget(self.lbl_status)

        btn_layout = QHBoxLayout()
        btn_layout.setSpacing(10)
        btn_layout.addStretch(1)

        self.btn_cancel = QPushButton("Cancelar")
        self.btn_cancel.setObjectName("btnCancel")
        self.btn_cancel.clicked.connect(self.reject)
        btn_layout.addWidget(self.btn_cancel)

        self.btn_confirm = QPushButton(confirm_text)
        self.btn_confirm.setObjectName("btnConfirm")
        self.btn_confirm.clicked.connect(self.on_confirm)
        btn_layout.addWidget(self.btn_confirm)

        layout.addLayout(btn_layout)

        self.lock_timer = QTimer(self)
        self.lock_timer.timeout.connect(self.update_lockout_tick)
        self.lock_timer.start(1000)

        self.update_lockout_tick()
        QTimer.singleShot(50, self.edit_pwd.setFocus)

    def toggle_password_visibility(self):
        if self.edit_pwd.echoMode() == QLineEdit.EchoMode.Password:
            self.edit_pwd.setEchoMode(QLineEdit.EchoMode.Normal)
            self.btn_eye.setText("🔒")
        else:
            self.edit_pwd.setEchoMode(QLineEdit.EchoMode.Password)
            self.btn_eye.setText("👁️")

    def update_lockout_tick(self):
        st = get_password_lockout_status()
        if st["is_locked"]:
            rem_s = st["remaining_seconds"]
            dur_str = format_lockout_duration(rem_s)
            self.lbl_status.setText(f"⏳ Sistema temporariamente bloqueado por excesso de tentativas incorretas.\nAguarde {dur_str} antes de tentar novamente.")
            self.lbl_status.setStyleSheet("color: #f38ba8; font-size: 12px; font-weight: bold;")
            self.btn_confirm.setEnabled(False)
            self.edit_pwd.setEnabled(False)
        else:
            if not self.btn_confirm.isEnabled() and not self._verifying:
                self.btn_confirm.setEnabled(True)
                self.edit_pwd.setEnabled(True)
                self.edit_pwd.setFocus()
            failed = st["failed_count"]
            if failed > 0 and not self._verifying and not self._has_error:
                rem_att = st["remaining_attempts"]
                self.lbl_status.setText(f"⚠️ Atenção: {failed}/5 tentativas incorretas registradas. Restam {rem_att} tentativa[s].")
                self.lbl_status.setStyleSheet("color: #fab387; font-size: 12px;")

    def on_confirm(self):
        pwd = self.edit_pwd.text().strip()
        if not pwd:
            self.lbl_status.setText("⚠️ Por favor, digite a sua palavra-passe.")
            self.lbl_status.setStyleSheet("color: #fab387; font-size: 12px;")
            self.edit_pwd.setFocus()
            return

        st = get_password_lockout_status()
        if st["is_locked"]:
            self.update_lockout_tick()
            return

        if self.verify_fn:
            self._verifying = True
            self.btn_confirm.setEnabled(False)
            self.edit_pwd.setEnabled(False)
            self.btn_cancel.setEnabled(False)
            self.lbl_status.setText("🔄 Validando palavra-passe com autenticidade matemática...")
            self.lbl_status.setStyleSheet("color: #89b4fa; font-size: 12px;")

            def _bg_worker():
                try:
                    ok, msg = self.verify_fn(pwd)
                except Exception as ex:
                    ok, msg = False, f"Erro inesperado: {ex}"

                def _ui_callback():
                    self._verifying = False
                    self.btn_confirm.setEnabled(True)
                    self.edit_pwd.setEnabled(True)
                    self.btn_cancel.setEnabled(True)
                    if ok:
                        self._has_error = False
                        self.lbl_status.setText("✅ Palavra-passe validada com sucesso!")
                        self.lbl_status.setStyleSheet("color: #a6e3a1; font-size: 12px; font-weight: bold;")
                        self.verified_password = pwd
                        QTimer.singleShot(250, self.accept)
                    else:
                        self._has_error = True
                        self.lbl_status.setText(f"❌ {msg}")
                        self.lbl_status.setStyleSheet("color: #f38ba8; font-size: 12px; font-weight: bold;")
                        self.edit_pwd.selectAll()
                        self.edit_pwd.setFocus()
                        self.update_lockout_tick()

                QTimer.singleShot(0, _ui_callback)

            threading.Thread(target=_bg_worker, daemon=True).start()
        else:
            self.verified_password = pwd
            self.accept()

    @classmethod
    def get_verified_password(
        cls,
        title: str,
        prompt: str,
        verify_fn: Optional[Callable[[str], Tuple[bool, str]]] = None,
        parent=None,
        confirm_text: str = "Confirmar"
    ) -> Tuple[str, bool]:
        dlg = cls(title, prompt, verify_fn=verify_fn, parent=parent, confirm_text=confirm_text)
        res = dlg.exec()
        if res == QDialog.DialogCode.Accepted:
            return dlg.verified_password, True
        return "", False


# -----------------------------------------------------------------------------
# SISTEMA DE VERIFICAÇÃO E ATUALIZAÇÃO DO APLICATIVO
# -----------------------------------------------------------------------------
APP_VERSION = "2.1.0"
GITHUB_REPO_URL = "https://github.com/egurken/admin-bridge"


class UpdateCheckWorker(QThread):
    finished_signal = pyqtSignal(bool, str, dict)

    def run(self):
        """Consulta as atualizações do aplicativo via Git local ou GitHub REST API."""
        result_data = {
            "current_version": APP_VERSION,
            "remote_commit": "",
            "remote_date": "",
            "commit_msg": "",
            "has_update": False,
            "is_git_repo": False,
            "git_status": ""
        }
        git_dir = BASE_DIR / ".git"
        if not git_dir.exists():
            curr_git = Path(__file__).resolve().parent / ".git"
            if curr_git.exists():
                git_dir = curr_git

        if git_dir.exists():
            result_data["is_git_repo"] = True
            try:
                subprocess.run(
                    ["git", "fetch", "origin", "main"],
                    cwd=str(git_dir.parent),
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=10,
                    creationflags=0x08000000 if sys.platform == "win32" else 0
                )
                proc_log = subprocess.run(
                    ["git", "log", "HEAD..origin/main", "--oneline"],
                    cwd=str(git_dir.parent),
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=5,
                    creationflags=0x08000000 if sys.platform == "win32" else 0
                )
                unpulled = proc_log.stdout.strip()
                if unpulled:
                    result_data["has_update"] = True
                    lines = unpulled.splitlines()
                    result_data["remote_commit"] = lines[0].split()[0]
                    result_data["commit_msg"] = "\n".join(lines[:5])
                    self.finished_signal.emit(True, f"Há {len(lines)} nova(s) atualização(ões) no repositório GitHub!", result_data)
                    return
                else:
                    self.finished_signal.emit(True, "Seu utilitário já está atualizado na versão mais recente do Git!", result_data)
                    return
            except Exception as e:
                result_data["git_status"] = f"Aviso Git: {e}"

        # Fallback: GitHub REST API pública
        try:
            import urllib.request
            req = urllib.request.Request(
                "https://api.github.com/repos/egurken/admin-bridge/commits/main",
                headers={"User-Agent": "AdminBridge-Updater-Client"}
            )
            with urllib.request.urlopen(req, timeout=6.0) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                sha = data.get("sha", "")[:7]
                commit_info = data.get("commit", {})
                msg = commit_info.get("message", "").split("\n")[0]
                dt = commit_info.get("author", {}).get("date", "")[:10]
                result_data["remote_commit"] = sha
                result_data["commit_msg"] = msg
                result_data["remote_date"] = dt
                self.finished_signal.emit(True, f"Último commit remoto verificado: [{sha}] - {msg}", result_data)
                return
        except Exception as e:
            self.finished_signal.emit(False, f"Não foi possível consultar o GitHub: {e}", result_data)


class UpdateDialog(QDialog):
    """Diálogo moderno e interativo de verificação e aplicação de atualizações."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("🚀 Atualização do Sistema • Admin Bridge")
        self.resize(520, 320)
        self.setMinimumWidth(440)
        self.setModal(True)
        self.last_data = {}

        app_icon = get_app_icon()
        if app_icon and not app_icon.isNull():
            self.setWindowIcon(app_icon)

        self.setStyleSheet("""
            QDialog {
                background-color: #181825;
                color: #cdd6f4;
                font-family: 'Segoe UI', system-ui, sans-serif;
            }
            QLabel {
                color: #cdd6f4;
            }
            QProgressBar {
                border: 1px solid #313244;
                border-radius: 6px;
                text-align: center;
                background-color: #11111b;
                color: #cdd6f4;
                font-weight: bold;
                height: 18px;
            }
            QProgressBar::chunk {
                background-color: #89b4fa;
                border-radius: 5px;
            }
            QPushButton {
                font-weight: bold;
                border-radius: 6px;
                padding: 10px 16px;
                font-size: 13px;
                border: none;
            }
            QPushButton#btnUpdate {
                background-color: #a6e3a1;
                color: #11111b;
            }
            QPushButton#btnUpdate:hover {
                background-color: #94e2d5;
            }
            QPushButton#btnClose {
                background-color: #313244;
                color: #cdd6f4;
            }
            QPushButton#btnClose:hover {
                background-color: #45475a;
            }
            QPlainTextEdit {
                background-color: #11111b;
                color: #a6adc8;
                border: 1px solid #313244;
                border-radius: 6px;
                font-family: 'Consolas', monospace;
                font-size: 11px;
                padding: 8px;
            }
        """)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(12)

        lbl_title = QLabel("<b>Central de Atualizações do Admin Bridge</b>")
        lbl_title.setStyleSheet("font-size: 15px; color: #89b4fa;")
        layout.addWidget(lbl_title)

        self.lbl_info = QLabel(f"Versão Instalada: <b>v{APP_VERSION}</b>\nVerificando atualizações no repositório GitHub...")
        self.lbl_info.setStyleSheet("font-size: 12px; color: #cdd6f4;")
        layout.addWidget(self.lbl_info)

        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 0)
        layout.addWidget(self.progress_bar)

        self.txt_notes = QPlainTextEdit()
        self.txt_notes.setReadOnly(True)
        self.txt_notes.hide()
        layout.addWidget(self.txt_notes, stretch=1)

        btn_layout = QHBoxLayout()
        btn_layout.setSpacing(10)
        btn_layout.addStretch(1)

        self.btn_close = QPushButton("Fechar")
        self.btn_close.setObjectName("btnClose")
        self.btn_close.clicked.connect(self.accept)
        btn_layout.addWidget(self.btn_close)

        self.btn_update = QPushButton("📥 Atualizar Agora")
        self.btn_update.setObjectName("btnUpdate")
        self.btn_update.hide()
        self.btn_update.clicked.connect(self.execute_update)
        btn_layout.addWidget(self.btn_update)

        layout.addLayout(btn_layout)

        self.worker = UpdateCheckWorker(self)
        self.worker.finished_signal.connect(self.on_check_finished)
        self.worker.start()

    def on_check_finished(self, success: bool, message: str, data: dict):
        self.progress_bar.hide()
        self.last_data = data
        if not success:
            self.lbl_info.setText(f"❌ {message}")
            self.lbl_info.setStyleSheet("color: #f38ba8; font-size: 12px;")
            return

        if data.get("has_update"):
            self.lbl_info.setText(f"🚀 <b>Nova atualização disponível!</b>\nCommit: {data.get('remote_commit', '')}")
            self.lbl_info.setStyleSheet("color: #a6e3a1; font-size: 13px;")
            self.txt_notes.setPlainText(data.get("commit_msg", ""))
            self.txt_notes.show()
            self.btn_update.show()
        else:
            self.lbl_info.setText(f"✅ {message}\nSeu sistema está 100% atualizado e alinhado.")
            self.lbl_info.setStyleSheet("color: #a6e3a1; font-size: 12px;")
            if data.get("commit_msg"):
                self.txt_notes.setPlainText(f"Último commit: {data.get('remote_commit', '')}\n{data.get('commit_msg', '')}")
                self.txt_notes.show()

    def execute_update(self):
        self.btn_update.setEnabled(False)
        self.btn_close.setEnabled(False)
        self.lbl_info.setText("🔄 Baixando e aplicando atualização do repositório...")
        self.progress_bar.show()

        def _pull_worker():
            try:
                git_dir = BASE_DIR / ".git"
                if not git_dir.exists():
                    curr_git = Path(__file__).resolve().parent / ".git"
                    if curr_git.exists():
                        git_dir = curr_git
                if git_dir.exists():
                    p = subprocess.run(
                        ["git", "pull", "origin", "main"],
                        cwd=str(git_dir.parent),
                        capture_output=True,
                        text=True,
                        check=False,
                        timeout=30,
                        creationflags=0x08000000 if sys.platform == "win32" else 0
                    )
                    return True, p.stdout or "Atualizado com sucesso."
                return False, "Repositório local não configurado para git pull."
            except Exception as e:
                return False, str(e)

        def _on_done(res):
            ok, msg = res
            self.progress_bar.hide()
            self.btn_close.setEnabled(True)
            if ok:
                self.lbl_info.setText("✅ <b>Atualização aplicada com sucesso!</b>\nReinicie a Central de Gestão para carregar os novos arquivos.")
                self.lbl_info.setStyleSheet("color: #a6e3a1; font-size: 13px;")
                self.txt_notes.setPlainText(msg)
                self.btn_update.setText("Reiniciar Agora")
                self.btn_update.setEnabled(True)
                self.btn_update.clicked.disconnect()
                self.btn_update.clicked.connect(self.restart_app)
            else:
                self.lbl_info.setText(f"❌ Falha ao aplicar atualização: {msg}")
                self.lbl_info.setStyleSheet("color: #f38ba8; font-size: 12px;")

        threading.Thread(target=lambda: _on_done(_pull_worker()), daemon=True).start()

    def restart_app(self):
        try:
            subprocess.Popen([sys.executable] + sys.argv[1:], creationflags=0x08000000 if sys.platform == "win32" else 0)
        except Exception:
            pass
        QApplication.quit()


# -----------------------------------------------------------------------------
# JANELA PRINCIPAL DA CENTRAL DE GESTÃO (SYSTEM TRAY & DASHBOARD)
# -----------------------------------------------------------------------------

class LocalAIWorker(QThread):
    progress_signal = pyqtSignal(int, str, str)
    finished_signal = pyqtSignal(bool, str)

    def run(self):
        def _cb(percent: int, msg: str, stage: str = ""):
            self.progress_signal.emit(percent, msg, stage)

        ok, msg = pull_and_test_local_slm(progress_callback=_cb)
        self.finished_signal.emit(ok, msg)


class LocalAIInstallerDialog(QDialog):
    """Diálogo visual moderno com barra de progresso, taxa em MB e log em tempo real do download da Mini-IA."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Instalador da Mini-IA Local [Qwen 2.5 0.5B]")
        self.resize(560, 380)
        self.setMinimumWidth(480)
        self.setModal(True)
        self.worker = None

        app_icon = get_app_icon()
        if app_icon and not app_icon.isNull():
            self.setWindowIcon(app_icon)

        self.setStyleSheet("""
            QDialog {
                background-color: #181825;
                color: #cdd6f4;
                font-family: 'Segoe UI', system-ui, sans-serif;
            }
            QLabel {
                color: #cdd6f4;
            }
            QProgressBar {
                background-color: #11111b;
                border: 1px solid #313244;
                border-radius: 6px;
                text-align: center;
                color: #cdd6f4;
                font-weight: bold;
                height: 24px;
            }
            QProgressBar::chunk {
                background-color: #89b4fa;
                border-radius: 5px;
            }
            QPlainTextEdit {
                background-color: #11111b;
                color: #a6adc8;
                border: 1px solid #313244;
                border-radius: 6px;
                font-family: Consolas, monospace;
                font-size: 11px;
                padding: 6px;
            }
            QPushButton {
                font-weight: bold;
                border-radius: 6px;
                padding: 9px 18px;
                font-size: 13px;
                border: none;
                background-color: #313244;
                color: #cdd6f4;
            }
            QPushButton:hover {
                background-color: #45475a;
            }
        """)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(22, 18, 22, 18)
        layout.setSpacing(10)

        lbl_title = QLabel("<b>🤖 Assistente de Segurança Local [Mini-IA]</b>")
        lbl_title.setStyleSheet("font-size: 15px; color: #89b4fa;")
        layout.addWidget(lbl_title)

        lbl_desc = QLabel(
            "Configuração e validação automática do modelo ultraleve 'qwen2.5:0.5b' [~397 MB].\n"
            "O modelo é mantido fora da memória RAM [0 MB consumidos em repouso] e ativado apenas sob demanda na Camada 3."
        )
        lbl_desc.setWordWrap(True)
        lbl_desc.setStyleSheet("font-size: 12px; color: #a6adc8; line-height: 1.4;")
        layout.addWidget(lbl_desc)

        self.lbl_status = QLabel("Iniciando processo de verificação...")
        self.lbl_status.setStyleSheet("font-size: 12px; font-weight: bold; color: #cdd6f4;")
        layout.addWidget(self.lbl_status)

        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(5)
        layout.addWidget(self.progress_bar)

        self.lbl_details = QLabel("Aguardando conexão com o motor Ollama...")
        self.lbl_details.setStyleSheet("font-size: 11px; color: #89b4fa;")
        layout.addWidget(self.lbl_details)

        self.log_view = QPlainTextEdit()
        self.log_view.setReadOnly(True)
        self.log_view.setFixedHeight(120)
        layout.addWidget(self.log_view)

        btn_row = QHBoxLayout()
        btn_row.addStretch(1)
        self.btn_action = QPushButton("Cancelar")
        self.btn_action.clicked.connect(self.on_btn_clicked)
        btn_row.addWidget(self.btn_action)
        layout.addLayout(btn_row)

        self._finished = False
        self._success = False
        self._success_msg = ""

        QTimer.singleShot(150, self.start_installation)

    def start_installation(self):
        self.worker = LocalAIWorker(self)
        self.worker.progress_signal.connect(self.on_progress)
        self.worker.finished_signal.connect(self.on_finished)
        self.worker.start()

    def on_progress(self, percent: int, msg: str, stage: str):
        self.progress_bar.setValue(percent)
        self.lbl_details.setText(msg)
        if stage == "server":
            self.lbl_status.setText("1/3 Conectando ao motor Ollama...")
        elif stage == "download":
            self.lbl_status.setText("2/3 Baixando modelo neural...")
        elif stage == "test":
            self.lbl_status.setText("3/3 Executando teste prático de inferência...")
        elif stage == "done":
            self.lbl_status.setText("Concluído!")

        self.log_view.appendPlainText(msg)
        sb = self.log_view.verticalScrollBar()
        if sb:
            sb.setValue(sb.maximum())

    def on_finished(self, success: bool, msg: str):
        self._finished = True
        self._success = success
        self._success_msg = msg
        if success:
            self.progress_bar.setValue(100)
            self.progress_bar.setStyleSheet("QProgressBar::chunk { background-color: #a6e3a1; }")
            self.lbl_status.setText("✅ Mini-IA instalada e validada com sucesso!")
            self.lbl_status.setStyleSheet("font-size: 13px; font-weight: bold; color: #a6e3a1;")
            self.lbl_details.setText("Modelo homologado. Zero consumo de RAM em repouso [keep_alive=0s].")
            self.btn_action.setText("Concluir")
            self.btn_action.setStyleSheet("background-color: #a6e3a1; color: #11111b; font-weight: bold;")
            self.log_view.appendPlainText(f"\n{msg}")
            if self.parent() and hasattr(self.parent(), "act_install_ai"):
                self.parent().act_install_ai.setVisible(False)
        else:
            self.lbl_status.setText("❌ Falha na instalação ou no teste de verificação.")
            self.lbl_status.setStyleSheet("font-size: 13px; font-weight: bold; color: #f38ba8;")
            self.lbl_details.setText("Consulte os detalhes abaixo para corrigir.")
            self.btn_action.setText("Fechar")
            self.log_view.appendPlainText(f"\nERRO: {msg}")

        sb = self.log_view.verticalScrollBar()
        if sb:
            sb.setValue(sb.maximum())

    def on_btn_clicked(self):
        if self._finished:
            if self._success:
                self.accept()
            else:
                self.reject()
        else:
            self.reject()

    def closeEvent(self, event):
        if not self._finished and self.worker and self.worker.isRunning():
            try:
                self.worker.terminate()
            except Exception:
                pass
        event.accept()


def pull_and_test_local_ai_with_ui(parent=None) -> Tuple[bool, str]:
    """Abre o diálogo interativo de instalação e validação da Mini-IA com feedback em tempo real."""
    dlg = LocalAIInstallerDialog(parent)
    res = dlg.exec()
    if res == QDialog.DialogCode.Accepted:
        return True, dlg._success_msg
    return dlg._success, dlg._success_msg or "Operação cancelada pelo usuário."


class AdminBridgeWindow(QMainWindow):
    def __init__(self, hotp_auth: HOTPAuth):
        super().__init__()
        self.hotp_auth = hotp_auth
        self.current_request = None
        self.exec_thread = None

        self.setWindowTitle("Admin Bridge • Central de Gestão")
        self.resize(1080, 580)
        self.setMinimumSize(560, 460)
        self._history_user_hidden = False

        app_icon = get_app_icon()
        self.setWindowIcon(app_icon)

        self.init_ui()
        self.init_tray()

        self._last_history_sig = None
        self._last_metrics_sig = None

        # Timer de verificação rápida da fila de comandos (350ms para resposta imediata na UI)
        self.timer_queue = QTimer(self)
        self.timer_queue.timeout.connect(self.check_requests)
        self.timer_queue.start(350)

        # Timer de heartbeat
        self.timer_heartbeat = QTimer(self)
        self.timer_heartbeat.timeout.connect(self.write_heartbeat)
        self.timer_heartbeat.start(3000)
        self.write_heartbeat()

        # Timer de atualizacao automatica periodica do dashboard
        self.timer_dashboard = QTimer(self)
        self.timer_dashboard.timeout.connect(self.refresh_dashboard)
        self.timer_dashboard.start(2500)

        # Atualiza métricas iniciais
        self.refresh_dashboard()

        # Checagem não-bloqueante em segundo plano do motor de IA
        QTimer.singleShot(1500, self._check_ai_status_background)

    def init_ui(self):
        central_widget = QWidget()
        central_widget.setObjectName("centralWidget")
        self.setCentralWidget(central_widget)

        self.setStyleSheet("""
            QMainWindow {
                background-color: #11111b;
            }
            #centralWidget {
                background-color: #11111b;
                font-family: 'Segoe UI', system-ui, sans-serif;
            }
            QFrame.card {
                background-color: #181825;
                border: 1px solid #313244;
                border-radius: 8px;
                padding: 14px;
            }
            QLabel {
                color: #cdd6f4;
            }
            QLabel.metricTitle {
                color: #a6adc8;
                font-size: 11px;
                font-weight: 600;
                text-transform: uppercase;
            }
            QLabel.metricValue {
                font-size: 22px;
                font-weight: bold;
                color: #cdd6f4;
            }
            QPlainTextEdit#codeViewer {
                background-color: #11111b;
                color: #a6e3a1;
                font-family: 'Consolas', 'Courier New', monospace;
                font-size: 12px;
                border: 1px solid #313244;
                border-radius: 6px;
                padding: 10px;
            }
            QPushButton {
                font-weight: bold;
                border-radius: 6px;
                padding: 10px 16px;
                font-size: 13px;
                border: none;
            }
            QPushButton#btnApprove {
                background-color: #a6e3a1;
                color: #11111b;
            }
            QPushButton#btnApprove:hover {
                background-color: #94e2d5;
            }
            QPushButton#btnReject {
                background-color: #f38ba8;
                color: #11111b;
            }
            QPushButton#btnReject:hover {
                background-color: #eba0ac;
            }
            QPushButton#btnAction {
                background-color: #313244;
                color: #cdd6f4;
            }
            QPushButton#btnAction:hover {
                background-color: #45475a;
            }
            QPushButton#btnDanger {
                background-color: #452a36;
                color: #f38ba8;
                border: 1px solid #f38ba8;
            }
            QPushButton#btnDanger:hover {
                background-color: #f38ba8;
                color: #11111b;
            }
            QPushButton#btnIconAction {
                background-color: #181825;
                color: #cdd6f4;
                border: 1px solid #313244;
                border-radius: 6px;
                font-size: 15px;
                padding: 4px;
                min-width: 32px;
                max-width: 32px;
                min-height: 32px;
                max-height: 32px;
            }
            QPushButton#btnIconAction:hover {
                background-color: #313244;
                border-color: #89b4fa;
            }
            QPushButton#btnIconAction::menu-indicator {
                image: none;
                width: 0px;
            }
            QTableWidget {
                background-color: #181825;
                color: #cdd6f4;
                gridline-color: #313244;
                border: 1px solid #313244;
                border-radius: 6px;
                font-size: 12px;
            }
            QHeaderView::section {
                background-color: #1e1e2e;
                color: #a6adc8;
                padding: 6px;
                font-weight: bold;
                border: 1px solid #313244;
            }
            QTableWidget::item:selected {
                background-color: #313244;
                color: #89b4fa;
            }
        """)

        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(18, 16, 18, 16)
        main_layout.setSpacing(12)

        # -------------------------------------------------------------
        # BARRA DE TÍTULO SUPERIOR & AÇÕES (🔄 e ⚙️)
        # -------------------------------------------------------------
        top_bar = QHBoxLayout()
        top_bar.setContentsMargins(0, 0, 0, 2)

        title_layout = QVBoxLayout()
        title_layout.setSpacing(1)
        lbl_app_title = QLabel("Admin Bridge")
        lbl_app_title.setStyleSheet("font-size: 16px; font-weight: bold; color: #cdd6f4;")
        lbl_app_sub = QLabel("Central de Gestão e Autorização Elevada HOTP")
        lbl_app_sub.setStyleSheet("font-size: 11px; color: #a6adc8;")
        title_layout.addWidget(lbl_app_title)
        title_layout.addWidget(lbl_app_sub)
        top_bar.addLayout(title_layout)

        top_bar.addStretch()

        # Botão Alternar Painel Lateral de Histórico (📜)
        self.btn_toggle_hist = QPushButton("📜")
        self.btn_toggle_hist.setObjectName("btnIconAction")
        self.btn_toggle_hist.setToolTip("Mostrar / Ocultar Painel Lateral de Histórico")
        self.btn_toggle_hist.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.btn_toggle_hist.clicked.connect(self.toggle_history_panel)
        top_bar.addWidget(self.btn_toggle_hist)

        # Botão Recarregar (apenas a setinha 🔄)
        self.btn_refresh = QPushButton("🔄")
        self.btn_refresh.setObjectName("btnIconAction")
        self.btn_refresh.setToolTip("Recarregar Histórico e Métricas")
        self.btn_refresh.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.btn_refresh.clicked.connect(self.refresh_dashboard)
        top_bar.addWidget(self.btn_refresh)

        # Botão Engrenagem (⚙️ com menu suspenso para Reset, Desinstalação e Status)
        self.btn_settings = QPushButton("⚙️")
        self.btn_settings.setObjectName("btnIconAction")
        self.btn_settings.setToolTip("Opções e Configurações")
        self.btn_settings.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))

        self.settings_menu = QMenu(self)
        self.settings_menu.setStyleSheet("""
            QMenu {
                background-color: #1e1e2e;
                color: #cdd6f4;
                border: 1px solid #313244;
                border-radius: 6px;
                padding: 4px;
                font-family: 'Segoe UI', system-ui, sans-serif;
                font-size: 12px;
            }
            QMenu::item {
                padding: 6px 16px;
                border-radius: 4px;
            }
            QMenu::item:selected {
                background-color: #313244;
                color: #89b4fa;
            }
        """)

        act_sync = QAction("🔍 Testar Sincronia do Autenticador...", self)
        act_sync.triggered.connect(self.show_sync_test_dialog)
        self.settings_menu.addAction(act_sync)

        self.act_install_ai = QAction("🤖 Instalar e Testar Mini-IA Local [Qwen 0.5B]...", self)
        self.act_install_ai.triggered.connect(self.install_local_ai_assistant)
        self.settings_menu.addAction(self.act_install_ai)
        if is_local_slm_verified(probe_network=False):
            self.act_install_ai.setVisible(False)

        act_status = QAction("📋 Status Detalhado do Contador", self)
        act_status.triggered.connect(self.show_counter_status_dialog)
        self.settings_menu.addAction(act_status)

        act_revoke_auth = QAction("⏹️ Encerrar Modo Auth [45 min]", self)
        act_revoke_auth.triggered.connect(self.revoke_auth_session)
        self.settings_menu.addAction(act_revoke_auth)

        self.settings_menu.addSeparator()

        act_update = QAction("🚀 Verificar Atualizações...", self)
        act_update.triggered.connect(self.show_update_dialog)
        self.settings_menu.addAction(act_update)

        act_reset = QAction("🔄 Reiniciar Configuração...", self)
        act_reset.triggered.connect(self.open_reset_dialog)
        self.settings_menu.addAction(act_reset)

        act_uninstall = QAction("🗑️ Desinstalar Utilitário...", self)
        act_uninstall.triggered.connect(self.open_uninstall_dialog)
        self.settings_menu.addAction(act_uninstall)

        self.settings_menu.addSeparator()

        act_quit = QAction("❌ Encerrar Utilitário", self)
        act_quit.triggered.connect(self.quit_app)
        self.settings_menu.addAction(act_quit)

        self.btn_settings.setMenu(self.settings_menu)
        top_bar.addWidget(self.btn_settings)

        main_layout.addLayout(top_bar)

        # Layout Horizontal de 2 Colunas: Esquerda (Controle/Aprovação) | Direita (Histórico Lateral Auto-Ocultável)
        body_split_layout = QHBoxLayout()
        body_split_layout.setContentsMargins(0, 0, 0, 0)
        body_split_layout.setSpacing(14)
        main_layout.addLayout(body_split_layout, stretch=1)

        left_panel = QWidget()
        left_layout = QVBoxLayout(left_panel)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.setSpacing(12)
        body_split_layout.addWidget(left_panel, stretch=3)

        # -------------------------------------------------------------
        # CABEÇALHO & PAINEL SUPERIOR DE MÉTRICAS (REQUISITO 2a)
        # -------------------------------------------------------------
        metrics_layout = QHBoxLayout()
        metrics_layout.setSpacing(12)

        # Card 1: Contador Atual
        card_counter = QFrame()
        card_counter.setProperty("class", "card")
        cc_layout = QVBoxLayout(card_counter)
        lbl_c_title = QLabel("Contador HOTP Atual")
        lbl_c_title.setProperty("class", "metricTitle")
        self.lbl_counter_val = QLabel("0")
        self.lbl_counter_val.setProperty("class", "metricValue")
        self.lbl_counter_val.setStyleSheet("color: #89b4fa;")
        cc_layout.addWidget(lbl_c_title)
        cc_layout.addWidget(self.lbl_counter_val)
        metrics_layout.addWidget(card_counter, 1)

        # Card 2: Estado do Serviço
        card_status = QFrame()
        card_status.setProperty("class", "card")
        cs_layout = QVBoxLayout(card_status)
        lbl_s_title = QLabel("Estado do Serviço")
        lbl_s_title.setProperty("class", "metricTitle")
        self.lbl_status_val = QLabel("Ativo")
        self.lbl_status_val.setProperty("class", "metricValue")
        self.lbl_status_val.setStyleSheet("color: #a6e3a1;")
        cs_layout.addWidget(lbl_s_title)
        cs_layout.addWidget(self.lbl_status_val)

        self.btn_repair = QPushButton("🔧 Corrigir")
        self.btn_repair.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.btn_repair.setStyleSheet("background-color: #f38ba8; color: #11111b; font-weight: bold; border-radius: 4px; padding: 4px 8px; font-size: 11px;")
        self.btn_repair.clicked.connect(self.prompt_and_execute_repair)
        self.btn_repair.hide()
        cs_layout.addWidget(self.btn_repair)

        metrics_layout.addWidget(card_status, 1)

        # Card 3: Falhas Recentes (Fail-Safe)
        card_fails = QFrame()
        card_fails.setProperty("class", "card")
        cf_layout = QVBoxLayout(card_fails)
        lbl_f_title = QLabel("Disjuntor Fail-Safe")
        lbl_f_title.setProperty("class", "metricTitle")
        self.lbl_fails_val = QLabel("0 / 3 Falhas")
        self.lbl_fails_val.setProperty("class", "metricValue")
        self.lbl_fails_val.setStyleSheet("color: #fab387;")
        cf_layout.addWidget(lbl_f_title)
        cf_layout.addWidget(self.lbl_fails_val)
        metrics_layout.addWidget(card_fails, 1)

        left_layout.addLayout(metrics_layout)

        # -------------------------------------------------------------
        # ÁREA DE COMANDO PENDENTE (MODO HÍBRIDO / UAC)
        # -------------------------------------------------------------
        self.card_pending = QFrame()
        self.card_pending.setProperty("class", "card")
        pending_layout = QVBoxLayout(self.card_pending)
        pending_layout.setContentsMargins(14, 12, 14, 12)
        pending_layout.setSpacing(8)

        header_pending = QHBoxLayout()
        self.lbl_req_title = QLabel("Aguardando solicitações...")
        self.lbl_req_title.setStyleSheet("font-size: 14px; font-weight: bold; color: #89b4fa;")
        header_pending.addWidget(self.lbl_req_title)

        header_pending.addStretch()

        self.lbl_badge = QLabel("INATIVO")
        self.lbl_badge.setFixedHeight(24)
        self.lbl_badge.setMinimumWidth(72)
        self.lbl_badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
        if QSizePolicy is not None:
            self.lbl_badge.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)
        self.lbl_badge.setStyleSheet("background-color: #313244; color: #a6adc8; padding: 2px 10px; border-radius: 4px; font-size: 11px; font-weight: bold;")
        header_pending.addWidget(self.lbl_badge)
        pending_layout.addLayout(header_pending)

        self.lbl_req_sub = QLabel("Aplicações clientes enviarão solicitações aqui quando precisarem executar comandos.")
        self.lbl_req_sub.setStyleSheet("font-size: 12px; color: #a6adc8;")
        pending_layout.addWidget(self.lbl_req_sub)

        self.code_viewer = QPlainTextEdit()
        self.code_viewer.setObjectName("codeViewer")
        self.code_viewer.setReadOnly(True)
        self.code_viewer.setFixedHeight(110)
        self.code_viewer.setPlaceholderText("Nenhum comando pendente de aprovação.")
        self.code_viewer.hide()
        pending_layout.addWidget(self.code_viewer)

        self.btn_box_widget = QWidget()
        btn_box_main = QVBoxLayout(self.btn_box_widget)
        btn_box_main.setContentsMargins(0, 4, 0, 0)
        btn_box_main.setSpacing(8)

        # Linha 1: Autorização rápida com NOVO código OTP de 6 dígitos (para scripts pausados pela IA / Camada 3)
        otp_stepup_row = QHBoxLayout()
        otp_stepup_row.setSpacing(8)
        self.txt_stepup_otp = QLineEdit()
        self.txt_stepup_otp.setMaxLength(6)
        self.txt_stepup_otp.setPlaceholderText("Novo OTP (6 dígitos)")
        self.txt_stepup_otp.setFixedWidth(180)
        self.txt_stepup_otp.setStyleSheet("background-color: #1e1e2e; color: #a6e3a1; font-family: Consolas, monospace; font-size: 14px; font-weight: bold; padding: 6px 10px; border: 1px solid #45475a; border-radius: 6px;")
        self.txt_stepup_otp.returnPressed.connect(self.approve_request_with_new_otp)
        otp_stepup_row.addWidget(self.txt_stepup_otp)

        self.btn_approve_otp = QPushButton("🔑 Autorizar Mesmo Assim com Novo OTP")
        self.btn_approve_otp.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.btn_approve_otp.setStyleSheet("background-color: #89b4fa; color: #11111b; font-weight: bold; border-radius: 6px; padding: 8px 14px;")
        self.btn_approve_otp.clicked.connect(self.approve_request_with_new_otp)
        otp_stepup_row.addWidget(self.btn_approve_otp, 1)
        btn_box_main.addLayout(otp_stepup_row)

        # Linha 2: Rejeitar ou Autorizar via clique UAC na tela
        btn_box = QHBoxLayout()
        btn_box.setSpacing(10)

        self.btn_reject = QPushButton("✖ Rejeitar e Bloquear Script")
        self.btn_reject.setObjectName("btnReject")
        self.btn_reject.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.btn_reject.clicked.connect(self.reject_request)
        self.btn_reject.setEnabled(False)
        btn_box.addWidget(self.btn_reject)

        self.btn_approve = QPushButton("✔ Autorizar Mesmo Assim via UAC")
        self.btn_approve.setObjectName("btnApprove")
        self.btn_approve.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.btn_approve.clicked.connect(self.approve_request)
        self.btn_approve.setEnabled(False)
        btn_box.addWidget(self.btn_approve)

        btn_box_main.addLayout(btn_box)
        self.btn_box_widget.hide()
        pending_layout.addWidget(self.btn_box_widget)
        pending_layout.addStretch(1)

        left_layout.addWidget(self.card_pending, stretch=1)

        # -------------------------------------------------------------
        # PAINEL LATERAL DIREITO DE HISTÓRICO (AUTO-OCULTÁVEL SE FALTAR ESPAÇO)
        # -------------------------------------------------------------
        self.history_panel = QFrame()
        self.history_panel.setProperty("class", "card")
        self.history_panel.setMinimumWidth(360)
        hist_layout = QVBoxLayout(self.history_panel)
        hist_layout.setContentsMargins(10, 10, 10, 10)
        hist_layout.setSpacing(8)

        lbl_hist_title = QLabel("📜 Histórico de Auditoria")
        lbl_hist_title.setStyleSheet("font-size: 13px; font-weight: bold; color: #a6adc8;")
        hist_layout.addWidget(lbl_hist_title)

        self.table_history = QTableWidget()
        self.table_history.setColumnCount(4)
        self.table_history.setHorizontalHeaderLabels(["Data/Hora", "Operação", "Estado", "OTP"])
        self.table_history.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.table_history.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.table_history.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.table_history.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self.table_history.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table_history.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        hist_layout.addWidget(self.table_history, stretch=1)

        body_split_layout.addWidget(self.history_panel, stretch=2)

    def init_tray(self):
        self.tray_icon = QSystemTrayIcon(self)
        self.tray_icon.setToolTip("Admin Bridge")
        app_icon = get_app_icon()
        self.tray_icon.setIcon(app_icon)

        tray_menu = QMenu()
        tray_menu.setStyleSheet("""
            QMenu {
                background-color: #1e1e2e;
                color: #cdd6f4;
                border: 1px solid #313244;
                border-radius: 6px;
                padding: 4px;
                font-family: 'Segoe UI', system-ui, sans-serif;
                font-size: 12px;
            }
            QMenu::item {
                padding: 6px 14px;
                border-radius: 4px;
            }
            QMenu::item:selected {
                background-color: #313244;
                color: #89b4fa;
            }
        """)
        open_action = QAction("Abrir Central de Gestão", self)
        open_action.triggered.connect(self.show_window)
        tray_menu.addAction(open_action)

        status_action = QAction("📋 Status do Contador", self)
        status_action.triggered.connect(self.show_counter_status_dialog)
        tray_menu.addAction(status_action)

        tray_menu.addSeparator()

        reset_action = QAction("🔄 Reiniciar Configuração...", self)
        reset_action.triggered.connect(self.open_reset_dialog)
        tray_menu.addAction(reset_action)

        uninstall_action = QAction("🗑️ Desinstalar Utilitário...", self)
        uninstall_action.triggered.connect(self.open_uninstall_dialog)
        tray_menu.addAction(uninstall_action)

        tray_menu.addSeparator()

        update_action = QAction("🚀 Verificar Atualizações...", self)
        update_action.triggered.connect(self.show_update_dialog)
        tray_menu.addAction(update_action)

        quit_action = QAction("❌ Encerrar Utilitário", self)
        quit_action.triggered.connect(self.quit_app)
        tray_menu.addAction(quit_action)

        self.tray_icon.setContextMenu(tray_menu)
        self.tray_icon.activated.connect(self.on_tray_activated)
        self.tray_icon.show()

    def on_tray_activated(self, reason):
        if reason == QSystemTrayIcon.ActivationReason.Trigger:
            if self.isVisible():
                self.hide()
            else:
                self.show_window()

    def show_window(self):
        self.show()
        self.setWindowState(self.windowState() & ~Qt.WindowState.WindowMinimized | Qt.WindowState.WindowActive)
        self.raise_()
        self.activateWindow()
        try:
            hwnd = int(self.winId())
            ctypes.windll.user32.ShowWindow(hwnd, 9)  # SW_RESTORE
            ctypes.windll.user32.SetForegroundWindow(hwnd)
        except Exception:
            pass
        self.refresh_dashboard()

    def closeEvent(self, event):
        # Fecha para a bandeja sem encerrar o processo
        event.ignore()
        self.hide()
        if self.tray_icon.isVisible():
            self.tray_icon.showMessage(
                "Admin Bridge",
                "A Central continua em execução na bandeja do sistema.",
                QSystemTrayIcon.MessageIcon.Information,
                2000
            )

    def toggle_history_panel(self):
        """Alterna manualmente a exibição do painel lateral de histórico."""
        if self.history_panel.isVisible():
            self._history_user_hidden = True
            self.history_panel.hide()
        else:
            self._history_user_hidden = False
            self.history_panel.show()

    def resizeEvent(self, event):
        """Esconde automaticamente o painel lateral de histórico se a janela ficar estreita (< 880px)."""
        super().resizeEvent(event)
        if hasattr(self, "history_panel"):
            if self.width() < 880:
                if self.history_panel.isVisible():
                    self.history_panel.hide()
            else:
                if not getattr(self, "_history_user_hidden", False) and not self.history_panel.isVisible():
                    self.history_panel.show()

    def show_update_dialog(self):
        """Abre o diálogo interativo de verificação e aplicação de atualizações."""
        dlg = UpdateDialog(self)
        dlg.exec()

    def _check_ai_status_background(self):
        """Verifica se a Mini-IA Local está pronta em background sem engasgar o startup."""
        def _bg():
            try:
                if is_local_slm_verified(probe_network=True):
                    if hasattr(self, "act_install_ai"):
                        QTimer.singleShot(0, lambda: self.act_install_ai.setVisible(False))
            except Exception:
                pass
        threading.Thread(target=_bg, daemon=True).start()

    def quit_app(self, force_no_prompt: bool = False):
        """Exige a Palavra-passe de Recuperação antes de permitir encerrar a Central de Gestão."""
        if not force_no_prompt and self.hotp_auth.is_provisioned():
            # Se o serviço estiver offline e o processo não for admin, tenta acordar o serviço via schtasks
            if not is_admin() and not self.hotp_auth._is_daemon_alive_other_process():
                try:
                    subprocess.run(["schtasks", "/run", "/tn", "AdminBridge"], capture_output=True, check=False, creationflags=0x08000000)
                    time.sleep(0.5)
                except Exception:
                    pass

            pwd, ok = ResponsivePasswordDialog.get_verified_password(
                title="Autenticação Obrigatória • Encerrar Utilitário",
                prompt="Digite sua Palavra-passe de Recuperação para encerrar o Admin Bridge:",
                verify_fn=self.hotp_auth.verify_quit_password,
                parent=self,
                confirm_text="Encerrar"
            )
            if not ok or not pwd:
                # Se falhou porque o serviço está offline e sem permissões, oferece encerramento com confirmação
                if not is_admin() and not self.hotp_auth._is_daemon_alive_other_process():
                    force_ans = QMessageBox.question(
                        self,
                        "Serviço Offline",
                        "O serviço em segundo plano está offline e não foi possível validar a senha localmente.\n\nDeseja forçar o encerramento da interface gráfica agora?",
                        QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                        QMessageBox.StandardButton.No
                    )
                    if force_ans == QMessageBox.StandardButton.Yes:
                        self.tray_icon.hide()
                        QApplication.quit()
                return
        self.tray_icon.hide()
        QApplication.quit()

    def write_heartbeat(self):
        # Somente grava heartbeat da GUI se o daemon SYSTEM não estiver ativo e se tiver permissão
        if not is_admin():
            return
        try:
            if HEARTBEAT_FILE.exists():
                hb = json.loads(HEARTBEAT_FILE.read_text(encoding="utf-8"))
                if hb.get("mode") == "daemon" and (time.time() - float(hb.get("timestamp", 0))) < 6.0:
                    return
            with open(HEARTBEAT_FILE, "w", encoding="utf-8") as f:
                json.dump({
                    "timestamp": time.time(),
                    "status": "online",
                    "mode": "gui",
                    "pid": os.getpid()
                }, f)
        except Exception:
            pass

    def refresh_dashboard(self):
        """Atualiza os cards de métricas e a tabela de histórico recente."""
        # 1. Lê metadados passivos
        status_data = self.hotp_auth.get_counter_status()
        counter = status_data.get("counter", 0)
        status_text = status_data.get("status_text", "Ativo")
        fails = status_data.get("recent_failures", 0)
        max_fails = status_data.get("max_failures", 3)

        self.lbl_counter_val.setText(str(counter))
        self.lbl_status_val.setText(status_text)
        self.lbl_fails_val.setText(f"{fails} / {max_fails} Falhas")

        if status_data.get("auth_mode_active"):
            mins = status_data.get("auth_expires_in", 0) // 60
            self.lbl_status_val.setText(f"Modo Auth Ativo [{mins}m]")
            self.lbl_status_val.setStyleSheet("color: #89b4fa;")
            self.btn_repair.hide()
        elif "adulteração" in status_text.lower() or status_data.get("tampered"):
            self.lbl_status_val.setText("Bloqueado por adulteração")
            self.lbl_status_val.setStyleSheet("color: #f38ba8;")
            self.btn_repair.show()
        elif "Bloqueado" in status_text or status_data.get("lockdown"):
            self.lbl_status_val.setStyleSheet("color: #f38ba8;")
            self.btn_repair.hide()
        elif "Aguardando" in status_text:
            self.lbl_status_val.setStyleSheet("color: #f9e2af;")
            self.btn_repair.hide()
        else:
            self.lbl_status_val.setStyleSheet("color: #a6e3a1;")
            self.btn_repair.hide()

        # 2. Popula a tabela de histórico apenas quando auth.log ou status.json realmente mudaram (preserva rolagem, seleção e zero uso de CPU)
        curr_log_sig = None
        try:
            if AUTH_LOG_FILE.exists():
                st_log = AUTH_LOG_FILE.stat()
                curr_log_sig = (int(st_log.st_mtime_ns), int(st_log.st_size))
        except Exception:
            curr_log_sig = None

        if curr_log_sig is None:
            try:
                if STATUS_FILE.exists():
                    st_stat = STATUS_FILE.stat()
                    curr_log_sig = ("status", int(st_stat.st_mtime_ns), int(st_stat.st_size))
            except Exception:
                curr_log_sig = None


        if curr_log_sig != getattr(self, "_last_history_sig", object()):
            self._last_history_sig = curr_log_sig
            history_items = load_recent_history(50)
            self.table_history.setUpdatesEnabled(False)
            try:
                self.table_history.setRowCount(len(history_items))
                for row, item in enumerate(history_items):
                    it_date = QTableWidgetItem(item["datetime"])
                    it_cmd = QTableWidgetItem(item["command"])
                    it_status = QTableWidgetItem(item["status"])
                    it_otp = QTableWidgetItem(item["otp"])

                    if item["status"] == "Aprovado":
                        it_status.setForeground(QColor("#a6e3a1"))
                    else:
                        it_status.setForeground(QColor("#f38ba8"))

                    it_otp.setForeground(QColor("#fab387"))

                    self.table_history.setItem(row, 0, it_date)
                    self.table_history.setItem(row, 1, it_cmd)
                    self.table_history.setItem(row, 2, it_status)
                    self.table_history.setItem(row, 3, it_otp)
            finally:
                self.table_history.setUpdatesEnabled(True)

    # -------------------------------------------------------------
    # PROCESSAMENTO ATÔMICO DA FILA DE REQUISIÇÕES
    # -------------------------------------------------------------
    def check_requests(self):
        if self.current_request or (self.exec_thread and self.exec_thread.isRunning()):
            return

        req_files = []
        try:
            if GUI_PENDING_DIR.exists():
                req_files.extend(sorted(GUI_PENDING_DIR.glob("*.json"), key=lambda p: p.stat().st_ctime_ns if p.exists() else 0))
        except Exception:
            pass
        if not req_files and is_admin():
            try:
                if REQUESTS_DIR.exists():
                    req_files.extend(sorted(REQUESTS_DIR.glob("*.json"), key=lambda p: p.stat().st_ctime_ns if p.exists() else 0))
            except Exception:
                pass
        if not req_files:
            return

        target_file = req_files[0]
        req_id = target_file.stem

        try:
            with open(target_file, "r", encoding="utf-8") as f:
                peek_req = json.load(f)
            if peek_req.get("script_type") in ("sync_probe", "control_rpc"):
                return
            if peek_req.get("step_up_gui_pending"):
                # O daemon SYSTEM pausou este script sensível (Camada 3) e encaminhou para aprovação visual na tela do usuário!
                pass
            else:
                has_auth_payload = bool(
                    peek_req.get("otp")
                    or peek_req.get("otp_dpapi")
                    or peek_req.get("preauth_token")
                    or peek_req.get("preauth_token_dpapi")
                )
                if has_auth_payload and not is_admin():
                    return
        except Exception:
            return

        # Reivindicação atômica: move para processing/ (se Admin) ou mantém em gui_pending/ (se Usuário padrão)
        active_proc_dir = PROCESSING_DIR if is_admin() else GUI_PENDING_DIR
        try:
            active_proc_dir.mkdir(parents=True, exist_ok=True)
        except Exception:
            pass
        processing_file = active_proc_dir / f"{req_id}.claim.json"
        try:
            target_file.rename(processing_file)
        except Exception:
            return

        try:
            with open(processing_file, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            processing_file.unlink(missing_ok=True)
            return

        code_str = data.get("code", "")
        expected_code_hash = data.get("code_hash") or hashlib.sha256(code_str.encode("utf-8")).hexdigest()
        actual_code_hash = hashlib.sha256(code_str.encode("utf-8")).hexdigest()
        if not hmac.compare_digest(actual_code_hash, expected_code_hash):
            processing_file.unlink(missing_ok=True)
            return

        provided_otp = data.get("otp")
        if not provided_otp and data.get("otp_dpapi"):
            provided_otp = unprotect_transit_token(data["otp_dpapi"], req_id, actual_code_hash)
        if data.get("preauth_token_dpapi") and not data.get("preauth_token"):
            data["preauth_token"] = unprotect_transit_token(data["preauth_token_dpapi"], req_id, actual_code_hash)
        caller_info = data.get("caller")

        if data.get("step_up_gui_pending"):
            logging.warning(f"[CAMADA 3 STEP-UP] Req: {req_id} pausada para revisao de risco pelo usuario na tela.")
            self.display_manual_uac_request(data, processing_file, data.get("step_up_report"))
            return

        if provided_otp:
            is_valid, auth_msg, used_counter = self.hotp_auth.verify_and_advance(provided_otp, caller_info)
            if not is_valid:
                is_lockdown = "FAIL_SAFE_LOCKDOWN" in auth_msg or self.hotp_auth.is_lockdown()
                masked_otp = (str(provided_otp)[:2] + "****") if len(str(provided_otp)) >= 2 else "******"
                logging.warning(f"[HOTP REJEITADO] Req: {req_id} | Motivo: {auth_msg} | OTP: {masked_otp}")

                res_file = RESPONSES_DIR / f"{req_id}.json"
                response = {
                    "id": req_id,
                    "status": "lockdown" if is_lockdown else "rejected_auth",
                    "reason": f"Autenticação HOTP recusada: {auth_msg}",
                    "exit_code": 403 if is_lockdown else 401,
                    "output": f"[ACESSO RECUSADO]: {auth_msg}\nEnvie um código válido no formato 'OTP: 123456'.",
                    "completed_at": datetime.now().astimezone().isoformat()
                }
                try:
                    with open(res_file, "w", encoding="utf-8") as f:
                        json.dump(response, f, indent=2, ensure_ascii=False)
                except Exception:
                    pass

                processing_file.unlink(missing_ok=True)
                self.refresh_dashboard()

                if is_lockdown:
                    if self.tray_icon.isVisible():
                        self.tray_icon.showMessage(
                            "Admin Bridge • LOCKDOWN ATIVADO",
                            "3 falhas consecutivas detectadas! Tarefa elevada removida.",
                            QSystemTrayIcon.MessageIcon.Critical,
                            6000
                        )
                    QTimer.singleShot(1500, lambda: self.quit_app(force_no_prompt=True))
                return

            # Código válido: executa com permissões elevadas
            logging.info(f"[HOTP APROVADO] Req: {req_id} autenticado! Contador: {used_counter - 1}")
            self.execute_authenticated_request(data, used_counter - 1, processing_file)
        else:
            # Verifica se há ticket de pré-autorização ativo (gerado via preauth no início do chat)
            preauth_token = data.get("preauth_token")
            caller_user = (caller_info or {}).get("user")
            ok_ticket, ticket_msg = self.hotp_auth.consume_preauth_ticket(preauth_token, caller_user)
            if ok_ticket:
                logging.info(f"[PRÉ-AUTORIZAÇÃO APROVADA] Req: {req_id} autenticado e executado via ticket.")
                self.execute_authenticated_request(data, 0, processing_file)
                return

            # Modo Híbrido: sem OTP nem ticket prévio, exibe na tela para aprovação
            logging.info(f"[MODO HÍBRIDO] Req: {req_id} sem OTP nem ticket prévio. Exigindo confirmação.")
            self.display_manual_uac_request(data, processing_file)

    def display_manual_uac_request(self, data, processing_file: Path, risk_report: Optional[dict] = None):
        self.current_request = data
        self.current_processing_file = processing_file

        title = data.get("title", "Comando Administrativo")
        desc = data.get("description", "Sem descrição informada.")
        script_type = data.get("script_type", "bat").upper()
        code = data.get("code", "")
        if risk_report is None:
            risk_report = data.get("step_up_report") or inspect_script_3_layers(code)

        if risk_report and risk_report.get("requires_step_up"):
            score = risk_report.get("risk_score", 50)
            self.lbl_req_title.setText(f"⚠️ Alerta de Script Sensível (Risco {score}/100): {title}")
            self.lbl_req_sub.setText("A Camada 3 pausou este comando para você revisar o que ele faz antes de liberar:")
            self.lbl_badge.setText(f"REVISÃO DE RISCO • {script_type}")
            self.lbl_badge.setStyleSheet("background-color: #f38ba8; color: #11111b; padding: 2px 10px; border-radius: 4px; font-size: 11px; font-weight: bold;")
            shown_code = risk_report.get("unrolled_code") or code
            viewer_text = f"{risk_report.get('explanation', '')}\n\n--- CÓDIGO DO SCRIPT (INCLUINDO ARQUIVOS EXTERNOS) ---\n{shown_code}"
            self.code_viewer.setFixedHeight(170)
        else:
            self.lbl_req_title.setText(title)
            self.lbl_req_sub.setText(f"[Sem OTP] Confirmação manual requerida • {desc}")
            self.lbl_badge.setText(f"UAC REQUERIDO - {script_type}")
            self.lbl_badge.setStyleSheet("background-color: #f9e2af; color: #11111b; padding: 2px 10px; border-radius: 4px; font-size: 11px; font-weight: bold;")
            viewer_text = code
            self.code_viewer.setFixedHeight(110)

        self.code_viewer.setPlainText(viewer_text)
        self.code_viewer.show()
        self.txt_stepup_otp.clear()
        self.btn_box_widget.show()
        self.btn_reject.setEnabled(True)
        self.btn_approve.setEnabled(True)

        if self.tray_icon.isVisible():
            self.tray_icon.showMessage(
                "Admin Bridge • Confirmação UAC",
                f"{title}\nClique para autorizar via prompt UAC.",
                QSystemTrayIcon.MessageIcon.Information,
                5000
            )

        self.show_window()

    def execute_authenticated_request(self, data, counter, processing_file: Path):
        self.current_request = data
        self.current_processing_file = processing_file

        title = data.get("title", "Comando Administrativo")
        desc = data.get("description", "Sem descrição.")
        script_type = data.get("script_type", "bat").upper()
        code = data.get("code", "")

        # Bloqueia comandos auto-direcionados à pasta C:\Utilitario
        if is_self_targeting_command(code):
            trigger_incident_lockdown(data.get("id"), "Tentativa de comando auto-direcionado a C:\\Utilitario detectada")
            if processing_file:
                processing_file.unlink(missing_ok=True)
            self.reset_ui()
            self.refresh_dashboard()
            return

        self.lbl_req_title.setText(title)
        self.lbl_req_sub.setText(f"Autenticado via HOTP (Contador #{counter}) • {desc}")
        self.lbl_badge.setText(f"AUTORIZADO [{script_type}]")
        self.lbl_badge.setStyleSheet("background-color: #a6e3a1; color: #11111b; padding: 2px 10px; border-radius: 4px; font-size: 11px; font-weight: bold;")

        self.code_viewer.setPlainText(code)
        self.code_viewer.show()
        self.btn_box_widget.hide()

        self.exec_thread = ExecutionThread(self.current_request, int(self.winId()), force_uac=False)
        self.exec_thread.finished_signal.connect(self.on_execution_finished)
        self.exec_thread.start()

    def approve_request_with_new_otp(self):
        """Permite ao usuário autorizar um script pausado pela Camada 3 digitando um NOVO código OTP de 6 dígitos na tela."""
        if not self.current_request:
            return
        new_otp = self.txt_stepup_otp.text().strip()
        if len(new_otp) != 6 or not new_otp.isdigit():
            QMessageBox.warning(self, "Código OTP Necessário", "Digite um novo código de 6 dígitos gerado no seu celular ou clique em 'Autorizar via UAC'.")
            return
        code = self.current_request.get("code", "")
        if is_self_targeting_command(code):
            trigger_incident_lockdown(self.current_request.get("id"), "Tentativa de comando auto-direcionado a C:\\Utilitario detectada")
            if hasattr(self, "current_processing_file") and self.current_processing_file:
                self.current_processing_file.unlink(missing_ok=True)
            self.reset_ui()
            self.refresh_dashboard()
            return

        req_id = self.current_request["id"]
        code_hash = self.current_request.get("code_hash") or hashlib.sha256(code.encode("utf-8")).hexdigest()
        if not is_admin():
            # Reencaminha para o daemon SYSTEM com o novo OTP criptografado via X25519 e confirm_risk=True
            self.current_request["step_up_gui_pending"] = False
            self.current_request["confirm_risk"] = True
            self.current_request["otp_dpapi"] = protect_transit_token(new_otp, req_id, code_hash)
            req_back = REQUESTS_DIR / f"{req_id}.json"
            with open(req_back, "w", encoding="utf-8") as f:
                json.dump(self.current_request, f, indent=2, ensure_ascii=False)
            if hasattr(self, "current_processing_file") and self.current_processing_file:
                self.current_processing_file.unlink(missing_ok=True)
            self.lbl_badge.setText("ENVIADO AO DAEMON")
            self.lbl_badge.setStyleSheet("background-color: #89b4fa; color: #11111b; padding: 2px 10px; border-radius: 4px; font-size: 11px; font-weight: bold;")
            QTimer.singleShot(1200, self.reset_ui)
            return

        caller_info = self.current_request.get("caller") or {"pid": os.getpid(), "exe": sys.executable, "user": os.getenv("USERNAME", "unknown")}
        is_valid, auth_msg, used_counter = self.hotp_auth.verify_and_advance(new_otp, caller_info)
        if not is_valid:
            QMessageBox.critical(self, "OTP Recusado", f"Falha na validação do novo OTP: {auth_msg}")
            self.refresh_dashboard()
            return

        self.execute_authenticated_request(self.current_request, used_counter - 1, self.current_processing_file)

    def approve_request(self):
        if not self.current_request:
            return
        code = self.current_request.get("code", "")
        if is_self_targeting_command(code):
            trigger_incident_lockdown(self.current_request.get("id"), "Tentativa de comando auto-direcionado a C:\\Utilitario detectada")
            if hasattr(self, "current_processing_file") and self.current_processing_file:
                self.current_processing_file.unlink(missing_ok=True)
            self.reset_ui()
            self.refresh_dashboard()
            return

        self.btn_approve.setEnabled(False)
        self.btn_reject.setEnabled(False)
        self.lbl_badge.setText("EXECUTANDO VIA UAC...")
        self.lbl_badge.setStyleSheet("background-color: #f9e2af; color: #11111b; padding: 2px 10px; border-radius: 4px; font-size: 11px; font-weight: bold;")

        self.exec_thread = ExecutionThread(self.current_request, int(self.winId()), force_uac=True)
        self.exec_thread.finished_signal.connect(self.on_execution_finished)
        self.exec_thread.start()

    def reject_request(self):
        if not self.current_request:
            return
        req_id = self.current_request["id"]
        res_file = RESPONSES_DIR / f"{req_id}.json"
        response = {
            "id": req_id,
            "status": "rejected",
            "exit_code": -1,
            "output": "A solicitação foi recusada pelo usuário na Central de Gestão.",
            "completed_at": datetime.now().astimezone().isoformat()
        }
        try:
            with open(res_file, "w", encoding="utf-8") as f:
                json.dump(response, f, indent=2, ensure_ascii=False)
        except Exception:
            pass

        if hasattr(self, "current_processing_file") and self.current_processing_file:
            self.current_processing_file.unlink(missing_ok=True)

        self.reset_ui()
        self.refresh_dashboard()

    def on_execution_finished(self, response):
        req_id = response["id"]
        # Anexa nota de seguranca se o ciclo de 14 dias expirou
        try:
            is_valid_14d, _ = self.hotp_auth.check_owner_password_status()
            if not is_valid_14d:
                response["security_notice"] = "Aviso de Seguranca: Ciclo de 14 dias expirado. Confirme a Senha Mestra no painel para revalidar a ancoragem."
        except Exception:
            pass
        res_file = RESPONSES_DIR / f"{req_id}.json"
        try:
            with open(res_file, "w", encoding="utf-8") as f:
                json.dump(response, f, indent=2, ensure_ascii=False)
        except Exception:
            pass

        if hasattr(self, "current_processing_file") and self.current_processing_file:
            self.current_processing_file.unlink(missing_ok=True)

        exit_code = response.get("exit_code", 0)
        output_data = response.get("output", "")
        if exit_code == 0:
            self.lbl_req_title.setText("Executado com Sucesso! Retornado ao Chat.")
            self.lbl_req_sub.setText("O comando foi finalizado com código 0.")
            self.lbl_badge.setText("CONCLUÍDO")
            self.lbl_badge.setStyleSheet("background-color: #a6e3a1; color: #11111b; padding: 2px 10px; border-radius: 4px; font-size: 11px; font-weight: bold;")
            self.code_viewer.setPlainText(f"=== SAÍDA RETORNADA (CÓDIGO 0) ===\n\n{output_data}")
        else:
            self.lbl_req_title.setText(f"Finalizado com Erro (Código {exit_code})")
            self.lbl_badge.setText("ERRO")
            self.lbl_badge.setStyleSheet("background-color: #f38ba8; color: #11111b; padding: 2px 10px; border-radius: 4px; font-size: 11px; font-weight: bold;")
            self.code_viewer.setPlainText(f"=== SAÍDA DA EXECUÇÃO (CÓDIGO {exit_code}) ===\n\n{output_data}")

        self.code_viewer.show()
        self.btn_box_widget.hide()
        self.refresh_dashboard()
        QTimer.singleShot(2500, self.reset_ui)

    def reset_ui(self):
        self.current_request = None
        self.current_processing_file = None
        self.lbl_req_title.setText("Aguardando solicitações...")
        self.lbl_req_sub.setText("Aplicações clientes enviarão solicitações aqui quando precisarem executar comandos.")
        self.lbl_badge.setText("INATIVO")
        self.lbl_badge.setStyleSheet("background-color: #313244; color: #a6adc8; padding: 2px 10px; border-radius: 4px; font-size: 11px; font-weight: bold;")
        self.code_viewer.clear()
        self.code_viewer.hide()
        self.btn_box_widget.hide()
        self.btn_reject.setEnabled(False)
        self.btn_approve.setEnabled(False)

    def prompt_and_execute_repair(self):
        def _verify_and_repair(entered_pw: str) -> Tuple[bool, str]:
            success, msg = self.hotp_auth.repair_corrupted_installation(entered_pw)

            if not success and not is_admin() and ("Permissao" in msg or "Acesso" in msg or "nao foi possivel" in msg.lower()):
                try:
                    sei = SHELLEXECUTEINFO()
                    sei.cbSize = ctypes.sizeof(SHELLEXECUTEINFO)
                    sei.fMask = 0x00000040  # SEE_MASK_NOCLOSEPROCESS
                    sei.hwnd = int(self.winId())
                    sei.lpVerb = "runas"
                    sei.lpFile = sys.executable
                    if getattr(sys, "frozen", False):
                        sei.lpParameters = f'repair --password "{entered_pw}"'
                    else:
                        sei.lpParameters = f'"{Path(__file__).resolve()}" repair --password "{entered_pw}"'
                    sei.nShow = 0  # SW_HIDE
                    if ctypes.windll.shell32.ShellExecuteExW(ctypes.byref(sei)) and sei.hProcess:
                        ctypes.windll.kernel32.WaitForSingleObject(sei.hProcess, 15000)
                        ec = wintypes.DWORD()
                        ctypes.windll.kernel32.GetExitCodeProcess(sei.hProcess, ctypes.byref(ec))
                        ctypes.windll.kernel32.CloseHandle(sei.hProcess)
                        if ec.value == 0:
                            clear_integrity_caches()
                            reset_password_lockout()
                            return True, "Integridade revalidada, assinatura re-ancorada e serviço SYSTEM reativado com sucesso!"
                        else:
                            fail_st = record_password_failure()
                            if fail_st["is_locked"]:
                                return False, f"Palavra-passe de recuperação incorreta! Limite de 5 tentativas atingido. Sistema bloqueado por {format_lockout_duration(fail_st['remaining_seconds'])}."
                            return False, f"Palavra-passe de recuperação incorreta ou falha ao re-ancorar. Restam {fail_st['remaining_attempts']} tentativa(s)."
                except Exception as e:
                    return False, f"Falha ao elevar privilégios para reparo: {e}"
            return success, msg

        pwd, ok = ResponsivePasswordDialog.get_verified_password(
            title="Reparo e Re-Ancoragem do Sistema",
            prompt="Digite a sua Palavra-passe de Recuperação para revalidar a integridade e destravar o sistema:",
            verify_fn=_verify_and_repair,
            parent=self,
            confirm_text="Reparar e Destravar"
        )
        if not ok or not pwd:
            return

        if is_admin():
            threading.Thread(target=register_scheduled_task, daemon=True).start()
        clear_integrity_caches()
        self.refresh_dashboard()
        QMessageBox.information(
            self,
            "Reparo Concluído",
            "Integridade revalidada e re-ancorada com sucesso!\nO painel foi atualizado para o estado Ativo."
        )
        if not self.hotp_auth.is_provisioned():
            wizard = SetupWizardDialog(self.hotp_auth, self)
            wizard.exec()
        self.refresh_dashboard()

    def revoke_auth_session(self):
        ok, msg = self.hotp_auth.revoke_preauth_ticket()
        if ok:
            QMessageBox.information(
                self,
                "Modo Auth Encerrado",
                "O Modo Auth de 45 minutos foi encerrado com sucesso.\n"
                "Novas solicitações voltarão a exigir confirmação manual ou novo OTP."
            )
        else:
            QMessageBox.warning(self, "Modo Auth", f"Falha ao revogar: {msg}")
        self.refresh_dashboard()

    def open_reset_dialog(self):
        if not is_admin():
            try:
                request_elevation_with_args(["reset"])
                return
            except Exception as e:
                QMessageBox.critical(self, "Permissão Necessária", f"Privilégios de Administrador são necessários: {e}")
                return
        dlg = ResetWizardDialog(self.hotp_auth, self)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            wizard = SetupWizardDialog(self.hotp_auth, self)
            wizard.exec()
        self.refresh_dashboard()

    def open_uninstall_dialog(self):
        res = QMessageBox.question(
            self,
            "Desinstalar Utilitário",
            "Tem certeza que deseja desinstalar completamente o Admin Bridge?\n\n"
            "Esta ação irá:\n"
            "• Exigir sua Palavra-passe de Recuperação para liberar as travas de kernel\n"
            "• Remover as tarefas agendadas do Windows (schtasks)\n"
            "• Limpar os cofres externos e restaurar as permissões NTFS\n"
            "• Apagar todos os arquivos e pastas de C:\\Utilitario\n"
            "• Remover os atalhos da Área de Trabalho\n\n"
            "Deseja prosseguir?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )
        if res != QMessageBox.StandardButton.Yes:
            return

        pwd = ""
        # Se nao estiver elevado e o daemon estiver offline, solicita elevacao logo no inicio da desinstalacao
        if not is_admin() and not self.hotp_auth._is_daemon_alive_other_process():
            elev_ans = QMessageBox.question(
                self,
                "Elevacao Necessaria",
                "O servico em segundo plano esta offline. Para desinstalar o utilitario com seguranca, e necessario executar o assistente com privilegios de Administrador.\n\nDeseja autorizar a elevacao agora?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.Yes
            )
            if elev_ans == QMessageBox.StandardButton.Yes:
                try:
                    request_elevation_with_args(["uninstall"])
                    return
                except Exception as e:
                    QMessageBox.critical(self, "Erro de Elevacao", f"Nao foi possivel solicitar elevacao: {e}")
                    return
            return

        if self.hotp_auth.is_provisioned():
            pwd, ok_pw = ResponsivePasswordDialog.get_verified_password(
                title="Autenticação Obrigatória • Desinstalação",
                prompt="Digite sua Palavra-passe de Recuperação para destravar os arquivos e desinstalar:",
                verify_fn=lambda p: self.hotp_auth.authorize_and_prepare_uninstall(
                    p,
                    caller_info={"pid": os.getpid(), "exe": sys.executable, "user": os.getenv("USERNAME", "unknown")}
                ),
                parent=self,
                confirm_text="Destravar e Desinstalar"
            )
            if not ok_pw or not pwd.strip():
                return
            pwd = pwd.strip()
        else:
            ok_auth, auth_msg = self.hotp_auth.authorize_and_prepare_uninstall(
                "",
                caller_info={"pid": os.getpid(), "exe": sys.executable, "user": os.getenv("USERNAME", "unknown")}
            )
            if not ok_auth:
                QMessageBox.critical(self, "Desinstalação Bloqueada", auth_msg)
                return

        if not is_admin():
            try:
                elev_args = ["uninstall", "--force"]
                if pwd:
                    elev_args.extend(["--password", pwd])
                request_elevation_with_args(elev_args)
                return
            except Exception as e:
                QMessageBox.critical(self, "Permissão Necessária", f"Privilégios de Administrador são necessários: {e}")
                return

        success = perform_full_uninstall(self)
        if success:
            os._exit(0)
        else:
            QMessageBox.critical(
                self,
                "Erro",
                "Falha ao executar a rotina de desinstalação completa."
            )

    def show_counter_status_dialog(self):
        st = self.hotp_auth.get_counter_status()
        counter = st.get("counter", 0)
        lockdown = "SIM - Bloqueado" if st.get("lockdown") else "NÃO - Ativo"
        provisioned = "SIM - Flag=1" if st.get("provisioned_flag") == 1 else "NÃO - Flag=0"
        fails = st.get("recent_failures", 0)
        status_txt = st.get("status_text", "Ativo")

        QMessageBox.information(
            self,
            "Status do Contador HOTP",
            f"Contador Atual: {counter}\n"
            f"Estado do Serviço: {status_txt}\n"
            f"Provisionado: {provisioned}\n"
            f"Bloqueio Fail-Safe: {lockdown}\n"
            f"Falhas Recentes: {fails} / 3"
        )

    def install_local_ai_assistant(self):
        """Abre o instalador visual e reativo da Mini-IA com progresso contínuo e teste integrado."""
        dlg = LocalAIInstallerDialog(self)
        dlg.exec()

    def show_sync_test_dialog(self):
        try:
            dlg = SyncTestDialog(self.hotp_auth, self)
            dlg.exec()
        except Exception as e:
            QMessageBox.critical(self, "Erro", f"Não foi possível abrir o diagnóstico de sincronia: {e}")



# -----------------------------------------------------------------------------
# DAEMON EM SEGUNDO PLANO (HEADLESS PARA TAREFA AGENDADA COMO SYSTEM)
# -----------------------------------------------------------------------------
def run_daemon_loop(hotp_auth: HOTPAuth):
    """Executa o loop contínuo de processamento de comandos em segundo plano como SYSTEM."""
    logging.info("[DAEMON] Admin Bridge daemon iniciado sob conta de servico.")
    harden_process_dacl()
    apply_isolated_bridge_ntfs_acls()
    KernelFileGuard.lock_executable_file(BASE_DIR / "AdminBridge.exe")
    KernelFileGuard.acquire_exclusive_config_locks(CONFIG_DIR)

    ok_forensic, forensic_msg = check_forensic_integrity(CONFIG_FILE)
    if not ok_forensic:
        logging.critical(f"[FORENSE] {forensic_msg}")
        trigger_incident_lockdown(None, forensic_msg)
        return

    QUEUE_DIR.mkdir(parents=True, exist_ok=True)
    REQUESTS_DIR.mkdir(parents=True, exist_ok=True)
    PROCESSING_DIR.mkdir(parents=True, exist_ok=True)
    RESPONSES_DIR.mkdir(parents=True, exist_ok=True)
    SCRIPTS_DIR.mkdir(parents=True, exist_ok=True)

    last_hb_write = 0.0
    while True:
        try:
            now_ts = time.time()
            if (now_ts - last_hb_write) >= 2.5:
                with open(HEARTBEAT_FILE, "w", encoding="utf-8") as f:
                    json.dump({"timestamp": now_ts, "status": "online", "mode": "daemon", "pid": os.getpid()}, f)
                last_hb_write = now_ts

            req_files = sorted(
                REQUESTS_DIR.glob("*.json"),
                key=lambda p: p.stat().st_ctime_ns if p.exists() else 0
            )
            if req_files:
                target = req_files[0]
                try:
                    with open(target, "r", encoding="utf-8") as f:
                        peek_data = json.load(f)
                except Exception:
                    time.sleep(0.2)
                    continue

                if peek_data.get("step_up_gui_pending"):
                    # Aguardando decisão visual do usuário na GUI (Novo OTP ou UAC)
                    time.sleep(0.3)
                    continue

                is_rpc = peek_data.get("script_type") == "control_rpc"
                has_otp = bool(peek_data.get("otp") or peek_data.get("otp_dpapi"))
                has_token = bool(peek_data.get("preauth_token") or peek_data.get("preauth_token_dpapi"))
                has_ticket = PREAUTH_TICKET_FILE.exists()

                if not (is_rpc or has_otp or has_token or has_ticket):
                    # Solicitação manual sem OTP/ticket: move para GUI_PENDING_DIR para que a GUI (mesmo sem Admin) exiba na tela!
                    try:
                        GUI_PENDING_DIR.mkdir(parents=True, exist_ok=True)
                        target.rename(GUI_PENDING_DIR / target.name)
                    except Exception:
                        pass
                    time.sleep(0.2)
                    continue

                req_id = target.stem
                proc_file = PROCESSING_DIR / f"{req_id}.json"
                try:
                    target.rename(proc_file)
                except Exception:
                    time.sleep(0.5)
                    continue

                data = peek_data

                # Tratamento de operações administrativas internas (control_rpc) em memória pelo daemon SYSTEM
                if is_rpc:
                    rpc_action = str(data.get("rpc_action", ""))
                    expected_hash = data.get("code_hash", "")
                    actual_hash = hashlib.sha256(rpc_action.encode("utf-8")).hexdigest()
                    params = data.get("params") or {}
                    caller_rpc = data.get("caller") or {}
                    rpc_resp = {"id": req_id, "ok": False, "message": "Operacao RPC invalida."}

                    if hmac.compare_digest(actual_hash, expected_hash):
                        otp_val = unprotect_transit_token(params["otp_dpapi"], req_id, actual_hash) if params.get("otp_dpapi") else None
                        pw_val = unprotect_transit_token(params["password_dpapi"], req_id, actual_hash) if params.get("password_dpapi") else None

                        if rpc_action == "preauth":
                            ok_p, msg_p, res_p = hotp_auth.create_preauth_ticket(otp_val or "", caller_rpc, int(params.get("lifetime", 2700)))
                            rpc_resp = {"id": req_id, "ok": ok_p, "message": msg_p, "data": res_p}
                        elif rpc_action == "sync":
                            res_s = hotp_auth.diagnose_otp_sync(
                                otp_val or "",
                                allow_lookahead=bool(params.get("allow_lookahead", False)),
                                max_lookahead=int(params.get("max_lookahead", 10)),
                                max_lookback=params.get("max_lookback", 50)
                            )
                            rpc_resp = {"id": req_id, "ok": bool(res_s.get("success")), "result": res_s}
                        elif rpc_action == "revoke_preauth":
                            ok_r, msg_r = hotp_auth.revoke_preauth_ticket()
                            rpc_resp = {"id": req_id, "ok": ok_r, "message": msg_r}
                        elif rpc_action == "repair":
                            ok_rep, msg_rep = hotp_auth.repair_corrupted_installation(pw_val or "")
                            rpc_resp = {"id": req_id, "ok": ok_rep, "message": msg_rep}
                        elif rpc_action == "verify_password":
                            ok_vp, msg_vp = hotp_auth.verify_quit_password(pw_val or "")
                            rpc_resp = {"id": req_id, "ok": ok_vp, "message": msg_vp}
                        elif rpc_action == "uninstall_unlock":
                            ok_u, msg_u = hotp_auth.authorize_and_prepare_uninstall(pw_val or "", caller_rpc)
                            rpc_resp = {"id": req_id, "ok": ok_u, "message": msg_u}
                            with open(RESPONSES_DIR / f"{req_id}.json", "w", encoding="utf-8") as rf:
                                json.dump(rpc_resp, rf, indent=2, ensure_ascii=False)
                            proc_file.unlink(missing_ok=True)
                            if ok_u:
                                # Proprietário autenticado para desinstalar: libera locks, remove tarefas e encerra o daemon
                                KernelFileGuard.release_all_locks()
                                unregister_scheduled_task()
                                return
                            continue

                    with open(RESPONSES_DIR / f"{req_id}.json", "w", encoding="utf-8") as rf:
                        json.dump(rpc_resp, rf, indent=2, ensure_ascii=False)
                    proc_file.unlink(missing_ok=True)
                    continue

                # 0. Verifica integridade forense e âncora do proprietário antes de processar
                ok_for, for_msg = check_forensic_integrity(CONFIG_FILE)
                if not ok_for:
                    trigger_incident_lockdown(req_id, for_msg)
                    proc_file.unlink(missing_ok=True)
                    continue

                # 1. Valida integridade do hash do código ANTES de consumir o OTP (mitiga TOCTOU e queima de OTP)
                code = data.get("code", "")
                actual_code_hash = hashlib.sha256(code.encode("utf-8")).hexdigest()
                expected_code_hash = data.get("code_hash")
                if expected_code_hash and not hmac.compare_digest(actual_code_hash, expected_code_hash):
                    res = {
                        "id": req_id,
                        "status": "rejected_auth",
                        "reason": "Adulteracao detectada: hash do codigo nao coincide.",
                        "exit_code": 403,
                        "output": "[ACESSO RECUSADO]: Integridade do script violada.",
                        "completed_at": datetime.now().astimezone().isoformat()
                    }
                    with open(RESPONSES_DIR / f"{req_id}.json", "w", encoding="utf-8") as f:
                        json.dump(res, f, indent=2, ensure_ascii=False)
                    proc_file.unlink(missing_ok=True)
                    continue

                # 2. Descriptografa OTP ou token em trânsito vinculados criptograficamente ao req_id e actual_code_hash
                provided_otp = data.get("otp")
                if not provided_otp and data.get("otp_dpapi"):
                    provided_otp = unprotect_transit_token(data["otp_dpapi"], req_id, actual_code_hash)
                    if provided_otp is None:
                        res = {
                            "id": req_id,
                            "status": "rejected_auth",
                            "reason": "Falha ao descriptografar OTP em transito (possivel adulteracao TOCTOU).",
                            "exit_code": 403,
                            "output": "[ACESSO RECUSADO]: Token de transito invalido ou adulterado.",
                            "completed_at": datetime.now().astimezone().isoformat()
                        }
                        with open(RESPONSES_DIR / f"{req_id}.json", "w", encoding="utf-8") as f:
                            json.dump(res, f, indent=2, ensure_ascii=False)
                        proc_file.unlink(missing_ok=True)
                        continue

                preauth_token = data.get("preauth_token")
                if not preauth_token and data.get("preauth_token_dpapi"):
                    preauth_token = unprotect_transit_token(data["preauth_token_dpapi"], req_id, actual_code_hash)

                caller_info = data.get("caller") or {}
                real_os_user = get_os_process_username(caller_info.get("pid", 0))
                if real_os_user and real_os_user.lower() not in ("system", "sistema"):
                    caller_info["user"] = real_os_user
                caller_user = caller_info.get("user")

                # INSPETOR DE SCRIPTS EM 3 CAMADAS (AMSI + Classificador de Risco + IA Explicadora Sob Demanda)
                risk_report = inspect_script_3_layers(code)
                if risk_report.get("requires_step_up") and not data.get("confirm_risk"):
                    # Pausa a execução silenciosa, anexa a explicação da Camada 3 e encaminha para a GUI na tela do usuário
                    # para que ele leia o que o script faz e autorize com um NOVO código OTP ou clicando em Autorizar via UAC!
                    data["step_up_gui_pending"] = True
                    data["step_up_report"] = risk_report
                    data["otp"] = None
                    data["otp_dpapi"] = None
                    data["preauth_token"] = None
                    data["preauth_token_dpapi"] = None
                    try:
                        GUI_PENDING_DIR.mkdir(parents=True, exist_ok=True)
                        gui_target = GUI_PENDING_DIR / f"{req_id}.json"
                        with open(gui_target, "w", encoding="utf-8") as f:
                            json.dump(data, f, indent=2, ensure_ascii=False)
                        proc_file.unlink(missing_ok=True)
                    except Exception:
                        proc_file.unlink(missing_ok=True)
                    continue

                auth_approved = False
                auth_msg = ""

                if provided_otp or data.get("otp_dpapi"):
                    is_valid, auth_msg, used_counter = hotp_auth.verify_and_advance(provided_otp, caller_info)
                    auth_approved = is_valid
                else:
                    ok_ticket, ticket_msg = hotp_auth.consume_preauth_ticket(preauth_token, caller_user)
                    auth_approved = ok_ticket
                    auth_msg = ticket_msg

                if not auth_approved:
                    res = {
                        "id": req_id,
                        "status": "rejected_auth",
                        "reason": auth_msg,
                        "exit_code": 401,
                        "output": f"[ACESSO RECUSADO]: {auth_msg}",
                        "completed_at": datetime.now().astimezone().isoformat()
                    }
                    with open(RESPONSES_DIR / f"{req_id}.json", "w", encoding="utf-8") as f:
                        json.dump(res, f, indent=2, ensure_ascii=False)
                    proc_file.unlink(missing_ok=True)
                    continue

                # Bloqueia qualquer comando auto-direcionado a pasta do utilitário
                if is_self_targeting_command(code):
                    trigger_incident_lockdown(req_id, "Tentativa de comando auto-direcionado a C:\\Utilitario detectada")
                    proc_file.unlink(missing_ok=True)
                    continue

                # Executa comando autenticado diretamente em processo unico, sem runner.ps1 intermediario
                script_type = data.get("script_type", "cmd").lower()
                if script_type in ("bat", "cmd"):
                    cmd = ["cmd.exe", "/c", code]
                elif script_type == "ps1":
                    cmd = ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", code]
                else:
                    cmd = ["cmd.exe", "/c", code]

                safe_cwd = os.environ.get("SystemRoot", "C:\\Windows\\System32") if sys.platform == "win32" else None
                proc = subprocess.run(
                    cmd,
                    cwd=safe_cwd,
                    capture_output=True,
                    text=True,
                    check=False,
                    creationflags=0x08000000 if sys.platform == "win32" else 0
                )
                out_txt = proc.stdout
                if proc.stderr:
                    out_txt += ("\n[STDERR]:\n" if out_txt else "") + proc.stderr
                ec = proc.returncode

                # AUDITORIA PÓS-COMANDO (ANTI-MASCARAMENTO):
                # Verifica imediatamente após o comando terminar se houve tentativa de adulterar a Tarefa Agendada
                # AdminBridge ou os arquivos de C:\Utilitario durante a janela do prompt elevado!
                ok_post_for, post_for_msg = check_forensic_integrity(CONFIG_FILE)
                ok_post_task, post_task_msg = verify_scheduled_task_integrity(BASE_DIR)
                if not ok_post_for or not ok_post_task:
                    violation_reason = post_for_msg if not ok_post_for else post_task_msg
                    trigger_incident_lockdown(req_id, f"Violacao detectada apos execucao de comando: {violation_reason}")
                    proc_file.unlink(missing_ok=True)
                    return

                res = {
                    "id": req_id,
                    "status": "approved",
                    "exit_code": ec,
                    "output": out_txt,
                    "completed_at": datetime.now().astimezone().isoformat()
                }

                # Anexa nota de seguranca se o ciclo de 14 dias expirou
                try:
                    is_valid_14d, _ = hotp_auth.check_owner_password_status()
                    if not is_valid_14d:
                        res["security_notice"] = "Aviso de Seguranca: Ciclo de 14 dias expirado. Confirme a Senha Mestra no painel para revalidar a ancoragem."
                except Exception:
                    pass

                with open(RESPONSES_DIR / f"{req_id}.json", "w", encoding="utf-8") as f:
                    json.dump(res, f, indent=2, ensure_ascii=False)

                proc_file.unlink(missing_ok=True)

        except Exception as e:
            logging.error(f"[DAEMON ERROR]: {e}")

        time.sleep(0.15)


def safe_input(prompt: str = "") -> str:
    """Lê entrada com proteção absoluta contra 'RuntimeError: lost sys.stdin' e suporte a fallback de diálogo."""
    if sys.stdin is not None:
        try:
            return input(prompt)
        except (RuntimeError, EOFError):
            pass
        try:
            line = sys.stdin.readline()
            if line:
                return line.strip()
        except Exception:
            pass

    if sys.platform == "win32":
        try:
            # Diálogo nativo MB_ICONQUESTION (0x20) | MB_YESNO (0x04)
            ret = ctypes.windll.user32.MessageBoxW(0, prompt or "Confirmar ação?", "Admin Bridge", 0x24)
            if ret == 6:  # IDYES
                return "s"
            return "n"
        except Exception:
            pass
    return ""


# -----------------------------------------------------------------------------
# INTERFACE DE LINHA DE COMANDO (CLI) INTEGRAL
# -----------------------------------------------------------------------------
def run_cli_client(args, hotp_auth: HOTPAuth):
    """Executa operações em modo terminal de linha de comando."""
    if sys.platform == "win32":
        try:
            if ctypes.windll.kernel32.AttachConsole(-1):
                sys.stdout = open("CONOUT$", "w", encoding="utf-8", errors="replace")
                sys.stderr = open("CONOUT$", "w", encoding="utf-8", errors="replace")
                try:
                    sys.stdin = open("CONIN$", "r", encoding="utf-8", errors="replace")
                except Exception:
                    pass
        except Exception:
            pass

    if sys.stdin is None:
        import io
        sys.stdin = io.StringIO("")

    if args.subcommand == "status":
        st = hotp_auth.get_counter_status()
        print("=" * 60)
        print("             STATUS DO ADMIN BRIDGE")
        print("=" * 60)
        print(f"  Contador Atual:           {st.get('counter', 0)}")
        print(f"  Estado do Serviço:        {st.get('status_text', 'Ativo')}")
        print(f"  Provisionado:             {'SIM - Flag=1' if st.get('provisioned_flag') == 1 else 'NÃO - Flag=0'}")
        print(f"  Lockdown Fail-Safe:       {'ATIVADO' if st.get('lockdown') else 'NORMAL'}")
        print(f"  Falhas Recentes em 5 min: {st.get('recent_failures', 0)} / 3")
        print(f"  Integridade do Estado:    {'Íntegro' if not st.get('tampered') else 'VIOLADO - Adulterado'}")
        print(f"  Último Uso:               {st.get('last_used_at') or 'Nenhum'}")
        print("=" * 60)
        sys.exit(0)

    elif args.subcommand in ("sync", "check-otp"):
        lookahead = getattr(args, "lookahead", 10)
        lookback = getattr(args, "lookback", None)
        res = hotp_auth.diagnose_otp_sync(args.otp, allow_lookahead=False, max_lookahead=min(lookahead, 10), max_lookback=lookback)
        if not res.get("success") and res.get("status") == "prompt_lookahead":
            print("=" * 65)
            print("  [AVISO]: Código não encontrado no contador atual nem nos anteriores.")
            print("  Deseja pesquisar nas próximas 10 posições futuras do seu autenticador?")
            print("  Atenção: caso não encontre, o contador do sistema saltará 10 posições.")
            ans = safe_input("  Autorizar busca à frente? [s/n]: ").strip().lower()
            if ans in ("s", "sim", "y", "yes"):
                res = hotp_auth.diagnose_otp_sync(args.otp, allow_lookahead=True, max_lookahead=min(lookahead, 10), max_lookback=lookback)
            else:
                print("  Busca à frente cancelada. O contador permaneceu inalterado.")
                sys.exit(1)
        print("=" * 65)
        print("          DIAGNÓSTICO E SINCRONIZAÇÃO HOTP")
        print("=" * 65)
        if res.get("success"):
            st_badge = res.get("status_label", res.get("status", "").upper())
            print(f"  Diagnóstico:        {st_badge}")
            print(f"  Contador no PC:     #{res.get('current_counter')}")
            print(f"  Contador no App:    #{res.get('matched_counter')}")
            print(f"  Próximo Contador:   #{res.get('next_counter')}")
            print("-" * 65)
            if res.get("summary"):
                print(f"  Resumo:             {res.get('summary')}")
            if res.get("action_instruction"):
                print(f"  Instrução:          {res.get('action_instruction')}")
            print("-" * 65)
            print(f"  {res.get('message')}")
        else:
            print(f"  Status:             {res.get('status_label', 'NÃO ENCONTRADO')}")
            if res.get("current_counter") is not None:
                print(f"  Contador no PC:     #{res.get('current_counter')}")
            if res.get("next_counter") is not None:
                print(f"  Próximo Contador:   #{res.get('next_counter')}")
            print("-" * 65)
            if res.get("summary"):
                print(f"  Resumo:             {res.get('summary')}")
            if res.get("action_instruction"):
                print(f"  Instrução:          {res.get('action_instruction')}")
            print("-" * 65)
            print(f"  {res.get('message', res.get('error'))}")
        print("=" * 65)
        if res.get("next_counter") is not None:
            print(f"  [INFO]: Contador atualizado no sistema para #{res.get('next_counter')}.")
        print("=" * 65)
        sys.exit(0 if res.get("success") else 1)

    elif args.subcommand == "history":
        hist = load_recent_history(20)
        print("=" * 70)
        print("         HISTÓRICO RECENTE DE AUDITORIA & EXECUÇÃO")
        print("=" * 70)
        if not hist:
            print("  Nenhum registro encontrado no histórico de auditoria.")
        else:
            for item in hist:
                print(f"  [{item['datetime']}] [{item['status']}] OTP: {item['otp']} | {item['command']}")
        print("=" * 70)
        sys.exit(0)

    elif args.subcommand == "reset":
        expected_ch = generate_physical_challenge()
        print("=" * 60)
        print("   REVOGAÇÃO DE PRIVILÉGIOS E RESET DO AUTENTICADOR")
        print("=" * 60)
        print(f"  CÓDIGO DE PRESENÇA FÍSICA: [{expected_ch}]")
        print("=" * 60)
        user_ch = getattr(args, "challenge", None)
        if not user_ch:
            user_ch = safe_input("Digite o código de presença física acima: ").strip()

        pw = getattr(args, "password", None)
        if not pw:
            try:
                import getpass
                pw = getpass.getpass("Digite sua Palavra-passe de Recuperação: ").strip()
            except Exception:
                pw = safe_input("Digite sua Palavra-passe de Recuperação: ").strip()

        try:
            caller_info = {
                "pid": os.getpid(),
                "exe": sys.executable,
                "script": "CLI_reset",
                "user": os.getenv("USERNAME", "unknown")
            }
            res = hotp_auth.reset_and_destroy_privileges(
                recovery_password=pw,
                physical_challenge_response=user_ch,
                expected_challenge=expected_ch,
                caller_info=caller_info
            )
            print("\n[SUCESSO]:", res.get("message"))
            sys.exit(0)
        except Exception as e:
            print(f"\n[ERRO]: Falha na revogação: {e}", file=sys.stderr)
            sys.exit(1)

    elif args.subcommand == "uninstall":
        force = getattr(args, "force", False)
        if not force:
            ans = safe_input("Tem certeza que deseja desinstalar completamente o utilitário? [s/N]: ").strip().lower()
            if ans not in ("s", "sim", "y", "yes"):
                print("Operação cancelada.")
                sys.exit(0)

        pw = getattr(args, "password", None)
        if hotp_auth.is_provisioned() and not pw:
            try:
                import getpass
                pw = getpass.getpass("Digite sua Palavra-passe de Recuperação para autorizar a desinstalação: ").strip()
            except Exception:
                pw = safe_input("Digite sua Palavra-passe de Recuperação para autorizar a desinstalação: ").strip()

        ok_auth, auth_msg = hotp_auth.authorize_and_prepare_uninstall(
            pw or "",
            caller_info={"pid": os.getpid(), "exe": sys.executable, "user": os.getenv("USERNAME", "unknown")}
        )
        if not ok_auth:
            print(f"[ERRO CRÍTICO]: {auth_msg}", file=sys.stderr)
            sys.exit(1)

        print("[*] Senha validada! Destravando arquivos, removendo tarefas agendadas e limpando C:\\Utilitario...")
        ok = perform_full_uninstall()
        if ok:
            print("[SUCESSO]: Admin Bridge desinstalado com sucesso.")
            sys.exit(0)
        else:
            print("[ERRO]: Falha ao concluir desinstalação.", file=sys.stderr)
            sys.exit(1)

    elif args.subcommand == "repair":
        pw = getattr(args, "password", None) or ""
        ok_rep, msg_rep = hotp_auth.repair_corrupted_installation(pw)
        if ok_rep:
            register_scheduled_task()
            apply_isolated_bridge_ntfs_acls(BASE_DIR)
            print(f"[SUCESSO] {msg_rep}")
            sys.exit(0)
        else:
            print(f"[ERRO] {msg_rep}", file=sys.stderr)
            sys.exit(1)

    elif args.subcommand == "harden":
        if not is_admin():
            try:
                request_elevation_with_args(["harden"])
                return
            except Exception as e:
                print(f"[ERRO] Permissão de Administrador necessária: {e}", file=sys.stderr)
                sys.exit(1)
        print("[*] Aplicando isolamento e blindagem NTFS nativa em C:\\Utilitario...")
        ok = apply_isolated_bridge_ntfs_acls(BASE_DIR)
        if ok:
            print("[SUCESSO] Blindagem NTFS aplicada com sucesso!")
            print("Pasta C:\\Utilitario\\config e chave HOTP estritamente restritas a SYSTEM e Administradores.")
            sys.exit(0)
        else:
            print("[AVISO] Blindagem aplicada, mas a verificação de isolamento acusou pendências.", file=sys.stderr)
            sys.exit(1)

    elif args.subcommand == "setup-service":
        if not is_admin():
            try:
                request_elevation_with_args(["setup-service"])
                return
            except Exception as e:
                print(f"[ERRO] Permissão de Administrador necessária: {e}", file=sys.stderr)
                sys.exit(1)
        print("[*] Registrando tarefas agendadas sob conta SYSTEM no Windows...")
        ok = register_scheduled_task()
        if ok:
            print("[SUCESSO] Tarefa AdminBridge registrada e iniciada sob conta SYSTEM!")
            sys.exit(0)
        else:
            print("[ERRO] Falha ao registrar tarefas no Agendador de Tarefas.", file=sys.stderr)
            sys.exit(1)

    elif args.subcommand == "setup":
        run_cli_setup(args, hotp_auth)
        sys.exit(0)

    elif args.subcommand == "preauth":
        caller_info = {
            "pid": os.getpid(),
            "exe": sys.executable,
            "script": "CLI_preauth",
            "user": os.getenv("USERNAME", "unknown")
        }
        lifetime = getattr(args, "lifetime", 2700)
        ok, msg, res = hotp_auth.create_preauth_ticket(args.otp, caller_info, lifetime)
        output = {
            "status": "authorized" if ok else "rejected",
            "message": msg,
            **res
        }
        print(json.dumps(output, indent=2, ensure_ascii=False))
        sys.exit(0 if ok else 1)

    elif args.subcommand == "run":
        code = args.code
        otp = args.otp
        preauth_token = getattr(args, "preauth_token", None)
        caller_info = {
            "pid": os.getpid(),
            "exe": sys.executable,
            "user": os.getenv("USERNAME", "unknown")
        }

        # Se ja possui privilegios administrativos, executa diretamente no proprio processo unico
        if is_admin():
            if is_self_targeting_command(code):
                req_incident_id = str(uuid.uuid4())
                trigger_incident_lockdown(req_incident_id, "Tentativa de comando auto-direcionado a C:\\Utilitario detectada")
                res = {
                    "id": req_incident_id,
                    "status": "security_lockdown",
                    "reason": "Comando auto-direcionado bloqueado.",
                    "exit_code": 403,
                    "output": "[ACESSO BLOQUEADO]: Tentativa de afetar C:\\Utilitario detectada.",
                    "completed_at": datetime.now().astimezone().isoformat()
                }
                print(json.dumps(res, indent=2, ensure_ascii=False))
                sys.exit(1)

            auth_ok = False
            auth_msg = ""
            if otp:
                valid, auth_msg, _ = hotp_auth.verify_and_advance(otp, caller_info)
                auth_ok = valid
            elif preauth_token:
                valid, auth_msg = hotp_auth.consume_preauth_ticket(preauth_token, caller_info.get("user"))
                auth_ok = valid
            else:
                auth_ok = False
                auth_msg = "OTP ou token de pre-autorizacao obrigatorio para execucao automatizada."

            if not auth_ok:
                res = {
                    "id": str(uuid.uuid4()),
                    "status": "rejected_auth",
                    "reason": auth_msg,
                    "exit_code": 401,
                    "output": f"[ACESSO RECUSADO]: {auth_msg}",
                    "completed_at": datetime.now().astimezone().isoformat()
                }
                print(json.dumps(res, indent=2, ensure_ascii=False))
                sys.exit(1)

            st = (args.type or "cmd").lower()
            if st in ("bat", "cmd"):
                cmd = ["cmd.exe", "/c", code]
            elif st == "ps1":
                cmd = ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", code]
            else:
                cmd = ["cmd.exe", "/c", code]

            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=False,
                creationflags=0x08000000
            )
            out_txt = proc.stdout
            if proc.stderr:
                out_txt += ("\n[STDERR]:\n" if out_txt else "") + proc.stderr

            res = {
                "id": str(uuid.uuid4()),
                "status": "approved",
                "exit_code": proc.returncode,
                "output": out_txt,
                "completed_at": datetime.now().astimezone().isoformat()
            }
            print(json.dumps(res, indent=2, ensure_ascii=False))
            sys.exit(0 if proc.returncode == 0 else 1)

        # Se o processo chamador nao for elevado, envia para a fila do daemon
        REQUESTS_DIR.mkdir(parents=True, exist_ok=True)
        RESPONSES_DIR.mkdir(parents=True, exist_ok=True)

        req_id = str(uuid.uuid4())
        code_hash = hashlib.sha256(args.code.encode("utf-8")).hexdigest()
        raw_preauth = getattr(args, "preauth_token", None)
        otp_dpapi = protect_transit_token(args.otp, req_id, code_hash) if args.otp else None
        preauth_dpapi = protect_transit_token(raw_preauth, req_id, code_hash) if raw_preauth else None

        payload = {
            "id": req_id,
            "title": args.title or "Comando CLI",
            "description": args.description or "Execução via terminal",
            "script_type": args.type or "cmd",
            "code": args.code,
            "code_hash": code_hash,
            "otp": None,
            "otp_dpapi": otp_dpapi,
            "confirm_risk": bool(getattr(args, "confirm_risk", False) and args.otp),
            "preauth_token": None,
            "preauth_token_dpapi": preauth_dpapi,
            "timeout": args.timeout or 120,
            "created_at": datetime.now().astimezone().isoformat(),
            "caller": {
                "pid": os.getpid(),
                "exe": sys.executable,
                "user": os.getenv("USERNAME") or os.getenv("USER") or "unknown"
            }
        }

        req_file = REQUESTS_DIR / f"{req_id}.json"
        tmp_req = req_file.with_suffix(".tmp")
        with open(tmp_req, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, ensure_ascii=False)
        tmp_req.replace(req_file)

        print(f"[*] Solicitação [{req_id}] enviada. Aguardando execução...", file=sys.stderr)
        res_file = RESPONSES_DIR / f"{req_id}.json"
        start_time = time.time()
        timeout = args.timeout or 120

        while time.time() - start_time < timeout:
            if res_file.exists():
                try:
                    with open(res_file, "r", encoding="utf-8") as f:
                        response_data = json.load(f)
                    print(json.dumps(response_data, indent=2, ensure_ascii=False))
                    res_file.unlink(missing_ok=True)
                    ec = response_data.get("exit_code", 0)
                    sys.exit(0 if response_data.get("status") == "approved" and ec == 0 else 1)
                except Exception:
                    pass
            time.sleep(0.08)

        print("[ERRO]: Tempo limite esgotado ao aguardar execução.", file=sys.stderr)
        sys.exit(1)


def run_cli_setup(args, hotp_auth: HOTPAuth):
    """Executa o aprovisionamento inicial estritamente via terminal (zero janelas gráficas)."""
    if sys.platform == "win32":
        try:
            sys.stdout.reconfigure(encoding="utf-8")
            sys.stderr.reconfigure(encoding="utf-8")
        except Exception:
            pass

    print("=" * 65)
    print("      PROVISIONAMENTO INICIAL HOTP - MODO LINHA DE COMANDO")
    print("=" * 65)

    if hotp_auth.is_provisioned() and not getattr(args, "force", False):
        print("\n[AVISO]: O utilitário já está provisionado - Flag=1.")
        print("Para redefinir a chave, utilize o comando: AdminBridge.exe reset\n")
        sys.exit(1)

    pw = getattr(args, "password", None)
    if not pw:
        import getpass
        try:
            pw = getpass.getpass("Defina a Palavra-passe de Recuperação - mínimo 8 caracteres: ").strip()
            pw_conf = getpass.getpass("Confirme a Palavra-passe de Recuperação: ").strip()
        except Exception:
            pw = safe_input("Defina a Palavra-passe de Recuperação - mínimo 8 caracteres: ").strip()
            pw_conf = safe_input("Confirme a Palavra-passe de Recuperação: ").strip()

        if pw != pw_conf:
            print("\n[ERRO]: As senhas digitadas não coincidem. Operação cancelada.", file=sys.stderr)
            sys.exit(1)

    if len(pw) < 8:
        print("\n[ERRO]: A palavra-passe deve conter pelo menos 8 caracteres.", file=sys.stderr)
        sys.exit(1)

    caller_info = {
        "pid": os.getpid(),
        "exe": sys.executable,
        "script": "CLI_setup",
        "user": os.getenv("USERNAME", "unknown")
    }

    try:
        res = hotp_auth.provision(pw, force=getattr(args, "force", False), caller_info=caller_info)
    except Exception as e:
        print(f"\n[ERRO CRÍTICO NO PROVISIONAMENTO]: {e}", file=sys.stderr)
        sys.exit(1)

    uri = res.get("uri", "")
    secret_b32 = res.get("secret_base32", "")

    print("\n" + "=" * 65)
    print("  CHAVE GERADA COM SUCESSO EM MEMÓRIA RAM & PROTEGIDA VIA DPAPI")
    print("=" * 65)
    print(f"  Contador Inicial:  0")
    print(f"  Flag:              1 - Travado")
    print(f"  Dígitos:           6 | Algoritmo: HMAC-SHA1")
    print("=" * 65)
    print("  ESCANEE O QR CODE ABAIXO NO SEU CELULAR - Aegis, 2FAS, Google Auth:")
    print("-" * 65 + "\n")

    try:
        qr = qrcode.QRCode(box_size=1, border=1)
        qr.add_data(uri)
        qr.make(fit=True)
        qr.print_ascii(out=sys.stdout, invert=True)
    except Exception as e:
        print(f"  Não foi possível renderizar QR em ASCII: {e}")

    print("\n" + "-" * 65)
    print("  INSERÇÃO MANUAL NO AUTENTICADOR:")
    print(f"  Chave Secreta - Base32: {secret_b32}")
    print(f"  URI de Pareamento:      {uri}")
    print("=" * 65)
    print("  [IMPORTANTE]: Esta é a ÚNICA vez que este segredo será exibido!")
    print("  O computador nunca mais salvará nem exibirá esta chave.")
    print("=" * 65)

    print("\n[*] Registrando serviço no Agendador de Tarefas do Windows SYSTEM...")
    ok_task = register_scheduled_task()
    if ok_task:
        print("[*] Tarefa agendada registrada com sucesso (/ru 'SYSTEM' /rl HIGHEST).")
    else:
        print("[AVISO] Para registrar a tarefa agendada do sistema, execute este comando em console com privilégios de Administrador.")

    print("\n[SUCESSO] Provisionamento concluído via linha de comando com zero janelas!")


# -----------------------------------------------------------------------------
# PONTO DE ENTRADA PRINCIPAL
# -----------------------------------------------------------------------------
def main():
    _debug_log(f"main() entry - sys.argv: {sys.argv}")
    configure_anti_dump_mitigations()
    _debug_log("configure_anti_dump_mitigations() done")
    ensure_environment_installed()
    _debug_log("ensure_environment_installed() done")
    hotp_auth = HOTPAuth()
    _debug_log("HOTPAuth() initialized")


    parser = argparse.ArgumentParser(
        description="Admin Bridge • Central de Gestão HOTP",
        add_help=True
    )
    parser.add_argument("--daemon", action="store_true", help="Executa o daemon em segundo plano (modo serviço)")
    parser.add_argument("--gui", action="store_true", help="Abre a janela da Central de Gestão diretamente na tela")
    parser.add_argument("--minimized", action="store_true", help="Inicia minimizado na bandeja do sistema")

    subparsers = parser.add_subparsers(dest="subcommand", help="Comandos disponíveis")

    # Comando setup (100% terminal, zero janelas)
    p_setup = subparsers.add_parser("setup", help="Executa o provisionamento inicial via terminal sem abrir janelas")
    p_setup.add_argument("--password", help="Palavra-passe de recuperação (mínimo 8 caracteres)")
    p_setup.add_argument("--force", action="store_true", help="Força novo provisionamento se permitido")

    # Comando status
    subparsers.add_parser("status", help="Consulta o status atual do serviço e contador")

    # Comando sync (teste passivo de sincronia do contador)
    p_sync = subparsers.add_parser("sync", help="Diagnóstico e teste de sincronia HOTP sem avançar o contador")
    p_sync.add_argument("--otp", required=True, help="Código OTP de 6 dígitos gerado no aplicativo do celular")
    p_sync.add_argument("--lookahead", type=int, default=10, help="Janela máxima de busca à frente (padrão: 10)")
    p_sync.add_argument("--lookback", type=int, default=None, help="Janela máxima de busca atrás (padrão: até o zero)")

    # Comando history
    subparsers.add_parser("history", help="Exibe o histórico recente de auditoria e execuções")

    # Comando reset
    p_reset = subparsers.add_parser("reset", help="Executa revogação de privilégios e reset da chave")
    p_reset.add_argument("--password", help="Palavra-passe de recuperação")
    p_reset.add_argument("--challenge", help="Código de presença física")

    # Comando repair
    p_repair = subparsers.add_parser("repair", help="Revalida e re-ancora a instalação com a Senha de Recuperação")
    p_repair.add_argument("--password", required=True, help="Palavra-passe de recuperação do proprietário")

    # Comando harden
    subparsers.add_parser("harden", help="Aplica blindagem estrita de permissões NTFS na pasta config e arquivos")

    # Comando uninstall
    p_uninst = subparsers.add_parser("uninstall", help="Desinstala o utilitário completamente (exige Senha de Recuperação)")
    p_uninst.add_argument("--force", action="store_true", help="Pula pergunta de confirmação S/N")
    p_uninst.add_argument("--password", help="Palavra-passe de recuperação do proprietário")

    # Comando setup-service
    subparsers.add_parser("setup-service", help="Registra e inicia o serviço AdminBridge no Agendador de Tarefas do Windows sob conta SYSTEM")

    # Comando preauth (consome OTP imediatamente e gera ticket de pré-autorização)
    p_preauth = subparsers.add_parser("preauth", help="Consome o OTP imediatamente no início da interação e gera ticket válido por até 45 minutos")
    p_preauth.add_argument("--otp", required=True, help="Código OTP de 6 dígitos do autenticador")
    p_preauth.add_argument("--lifetime", type=int, default=2700, help="Tempo de validade em segundos (padrão: 2700s = 45 minutos)")

    # Comando run
    p_run = subparsers.add_parser("run", help="Envia um comando para execução elevada")
    p_run.add_argument("--title", default="Comando Administrativo", help="Título da solicitação")
    p_run.add_argument("--description", default="", help="Descrição da solicitação")
    p_run.add_argument("--type", choices=["bat", "cmd", "ps1"], default="cmd", help="Tipo de script")
    p_run.add_argument("--code", required=True, help="Comando ou código a executar")
    p_run.add_argument("--otp", default=None, help="Código OTP de 6 dígitos (modo legado imediato)")
    p_run.add_argument("--preauth-token", default=None, help="Token de pré-autorização opcional")
    p_run.add_argument("--confirm-risk", action="store_true", help="Confirma execução de script sensível mediante novo OTP")
    p_run.add_argument("--timeout", type=int, default=120, help="Tempo limite em segundos")

    args, unknown = parser.parse_known_args()

    # Se um subcomando CLI foi invocado
    if args.subcommand:
        if args.subcommand in ("setup", "reset", "uninstall", "harden", "setup-service") and not is_admin():
            try:
                request_elevation_with_args(sys.argv[1:])
                return
            except Exception as e:
                print(f"[ERRO] Permissão de Administrador necessária: {e}", file=sys.stderr)
                sys.exit(1)
        run_cli_client(args, hotp_auth)
        return

    # Se invocado em modo daemon
    if args.daemon:
        run_daemon_loop(hotp_auth)
        return

    # Inicia a Interface Gráfica PyQt6 (System Tray & Dashboard)
    try:
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("adminbridge.gui.2.0")
    except Exception:
        pass

    app = QApplication(sys.argv)
    app.setQuitOnLastWindowClosed(False)
    app_icon = get_app_icon()
    if not app_icon.isNull():
        app.setWindowIcon(app_icon)

    # Verificação de Instância Única (Single Instance) via QLocalSocket
    _debug_log(f"Testing QLocalSocket with {LOCAL_SERVER_NAME}...")
    local_socket = QLocalSocket()
    local_socket.connectToServer(LOCAL_SERVER_NAME)
    if local_socket.waitForConnected(500):
        _debug_log(f"Existing instance detected on {LOCAL_SERVER_NAME}! Sending SHOW and exiting.")
        local_socket.write(b"SHOW\n")
        local_socket.waitForBytesWritten(1000)
        local_socket.disconnectFromServer()
        sys.exit(0)
    _debug_log(f"No existing instance on {LOCAL_SERVER_NAME}. Starting new server.")

    # Inicia escuta local para instâncias futuras
    QLocalServer.removeServer(LOCAL_SERVER_NAME)
    ipc_server = QLocalServer(app)
    ipc_server.listen(LOCAL_SERVER_NAME)

    # Verifica se já está provisionado
    _debug_log("Checking is_provisioned()...")
    is_prov = hotp_auth.is_provisioned()
    _debug_log(f"is_provisioned result: {is_prov}")
    if not is_prov:
        if not is_admin():
            _debug_log("Not provisioned and not admin, requesting elevation...")
            try:
                request_elevation()
                return
            except Exception as e:
                _debug_log(f"Elevation request failed: {e}")
        wizard = SetupWizardDialog(hotp_auth)
        if wizard.exec() != QDialog.DialogCode.Accepted:
            _debug_log("Wizard cancelled, exiting with 0.")
            sys.exit(0)

    # Se provisionado e o daemon não estiver ativo em outro processo, acorda ou registra
    if is_prov and not hotp_auth._is_daemon_alive_other_process():
        try:
            if is_admin():
                register_scheduled_task()
            else:
                subprocess.run(["schtasks", "/run", "/tn", "AdminBridge"], capture_output=True, check=False, creationflags=0x08000000)
        except Exception:
            pass

    _debug_log("Creating AdminBridgeWindow...")
    window = AdminBridgeWindow(hotp_auth)
    _debug_log("AdminBridgeWindow created.")

    def handle_ipc_activation():
        while ipc_server.hasPendingConnections():
            client = ipc_server.nextPendingConnection()
            if client:
                if client.waitForReadyRead(1000):
                    msg = bytes(client.readAll()).decode("utf-8", errors="ignore")
                    if "SHOW" in msg:
                        window.show_window()
                client.disconnectFromServer()

    ipc_server.newConnection.connect(handle_ipc_activation)

    # Por padrão, abre a janela diretamente na tela do usuário.
    # Se --minimized for passado explicitamente, oculta na bandeja.
    if args.minimized:
        _debug_log("Hiding window (minimized requested)...")
        window.hide()
    else:
        _debug_log("Showing window...")
        window.show_window()

    _debug_log("Entering app.exec()...")
    rc = app.exec()
    _debug_log(f"app.exec() terminated with code {rc}")
    sys.exit(rc)



if __name__ == "__main__":
    main()
