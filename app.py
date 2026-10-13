import argparse
import ctypes
from ctypes import wintypes
import gc
import io
import json
import logging
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone
from typing import Optional, Tuple

import qrcode
from PyQt6.QtCore import Qt, QTimer, QThread, pyqtSignal
from PyQt6.QtGui import QFont, QIcon, QColor, QPalette, QCursor, QAction, QPixmap
from PyQt6.QtNetwork import QLocalServer, QLocalSocket
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QPlainTextEdit, QFrame, QSystemTrayIcon,
    QMenu, QMessageBox, QDialog, QLineEdit, QTableWidget, QTableWidgetItem,
    QHeaderView, QAbstractItemView
)

from hotp_auth import HOTPAuth, SecurityError
from hotp_crypto import (
    wipe_buffer, apply_system_only_ntfs_acls, restore_ntfs_acls_for_removal,
    verify_caller_origin, generate_physical_challenge, read_passive_metadata
)

LOCAL_SERVER_NAME = "AntigravityBridge_GUI_SingleInstance"
BASE_DIR = Path("C:/Utilitario")
CONFIG_DIR = BASE_DIR / "config"
QUEUE_DIR = BASE_DIR / "queue"
REQUESTS_DIR = QUEUE_DIR / "requests"
PROCESSING_DIR = QUEUE_DIR / "processing"
RESPONSES_DIR = QUEUE_DIR / "responses"
SCRIPTS_DIR = BASE_DIR / "scripts"
LOGS_DIR = BASE_DIR / "logs"
HEARTBEAT_FILE = QUEUE_DIR / "heartbeat.json"
STATUS_FILE = QUEUE_DIR / "status.json"
RUNNER_PS1 = BASE_DIR / "runner.ps1"
CONFIG_FILE = CONFIG_DIR / "hotp_config.json"
AUTH_LOG_FILE = LOGS_DIR / "auth.log"

LOGS_DIR.mkdir(parents=True, exist_ok=True)
logging.basicConfig(
    filename=str(LOGS_DIR / "app.log"),
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

# -----------------------------------------------------------------------------
# RUNNER POWERSHELL EMBUTIDO
# -----------------------------------------------------------------------------
RUNNER_PS1_SCRIPT = """param (
    [Parameter(Mandatory=$true)]
    [string]$ScriptPath,
    [Parameter(Mandatory=$true)]
    [string]$ScriptType,
    [Parameter(Mandatory=$true)]
    [string]$LogPath,
    [Parameter(Mandatory=$true)]
    [string]$ExitPath
)

$exitCode = 0
try {
    if ($ScriptType -eq "bat" -or $ScriptType -eq "cmd") {
        $process = Start-Process -FilePath "cmd.exe" -ArgumentList "/c `"$ScriptPath`"" -NoNewWindow -Wait -PassThru -RedirectStandardOutput $LogPath -RedirectStandardError "$LogPath.err"
        $exitCode = $process.ExitCode
        if (Test-Path "$LogPath.err") {
            $errContent = Get-Content "$LogPath.err" -Raw
            if ($errContent) {
                Add-Content -Path $LogPath -Value "`n[STDERR]:`n$errContent"
            }
            Remove-Item "$LogPath.err" -Force -ErrorAction SilentlyContinue
        }
    } else {
        $process = Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$ScriptPath`"" -NoNewWindow -Wait -PassThru -RedirectStandardOutput $LogPath -RedirectStandardError "$LogPath.err"
        $exitCode = $process.ExitCode
        if (Test-Path "$LogPath.err") {
            $errContent = Get-Content "$LogPath.err" -Raw
            if ($errContent) {
                Add-Content -Path $LogPath -Value "`n[STDERR]:`n$errContent"
            }
            Remove-Item "$LogPath.err" -Force -ErrorAction SilentlyContinue
        }
    }
} catch {
    $exitCode = 1
    Set-Content -Path $LogPath -Value "Erro ao executar runner: $_"
}

Set-Content -Path $ExitPath -Value $exitCode -Encoding ascii
"""


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
    """Garante a existência do atalho da Central de Gestão na Área de Trabalho do usuário."""
    try:
        desktop = get_desktop_dir()
        if not desktop:
            return
        lnk_path = desktop / "Antigravity Bridge.lnk"
        if lnk_path.exists():
            return
        target = (BASE_DIR / "AntigravityBridge.exe").resolve()
        icon_path = (BASE_DIR / "icon.ico").resolve()
        ps_cmd = (
            f'$ws = New-Object -ComObject WScript.Shell; '
            f'$s = $ws.CreateShortcut("{lnk_path}"); '
            f'$s.TargetPath = "{target}"; '
            f'$s.WorkingDirectory = "{BASE_DIR}"; '
            f'$s.IconLocation = "{icon_path},0"; '
            f'$s.Description = "Antigravity Admin Bridge & Central de Gestao"; '
            f'$s.Save()'
        )
        subprocess.run(
            ["powershell.exe", "-NoProfile", "-Command", ps_cmd],
            capture_output=True,
            check=False,
            creationflags=0x08000000
        )
    except Exception:
        pass


def ensure_environment_installed():
    """Garante a estrutura de diretórios e extração dos componentes essenciais."""
    BASE_DIR.mkdir(parents=True, exist_ok=True)
    try:
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    except Exception:
        pass
    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    QUEUE_DIR.mkdir(parents=True, exist_ok=True)
    REQUESTS_DIR.mkdir(parents=True, exist_ok=True)
    PROCESSING_DIR.mkdir(parents=True, exist_ok=True)
    RESPONSES_DIR.mkdir(parents=True, exist_ok=True)
    SCRIPTS_DIR.mkdir(parents=True, exist_ok=True)

    if not RUNNER_PS1.exists():
        with open(RUNNER_PS1, "w", encoding="utf-8") as f:
            f.write(RUNNER_PS1_SCRIPT)

    target_exe = (BASE_DIR / "AntigravityBridge.exe").resolve()
    current_exe = Path(sys.executable).resolve()
    if getattr(sys, "frozen", False) and current_exe != target_exe:
        try:
            shutil.copy2(str(current_exe), str(target_exe))
        except Exception as e:
            logging.warning(f"Aviso ao copiar executável para C:\\Utilitario: {e}")

    # Aplica permissões restritas exclusivas para SYSTEM se for Administrador
    if is_admin():
        apply_system_only_ntfs_acls(CONFIG_DIR)

    create_desktop_shortcut()


def register_scheduled_task() -> bool:
    """Registra o executável no Agendador de Tarefas do Windows como SYSTEM com privilégios HIGHEST."""
    exe_path = str(BASE_DIR / "AntigravityBridge.exe")
    cmd = [
        "schtasks", "/create",
        "/tn", "AntigravityAdminBridge",
        "/tr", f'"{exe_path}" --daemon',
        "/rl", "HIGHEST",
        "/ru", "SYSTEM",
        "/sc", "ONSTART",
        "/f"
    ]
    res = subprocess.run(cmd, capture_output=True, text=True, check=False, creationflags=0x08000000)
    if res.returncode == 0:
        logging.info("Tarefa agendada registrada sob conta SYSTEM com sucesso.")
        subprocess.run(["schtasks", "/run", "/tn", "AntigravityAdminBridge"], capture_output=True, check=False, creationflags=0x08000000)
        return True
    else:
        # Fallback para ONLOGON se ONSTART exigir permissões adicionais
        cmd_fallback = [
            "schtasks", "/create",
            "/tn", "AntigravityAdminBridge",
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
    cmd = ["schtasks", "/delete", "/tn", "AntigravityAdminBridge", "/f"]
    res = subprocess.run(cmd, capture_output=True, check=False, creationflags=0x08000000)
    return res.returncode == 0


def perform_full_uninstall(parent_widget=None) -> bool:
    """Executa o fluxo completo de desinstalação:

    1. Remove a tarefa agendada do Windows.
    2. Restaura permissões NTFS em C:\\Utilitario via takeown e icacls.
    3. Remove atalhos criados na Área de Trabalho.
    4. Limpa pastas de filas, logs e configurações.
    5. Agenda remoção da pasta C:\\Utilitario e encerra o processo.
    """
    try:
        # 1. Remove tarefa agendada
        unregister_scheduled_task()

        # 2. Restaura permissões NTFS de C:\Utilitario\config
        restore_ntfs_acls_for_removal(CONFIG_DIR)
        restore_ntfs_acls_for_removal(BASE_DIR)

        # 3. Remove atalhos da Área de Trabalho
        try:
            desktop = Path(os.environ.get("USERPROFILE", "")) / "Desktop"
            if desktop.exists():
                for lnk in desktop.glob("*Antigravity*.lnk"):
                    try:
                        lnk.unlink(missing_ok=True)
                    except Exception:
                        pass
        except Exception:
            pass

        # 4. Limpa dados em C:\Utilitario
        for d in [REQUESTS_DIR, PROCESSING_DIR, RESPONSES_DIR, SCRIPTS_DIR, CONFIG_DIR, LOGS_DIR]:
            if d.exists():
                try:
                    shutil.rmtree(d, ignore_errors=True)
                except Exception:
                    pass

        # 5. Se estiver executando de dentro de C:\Utilitario, agenda auto-remoção
        cleanup_cmd = (
            'cmd.exe /c "timeout /t 2 /nobreak >nul & '
            'takeown /f "C:\\Utilitario" /r /d y >nul 2>&1 & '
            'icacls "C:\\Utilitario" /grant "*S-1-5-32-544:(OI)(CI)(F)" /t >nul 2>&1 & '
            'rd /s /q "C:\\Utilitario" >nul 2>&1"'
        )
        subprocess.Popen(cleanup_cmd, shell=True, creationflags=0x08000000)
        return True
    except Exception as e:
        logging.error(f"Erro na desinstalação: {e}")
        return False


def load_recent_history(max_items: int = 50) -> list:
    """Carrega o histórico recente de auditoria e comandos a partir de logs/auth.log."""
    items = []
    if not AUTH_LOG_FILE.exists():
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
                    dt = datetime.fromisoformat(ts_raw)
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

        self.setWindowTitle("Antigravity • Provisionamento de Segurança (HOTP)")
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

        lbl_p1 = QLabel("Palavra-passe de Recuperação (mínimo 8 caracteres):")
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

        self.btn_next = QPushButton("Gerar Pareamento Seguro (QR Code em RAM)")
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

        try:
            caller_info = {
                "pid": os.getpid(),
                "exe": sys.executable,
                "script": "SetupWizardDialog",
                "user": os.getenv("USERNAME", "unknown")
            }
            res = self.hotp_auth.provision(p1, force=False, caller_info=caller_info)
            self.show_qr_step(res)
        except Exception as e:
            QMessageBox.critical(self, "Erro no Provisionamento", f"Falha ao gerar chave: {e}")

    def show_qr_step(self, res):
        while self.layout.count():
            item = self.layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        lbl_title = QLabel("📷 Escaneie o QR Code no seu Celular")
        lbl_title.setStyleSheet("font-size: 18px; font-weight: bold; color: #89b4fa;")
        lbl_title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.layout.addWidget(lbl_title)

        lbl_sub = QLabel("Abra o Aegis, 2FAS ou Google Authenticator no celular e escaneie:")
        lbl_sub.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lbl_sub.setStyleSheet("font-size: 12px; color: #a6adc8;")
        self.layout.addWidget(lbl_sub)

        pixmap, self.raw_qr_buffer = render_qr_in_memory(res["uri"])

        lbl_img = QLabel()
        lbl_img.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lbl_img.setPixmap(pixmap.scaled(240, 240, Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation))
        self.layout.addWidget(lbl_img)

        lbl_manual = QLabel("Chave Secreta para Inserção Manual:")
        lbl_manual.setStyleSheet("font-size: 11px; font-weight: 600; color: #a6adc8;")
        self.layout.addWidget(lbl_manual)

        txt_secret = QLineEdit(res.get("secret_base32", ""))
        txt_secret.setReadOnly(True)
        txt_secret.setStyleSheet("font-family: Consolas, monospace; font-size: 12px; background-color: #181825; color: #f9e2af;")
        self.layout.addWidget(txt_secret)

        lbl_meta = QLabel("Tipo: Baseado em Contador (HOTP) • Contador Inicial: 0 • Dígitos: 6 • SHA-1")
        lbl_meta.setStyleSheet("font-size: 10px; color: #6c7086;")
        lbl_meta.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.layout.addWidget(lbl_meta)

        lbl_warn = QLabel("⚠️ ATENÇÃO: Esta é a ÚNICA vez que este código será exibido. A chave não será salva em disco.")
        lbl_warn.setWordWrap(True)
        lbl_warn.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lbl_warn.setStyleSheet("font-size: 11px; color: #f38ba8; font-weight: 600;")
        self.layout.addWidget(lbl_warn)

        btn_finish = QPushButton("Concluir Pareamento • Já Escaneei no Celular")
        btn_finish.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        btn_finish.setStyleSheet("background-color: #a6e3a1; color: #11111b; font-weight: bold; padding: 12px;")
        btn_finish.clicked.connect(self.finalize_provisioning)
        self.layout.addWidget(btn_finish)

    def finalize_provisioning(self):
        if self.raw_qr_buffer is not None:
            wipe_buffer(self.raw_qr_buffer)
            self.raw_qr_buffer = None
        gc.collect()

        # Registra a tarefa elevada no Windows com /ru "SYSTEM" /rl HIGHEST
        register_scheduled_task()
        self.accept()

    def closeEvent(self, event):
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

        self.setWindowTitle("Antigravity • Revogar Privilégios & Resetar HOTP")
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
        lbl_title = QLabel("⚠️ Revogação de Privilégios & Reset")
        lbl_title.setStyleSheet("font-size: 18px; font-weight: bold; color: #f38ba8;")
        self.layout.addWidget(lbl_title)

        lbl_desc = QLabel(
            "Esta operação destrói permanentemente a chave HOTP atual, remove a tarefa elevada "
            "do Agendador de Tarefas do Windows e encerra todas as permissões administrativas.\n"
            "Para reativar a Central no futuro, será exigida nova aprovação manual no Windows UAC."
        )
        lbl_desc.setWordWrap(True)
        lbl_desc.setStyleSheet("font-size: 12px; color: #a6adc8; line-height: 1.4;")
        self.layout.addWidget(lbl_desc)

        lbl_ch_title = QLabel("Confirmação de Presença Física (digite o código abaixo):")
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
        self.txt_challenge.setPlaceholderText("Digite o código exibido acima (ex: PHYS-123456)")
        self.layout.addWidget(self.txt_challenge)

        lbl_curr_pw = QLabel("Palavra-passe de Recuperação:")
        lbl_curr_pw.setStyleSheet("font-weight: 600; font-size: 12px;")
        self.layout.addWidget(lbl_curr_pw)

        self.txt_curr_pw = QLineEdit()
        self.txt_curr_pw.setEchoMode(QLineEdit.EchoMode.Password)
        self.txt_curr_pw.setPlaceholderText("Digite sua palavra-passe de recuperação")
        self.layout.addWidget(self.txt_curr_pw)

        self.btn_submit = QPushButton("Confirmar Destruição de Chave & Revogar Tarefa")
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
                "Privilégios Revogados",
                "Sucesso! A chave HOTP foi destruída e a tarefa elevada do Windows foi removida.\n"
                "A central de gestão será encerrada agora."
            )
            self.accept()
            QApplication.quit()
        except Exception as e:
            QMessageBox.critical(self, "Erro no Reset", f"Falha na revogação: {e}")


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
        exit_file = RESPONSES_DIR / f"{req_id}.exit"

        with open(script_file, "w", encoding="utf-8") as f:
            f.write(code)

        exit_code = 0
        output_data = ""

        try:
            if self.force_uac:
                # Dispara via ShellExecuteEx com 'runas' para exigir UAC na tela
                params = (
                    f'-NoProfile -ExecutionPolicy Bypass -File "{RUNNER_PS1}" '
                    f'-ScriptPath "{script_file}" -ScriptType "{script_type}" '
                    f'-LogPath "{log_file}" -ExitPath "{exit_file}"'
                )

                sei = SHELLEXECUTEINFO()
                sei.cbSize = ctypes.sizeof(SHELLEXECUTEINFO)
                sei.fMask = 0x00000040  # SEE_MASK_NOCLOSEPROCESS
                sei.hwnd = self.hwnd
                sei.lpVerb = "runas"
                sei.lpFile = "powershell.exe"
                sei.lpParameters = params
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
                            "completed_at": datetime.now(timezone.utc).isoformat()
                        }
                        self.finished_signal.emit(response)
                        return
                    else:
                        raise ctypes.WinError(err)

                ctypes.windll.kernel32.WaitForSingleObject(sei.hProcess, 0xFFFFFFFF)
                ctypes.windll.kernel32.CloseHandle(sei.hProcess)
            else:
                # Modo HOTP automatizado (CREATE_NO_WINDOW)
                cmd = [
                    "powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass",
                    "-File", str(RUNNER_PS1),
                    "-ScriptPath", str(script_file),
                    "-ScriptType", script_type,
                    "-LogPath", str(log_file),
                    "-ExitPath", str(exit_file)
                ]
                proc = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    check=False,
                    creationflags=0x08000000  # CREATE_NO_WINDOW
                )
                if proc.returncode != 0 and not exit_file.exists():
                    exit_code = proc.returncode
                    output_data = f"[ERRO NO RUNNER]: {proc.stderr}\n{proc.stdout}"

            if exit_file.exists():
                try:
                    with open(exit_file, "r", encoding="utf-8") as f:
                        exit_code = int(f.read().strip())
                except Exception:
                    exit_code = 0

            if log_file.exists():
                try:
                    with open(log_file, "r", encoding="utf-8", errors="replace") as f:
                        output_data = f.read()
                except Exception:
                    output_data = ""

        except Exception as e:
            exit_code = -1
            output_data = f"Falha na execução: {e}"

        response = {
            "id": req_id,
            "status": "approved",
            "exit_code": exit_code,
            "output": output_data,
            "completed_at": datetime.now(timezone.utc).isoformat()
        }

        # Limpeza segura do script temporário
        try:
            script_file.unlink(missing_ok=True)
            log_file.unlink(missing_ok=True)
            exit_file.unlink(missing_ok=True)
        except Exception:
            pass

        self.finished_signal.emit(response)


# -----------------------------------------------------------------------------
# JANELA PRINCIPAL DA CENTRAL DE GESTÃO (SYSTEM TRAY & DASHBOARD)
# -----------------------------------------------------------------------------
class AdminBridgeWindow(QMainWindow):
    def __init__(self, hotp_auth: HOTPAuth):
        super().__init__()
        self.hotp_auth = hotp_auth
        self.current_request = None
        self.exec_thread = None

        self.setWindowTitle("Antigravity Admin Bridge • Central de Gestão")
        self.resize(780, 680)
        self.setMinimumSize(680, 560)

        icon_path = str(BASE_DIR / "icon.ico")
        if os.path.exists(icon_path):
            self.setWindowIcon(QIcon(icon_path))

        self.init_ui()
        self.init_tray()

        # Timer de verificação da fila de comandos (1 segundo)
        self.timer_queue = QTimer(self)
        self.timer_queue.timeout.connect(self.check_requests)
        self.timer_queue.start(1000)

        # Timer de heartbeat
        self.timer_heartbeat = QTimer(self)
        self.timer_heartbeat.timeout.connect(self.write_heartbeat)
        self.timer_heartbeat.start(3000)
        self.write_heartbeat()

        # Atualiza métricas iniciais
        self.refresh_dashboard()

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
        main_layout.setContentsMargins(20, 20, 20, 20)
        main_layout.setSpacing(14)

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

        main_layout.addLayout(metrics_layout)

        # -------------------------------------------------------------
        # ÁREA DE COMANDO PENDENTE (MODO HÍBRIDO / UAC)
        # -------------------------------------------------------------
        self.card_pending = QFrame()
        self.card_pending.setProperty("class", "card")
        pending_layout = QVBoxLayout(self.card_pending)
        pending_layout.setSpacing(10)

        header_pending = QHBoxLayout()
        self.lbl_req_title = QLabel("Aguardando solicitações...")
        self.lbl_req_title.setStyleSheet("font-size: 15px; font-weight: bold; color: #89b4fa;")
        header_pending.addWidget(self.lbl_req_title)

        header_pending.addStretch()

        self.lbl_badge = QLabel("INATIVO")
        self.lbl_badge.setStyleSheet("background-color: #313244; color: #cdd6f4; padding: 4px 10px; border-radius: 4px; font-size: 11px; font-weight: bold;")
        header_pending.addWidget(self.lbl_badge)
        pending_layout.addLayout(header_pending)

        self.lbl_req_sub = QLabel("O assistente Antigravity enviará solicitações aqui quando precisar executar comandos.")
        self.lbl_req_sub.setStyleSheet("font-size: 12px; color: #a6adc8;")
        pending_layout.addWidget(self.lbl_req_sub)

        self.code_viewer = QPlainTextEdit()
        self.code_viewer.setObjectName("codeViewer")
        self.code_viewer.setReadOnly(True)
        self.code_viewer.setFixedHeight(120)
        self.code_viewer.setPlaceholderText("Nenhum comando pendente de aprovação.")
        pending_layout.addWidget(self.code_viewer)

        btn_box = QHBoxLayout()
        btn_box.setSpacing(10)

        self.btn_reject = QPushButton("Rejeitar Solicitação")
        self.btn_reject.setObjectName("btnReject")
        self.btn_reject.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.btn_reject.clicked.connect(self.reject_request)
        self.btn_reject.setEnabled(False)
        btn_box.addWidget(self.btn_reject)

        self.btn_approve = QPushButton("Aprovar & Executar via UAC")
        self.btn_approve.setObjectName("btnApprove")
        self.btn_approve.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.btn_approve.clicked.connect(self.approve_request)
        self.btn_approve.setEnabled(False)
        btn_box.addWidget(self.btn_approve)

        pending_layout.addLayout(btn_box)
        main_layout.addWidget(self.card_pending)

        # -------------------------------------------------------------
        # TABELA DE HISTÓRICO RECENTE (REQUISITO 2b)
        # -------------------------------------------------------------
        lbl_hist_title = QLabel("📋 Histórico Recente de Requisições & Auditoria")
        lbl_hist_title.setStyleSheet("font-size: 13px; font-weight: bold; color: #a6adc8; margin-top: 6px;")
        main_layout.addWidget(lbl_hist_title)

        self.table_history = QTableWidget()
        self.table_history.setColumnCount(4)
        self.table_history.setHorizontalHeaderLabels(["Data/Hora", "Comando / Operação", "Estado", "OTP (Mascarado)"])
        self.table_history.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.table_history.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.table_history.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.table_history.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self.table_history.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table_history.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        main_layout.addWidget(self.table_history, stretch=1)

        # -------------------------------------------------------------
        # PAINEL DE AÇÕES (REQUISITO 2c)
        # -------------------------------------------------------------
        action_layout = QHBoxLayout()
        action_layout.setSpacing(10)

        self.btn_reset_key = QPushButton("🔄 Resetar HOTP (Revogar Privilégios)")
        self.btn_reset_key.setObjectName("btnDanger")
        self.btn_reset_key.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.btn_reset_key.clicked.connect(self.open_reset_dialog)
        action_layout.addWidget(self.btn_reset_key)

        self.btn_uninstall = QPushButton("🗑️ Desinstalar Utilitário")
        self.btn_uninstall.setObjectName("btnDanger")
        self.btn_uninstall.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.btn_uninstall.clicked.connect(self.open_uninstall_dialog)
        action_layout.addWidget(self.btn_uninstall)

        action_layout.addStretch()

        self.btn_refresh = QPushButton("🔃 Recarregar Histórico")
        self.btn_refresh.setObjectName("btnAction")
        self.btn_refresh.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.btn_refresh.clicked.connect(self.refresh_dashboard)
        action_layout.addWidget(self.btn_refresh)

        self.btn_minimize = QPushButton("Minimizar para a Bandeja")
        self.btn_minimize.setObjectName("btnAction")
        self.btn_minimize.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.btn_minimize.clicked.connect(self.hide)
        action_layout.addWidget(self.btn_minimize)

        main_layout.addLayout(action_layout)

    def init_tray(self):
        self.tray_icon = QSystemTrayIcon(self)
        self.tray_icon.setToolTip("Antigravity Admin Bridge")

        icon_path = str(BASE_DIR / "icon.ico")
        if os.path.exists(icon_path):
            self.tray_icon.setIcon(QIcon(icon_path))

        tray_menu = QMenu()
        open_action = QAction("Abrir Central de Gestão", self)
        open_action.triggered.connect(self.show_window)
        tray_menu.addAction(open_action)

        status_action = QAction("Status do Contador", self)
        status_action.triggered.connect(self.show_counter_status_dialog)
        tray_menu.addAction(status_action)

        tray_menu.addSeparator()

        reset_action = QAction("Resetar HOTP (Revogar Privilégios)", self)
        reset_action.triggered.connect(self.open_reset_dialog)
        tray_menu.addAction(reset_action)

        uninstall_action = QAction("Desinstalar Utilitário", self)
        uninstall_action.triggered.connect(self.open_uninstall_dialog)
        tray_menu.addAction(uninstall_action)

        tray_menu.addSeparator()

        quit_action = QAction("Sair", self)
        quit_action.triggered.connect(self.quit_app)
        tray_menu.addAction(quit_action)

        self.tray_icon.setContextMenu(tray_menu)
        # Clique com botão esquerdo abre a janela da Central de Gestão
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
                "Antigravity Admin Bridge",
                "A Central continua em execução na bandeja do sistema.",
                QSystemTrayIcon.MessageIcon.Information,
                2000
            )

    def quit_app(self):
        self.tray_icon.hide()
        QApplication.quit()

    def write_heartbeat(self):
        try:
            with open(HEARTBEAT_FILE, "w", encoding="utf-8") as f:
                json.dump({
                    "timestamp": time.time(),
                    "status": "online",
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

        if "Bloqueado" in status_text or status_data.get("lockdown"):
            self.lbl_status_val.setStyleSheet("color: #f38ba8;")
        elif "Aguardando" in status_text:
            self.lbl_status_val.setStyleSheet("color: #f9e2af;")
        else:
            self.lbl_status_val.setStyleSheet("color: #a6e3a1;")

        # 2. Popula a tabela de histórico
        history_items = load_recent_history(50)
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

    # -------------------------------------------------------------
    # PROCESSAMENTO ATÔMICO DA FILA DE REQUISIÇÕES
    # -------------------------------------------------------------
    def check_requests(self):
        if self.current_request or (self.exec_thread and self.exec_thread.isRunning()):
            return

        if not REQUESTS_DIR.exists():
            return

        req_files = list(REQUESTS_DIR.glob("*.json"))
        if not req_files:
            return

        target_file = req_files[0]
        req_id = target_file.stem

        # Reivindicação atômica: move imediatamente para processing/
        PROCESSING_DIR.mkdir(parents=True, exist_ok=True)
        processing_file = PROCESSING_DIR / f"{req_id}.json"
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

        provided_otp = data.get("otp")
        caller_info = data.get("caller")

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
                    "completed_at": datetime.now(timezone.utc).isoformat()
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
                            "Antigravity • LOCKDOWN ATIVADO",
                            "3 falhas consecutivas detectadas! Tarefa elevada removida.",
                            QSystemTrayIcon.MessageIcon.Critical,
                            6000
                        )
                    QTimer.singleShot(1500, self.quit_app)
                return

            # Código válido: executa com permissões elevadas
            logging.info(f"[HOTP APROVADO] Req: {req_id} autenticado! Contador: {used_counter - 1}")
            self.execute_authenticated_request(data, used_counter - 1, processing_file)
        else:
            # Modo Híbrido: exige UAC manual na tela
            logging.info(f"[MODO HÍBRIDO] Req: {req_id} sem OTP. Exigindo confirmação UAC.")
            self.display_manual_uac_request(data, processing_file)

    def display_manual_uac_request(self, data, processing_file: Path):
        self.current_request = data
        self.current_processing_file = processing_file

        title = data.get("title", "Comando Administrativo")
        desc = data.get("description", "Sem descrição informada.")
        script_type = data.get("script_type", "bat").upper()
        code = data.get("code", "")

        self.lbl_req_title.setText(title)
        self.lbl_req_sub.setText(f"[Sem OTP] Confirmação manual requerida via UAC • {desc}")
        self.lbl_badge.setText(f"UAC REQUERIDO ({script_type})")
        self.lbl_badge.setStyleSheet("background-color: #f9e2af; color: #11111b; padding: 4px 10px; border-radius: 4px;")

        self.code_viewer.setPlainText(code)
        self.btn_reject.setEnabled(True)
        self.btn_approve.setEnabled(True)

        if self.tray_icon.isVisible():
            self.tray_icon.showMessage(
                "Antigravity • Confirmação UAC",
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

        self.lbl_req_title.setText(title)
        self.lbl_req_sub.setText(f"Autenticado via HOTP (Contador #{counter}) • {desc}")
        self.lbl_badge.setText(f"AUTORIZADO ({script_type})")
        self.lbl_badge.setStyleSheet("background-color: #a6e3a1; color: #11111b; padding: 4px 10px; border-radius: 4px;")

        self.code_viewer.setPlainText(code)
        self.btn_reject.setEnabled(False)
        self.btn_approve.setEnabled(False)

        self.exec_thread = ExecutionThread(self.current_request, int(self.winId()), force_uac=False)
        self.exec_thread.finished_signal.connect(self.on_execution_finished)
        self.exec_thread.start()

    def approve_request(self):
        if not self.current_request:
            return
        self.btn_approve.setEnabled(False)
        self.btn_reject.setEnabled(False)
        self.lbl_badge.setText("EXECUTANDO VIA UAC...")
        self.lbl_badge.setStyleSheet("background-color: #f9e2af; color: #11111b; padding: 4px 10px; border-radius: 4px;")

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
            "completed_at": datetime.now(timezone.utc).isoformat()
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
            self.lbl_badge.setStyleSheet("background-color: #a6e3a1; color: #11111b; padding: 4px 10px; border-radius: 4px;")
            self.code_viewer.setPlainText(f"=== SAÍDA RETORNADA (CÓDIGO 0) ===\n\n{output_data}")
        else:
            self.lbl_req_title.setText(f"Finalizado com Erro (Código {exit_code})")
            self.lbl_badge.setText("ERRO")
            self.lbl_badge.setStyleSheet("background-color: #f38ba8; color: #11111b; padding: 4px 10px; border-radius: 4px;")
            self.code_viewer.setPlainText(f"=== SAÍDA DA EXECUÇÃO (CÓDIGO {exit_code}) ===\n\n{output_data}")

        self.refresh_dashboard()
        QTimer.singleShot(2500, self.reset_ui)

    def reset_ui(self):
        self.current_request = None
        self.current_processing_file = None
        self.lbl_req_title.setText("Aguardando solicitações...")
        self.lbl_req_sub.setText("O assistente Antigravity enviará solicitações aqui quando precisar executar comandos.")
        self.lbl_badge.setText("INATIVO")
        self.lbl_badge.setStyleSheet("background-color: #313244; color: #cdd6f4; padding: 4px 10px; border-radius: 4px;")
        self.code_viewer.clear()
        self.btn_reject.setEnabled(False)
        self.btn_approve.setEnabled(False)

    def open_reset_dialog(self):
        if not is_admin():
            try:
                request_elevation_with_args(["reset"])
                return
            except Exception as e:
                QMessageBox.critical(self, "Permissão Necessária", f"Privilégios de Administrador são necessários: {e}")
                return
        dlg = ResetWizardDialog(self.hotp_auth, self)
        dlg.exec()
        self.refresh_dashboard()

    def open_uninstall_dialog(self):
        if not is_admin():
            try:
                request_elevation_with_args(["uninstall"])
                return
            except Exception as e:
                QMessageBox.critical(self, "Permissão Necessária", f"Privilégios de Administrador são necessários: {e}")
                return
        res = QMessageBox.question(
            self,
            "Desinstalar Utilitário",
            "Tem certeza que deseja desinstalar completamente o Antigravity Bridge?\n\n"
            "Esta ação irá:\n"
            "• Remover a tarefa agendada do Windows (schtasks)\n"
            "• Restaurar as permissões de acesso NTFS\n"
            "• Apagar todos os arquivos e filas de C:\\Utilitario\n"
            "• Remover os atalhos da Área de Trabalho\n\n"
            "Deseja prosseguir?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )
        if res == QMessageBox.StandardButton.Yes:
            success = perform_full_uninstall(self)
            if success:
                QMessageBox.information(
                    self,
                    "Desinstalação Concluída",
                    "O Antigravity Bridge foi desinstalado com sucesso da máquina."
                )
                self.quit_app()
            else:
                QMessageBox.critical(
                    self,
                    "Erro",
                    "Falha ao executar a rotina de desinstalação completa."
                )

    def show_counter_status_dialog(self):
        st = self.hotp_auth.get_counter_status()
        counter = st.get("counter", 0)
        lockdown = "SIM (Bloqueado)" if st.get("lockdown") else "NÃO (Ativo)"
        provisioned = "SIM (Flag=1)" if st.get("provisioned_flag") == 1 else "NÃO (Flag=0)"
        fails = st.get("recent_failures", 0)
        status_txt = st.get("status_text", "Ativo")

        QMessageBox.information(
            self,
            "Status do Contador HOTP",
            f"Contador Atual: {counter}\n"
            f"Estado do Serviço: {status_txt}\n"
            f"Provisionado: {provisioned}\n"
            f"Bloqueio Fail-Safe: {lockdown}\n"
            f"Falhas Recentes (5m): {fails} / 3\n\n"
            "O código OTP nunca é exibido no computador por segurança.\n"
            "Consulte seu aplicativo autenticador no telemóvel."
        )


# -----------------------------------------------------------------------------
# DAEMON EM SEGUNDO PLANO (HEADLESS PARA TAREFA AGENDADA COMO SYSTEM)
# -----------------------------------------------------------------------------
def run_daemon_loop(hotp_auth: HOTPAuth):
    """Executa o loop contínuo de processamento de comandos em segundo plano como SYSTEM."""
    logging.info("[DAEMON] AntigravityBridge daemon iniciado sob conta de serviço.")
    QUEUE_DIR.mkdir(parents=True, exist_ok=True)
    REQUESTS_DIR.mkdir(parents=True, exist_ok=True)
    PROCESSING_DIR.mkdir(parents=True, exist_ok=True)
    RESPONSES_DIR.mkdir(parents=True, exist_ok=True)
    SCRIPTS_DIR.mkdir(parents=True, exist_ok=True)

    while True:
        try:
            # Atualiza heartbeat
            with open(HEARTBEAT_FILE, "w", encoding="utf-8") as f:
                json.dump({"timestamp": time.time(), "status": "online", "mode": "daemon", "pid": os.getpid()}, f)

            req_files = list(REQUESTS_DIR.glob("*.json"))
            if req_files:
                target = req_files[0]
                # Verifica se a solicitação possui OTP antes de retirar da fila
                try:
                    with open(target, "r", encoding="utf-8") as f:
                        peek_data = json.load(f)
                except Exception:
                    time.sleep(0.5)
                    continue

                if not peek_data.get("otp"):
                    # Sem OTP: é solicitação manual que requer confirmação UAC na tela do usuário
                    time.sleep(1.0)
                    continue

                req_id = target.stem
                proc_file = PROCESSING_DIR / f"{req_id}.json"
                try:
                    target.rename(proc_file)
                except Exception:
                    time.sleep(0.5)
                    continue

                data = peek_data

                provided_otp = data.get("otp")
                caller_info = data.get("caller")

                if provided_otp:
                    is_valid, auth_msg, used_counter = hotp_auth.verify_and_advance(provided_otp, caller_info)
                    if not is_valid:
                        res = {
                            "id": req_id,
                            "status": "rejected_auth",
                            "reason": auth_msg,
                            "exit_code": 401,
                            "output": f"[ACESSO RECUSADO]: {auth_msg}",
                            "completed_at": datetime.now(timezone.utc).isoformat()
                        }
                        with open(RESPONSES_DIR / f"{req_id}.json", "w", encoding="utf-8") as f:
                            json.dump(res, f, indent=2, ensure_ascii=False)
                        proc_file.unlink(missing_ok=True)
                        continue

                    # Executa comando autenticado
                    script_type = data.get("script_type", "bat").lower()
                    code = data.get("code", "")
                    ext = "ps1" if script_type == "ps1" else "bat"
                    sc_path = SCRIPTS_DIR / f"{req_id}.{ext}"
                    lg_path = RESPONSES_DIR / f"{req_id}.log"
                    ex_path = RESPONSES_DIR / f"{req_id}.exit"

                    with open(sc_path, "w", encoding="utf-8") as f:
                        f.write(code)

                    cmd = [
                        "powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass",
                        "-File", str(RUNNER_PS1),
                        "-ScriptPath", str(sc_path),
                        "-ScriptType", script_type,
                        "-LogPath", str(lg_path),
                        "-ExitPath", str(ex_path)
                    ]
                    subprocess.run(cmd, capture_output=True, check=False, creationflags=0x08000000)

                    out_txt = ""
                    ec = 0
                    if lg_path.exists():
                        try:
                            with open(lg_path, "r", encoding="utf-8", errors="replace") as f:
                                out_txt = f.read()
                        except Exception:
                            pass
                    if ex_path.exists():
                        try:
                            with open(ex_path, "r", encoding="utf-8") as f:
                                ec = int(f.read().strip())
                        except Exception:
                            pass

                    res = {
                        "id": req_id,
                        "status": "approved",
                        "exit_code": ec,
                        "output": out_txt,
                        "completed_at": datetime.now(timezone.utc).isoformat()
                    }
                    with open(RESPONSES_DIR / f"{req_id}.json", "w", encoding="utf-8") as f:
                        json.dump(res, f, indent=2, ensure_ascii=False)

                    sc_path.unlink(missing_ok=True)
                    lg_path.unlink(missing_ok=True)
                    ex_path.unlink(missing_ok=True)
                    proc_file.unlink(missing_ok=True)

        except Exception as e:
            logging.error(f"[DAEMON ERROR]: {e}")

        time.sleep(1.0)


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
        except Exception:
            pass

    if args.subcommand == "status":
        st = hotp_auth.get_counter_status()
        print("=" * 60)
        print("         STATUS DO ANTIGRAVITY ADMIN BRIDGE")
        print("=" * 60)
        print(f"  Contador Atual:           {st.get('counter', 0)}")
        print(f"  Estado do Serviço:        {st.get('status_text', 'Ativo')}")
        print(f"  Provisionado:             {'SIM (Flag=1)' if st.get('provisioned_flag') == 1 else 'NÃO (Flag=0)'}")
        print(f"  Lockdown Fail-Safe:       {'ATIVADO' if st.get('lockdown') else 'NORMAL'}")
        print(f"  Falhas Recentes (5m):     {st.get('recent_failures', 0)} / 3")
        print(f"  Integridade do Estado:    {'Íntegro' if not st.get('tampered') else 'VIOLADO (Adulterado)'}")
        print(f"  Último Uso:               {st.get('last_used_at') or 'Nenhum'}")
        print("=" * 60)
        sys.exit(0)

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
            user_ch = input("Digite o código de presença física acima: ").strip()

        pw = getattr(args, "password", None)
        if not pw:
            import getpass
            pw = getpass.getpass("Digite sua Palavra-passe de Recuperação: ").strip()

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
            ans = input("Tem certeza que deseja desinstalar completamente o utilitário? (s/N): ").strip().lower()
            if ans not in ("s", "sim", "y", "yes"):
                print("Operação cancelada.")
                sys.exit(0)

        print("[*] Removendo tarefas agendadas, filas e restaurando permissões...")
        ok = perform_full_uninstall()
        if ok:
            print("[SUCESSO]: Antigravity Admin Bridge desinstalado com sucesso.")
            sys.exit(0)
        else:
            print("[ERRO]: Falha ao concluir desinstalação.", file=sys.stderr)
            sys.exit(1)

    elif args.subcommand == "setup":
        run_cli_setup(args, hotp_auth)
        sys.exit(0)

    elif args.subcommand == "run":
        # Envia requisição para a fila
        REQUESTS_DIR.mkdir(parents=True, exist_ok=True)
        RESPONSES_DIR.mkdir(parents=True, exist_ok=True)

        req_id = str(uuid.uuid4())
        payload = {
            "id": req_id,
            "title": args.title or "Comando CLI",
            "description": args.description or "Execução via terminal",
            "script_type": args.type or "cmd",
            "code": args.code,
            "otp": args.otp,
            "timeout": args.timeout or 120,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "caller": {
                "pid": os.getpid(),
                "exe": sys.executable,
                "user": os.getenv("USERNAME", "unknown")
            }
        }

        req_file = REQUESTS_DIR / f"{req_id}.json"
        with open(req_file, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, ensure_ascii=False)

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
            time.sleep(0.5)

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
    print("      PROVISIONAMENTO INICIAL HOTP (MODO LINHA DE COMANDO)")
    print("=" * 65)

    if hotp_auth.is_provisioned() and not getattr(args, "force", False):
        print("\n[AVISO]: O utilitário já está provisionado (Flag=1).")
        print("Para redefinir a chave, utilize o comando: AntigravityBridge.exe reset\n")
        sys.exit(1)

    pw = getattr(args, "password", None)
    if not pw:
        import getpass
        try:
            pw = getpass.getpass("Defina a Palavra-passe de Recuperação (mínimo 8 caracteres): ").strip()
            pw_conf = getpass.getpass("Confirme a Palavra-passe de Recuperação: ").strip()
        except Exception:
            pw = input("Defina a Palavra-passe de Recuperação (mínimo 8 caracteres): ").strip()
            pw_conf = input("Confirme a Palavra-passe de Recuperação: ").strip()

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
    print(f"  Flag:              1 (Travado)")
    print(f"  Dígitos:           6 | Algoritmo: HMAC-SHA1")
    print("=" * 65)
    print("  ESCANEE O QR CODE ABAIXO NO SEU CELULAR (Aegis, 2FAS, Google Auth):")
    print("-" * 65 + "\n")

    try:
        qr = qrcode.QRCode(box_size=1, border=1)
        qr.add_data(uri)
        qr.make(fit=True)
        qr.print_ascii(out=sys.stdout, invert=True)
    except Exception as e:
        print(f"  (Não foi possível renderizar QR em ASCII: {e})")

    print("\n" + "-" * 65)
    print("  INSERÇÃO MANUAL NO AUTENTICADOR:")
    print(f"  Chave Secreta (Base32): {secret_b32}")
    print(f"  URI de Pareamento:      {uri}")
    print("=" * 65)
    print("  [IMPORTANTE]: Esta é a ÚNICA vez que este segredo será exibido!")
    print("  O computador nunca mais salvará nem exibirá esta chave.")
    print("=" * 65)

    print("\n[*] Registrando serviço no Agendador de Tarefas do Windows (SYSTEM)...")
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
    ensure_environment_installed()
    hotp_auth = HOTPAuth()

    parser = argparse.ArgumentParser(
        description="Antigravity Admin Bridge & Central de Gestão HOTP",
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

    # Comando history
    subparsers.add_parser("history", help="Exibe o histórico recente de auditoria e execuções")

    # Comando reset
    p_reset = subparsers.add_parser("reset", help="Executa revogação de privilégios e reset da chave")
    p_reset.add_argument("--password", help="Palavra-passe de recuperação")
    p_reset.add_argument("--challenge", help="Código de presença física")

    # Comando uninstall
    p_uninst = subparsers.add_parser("uninstall", help="Desinstala o utilitário completamente")
    p_uninst.add_argument("--force", action="store_true", help="Força desinstalação sem confirmação")

    # Comando run
    p_run = subparsers.add_parser("run", help="Envia um comando para execução elevada")
    p_run.add_argument("--title", default="Comando Administrativo", help="Título da solicitação")
    p_run.add_argument("--description", default="", help="Descrição da solicitação")
    p_run.add_argument("--type", choices=["bat", "cmd", "ps1"], default="cmd", help="Tipo de script")
    p_run.add_argument("--code", required=True, help="Comando ou código a executar")
    p_run.add_argument("--otp", default=None, help="Código OTP de 6 dígitos")
    p_run.add_argument("--timeout", type=int, default=120, help="Tempo limite em segundos")

    args, unknown = parser.parse_known_args()

    # Se um subcomando CLI foi invocado
    if args.subcommand:
        if args.subcommand in ("setup", "reset", "uninstall") and not is_admin():
            try:
                request_elevation()
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
    app = QApplication(sys.argv)
    app.setQuitOnLastWindowClosed(False)

    # Verificação de Instância Única (Single Instance) via QLocalSocket
    local_socket = QLocalSocket()
    local_socket.connectToServer(LOCAL_SERVER_NAME)
    if local_socket.waitForConnected(500):
        # Outra instância já está ativa: solicita foco e encerra o novo processo
        local_socket.write(b"SHOW\n")
        local_socket.waitForBytesWritten(1000)
        local_socket.disconnectFromServer()
        sys.exit(0)

    # Inicia escuta local para instâncias futuras
    QLocalServer.removeServer(LOCAL_SERVER_NAME)
    ipc_server = QLocalServer(app)
    ipc_server.listen(LOCAL_SERVER_NAME)

    # Verifica se já está provisionado
    if not hotp_auth.is_provisioned():
        # Primeira execução: se não for admin, eleva para conseguir salvar chave e permissões SYSTEM
        if not is_admin():
            try:
                request_elevation()
                return
            except Exception:
                pass
        wizard = SetupWizardDialog(hotp_auth)
        if wizard.exec() != QDialog.DialogCode.Accepted:
            sys.exit(0)

    window = AdminBridgeWindow(hotp_auth)

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
        window.hide()
    else:
        window.show_window()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
