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
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QPlainTextEdit, QFrame, QSystemTrayIcon,
    QMenu, QMessageBox, QDialog, QLineEdit
)

from hotp_auth import HOTPAuth
from hotp_crypto import wipe_buffer, apply_strict_acls, verify_caller_origin

BASE_DIR = Path("C:/Utilitario")
CONFIG_DIR = BASE_DIR / "config"
REQUESTS_DIR = BASE_DIR / "queue" / "requests"
RESPONSES_DIR = BASE_DIR / "queue" / "responses"
SCRIPTS_DIR = BASE_DIR / "scripts"
LOGS_DIR = BASE_DIR / "logs"
HEARTBEAT_FILE = BASE_DIR / "queue" / "heartbeat.json"
RUNNER_PS1 = BASE_DIR / "runner.ps1"
CONFIG_FILE = CONFIG_DIR / "hotp_config.json"

LOGS_DIR.mkdir(parents=True, exist_ok=True)
logging.basicConfig(
    filename=str(LOGS_DIR / "app.log"),
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

# -----------------------------------------------------------------------------
# RUNNER POWERSHELL EMBUTIDO (SEM NECESSIDADE DE ARQUIVOS SOLTOS PRÉVIOS)
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


# -----------------------------------------------------------------------------
# FUNÇÕES NATIVAS DO WINDOWS & AUTO-ELEVAÇÃO
# -----------------------------------------------------------------------------
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
        ("lpIDList", wintypes.LPVOID),
        ("lpClass", wintypes.LPCWSTR),
        ("hkeyClass", wintypes.HKEY),
        ("dwHotKey", wintypes.DWORD),
        ("hIcon", wintypes.HANDLE),
        ("hProcess", wintypes.HANDLE)
    ]


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
        1  # SW_SHOWNORMAL
    )
    if ret > 32:
        sys.exit(0)
    else:
        raise PermissionError("Elevação de privilégios UAC foi recusada pelo usuário.")


def ensure_environment_installed():
    """Garante a estrutura de diretórios e extração dos componentes essenciais."""
    BASE_DIR.mkdir(parents=True, exist_ok=True)
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    REQUESTS_DIR.mkdir(parents=True, exist_ok=True)
    RESPONSES_DIR.mkdir(parents=True, exist_ok=True)
    SCRIPTS_DIR.mkdir(parents=True, exist_ok=True)

    # Cria runner.ps1 a partir do código embutido se ausente
    if not RUNNER_PS1.exists():
        with open(RUNNER_PS1, "w", encoding="utf-8") as f:
            f.write(RUNNER_PS1_SCRIPT)

    # Copia a si mesmo para o local definitivo em C:\Utilitario\AntigravityBridge.exe se executado de fora
    target_exe = (BASE_DIR / "AntigravityBridge.exe").resolve()
    current_exe = Path(sys.executable).resolve()
    if getattr(sys, "frozen", False) and current_exe != target_exe:
        try:
            shutil.copy2(str(current_exe), str(target_exe))
        except Exception as e:
            logging.warning(f"Aviso ao copiar executável para C:\\Utilitario: {e}")

    # Aplica permissões NTFS restritivas na pasta raiz
    apply_strict_acls(BASE_DIR)


def register_scheduled_task() -> bool:
    """Registra o executável no Agendador de Tarefas do Windows com privilégios HIGHEST."""
    exe_path = str(BASE_DIR / "AntigravityBridge.exe")
    cmd = [
        "schtasks", "/create",
        "/tn", "AntigravityAdminBridge",
        "/tr", f'"{exe_path}"',
        "/rl", "HIGHEST",
        "/sc", "ONLOGON",
        "/f"
    ]
    res = subprocess.run(cmd, capture_output=True, text=True, check=False, creationflags=0x08000000)
    if res.returncode == 0:
        logging.info("Tarefa agendada AntigravityAdminBridge registrada com sucesso.")
        subprocess.run(["schtasks", "/run", "/tn", "AntigravityAdminBridge"], capture_output=True, check=False, creationflags=0x08000000)
        return True
    else:
        logging.error(f"Erro ao registrar tarefa agendada: {res.stderr}")
        return False


# -----------------------------------------------------------------------------
# GERAÇÃO EFÊMERA DE QR CODE EM MEMÓRIA (ZERO VESTÍGIOS EM DISCO)
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
# ASSISTENTE DE PROVISIONAMENTO INTERATIVO (ZERO-KNOWLEDGE / MEMÓRIA PURA)
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
            "Esta chave protegerá o segredo localmente via TPM/DPAPI e será necessária "
            "caso queira redefinir o autenticador no futuro."
        )
        lbl_desc.setWordWrap(True)
        lbl_desc.setStyleSheet("font-size: 12px; color: #a6adc8; line-height: 1.4;")
        self.layout.addWidget(lbl_desc)

        lbl_p1 = QLabel("Palavra-passe de Recuperação (mínimo 8 caracteres):")
        lbl_p1.setStyleSheet("font-weight: 600; font-size: 12px; margin-top: 10px;")
        self.layout.addWidget(lbl_p1)

        self.txt_p1 = QLineEdit()
        self.txt_p1.setEchoMode(QLineEdit.EchoMode.Password)
        self.txt_p1.setPlaceholderText("Digite a palavra-passe desejada")
        self.layout.addWidget(self.txt_p1)

        lbl_p2 = QLabel("Confirmar Palavra-passe:")
        lbl_p2.setStyleSheet("font-weight: 600; font-size: 12px;")
        self.layout.addWidget(lbl_p2)

        self.txt_p2 = QLineEdit()
        self.txt_p2.setEchoMode(QLineEdit.EchoMode.Password)
        self.txt_p2.setPlaceholderText("Repita a palavra-passe")
        self.layout.addWidget(self.txt_p2)

        self.layout.addSpacing(10)

        self.btn_gen = QPushButton("Gerar Chave e Exibir QR Code na Tela")
        self.btn_gen.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.btn_gen.clicked.connect(self.generate_keys)
        self.layout.addWidget(self.btn_gen)

        self.btn_cancel = QPushButton("Cancelar")
        self.btn_cancel.setObjectName("btnCancel")
        self.btn_cancel.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.btn_cancel.clicked.connect(self.reject)
        self.layout.addWidget(self.btn_cancel)

    def generate_keys(self):
        p1 = self.txt_p1.text().strip()
        p2 = self.txt_p2.text().strip()

        if len(p1) < 8:
            QMessageBox.warning(self, "Aviso", "A palavra-passe deve conter pelo menos 8 caracteres.")
            return

        if p1 != p2:
            QMessageBox.warning(self, "Aviso", "As palavras-passe não coincidem. Digite novamente.")
            return

        try:
            caller_info = {
                "pid": os.getpid(),
                "exe": sys.executable,
                "script": "SetupWizardDialog",
                "user": os.getenv("USERNAME", "unknown")
            }
            res = self.hotp_auth.provision(p1, caller_info=caller_info)
            self.show_qr_step(res)
        except Exception as e:
            QMessageBox.critical(self, "Erro", f"Falha no provisionamento: {e}")

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

        # Renderização efêmera em memória (zero vestígios em disco)
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
        # Destrói e sobrescreve buffers de memória com zeros
        if self.raw_qr_buffer is not None:
            wipe_buffer(self.raw_qr_buffer)
            self.raw_qr_buffer = None
        gc.collect()

        # Registra a tarefa elevada no Windows
        register_scheduled_task()
        self.accept()

    def closeEvent(self, event):
        if self.raw_qr_buffer is not None:
            wipe_buffer(self.raw_qr_buffer)
            self.raw_qr_buffer = None
        gc.collect()
        super().closeEvent(event)


# -----------------------------------------------------------------------------
# ASSISTENTE DE RESET SEGURO (SENHA + DESAFIO DE PRESENÇA FÍSICA)
# -----------------------------------------------------------------------------
class ResetWizardDialog(QDialog):
    """Diálogo de redefinição de chave HOTP com presença física e senha."""

    def __init__(self, hotp_auth: HOTPAuth, parent=None):
        super().__init__(parent)
        self.hotp_auth = hotp_auth
        self.raw_qr_buffer: Optional[bytearray] = None
        self.challenge_code = f"PHYS-{secrets.randbelow(900000) + 100000}"

        self.setWindowTitle("Antigravity • Redefinir Autenticador (Reset)")
        self.setMinimumSize(480, 620)
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
        self.layout.setSpacing(14)

        self.init_reset_step()

    def init_reset_step(self):
        while self.layout.count():
            item = self.layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        lbl_title = QLabel("🔄 Redefinição de Chave HOTP")
        lbl_title.setStyleSheet("font-size: 18px; font-weight: bold; color: #f9e2af;")
        self.layout.addWidget(lbl_title)

        lbl_desc = QLabel(
            "Esta operação revoga a chave anterior e gera um novo pareamento.\n"
            "Exige confirmação de presença física na tela e a senha de recuperação atual."
        )
        lbl_desc.setWordWrap(True)
        lbl_desc.setStyleSheet("font-size: 12px; color: #a6adc8; line-height: 1.4;")
        self.layout.addWidget(lbl_desc)

        lbl_ch_title = QLabel("Confirmação de Presença Física (digite o código abaixo):")
        lbl_ch_title.setStyleSheet("font-weight: 600; font-size: 12px; color: #fab387;")
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

        lbl_curr_pw = QLabel("Palavra-passe de Recuperação Atual:")
        lbl_curr_pw.setStyleSheet("font-weight: 600; font-size: 12px;")
        self.layout.addWidget(lbl_curr_pw)

        self.txt_curr_pw = QLineEdit()
        self.txt_curr_pw.setEchoMode(QLineEdit.EchoMode.Password)
        self.txt_curr_pw.setPlaceholderText("Digite sua senha de recuperação atual")
        self.layout.addWidget(self.txt_curr_pw)

        lbl_new_pw = QLabel("Nova Palavra-passe de Recuperação:")
        lbl_new_pw.setStyleSheet("font-weight: 600; font-size: 12px;")
        self.layout.addWidget(lbl_new_pw)

        self.txt_new_pw = QLineEdit()
        self.txt_new_pw.setEchoMode(QLineEdit.EchoMode.Password)
        self.txt_new_pw.setPlaceholderText("Defina uma nova palavra-passe (mínimo 8 caracteres)")
        self.layout.addWidget(self.txt_new_pw)

        lbl_new_pw2 = QLabel("Confirmar Nova Palavra-passe:")
        lbl_new_pw2.setStyleSheet("font-weight: 600; font-size: 12px;")
        self.layout.addWidget(lbl_new_pw2)

        self.txt_new_pw2 = QLineEdit()
        self.txt_new_pw2.setEchoMode(QLineEdit.EchoMode.Password)
        self.txt_new_pw2.setPlaceholderText("Repita a nova palavra-passe")
        self.layout.addWidget(self.txt_new_pw2)

        self.btn_submit = QPushButton("Validar Presença e Gerar Novo Pareamento")
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
        new_pw = self.txt_new_pw.text().strip()
        new_pw2 = self.txt_new_pw2.text().strip()

        if len(new_pw) < 8:
            QMessageBox.warning(self, "Aviso", "A nova palavra-passe deve conter pelo menos 8 caracteres.")
            return

        if new_pw != new_pw2:
            QMessageBox.warning(self, "Aviso", "A confirmação da nova palavra-passe não confere.")
            return

        try:
            caller_info = {
                "pid": os.getpid(),
                "exe": sys.executable,
                "script": "ResetWizardDialog",
                "user": os.getenv("USERNAME", "unknown")
            }
            res = self.hotp_auth.reset_and_reprovision(
                recovery_password=curr_pw,
                physical_challenge_response=user_ch,
                expected_challenge=self.challenge_code,
                new_recovery_password=new_pw,
                caller_info=caller_info
            )
            self.show_new_qr_step(res)
        except Exception as e:
            QMessageBox.critical(self, "Erro no Reset", f"Falha na redefinição: {e}")

    def show_new_qr_step(self, res):
        while self.layout.count():
            item = self.layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        lbl_title = QLabel("📷 Novo QR Code de Pareamento")
        lbl_title.setStyleSheet("font-size: 18px; font-weight: bold; color: #a6e3a1;")
        lbl_title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.layout.addWidget(lbl_title)

        lbl_sub = QLabel("Chave anterior invalidada. Cadastre a nova chave no seu celular:")
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

        btn_finish = QPushButton("Concluir • Já Cadastrei no Celular")
        btn_finish.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        btn_finish.setStyleSheet("background-color: #a6e3a1; color: #11111b; font-weight: bold; padding: 12px;")
        btn_finish.clicked.connect(self.finalize_reset)
        self.layout.addWidget(btn_finish)

    def finalize_reset(self):
        if self.raw_qr_buffer is not None:
            wipe_buffer(self.raw_qr_buffer)
            self.raw_qr_buffer = None
        gc.collect()
        self.accept()

    def closeEvent(self, event):
        if self.raw_qr_buffer is not None:
            wipe_buffer(self.raw_qr_buffer)
            self.raw_qr_buffer = None
        gc.collect()
        super().closeEvent(event)


# -----------------------------------------------------------------------------
# THREAD DE EXECUÇÃO EM SEGUNDO PLANO
# -----------------------------------------------------------------------------
class ExecutionThread(QThread):
    finished_signal = pyqtSignal(dict)

    def __init__(self, request_data, hwnd=None, force_uac=False):
        super().__init__()
        self.request_data = request_data
        self.hwnd = hwnd
        self.force_uac = force_uac

    def run(self):
        req_id = self.request_data["id"]
        script_type = self.request_data.get("script_type", "bat").lower()
        code = self.request_data.get("code", "")

        SCRIPTS_DIR.mkdir(parents=True, exist_ok=True)
        LOGS_DIR.mkdir(parents=True, exist_ok=True)

        ext = "ps1" if script_type == "ps1" else "bat"
        script_path = SCRIPTS_DIR / f"{req_id}.{ext}"
        log_path = LOGS_DIR / f"{req_id}.log"
        exit_path = LOGS_DIR / f"{req_id}.exit"

        with open(script_path, "w", encoding="utf-8") as f:
            f.write(code)

        is_admin_user = is_admin()
        if is_admin_user and not self.force_uac:
            logging.info(f"Processo elevado e autenticado via HOTP! Executando sem UAC para {req_id}...")
            cmd = [
                "powershell.exe",
                "-NoProfile",
                "-ExecutionPolicy", "Bypass",
                "-File", str(RUNNER_PS1),
                "-ScriptPath", str(script_path),
                "-ScriptType", script_type,
                "-LogPath", str(log_path),
                "-ExitPath", str(exit_path)
            ]
            CREATE_NO_WINDOW = 0x08000000
            try:
                subprocess.run(
                    cmd,
                    cwd=str(BASE_DIR),
                    creationflags=CREATE_NO_WINDOW,
                    check=False
                )
            except Exception as e:
                logging.error(f"Erro na execução direta com admin: {e}")
        else:
            sei = SHELLEXECUTEINFO()
            sei.cbSize = ctypes.sizeof(sei)
            sei.fMask = 0x00000040  # SEE_MASK_NOCLOSEPROCESS
            sei.hwnd = self.hwnd if self.hwnd else 0
            sei.lpVerb = "runas"
            sei.lpFile = "powershell.exe"
            sei.lpParameters = (
                f'-NoProfile -ExecutionPolicy Bypass -File "{RUNNER_PS1}" '
                f'-ScriptPath "{script_path}" -ScriptType "{script_type}" '
                f'-LogPath "{log_path}" -ExitPath "{exit_path}"'
            )
            sei.lpDirectory = str(BASE_DIR)
            sei.nShow = 0  # SW_HIDE

            success = ctypes.windll.shell32.ShellExecuteExW(ctypes.byref(sei))
            if success and sei.hProcess:
                INFINITE = 0xFFFFFFFF
                ctypes.windll.kernel32.WaitForSingleObject(sei.hProcess, INFINITE)
                ctypes.windll.kernel32.CloseHandle(sei.hProcess)
            else:
                with open(exit_path, "w", encoding="utf-8") as f:
                    f.write("-1")
                with open(log_path, "w", encoding="utf-8") as f:
                    f.write("[ERRO]: O usuário rejeitou a elevação UAC do Windows ou ocorreu falha na chamada.")

        exit_code = 0
        output_text = ""
        if exit_path.exists():
            try:
                exit_code = int(exit_path.read_text(encoding="utf-8").strip())
            except Exception:
                exit_code = 1

        if log_path.exists():
            try:
                output_text = log_path.read_text(encoding="utf-8", errors="replace")
            except Exception:
                pass

        logging.info(f"Execução finalizada com exit_code: {exit_code}")
        response = {
            "id": req_id,
            "status": "approved",
            "exit_code": exit_code,
            "output": output_text,
            "completed_at": datetime.now(timezone.utc).isoformat()
        }

        self.finished_signal.emit(response)


# -----------------------------------------------------------------------------
# APLICAÇÃO PRINCIPAL (CENTRAL ADMINISTRATIVA & BRIDGE ELEVADO)
# -----------------------------------------------------------------------------
class AdminBridgeApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.current_request = None
        self.exec_thread = None
        self.hotp_auth = HOTPAuth()

        self.init_ui()
        self.init_tray()
        self.init_timers()

        # Se não provisionado, abre imediatamente o assistente de provisionamento
        if not self.hotp_auth.is_provisioned():
            QTimer.singleShot(400, self.open_setup_dialog)

    def init_ui(self):
        self.setWindowTitle("Antigravity • Central de Aprovação de Comandos")
        self.setMinimumSize(800, 580)
        self.resize(850, 620)

        icon_path = str(BASE_DIR / "icon.ico")
        if os.path.exists(icon_path):
            self.setWindowIcon(QIcon(icon_path))

        self.setStyleSheet("""
            QMainWindow {
                background-color: #11111b;
            }
            QWidget {
                color: #cdd6f4;
                font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
            }
            QFrame#cardFrame {
                background-color: #181825;
                border: 1px solid #313244;
                border-radius: 12px;
            }
            QLabel#statusTitle {
                font-size: 18px;
                font-weight: 700;
                color: #cdd6f4;
            }
            QLabel#statusSub {
                font-size: 13px;
                color: #a6adc8;
            }
            QLabel#badgeLabel {
                padding: 4px 12px;
                border-radius: 6px;
                font-weight: 600;
                font-size: 11px;
                text-transform: uppercase;
            }
            QPlainTextEdit#codeViewer {
                background-color: #0c0c14;
                color: #a6e3a1;
                border: 1px solid #313244;
                border-radius: 8px;
                padding: 10px;
                font-family: 'Cascadia Code', 'Consolas', monospace;
                font-size: 12px;
                line-height: 1.4;
            }
            QPushButton {
                font-size: 13px;
                font-weight: 600;
                border-radius: 8px;
                padding: 10px 20px;
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
                background-color: #313244;
                color: #f38ba8;
                border: 1px solid #45475a;
            }
            QPushButton#btnReject:hover {
                background-color: #f38ba8;
                color: #11111b;
            }
            QPushButton#btnAction {
                background-color: #313244;
                color: #89b4fa;
                font-size: 12px;
                padding: 6px 14px;
                border-radius: 6px;
            }
            QPushButton#btnAction:hover {
                background-color: #45475a;
            }
        """)

        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(24, 24, 24, 24)
        main_layout.setSpacing(16)

        card = QFrame()
        card.setObjectName("cardFrame")
        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(20, 20, 20, 20)
        card_layout.setSpacing(14)

        header_layout = QHBoxLayout()
        header_text_layout = QVBoxLayout()

        self.lbl_title = QLabel("Aguardando solicitações...")
        self.lbl_title.setObjectName("statusTitle")

        self.lbl_sub = QLabel("O assistente Antigravity enviará solicitações aqui quando precisar executar comandos.")
        self.lbl_sub.setObjectName("statusSub")
        self.lbl_sub.setWordWrap(True)

        header_text_layout.addWidget(self.lbl_title)
        header_text_layout.addWidget(self.lbl_sub)
        header_layout.addLayout(header_text_layout, stretch=1)

        self.lbl_badge = QLabel("INATIVO")
        self.lbl_badge.setObjectName("badgeLabel")
        self.lbl_badge.setStyleSheet("background-color: #313244; color: #a6adc8;")
        header_layout.addWidget(self.lbl_badge, alignment=Qt.AlignmentFlag.AlignTop)

        card_layout.addLayout(header_layout)

        # Barra de Ações Rápidas de Segurança
        action_bar = QHBoxLayout()
        self.btn_reset_key = QPushButton("🔄 Redefinir Autenticador")
        self.btn_reset_key.setObjectName("btnAction")
        self.btn_reset_key.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.btn_reset_key.clicked.connect(self.open_reset_dialog)
        action_bar.addWidget(self.btn_reset_key)

        self.btn_status_key = QPushButton("ℹ️ Status do Contador")
        self.btn_status_key.setObjectName("btnAction")
        self.btn_status_key.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.btn_status_key.clicked.connect(self.show_counter_status_dialog)
        action_bar.addWidget(self.btn_status_key)

        action_bar.addStretch()

        self.btn_copy = QPushButton("Copiar Script")
        self.btn_copy.setObjectName("btnAction")
        self.btn_copy.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.btn_copy.clicked.connect(self.copy_script_to_clipboard)
        self.btn_copy.setEnabled(False)
        action_bar.addWidget(self.btn_copy)

        card_layout.addLayout(action_bar)

        self.code_viewer = QPlainTextEdit()
        self.code_viewer.setObjectName("codeViewer")
        self.code_viewer.setReadOnly(True)
        self.code_viewer.setPlaceholderText("Nenhum comando pendente de aprovação no momento.")
        card_layout.addWidget(self.code_viewer, stretch=1)

        btn_layout = QHBoxLayout()
        btn_layout.setSpacing(12)

        self.btn_reject = QPushButton("Rejeitar Solicitação")
        self.btn_reject.setObjectName("btnReject")
        self.btn_reject.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.btn_reject.clicked.connect(self.reject_request)
        self.btn_reject.setEnabled(False)
        btn_layout.addWidget(self.btn_reject)

        self.btn_approve = QPushButton("Aprovar & Executar via UAC")
        self.btn_approve.setObjectName("btnApprove")
        self.btn_approve.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.btn_approve.clicked.connect(self.approve_request)
        self.btn_approve.setEnabled(False)
        btn_layout.addWidget(self.btn_approve)

        card_layout.addLayout(btn_layout)
        main_layout.addWidget(card)

    def init_tray(self):
        self.tray_icon = QSystemTrayIcon(self)
        self.tray_icon.setToolTip("Antigravity Admin Bridge")

        icon_path = str(BASE_DIR / "icon.ico")
        if os.path.exists(icon_path):
            self.tray_icon.setIcon(QIcon(icon_path))

        self.update_tray_menu()
        self.tray_icon.show()

    def update_tray_menu(self):
        tray_menu = QMenu()
        open_action = QAction("Abrir Central", self)
        open_action.triggered.connect(self.show_window)
        tray_menu.addAction(open_action)

        if not self.hotp_auth.is_provisioned():
            setup_action = QAction("🔑 Configurar Autenticador (HOTP)", self)
            setup_action.triggered.connect(self.open_setup_dialog)
            tray_menu.addAction(setup_action)
        else:
            reset_action = QAction("🔄 Redefinir Autenticador (Reset)", self)
            reset_action.triggered.connect(self.open_reset_dialog)
            tray_menu.addAction(reset_action)

        status_action = QAction("Consultar Posição do Contador (Sem Avançar)", self)
        status_action.triggered.connect(self.show_counter_status_dialog)
        tray_menu.addAction(status_action)

        exit_action = QAction("Sair", self)
        exit_action.triggered.connect(self.quit_app)
        tray_menu.addAction(exit_action)

        self.tray_icon.setContextMenu(tray_menu)

    def init_timers(self):
        self.heartbeat_timer = QTimer(self)
        self.heartbeat_timer.timeout.connect(self.update_heartbeat)
        self.heartbeat_timer.start(3000)
        self.update_heartbeat()

        self.queue_timer = QTimer(self)
        self.queue_timer.timeout.connect(self.check_requests)
        self.queue_timer.start(500)

    def update_heartbeat(self):
        HEARTBEAT_FILE.parent.mkdir(parents=True, exist_ok=True)
        try:
            with open(HEARTBEAT_FILE, "w", encoding="utf-8") as f:
                json.dump({
                    "pid": os.getpid(),
                    "timestamp": time.time(),
                    "status": "idle" if not self.current_request else "reviewing"
                }, f)
        except Exception:
            pass

    def check_requests(self):
        if self.current_request:
            req_file = REQUESTS_DIR / f"{self.current_request['id']}.json"
            if not req_file.exists():
                self.reset_ui()
            return

        if self.exec_thread and self.exec_thread.isRunning():
            return

        if not REQUESTS_DIR.exists():
            return

        req_files = list(REQUESTS_DIR.glob("*.json"))
        if not req_files:
            return

        target_file = req_files[0]
        try:
            with open(target_file, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            return

        req_id = data.get("id")
        if not req_id:
            try:
                target_file.unlink(missing_ok=True)
            except Exception:
                pass
            return

        provided_otp = data.get("otp")
        caller_info = data.get("caller")

        if provided_otp:
            is_valid, auth_msg, used_counter = self.hotp_auth.verify_and_advance(provided_otp, caller_info)

            if not is_valid:
                is_lockdown = "FAIL_SAFE_LOCKDOWN" in auth_msg or self.hotp_auth.is_lockdown()
                masked_otp = f"{str(provided_otp)[:2]}****" if len(str(provided_otp)) >= 2 else "******"
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
                    target_file.unlink(missing_ok=True)
                except Exception as e:
                    logging.error(f"Erro ao gravar resposta: {e}")

                if self.tray_icon.isVisible():
                    if is_lockdown:
                        self.tray_icon.showMessage(
                            "Antigravity • LOCKDOWN ATIVADO",
                            f"3 falhas consecutivas detectadas!\nA central elevada foi desativada por segurança.",
                            QSystemTrayIcon.MessageIcon.Critical,
                            6000
                        )
                    else:
                        self.tray_icon.showMessage(
                            "Antigravity • Acesso Negado",
                            f"Tentativa de execução bloqueada!\n{auth_msg}",
                            QSystemTrayIcon.MessageIcon.Warning,
                            4000
                        )

                if is_lockdown:
                    logging.critical("[FAIL-SAFE] Encerrando AntigravityBridge.exe devido a bloqueio de segurança.")
                    QTimer.singleShot(1500, self.quit_app)

                return

            logging.info(f"[HOTP APROVADO] Req: {req_id} autenticado! Contador: {used_counter - 1}")
            self.execute_authenticated_request(data, used_counter - 1)
        else:
            logging.info(f"[MODO HÍBRIDO] Req: {req_id} sem OTP. Solicitando confirmação interativa UAC.")
            self.display_manual_uac_request(data)

    def display_manual_uac_request(self, data):
        self.current_request = data
        title = data.get("title", "Comando Administrativo")
        desc = data.get("description", "Sem descrição informada.")
        script_type = data.get("script_type", "bat").upper()
        code = data.get("code", "")

        self.lbl_title.setText(title)
        self.lbl_sub.setText(f"[Sem OTP] Aprovação manual requerida via UAC • {desc}")
        self.lbl_badge.setText(f"UAC REQUERIDO ({script_type})")
        self.lbl_badge.setStyleSheet("background-color: #f9e2af; color: #11111b;")

        self.code_viewer.setPlainText(code)
        self.btn_copy.setEnabled(True)
        self.btn_reject.setEnabled(True)
        self.btn_approve.setEnabled(True)

        if self.tray_icon.isVisible():
            self.tray_icon.showMessage(
                "Antigravity • Confirmação UAC Necessária",
                f"{title}\nRequisição sem OTP: clique para autorizar via UAC.",
                QSystemTrayIcon.MessageIcon.Information,
                5000
            )

        self.show_window()

    def execute_authenticated_request(self, data, counter):
        self.current_request = data
        title = data.get("title", "Comando Administrativo")
        desc = data.get("description", "Sem descrição informada.")
        script_type = data.get("script_type", "bat").upper()
        code = data.get("code", "")

        self.lbl_title.setText(title)
        self.lbl_sub.setText(f"Autenticado via HOTP (Contador #{counter}) • {desc}")
        self.lbl_badge.setText(f"AUTORIZADO ({script_type})")
        self.lbl_badge.setStyleSheet("background-color: #a6e3a1; color: #11111b;")

        self.code_viewer.setPlainText(code)
        self.btn_copy.setEnabled(True)
        self.btn_reject.setEnabled(False)
        self.btn_approve.setEnabled(False)

        if self.tray_icon.isVisible():
            self.tray_icon.showMessage(
                "Antigravity • Executando Comando",
                f"{title}\nAutenticado com sucesso via HOTP #{counter}.",
                QSystemTrayIcon.MessageIcon.Information,
                3000
            )

        self.show_window()

        self.exec_thread = ExecutionThread(self.current_request, int(self.winId()), force_uac=False)
        self.exec_thread.finished_signal.connect(self.on_execution_finished)
        self.exec_thread.start()

    def approve_request(self):
        if not self.current_request:
            return
        self.btn_approve.setEnabled(False)
        self.btn_reject.setEnabled(False)
        self.lbl_badge.setText("EXECUTANDO...")
        self.lbl_badge.setStyleSheet("background-color: #f9e2af; color: #11111b;")

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
            "output": "A solicitação foi recusada pelo usuário na Central de Aprovação.",
            "completed_at": datetime.now(timezone.utc).isoformat()
        }
        try:
            with open(res_file, "w", encoding="utf-8") as f:
                json.dump(response, f, indent=2, ensure_ascii=False)
            req_file = REQUESTS_DIR / f"{req_id}.json"
            req_file.unlink(missing_ok=True)
        except Exception:
            pass

        self.reset_ui()
        self.hide()

    def on_execution_finished(self, response):
        req_id = response["id"]
        res_file = RESPONSES_DIR / f"{req_id}.json"
        try:
            with open(res_file, "w", encoding="utf-8") as f:
                json.dump(response, f, indent=2, ensure_ascii=False)
        except Exception:
            pass

        req_file = REQUESTS_DIR / f"{req_id}.json"
        try:
            req_file.unlink(missing_ok=True)
        except Exception:
            pass

        exit_code = response.get("exit_code", 0)
        output_data = response.get("output", "")
        if exit_code == 0:
            self.lbl_title.setText("Executado com Sucesso! Retornado ao Chat.")
            self.lbl_sub.setText("O comando foi finalizado com código 0.")
            self.lbl_badge.setText("CONCLUÍDO")
            self.lbl_badge.setStyleSheet("background-color: #a6e3a1; color: #11111b;")
            self.code_viewer.setPlainText(f"=== SAÍDA RETORNADA (CÓDIGO 0) ===\n\n{output_data}")
        else:
            self.lbl_title.setText(f"Finalizado (Código {exit_code})")
            self.lbl_badge.setText("FINALIZADO")
            self.lbl_badge.setStyleSheet("background-color: #eba0ac; color: #11111b;")
            self.code_viewer.setPlainText(f"=== SAÍDA DA EXECUÇÃO (CÓDIGO {exit_code}) ===\n\n{output_data}")

        QTimer.singleShot(1500, self.auto_close_window)

    def auto_close_window(self):
        self.reset_ui()
        self.hide()

    def reset_ui(self):
        self.current_request = None
        self.lbl_title.setText("Aguardando solicitações...")
        self.lbl_sub.setText("O assistente Antigravity enviará solicitações aqui quando precisar executar comandos.")
        self.lbl_badge.setText("INATIVO")
        self.lbl_badge.setStyleSheet("background-color: #313244; color: #a6adc8;")
        self.code_viewer.clear()
        self.btn_copy.setEnabled(False)
        self.btn_reject.setEnabled(False)
        self.btn_approve.setEnabled(False)

    def show_window(self):
        self.show()
        self.setWindowState(self.windowState() & ~Qt.WindowState.WindowMinimized | Qt.WindowState.WindowActive)
        self.raise_()
        self.activateWindow()

    def copy_script_to_clipboard(self):
        clipboard = QApplication.clipboard()
        clipboard.setText(self.code_viewer.toPlainText())

    def open_setup_dialog(self):
        dlg = SetupWizardDialog(self.hotp_auth, self)
        self.show_window()
        if dlg.exec() == QDialog.DialogCode.Accepted:
            self.update_tray_menu()
            QMessageBox.information(
                self,
                "Antigravity • Provisionamento Concluído",
                "Autenticador configurado com sucesso!\n"
                "A tarefa agendada foi registrada e a chave está protegida no TPM/DPAPI."
            )

    def open_reset_dialog(self):
        dlg = ResetWizardDialog(self.hotp_auth, self)
        self.show_window()
        if dlg.exec() == QDialog.DialogCode.Accepted:
            self.update_tray_menu()
            QMessageBox.information(
                self,
                "Antigravity • Reset Concluído",
                "Novo pareamento configurado com sucesso!"
            )

    def show_counter_status_dialog(self):
        st = self.hotp_auth.get_counter_status()
        prov_text = "SIM (Flag = 1 • Bloqueado)" if st.get("provisioned_flag") == 1 else "NÃO (Flag = 0)"
        lockdown_text = "ATIVO (Central Desativada por Falhas)" if st.get("lockdown") else "NORMAL"
        QMessageBox.information(
            self,
            "Antigravity • Status do Sistema",
            f"Contador Atual: #{st.get('counter')}\n"
            f"Provisionado e Travado: {prov_text}\n"
            f"Estado do Fail-Safe: {lockdown_text}\n"
            f"Último Sucesso: Contador #{st.get('last_success_counter')}\n\n"
            f"[*] O código de uso único deve ser consultado no aplicativo autenticador do telemóvel (Aegis, 2FAS, etc.).\n"
            f"[*] O computador NUNCA calcula nem exibe códigos OTP na tela.\n"
            f"[*] Consulta passiva realizada sem avançar o contador."
        )

    def closeEvent(self, event):
        if self.tray_icon.isVisible():
            self.hide()
            event.ignore()
        else:
            event.accept()

    def quit_app(self):
        try:
            HEARTBEAT_FILE.unlink(missing_ok=True)
        except Exception:
            pass
        QApplication.quit()


# -----------------------------------------------------------------------------
# CLIENTE CLI (INTEGRADO NO MESMO EXECUTÁVEL)
# -----------------------------------------------------------------------------
def check_heartbeat(max_age_seconds: float = 10.0) -> bool:
    if not HEARTBEAT_FILE.exists():
        return False
    try:
        with open(HEARTBEAT_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        last_beat = data.get("timestamp", 0)
        return (time.time() - last_beat) <= max_age_seconds
    except Exception:
        return False


def submit_request(title: str, description: str, script_type: str, code: str, otp: str = None, timeout: int = 120) -> dict:
    REQUESTS_DIR.mkdir(parents=True, exist_ok=True)
    RESPONSES_DIR.mkdir(parents=True, exist_ok=True)

    if not check_heartbeat(5.0):
        print("[*] Central offline. Disparando tarefa agendada...", file=sys.stderr)
        subprocess.run(["schtasks", "/run", "/tn", "AntigravityAdminBridge"], capture_output=True, check=False)
        time.sleep(1.5)

    req_id = str(uuid.uuid4())
    req_file = REQUESTS_DIR / f"{req_id}.json"
    res_file = RESPONSES_DIR / f"{req_id}.json"

    payload = {
        "id": req_id,
        "title": title,
        "description": description,
        "script_type": script_type.lower(),
        "code": code,
        "otp": otp,
        "caller": {
            "pid": os.getpid(),
            "exe": sys.executable,
            "script": str(Path(__file__).resolve()),
            "user": os.getenv("USERNAME", "unknown")
        },
        "created_at": datetime.now(timezone.utc).isoformat(),
        "status": "pending"
    }

    with open(req_file, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)

    print(f"[*] Solicitação [{req_id}] enviada para o utilitário.")
    start_time = time.time()
    while time.time() - start_time < timeout:
        if res_file.exists():
            try:
                with open(res_file, "r", encoding="utf-8") as f:
                    response = json.load(f)
                res_file.unlink(missing_ok=True)
                req_file.unlink(missing_ok=True)
                return response
            except (json.JSONDecodeError, PermissionError):
                time.sleep(0.3)
                continue
        time.sleep(0.5)

    req_file.unlink(missing_ok=True)
    return {
        "id": req_id,
        "status": "timeout",
        "error": f"Tempo limite de {timeout}s excedido.",
        "exit_code": -1,
        "output": ""
    }


# -----------------------------------------------------------------------------
# ENTRYPOINT DO EXECUTÁVEL ÚNICO
# -----------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="Antigravity Admin Bridge & Orchestrator")
    parser.add_argument("--setup", action="store_true", help="Executa o assistente de provisionamento interativo")
    parser.add_argument("--reset", action="store_true", help="Executa o assistente de reset com confirmação física")
    parser.add_argument("--status", action="store_true", help="Consulta os metadados do contador HOTP sem alterá-lo")

    subparsers = parser.add_subparsers(dest="cli_command")
    run_parser = subparsers.add_parser("run", help="Envia script para execução")
    run_parser.add_argument("--title", required=True)
    run_parser.add_argument("--description", required=True)
    run_parser.add_argument("--type", choices=["bat", "cmd", "ps1"], default="bat")
    run_parser.add_argument("--code", required=True)
    run_parser.add_argument("--otp", default=None)
    run_parser.add_argument("--timeout", type=int, default=120)

    subparsers.add_parser("status", help="Verifica se a central está ativa")

    args, unknown = parser.parse_known_args()

    # 1. Modo CLI: status do contador HOTP
    if args.status:
        auth = HOTPAuth()
        st = auth.get_counter_status()
        print("=" * 60)
        print("         STATUS DO CONTADOR HOTP (RFC 4226)")
        print("=" * 60)
        print(f"  Contador Atual:           {st['counter']}")
        print(f"  Provisionado / Travado:   {'SIM (Flag = 1)' if st['provisioned_flag'] == 1 else 'NÃO (Flag = 0)'}")
        print(f"  Estado Fail-Safe:         {'BLOQUEADO (LOCKDOWN)' if st['lockdown'] else 'NORMAL (Ativo)'}")
        print(f"  Falhas Recentes (5m):     {st.get('failures_in_window', 0)} / 3")
        print(f"  Último Contador Aceito:   {st['last_success_counter']}")
        print("=" * 60)
        print("  [*] MODELO DE VALIDAÇÃO CEGA ATIVO:")
        print("      O computador NUNCA calcula nem exibe códigos OTP.")
        print("      Gere o código exclusivamente no seu telemóvel (Aegis, 2FAS).")
        print("=" * 60)
        sys.exit(0)

    # 2. Modo CLI: envio de comando para aprovação
    if args.cli_command == "run":
        res = submit_request(
            title=args.title,
            description=args.description,
            script_type=args.type,
            code=args.code,
            otp=args.otp,
            timeout=args.timeout
        )
        print(json.dumps(res, indent=2, ensure_ascii=False))
        sys.exit(0 if res.get("exit_code") == 0 else 1)

    if args.cli_command == "status":
        online = check_heartbeat(5.0)
        print(f"STATUS: {'ONLINE' if online else 'OFFLINE'}")
        sys.exit(0 if online else 1)

    # 3. Auto-elevação via UAC se não for Administrador
    if not is_admin():
        print("[*] Privilégios administrativos necessários. Solicitando elevação UAC...")
        request_elevation()

    # 4. Garante instalação do ambiente local em C:\Utilitario
    ensure_environment_installed()

    # 5. Inicia aplicação gráfica PyQt6
    try:
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("antigravity.admin.bridge.1.0")
    except Exception:
        pass

    app = QApplication(sys.argv)
    app.setApplicationName("Antigravity Admin Bridge")

    icon_path = str(BASE_DIR / "icon.ico")
    if os.path.exists(icon_path):
        app.setWindowIcon(QIcon(icon_path))

    hotp_auth = HOTPAuth()

    # Se chamado com --reset
    if args.reset:
        dlg = ResetWizardDialog(hotp_auth)
        dlg.exec()
        sys.exit(0)

    # Se chamado com --setup ou não provisionado
    if args.setup or not hotp_auth.is_provisioned():
        dlg = SetupWizardDialog(hotp_auth)
        if dlg.exec() != QDialog.DialogCode.Accepted:
            print("[AVISO] Provisionamento cancelado pelo usuário.")
            sys.exit(1)

    # Operação contínua da Central em segundo plano
    window = AdminBridgeApp()
    window.hide()
    logging.info("Antigravity Admin Bridge ativo e operando em segundo plano.")
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
