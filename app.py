import argparse
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
    QHeaderView, QAbstractItemView, QInputDialog, QGridLayout, QLayout
)

from hotp_auth import HOTPAuth, SecurityError, PREAUTH_TICKET_FILE
from hotp_crypto import (
    wipe_buffer, apply_isolated_bridge_ntfs_acls, apply_system_only_ntfs_acls, restore_ntfs_acls_for_removal,
    verify_caller_origin, generate_physical_challenge, read_passive_metadata, check_forensic_integrity,
    configure_anti_dump_mitigations
)
from app_icon import get_app_icon

LOCAL_SERVER_NAME = f"AdminBridge_GUI_{os.getenv('USERNAME', 'default')}"
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
CONFIG_FILE = CONFIG_DIR / "hotp_config.json"
AUTH_LOG_FILE = LOGS_DIR / "auth.log"

LOGS_DIR.mkdir(parents=True, exist_ok=True)
logging.basicConfig(
    filename=str(LOGS_DIR / "app.log"),
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)


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
        desktops_to_create = []
        user_desktop = get_desktop_dir()
        if user_desktop:
            desktops_to_create.append(user_desktop)
        pub_desktop = Path(os.environ.get("PUBLIC", "C:/Users/Public")) / "Desktop"
        if pub_desktop.exists() and pub_desktop not in desktops_to_create:
            desktops_to_create.append(pub_desktop)

        target = (BASE_DIR / "AdminBridge.exe").resolve()
        if not target.exists():
            target = (BASE_DIR / "AntigravityBridge.exe").resolve()
        icon_path = (BASE_DIR / "icon.ico").resolve()

        for d in desktops_to_create:
            # Remove atalhos antigos com nomes legados
            for old_lnk in ["Antigravity Bridge.lnk", "Antigravity Admin Bridge.lnk", "Configurar Antigravity Bridge.lnk"]:
                (d / old_lnk).unlink(missing_ok=True)

            lnk_path = d / "Admin Bridge.lnk"
            ps_cmd = (
                f'$ws = New-Object -ComObject WScript.Shell; '
                f'$s = $ws.CreateShortcut("{lnk_path}"); '
                f'$s.TargetPath = "{target}"; '
                f'$s.WorkingDirectory = "{BASE_DIR}"; '
                f'$s.IconLocation = "{icon_path},0"; '
                f'$s.Description = "Admin Bridge • Central de Gestao e Autorizacao"; '
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

    # Remove runner.ps1 legado se existir em disco para garantir processo unico
    (BASE_DIR / "runner.ps1").unlink(missing_ok=True)

    target_exe = (BASE_DIR / "AdminBridge.exe").resolve()
    current_exe = Path(sys.executable).resolve()
    if getattr(sys, "frozen", False) and current_exe != target_exe:
        try:
            shutil.copy2(str(current_exe), str(target_exe))
        except Exception as e:
            logging.warning(f"Aviso ao copiar executavel para C:\\Utilitario: {e}")

    # Aplica permissões restritas exclusivas para SYSTEM se for Administrador
    if is_admin():
        apply_isolated_bridge_ntfs_acls(BASE_DIR)

    # Migração automática transparente para DPAPI de máquina
    try:
        hotp_auth = HOTPAuth()
        hotp_auth.migrate_config_to_machine_dpapi()
    except Exception:
        pass

    create_desktop_shortcut()


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
    for tn in ("AdminBridge", "AntigravityAdminBridge"):
        cmd = ["schtasks", "/delete", "/tn", tn, "/f"]
        res = subprocess.run(cmd, capture_output=True, check=False, creationflags=0x08000000)
        if res.returncode == 0:
            ok = True
    return ok


def perform_full_uninstall(parent_widget=None) -> bool:
    """Executa o fluxo completo de desinstalação:

    1. Encerra imediatamente qualquer processo interno do utilitário em execução.
    2. Remove as tarefas agendadas do Windows.
    3. Remove os atalhos criados na Área de Trabalho.
    4. Cria e dispara script autônomo na pasta TEMP para assumir posse e apagar completamente C:\\Utilitario.
    """
    try:
        # 1. Encerra processos em execucao
        try:
            subprocess.run(["taskkill", "/f", "/im", "AdminBridge.exe"], capture_output=True, check=False, creationflags=0x08000000)
            subprocess.run(["taskkill", "/f", "/im", "AntigravityBridge.exe"], capture_output=True, check=False, creationflags=0x08000000)
        except Exception:
            pass

        # 2. Remove tarefa agendada
        unregister_scheduled_task()

        # 3. Remove atalhos da Área de Trabalho
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
                        except Exception:
                            pass
        except Exception:
            pass

        # 4. Cria script desacoplado na pasta temporaria do Windows para exclusao total
        temp_dir = Path(os.environ.get("TEMP", "C:/Windows/Temp"))
        cleanup_bat = temp_dir / "adminbridge_cleanup.bat"
        bat_content = (
            "@echo off\r\n"
            "timeout /t 1 /nobreak >nul\r\n"
            "taskkill /f /im AdminBridge.exe >nul 2>&1\r\n"
            "taskkill /f /im AntigravityBridge.exe >nul 2>&1\r\n"
            "takeown /f \"C:\\Utilitario\" /r /d y >nul 2>&1\r\n"
            "icacls \"C:\\Utilitario\" /grant \"*S-1-5-32-544:(OI)(CI)(F)\" /t >nul 2>&1\r\n"
            "rd /s /q \"C:\\Utilitario\" >nul 2>&1\r\n"
            "del /f /q \"%~f0\" >nul 2>&1\r\n"
        )
        with open(cleanup_bat, "w", encoding="ascii") as f:
            f.write(bat_content)

        subprocess.Popen(["cmd.exe", "/c", str(cleanup_bat)], creationflags=0x08000000)
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
        # Aplica ambiente cego na tela impedindo captura ou visualização por softwares
        try:
            hwnd = int(self.winId())
            ret = ctypes.windll.user32.SetWindowDisplayAffinity(hwnd, 0x00000011)
            if not ret:
                ctypes.windll.user32.SetWindowDisplayAffinity(hwnd, 0x00000001)
        except Exception:
            pass

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

        lbl_meta = QLabel("Tipo: Baseado em Contador HOTP • Contador Inicial: 0 • Dígitos: 6 • SHA-1")
        lbl_meta.setStyleSheet("font-size: 10px; color: #6c7086;")
        lbl_meta.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.layout.addWidget(lbl_meta)

        lbl_warn = QLabel("⚠️ ATENÇÃO: Esta é a ÚNICA vez que este código será exibido. A chave não será salva em disco.")
        lbl_warn.setWordWrap(True)
        lbl_warn.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lbl_warn.setStyleSheet("font-size: 11px; color: #f38ba8; font-weight: 600;")
        self.layout.addWidget(lbl_warn)

        lbl_otp_input = QLabel("Código OTP de Verificação - digite os 6 dígitos gerados no celular:")
        lbl_otp_input.setStyleSheet("font-size: 12px; font-weight: 600; color: #89b4fa; margin-top: 6px;")
        self.layout.addWidget(lbl_otp_input)

        self.txt_verify_otp = QLineEdit()
        self.txt_verify_otp.setMaxLength(6)
        self.txt_verify_otp.setPlaceholderText("000000")
        self.txt_verify_otp.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.txt_verify_otp.setStyleSheet("font-family: Consolas, monospace; font-size: 20px; font-weight: bold; letter-spacing: 4px; color: #a6e3a1;")
        self.txt_verify_otp.returnPressed.connect(self.verify_and_finalize_pairing)
        self.layout.addWidget(self.txt_verify_otp)

        self.btn_finish = QPushButton("Validar Código e Concluir Pareamento")
        self.btn_finish.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.btn_finish.setStyleSheet("background-color: #a6e3a1; color: #11111b; font-weight: bold; padding: 12px;")
        self.btn_finish.clicked.connect(self.verify_and_finalize_pairing)
        self.layout.addWidget(self.btn_finish)

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

        register_scheduled_task()
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

                proc = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    check=False,
                    creationflags=0x08000000  # CREATE_NO_WINDOW
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

        try:
            res = self.hotp_auth.diagnose_otp_sync(otp)
        finally:
            self.btn_verify.setEnabled(True)
            self.btn_verify.setText("Verificar")

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
# JANELA PRINCIPAL DA CENTRAL DE GESTÃO (SYSTEM TRAY & DASHBOARD)
# -----------------------------------------------------------------------------
class AdminBridgeWindow(QMainWindow):
    def __init__(self, hotp_auth: HOTPAuth):
        super().__init__()
        self.hotp_auth = hotp_auth
        self.current_request = None
        self.exec_thread = None

        self.setWindowTitle("Admin Bridge • Central de Gestão")
        self.resize(760, 600)
        self.setMinimumSize(660, 480)

        app_icon = get_app_icon()
        self.setWindowIcon(app_icon)

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

        act_status = QAction("📋 Status Detalhado do Contador", self)
        act_status.triggered.connect(self.show_counter_status_dialog)
        self.settings_menu.addAction(act_status)

        self.settings_menu.addSeparator()

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

        main_layout.addLayout(metrics_layout)

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
        self.lbl_badge.setStyleSheet("background-color: #313244; color: #a6adc8; padding: 3px 8px; border-radius: 4px; font-size: 11px; font-weight: bold;")
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
        btn_box = QHBoxLayout(self.btn_box_widget)
        btn_box.setContentsMargins(0, 4, 0, 0)
        btn_box.setSpacing(10)

        self.btn_reject = QPushButton("✖ Rejeitar Solicitação")
        self.btn_reject.setObjectName("btnReject")
        self.btn_reject.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.btn_reject.clicked.connect(self.reject_request)
        self.btn_reject.setEnabled(False)
        btn_box.addWidget(self.btn_reject)

        self.btn_approve = QPushButton("✔ Aprovar & Executar via UAC")
        self.btn_approve.setObjectName("btnApprove")
        self.btn_approve.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.btn_approve.clicked.connect(self.approve_request)
        self.btn_approve.setEnabled(False)
        btn_box.addWidget(self.btn_approve)

        self.btn_box_widget.hide()
        pending_layout.addWidget(self.btn_box_widget)

        main_layout.addWidget(self.card_pending)

        # -------------------------------------------------------------
        # TABELA DE HISTÓRICO RECENTE
        # -------------------------------------------------------------
        lbl_hist_title = QLabel("📜 Histórico Recente de Requisições & Auditoria")
        lbl_hist_title.setStyleSheet("font-size: 13px; font-weight: bold; color: #a6adc8; margin-top: 4px;")
        main_layout.addWidget(lbl_hist_title)

        self.table_history = QTableWidget()
        self.table_history.setColumnCount(4)
        self.table_history.setHorizontalHeaderLabels(["Data e Hora", "Comando ou Operação", "Estado", "OTP Mascarado"])
        self.table_history.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.table_history.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.table_history.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.table_history.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self.table_history.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table_history.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        main_layout.addWidget(self.table_history, stretch=1)

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

        if "adulteração" in status_text.lower() or status_data.get("tampered"):
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

        # Se for uma solicitação de probe passivo do daemon (sync_probe), deixa o daemon SYSTEM processar
        try:
            with open(target_file, "r", encoding="utf-8") as f:
                peek_req = json.load(f)
            if peek_req.get("script_type") == "sync_probe":
                return
        except Exception:
            pass

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
                    QTimer.singleShot(1500, self.quit_app)
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

    def display_manual_uac_request(self, data, processing_file: Path):
        self.current_request = data
        self.current_processing_file = processing_file

        title = data.get("title", "Comando Administrativo")
        desc = data.get("description", "Sem descrição informada.")
        script_type = data.get("script_type", "bat").upper()
        code = data.get("code", "")

        self.lbl_req_title.setText(title)
        self.lbl_req_sub.setText(f"[Sem OTP] Confirmação manual requerida via UAC • {desc}")
        self.lbl_badge.setText(f"UAC REQUERIDO - {script_type}")
        self.lbl_badge.setStyleSheet("background-color: #f9e2af; color: #11111b; padding: 4px 10px; border-radius: 4px;")

        self.code_viewer.setPlainText(code)
        self.code_viewer.show()
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

        self.lbl_req_title.setText(title)
        self.lbl_req_sub.setText(f"Autenticado via HOTP (Contador #{counter}) • {desc}")
        self.lbl_badge.setText(f"AUTORIZADO ({script_type})")
        self.lbl_badge.setStyleSheet("background-color: #a6e3a1; color: #11111b; padding: 4px 10px; border-radius: 4px;")

        self.code_viewer.setPlainText(code)
        self.code_viewer.show()
        self.btn_box_widget.hide()

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
        self.lbl_badge.setStyleSheet("background-color: #313244; color: #a6adc8; padding: 3px 8px; border-radius: 4px; font-size: 11px; font-weight: bold;")
        self.code_viewer.clear()
        self.code_viewer.hide()
        self.btn_box_widget.hide()
        self.btn_reject.setEnabled(False)
        self.btn_approve.setEnabled(False)

    def prompt_and_execute_repair(self):
        if not is_admin():
            try:
                request_elevation_with_args(["gui"])
                return
            except Exception as e:
                QMessageBox.critical(self, "Permissão Necessária", f"Privilégios de Administrador são necessários: {e}")
                return

        pwd, ok = QInputDialog.getText(
            self,
            "Reparo do Sistema",
            "Digite a sua Palavra-passe de Recuperação para autorizar o reparo:",
            QLineEdit.EchoMode.Password
        )
        if not ok or not pwd:
            return

        success, msg = self.hotp_auth.repair_corrupted_installation(pwd)
        if success:
            QMessageBox.information(
                self,
                "Reparo Concluído",
                "As pastas e arquivos foram restaurados com sucesso.\nO assistente será iniciado agora para um novo pareamento."
            )
            wizard = SetupWizardDialog(self.hotp_auth, self)
            wizard.exec()
            self.refresh_dashboard()
        else:
            QMessageBox.critical(self, "Falha no Reparo", msg)

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
            "• Remover a tarefa agendada do Windows schtasks\n"
            "• Restaurar as permissões de acesso NTFS\n"
            "• Apagar todos os arquivos e pastas de C:\\Utilitario\n"
            "• Remover os atalhos da Área de Trabalho\n\n"
            "Deseja prosseguir?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )
        if res != QMessageBox.StandardButton.Yes:
            return

        if not is_admin():
            try:
                request_elevation_with_args(["uninstall", "--force"])
                return
            except Exception as e:
                QMessageBox.critical(self, "Permissão Necessária", f"Privilégios de Administrador são necessários: {e}")
                return

        success = perform_full_uninstall(self)
        if success:
            QMessageBox.information(
                self,
                "Desinstalação Concluída",
                "O Admin Bridge foi desinstalado com sucesso da máquina."
            )
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
    apply_isolated_bridge_ntfs_acls()

    ok_forensic, forensic_msg = check_forensic_integrity(CONFIG_FILE)
    if not ok_forensic:
        logging.critical(f"[FORENSE] {forensic_msg}")

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

                has_otp = bool(peek_data.get("otp"))
                has_token = bool(peek_data.get("preauth_token"))
                has_ticket = PREAUTH_TICKET_FILE.exists()

                if not (has_otp or has_token or has_ticket):
                    # Sem OTP e sem ticket pré-autorizado: é solicitação manual que requer confirmação UAC na tela
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
                preauth_token = data.get("preauth_token")
                caller_info = data.get("caller") or {}
                caller_user = caller_info.get("user")

                auth_approved = False
                auth_msg = ""

                if provided_otp:
                    is_valid, auth_msg, used_counter = hotp_auth.verify_and_advance(provided_otp, caller_info)
                    auth_approved = is_valid
                else:
                    # Valida via Ticket de Pré-Autorização (até 45 minutos) com token secreto obrigatório
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

                # Valida integridade do hash do código para mitigar TOCTOU
                code = data.get("code", "")
                expected_code_hash = data.get("code_hash")
                if expected_code_hash:
                    actual_code_hash = hashlib.sha256(code.encode("utf-8")).hexdigest()
                    if not hmac.compare_digest(actual_code_hash, expected_code_hash):
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

                # Executa comando autenticado diretamente em processo unico, sem runner.ps1 intermediario
                script_type = data.get("script_type", "cmd").lower()
                if script_type in ("bat", "cmd"):
                    cmd = ["cmd.exe", "/c", code]
                elif script_type == "ps1":
                    cmd = ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", code]
                else:
                    cmd = ["cmd.exe", "/c", code]

                proc = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    check=False,
                    creationflags=0x08000000  # CREATE_NO_WINDOW
                )
                out_txt = proc.stdout
                if proc.stderr:
                    out_txt += ("\n[STDERR]:\n" if out_txt else "") + proc.stderr
                ec = proc.returncode

                res = {
                    "id": req_id,
                    "status": "approved",
                    "exit_code": ec,
                    "output": out_txt,
                    "completed_at": datetime.now().astimezone().isoformat()
                }
                with open(RESPONSES_DIR / f"{req_id}.json", "w", encoding="utf-8") as f:
                    json.dump(res, f, indent=2, ensure_ascii=False)

                proc_file.unlink(missing_ok=True)

        except Exception as e:
            logging.error(f"[DAEMON ERROR]: {e}")

        time.sleep(1.0)


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
        res = hotp_auth.diagnose_otp_sync(args.otp, max_lookahead=min(lookahead, 10), max_lookback=lookback)
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

        print("[*] Removendo tarefas agendadas, filas e restaurando permissões...")
        ok = perform_full_uninstall()
        if ok:
            print("[SUCESSO]: Admin Bridge desinstalado com sucesso.")
            sys.exit(0)
        else:
            print("[ERRO]: Falha ao concluir desinstalação.", file=sys.stderr)
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
            auth_ok = False
            auth_msg = ""
            if otp:
                valid, auth_msg, _ = hotp_auth.verify_and_advance(otp, caller_info)
                auth_ok = valid
            elif preauth_token:
                valid, auth_msg = hotp_auth.consume_preauth_ticket(preauth_token, caller_info.get("user"))
                auth_ok = valid
            else:
                auth_ok = True

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
        payload = {
            "id": req_id,
            "title": args.title or "Comando CLI",
            "description": args.description or "Execução via terminal",
            "script_type": args.type or "cmd",
            "code": args.code,
            "code_hash": code_hash,
            "otp": args.otp,
            "preauth_token": getattr(args, "preauth_token", None),
            "timeout": args.timeout or 120,
            "created_at": datetime.now().astimezone().isoformat(),
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
    configure_anti_dump_mitigations()
    ensure_environment_installed()
    hotp_auth = HOTPAuth()

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

    # Comando uninstall
    p_uninst = subparsers.add_parser("uninstall", help="Desinstala o utilitário completamente")
    p_uninst.add_argument("--force", action="store_true", help="Força desinstalação sem confirmação")

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
    p_run.add_argument("--timeout", type=int, default=120, help="Tempo limite em segundos")

    args, unknown = parser.parse_known_args()

    # Se um subcomando CLI foi invocado
    if args.subcommand:
        if args.subcommand in ("setup", "reset", "uninstall") and not is_admin():
            try:
                cli_args = [args.subcommand]
                if getattr(args, "force", False):
                    cli_args.append("--force")
                request_elevation_with_args(cli_args)
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
