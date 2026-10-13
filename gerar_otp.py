import argparse
import getpass
import os
import secrets
import subprocess
import sys
from pathlib import Path

# Adiciona o diretório base ao sys.path
sys.path.insert(0, str(Path("C:/Utilitario")))

from hotp_auth import HOTPAuth
from hotp_crypto import get_current_caller_info


def show_qr_dialog_once(image_path: str, uri: str):
    """Exibe o diálogo visual com o QR Code exclusivamente durante o provisionamento inicial ou reset."""
    try:
        from PyQt6.QtWidgets import QApplication, QDialog, QVBoxLayout, QLabel, QPushButton
        from PyQt6.QtGui import QPixmap
        from PyQt6.QtCore import Qt

        app = QApplication.instance()
        created_app = False
        if not app:
            app = QApplication(sys.argv)
            created_app = True

        dlg = QDialog()
        dlg.setWindowTitle("Antigravity • Emparelhamento Inicial de Autenticador")
        dlg.setMinimumSize(420, 500)
        dlg.setStyleSheet("background-color: #11111b; color: #cdd6f4;")

        layout = QVBoxLayout(dlg)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)

        title = QLabel("Escaneie o QR Code no Telemóvel")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setStyleSheet("font-size: 16px; font-weight: bold; color: #a6e3a1;")
        layout.addWidget(title)

        sub = QLabel("Aegis, 2FAS, Google Authenticator\n(Exibição única: este código NÃO será reexibido)")
        sub.setAlignment(Qt.AlignmentFlag.AlignCenter)
        sub.setStyleSheet("font-size: 12px; color: #a6adc8;")
        layout.addWidget(sub)

        lbl_img = QLabel()
        lbl_img.setAlignment(Qt.AlignmentFlag.AlignCenter)
        if os.path.exists(image_path):
            pix = QPixmap(image_path).scaled(260, 260, Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation)
            lbl_img.setPixmap(pix)
        else:
            lbl_img.setText("(Imagem do QR Code não encontrada)")
        layout.addWidget(lbl_img)

        lbl_warn = QLabel("IMPORTANTE: Após fechar esta janela, a chave nunca mais será exibida no computador.")
        lbl_warn.setWordWrap(True)
        lbl_warn.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lbl_warn.setStyleSheet("font-size: 11px; color: #f38ba8;")
        layout.addWidget(lbl_warn)

        btn_ok = QPushButton("Concluído • Já Escaneei no Telemóvel")
        btn_ok.setStyleSheet("background-color: #89b4fa; color: #11111b; font-weight: bold; padding: 12px; border-radius: 6px;")
        btn_ok.clicked.connect(dlg.accept)
        layout.addWidget(btn_ok)

        dlg.exec()
        if created_app:
            app.quit()
    except Exception as e:
        print(f"[AVISO] Não foi possível abrir janela visual: {e}")


def interactive_reset(auth: HOTPAuth):
    """Procedimento de reset estrito sem credenciais estáticas."""
    print("=" * 65)
    print("      PROCEDIMENTO DE RESET DE CHAVE HOTP (RFC 4226)")
    print("=" * 65)
    print("[!] Este procedimento apagará a chave atual e gerará uma nova.")
    print("[!] Requisitos obrigatórios: Confirmação de Presença Física + Senha.")
    print("-" * 65)

    # 1. Desafio de Presença Física Local
    challenge_code = f"PHYS-{secrets.randbelow(900000) + 100000}"
    print(f"\n[DESAFIO DE PRESENÇA FÍSICA]")
    print(f"Para comprovar presença física no terminal desta máquina,")
    print(f"digite exatamente o código de confirmação abaixo:")
    print(f"\n        >>> {challenge_code} <<<\n")

    user_challenge = input("Digite o código de confirmação: ").strip()
    if user_challenge.upper() != challenge_code:
        print("\n[ERRO] Confirmação de presença física falhou! Operação cancelada.")
        sys.exit(1)

    # 2. Senha de Recuperação Atual
    try:
        pw = getpass.getpass("Digite a PALAVRA-PASSE DE RECUPERAÇÃO atual: ")
    except Exception:
        pw = input("Digite a PALAVRA-PASSE DE RECUPERAÇÃO atual: ")

    # 3. Nova Senha de Recuperação
    try:
        new_pw = getpass.getpass("Defina a NOVA PALAVRA-PASSE DE RECUPERAÇÃO (mínimo 8 caracteres): ")
    except Exception:
        new_pw = input("Defina a NOVA PALAVRA-PASSE DE RECUPERAÇÃO (mínimo 8 caracteres): ")

    if len(new_pw) < 8:
        print("\n[ERRO] A nova palavra-passe deve conter pelo menos 8 caracteres.")
        sys.exit(1)

    caller = get_current_caller_info()
    try:
        res = auth.reset_and_reprovision(
            recovery_password=pw,
            physical_challenge_response=user_challenge,
            expected_challenge=challenge_code,
            new_recovery_password=new_pw,
            caller_info=caller
        )
        print("\n" + "=" * 65)
        print("          RESET CONCLUÍDO COM SUCESSO!")
        print("=" * 65)
        print(f"[*] Contador reiniciado para:  {res['counter']}")
        print(f"[*] Flag de Provisionamento:   {res['provisioned_flag']} (Travado novamente)")
        print(f"[*] URI de Pareamento Único:   {res['uri']}")
        print("=" * 65)

        # Exibe o QR Code uma única vez para pareamento no autenticador
        show_qr_dialog_once(res['qr_code_file'], res['uri'])

        # Solicita elevação UAC para reconfigurar/reativar a tarefa agendada
        print("\n[*] Solicitando confirmação UAC para reativar a tarefa agendada do Windows...")
        try:
            subprocess.run(
                ["powershell.exe", "-Command", "Start-Process powershell -ArgumentList '-Command schtasks /change /tn AntigravityAdminBridge /enable' -Verb RunAs -Wait"],
                check=False
            )
            print("[*] Tarefa agendada reativada com privilégios de Administrador.")
        except Exception as e:
            print(f"[AVISO] Não foi possível reativar tarefa automaticamente: {e}")

    except Exception as e:
        print(f"\n[ERRO CRÍTICO] Falha no reset: {e}")
        sys.exit(1)


def print_status(auth: HOTPAuth):
    """Consulta metadados do contador sem avançar."""
    st = auth.get_counter_status()
    print("=" * 60)
    print("         STATUS DO CONTADOR HOTP (RFC 4226)")
    print("=" * 60)
    print(f"  Contador Atual:           {st['counter']}")
    print(f"  Provisionado / Travado:   {'SIM (Flag = 1)' if st['provisioned_flag'] == 1 else 'NÃO (Flag = 0)'}")
    print(f"  Estado Fail-Safe:         {'BLOQUEADO (LOCKDOWN)' if st['lockdown'] else 'NORMAL (Ativo)'}")
    print(f"  Falhas Recentes (5m):     {st.get('failures_in_window', 0)} / 3")
    print(f"  Último Contador Aceito:   {st['last_success_counter']}")
    print(f"  Criado em:                {st['created_at']}")
    print(f"  Último Uso:               {st['last_used_at']}")
    print("=" * 60)
    print("  [*] MODELO DE VALIDAÇÃO CEGA ATIVO:")
    print("      O computador NUNCA calcula nem exibe códigos OTP.")
    print("      Gere o código exclusivamente no seu telemóvel (Aegis, 2FAS).")
    print("=" * 60)


def main():
    parser = argparse.ArgumentParser(description="Central de Status e Gerenciamento HOTP (RFC 4226)")
    parser.add_argument("--status", action="store_true", help="Consulta os metadados do contador sem avançá-lo")
    parser.add_argument("--reset", action="store_true", help="Executa o reset estrito com senha e presença física")
    parser.add_argument("--provision", action="store_true", help="Executa o aprovisionamento inicial se ainda não provisionado")
    args = parser.parse_args()

    auth = HOTPAuth()

    # Reset
    if args.reset:
        interactive_reset(auth)
        sys.exit(0)

    # Aprovisionamento inicial (apenas se flag == 0)
    if not auth.is_provisioned() or args.provision:
        print("=" * 60)
        print("       APROVISIONAMENTO INICIAL HOTP (RFC 4226)")
        print("=" * 60)
        print("Defina a Palavra-passe de Recuperação para proteger a chave.")
        try:
            pw = getpass.getpass("Digite a PALAVRA-PASSE DE RECUPERAÇÃO (mínimo 8 caracteres): ")
        except Exception:
            pw = input("Digite a PALAVRA-PASSE DE RECUPERAÇÃO (mínimo 8 caracteres): ")

        if len(pw) < 8:
            print("[ERRO] A palavra-passe deve conter pelo menos 8 caracteres.")
            sys.exit(1)

        caller = get_current_caller_info()
        try:
            res = auth.provision(recovery_password=pw, caller_info=caller)
            print("\n[*] Chave provisionada e protegida com DPAPI no Windows!")
            print(f"[*] Contador Inicial: {res['counter']}")
            print(f"[*] Flag:             {res['provisioned_flag']} (Travado)")
            print(f"[*] URI de Pareamento: {res['uri']}")
            print("=" * 60)
            show_qr_dialog_once(res['qr_code_file'], res['uri'])
            sys.exit(0)
        except PermissionError as e:
            print(f"[ERRO] {e}")
            sys.exit(1)

    # Comportamento padrão: consulta passiva de status
    print_status(auth)


if __name__ == "__main__":
    main()
