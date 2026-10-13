import argparse
import getpass
import os
import secrets
import subprocess
import sys
from pathlib import Path

# Adiciona o diretório base ao sys.path
sys.path.insert(0, str(Path("C:/Utilitario")))
sys.path.insert(0, str(Path(__file__).parent.resolve()))

from hotp_auth import HOTPAuth
from hotp_crypto import get_current_caller_info, generate_physical_challenge


def interactive_reset(auth: HOTPAuth):
    """Procedimento de revogação de privilégios e reset estrito (Requisito 3)."""
    print("=" * 65)
    print("      REVOGAÇÃO DE PRIVILÉGIOS E RESET HOTP (RFC 4226)")
    print("=" * 65)
    print("[!] Este procedimento destrói permanentemente a chave HOTP atual")
    print("[!] e remove a tarefa agendada do Windows.")
    print("[!] Requisitos obrigatórios: Confirmação de Presença Física + Senha.")
    print("-" * 65)

    challenge_code = generate_physical_challenge()
    print(f"\n[DESAFIO DE PRESENÇA FÍSICA]")
    print(f"Para comprovar presença física no terminal desta máquina,")
    print(f"digite exatamente o código de confirmação abaixo:")
    print(f"\n        >>> {challenge_code} <<<\n")

    user_challenge = input("Digite o código de confirmação: ").strip()
    if user_challenge.upper() != challenge_code:
        print("\n[ERRO] Confirmação de presença física falhou! Operação cancelada.")
        sys.exit(1)

    try:
        pw = getpass.getpass("Digite a PALAVRA-PASSE DE RECUPERAÇÃO: ")
    except Exception:
        pw = input("Digite a PALAVRA-PASSE DE RECUPERAÇÃO: ")

    caller = get_current_caller_info()
    try:
        res = auth.reset_and_destroy_privileges(
            recovery_password=pw,
            physical_challenge_response=user_challenge,
            expected_challenge=challenge_code,
            caller_info=caller
        )
        print("\n" + "=" * 65)
        print("          REVOGAÇÃO CONCLUÍDA COM SUCESSO!")
        print("=" * 65)
        print(f"[*] Mensagem: {res.get('message')}")
        print("[*] Tarefa elevada removida. Privilégios administrativos encerrados.")
        print("=" * 65)
    except Exception as e:
        print(f"\n[ERRO CRÍTICO] Falha na revogação: {e}")
        sys.exit(1)


def print_status(auth: HOTPAuth):
    """Consulta metadados passivos do contador sem avançar."""
    st = auth.get_counter_status()
    print("=" * 60)
    print("         STATUS DO CONTADOR HOTP (RFC 4226)")
    print("=" * 60)
    print(f"  Contador Atual:           {st.get('counter', 0)}")
    print(f"  Estado do Serviço:        {st.get('status_text', 'Ativo')}")
    print(f"  Provisionado / Travado:   {'SIM (Flag = 1)' if st.get('provisioned_flag') == 1 else 'NÃO (Flag = 0)'}")
    print(f"  Estado Fail-Safe:         {'BLOQUEADO (LOCKDOWN)' if st.get('lockdown') else 'NORMAL (Ativo)'}")
    print(f"  Falhas Recentes (5m):     {st.get('recent_failures', 0)} / 3")
    print(f"  Integridade:              {'Íntegro' if not st.get('tampered') else 'VIOLADO'}")
    print(f"  Último Uso:               {st.get('last_used_at') or 'Nenhum'}")
    print("=" * 60)
    print("  [*] MODELO DE VALIDAÇÃO CEGA ATIVO:")
    print("      O computador NUNCA calcula nem exibe códigos OTP.")
    print("      Gere o código exclusivamente no seu telemóvel (Aegis, 2FAS).")
    print("=" * 60)


def main():
    parser = argparse.ArgumentParser(description="Central de Status e Gerenciamento HOTP (RFC 4226)")
    parser.add_argument("--status", action="store_true", help="Consulta os metadados do contador sem avançá-lo")
    parser.add_argument("--reset", action="store_true", help="Executa a revogação de privilégios e reset da chave")
    args = parser.parse_args()

    auth = HOTPAuth()

    if args.reset:
        interactive_reset(auth)
        sys.exit(0)

    print_status(auth)


if __name__ == "__main__":
    main()
