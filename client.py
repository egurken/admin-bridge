import argparse
import json
import os
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

BASE_DIR = Path("C:/Utilitario")
QUEUE_DIR = BASE_DIR / "queue"
REQUESTS_DIR = QUEUE_DIR / "requests"
RESPONSES_DIR = QUEUE_DIR / "responses"
HEARTBEAT_FILE = QUEUE_DIR / "heartbeat.json"
STATUS_FILE = QUEUE_DIR / "status.json"
AUTH_LOG_FILE = BASE_DIR / "logs" / "auth.log"


import hashlib


def check_heartbeat(max_age_seconds: float = 10.0) -> bool:
    """Verifica se o utilitário desktop está rodando e enviando heartbeat."""
    if not HEARTBEAT_FILE.exists():
        return False
    try:
        with open(HEARTBEAT_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        last_beat = data.get("timestamp", 0)
        return (time.time() - last_beat) <= max_age_seconds
    except Exception:
        return False


def get_bridge_exe() -> Path:
    """Retorna o executável preferencial da ponte administrativa."""
    p = BASE_DIR / "AdminBridge.exe"
    if p.exists():
        return p
    return BASE_DIR / "AntigravityBridge.exe"


def ensure_app_running(timeout_wait: float = 12.0) -> bool:
    """Verifica se o utilitário está ativo; se não estiver, tenta iniciá-lo."""
    if check_heartbeat(5.0):
        return True

    print("[*] Central offline. Tentando iniciar serviço...", file=sys.stderr)
    try:
        started_task = False
        for tn in ("AdminBridge", "AntigravityAdminBridge"):
            res = subprocess.run(["schtasks", "/run", "/tn", tn], capture_output=True, text=True)
            if res.returncode == 0:
                started_task = True
                break
        if not started_task:
            exe_path = get_bridge_exe()
            if exe_path.exists():
                subprocess.Popen([str(exe_path)], cwd=str(BASE_DIR))
            else:
                subprocess.Popen(["pythonw.exe", str(BASE_DIR / "app.py")], cwd=str(BASE_DIR))
    except Exception as e:
        print(f"[AVISO] Falha ao tentar iniciar automaticamente: {e}", file=sys.stderr)

    start = time.time()
    while time.time() - start < timeout_wait:
        time.sleep(0.5)
        if check_heartbeat(5.0):
            print("[*] Central iniciada e pronta!", file=sys.stderr)
            return True

    return False


def submit_request(title: str, description: str, script_type: str, code: str, otp: str = None, preauth_token: str = None, timeout: int = 120) -> dict:
    """Envia uma requisição de script para o utilitário desktop e aguarda a resposta."""
    REQUESTS_DIR.mkdir(parents=True, exist_ok=True)
    RESPONSES_DIR.mkdir(parents=True, exist_ok=True)

    is_running = ensure_app_running()
    if not is_running:
        print("[AVISO] Não foi possível confirmar a inicialização da central.", file=sys.stderr)

    req_id = str(uuid.uuid4())
    code_hash = hashlib.sha256(code.encode("utf-8")).hexdigest()
    payload = {
        "id": req_id,
        "title": title,
        "description": description,
        "script_type": script_type,
        "code": code,
        "code_hash": code_hash,
        "otp": otp,
        "preauth_token": preauth_token,
        "timeout": timeout,
        "created_at": datetime.now().astimezone().isoformat(),
        "caller": {
            "pid": os.getpid(),
            "exe": sys.executable,
            "script": str(Path(__file__).resolve()),
            "user": os.getenv("USERNAME", "unknown")
        }
    }

    req_file = REQUESTS_DIR / f"{req_id}.json"
    with open(req_file, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)

    print(f"[*] Solicitação [{req_id}] enviada.", file=sys.stderr)
    if otp:
        print(f"[*] Autenticação HOTP anexada - {otp[:2]}****. Aguardando execução...", file=sys.stderr)
    else:
        print("[*] Modo Híbrido: Aguardando aprovação UAC pelo usuário...", file=sys.stderr)

    res_file = RESPONSES_DIR / f"{req_id}.json"
    start_time = time.time()

    while time.time() - start_time < timeout:
        if res_file.exists():
            try:
                with open(res_file, "r", encoding="utf-8") as f:
                    response = json.load(f)

                try:
                    res_file.unlink(missing_ok=True)
                except Exception:
                    pass

                return response
            except (json.JSONDecodeError, PermissionError):
                time.sleep(0.3)
                continue

        time.sleep(0.5)

    try:
        req_file.unlink(missing_ok=True)
    except Exception:
        pass

    return {
        "id": req_id,
        "status": "timeout",
        "error": f"Tempo limite de {timeout}s excedido aguardando execução.",
        "exit_code": -1,
        "output": ""
    }


def main():
    parser = argparse.ArgumentParser(description="Cliente CLI do Admin Bridge.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Subcomando: status
    subparsers.add_parser("status", help="Consulta status atual do serviço e contador")

    # Subcomando: sync
    p_sync = subparsers.add_parser("sync", help="Diagnóstico e sincronização HOTP com avanço do contador")
    p_sync.add_argument("--otp", required=True, help="Código OTP de 6 dígitos gerado no celular")
    p_sync.add_argument("--lookahead", type=int, default=10, help="Janela máxima à frente - padrão: 10")

    # Subcomando: history
    subparsers.add_parser("history", help="Exibe histórico recente de execuções")

    # Subcomando: start
    subparsers.add_parser("start", help="Inicia o utilitário em segundo plano")

    # Subcomando: setup
    p_setup = subparsers.add_parser("setup", help="Executa o provisionamento inicial via terminal sem abrir janelas")
    p_setup.add_argument("--password", help="Palavra-passe de recuperação")

    # Subcomando: reset
    subparsers.add_parser("reset", help="Executa o reset e revogação de privilégios via terminal")

    # Subcomando: uninstall
    p_uninst = subparsers.add_parser("uninstall", help="Desinstala o utilitário completamente")
    p_uninst.add_argument("--force", action="store_true", help="Força desinstalação sem confirmação")

    # Subcomando: preauth
    p_preauth = subparsers.add_parser("preauth", help="Consome OTP e gera ticket de pré-autorização válido por até 45 minutos")
    p_preauth.add_argument("--otp", required=True, help="Código OTP de 6 dígitos")
    p_preauth.add_argument("--lifetime", type=int, default=2700, help="Tempo limite em segundos - padrão 2700s = 45 minutos")

    # Subcomando: run
    run_parser = subparsers.add_parser("run", help="Envia um script para execução elevada")
    run_parser.add_argument("--title", required=True, help="Título da tarefa")
    run_parser.add_argument("--description", required=True, help="Descrição da necessidade")
    run_parser.add_argument("--type", choices=["bat", "cmd", "ps1"], default="cmd", help="Tipo de script")
    run_parser.add_argument("--code", required=True, help="Comando ou código a ser executado")
    run_parser.add_argument("--otp", default=None, help="Código de uso único HOTP")
    run_parser.add_argument("--preauth-token", default=None, help="Token de pré-autorização")
    run_parser.add_argument("--timeout", type=int, default=120, help="Tempo limite em segundos")

    args = parser.parse_args()

    if args.command == "status":
        active = check_heartbeat()
        st_data = {}
        if STATUS_FILE.exists():
            try:
                with open(STATUS_FILE, "r", encoding="utf-8") as f:
                    st_data = json.load(f)
            except Exception:
                pass

        print("=" * 60)
        print("             STATUS DO ADMIN BRIDGE")
        print("=" * 60)
        print(f"  Serviço Heartbeat:        {'ONLINE' if active else 'OFFLINE'}")
        if st_data:
            print(f"  Contador Atual:           {st_data.get('counter', 0)}")
            print(f"  Estado:                   {st_data.get('status_text', 'Ativo')}")
            print(f"  Provisionado:             {'SIM - Flag=1' if st_data.get('provisioned_flag') == 1 else 'NÃO'}")
            print(f"  Lockdown:                 {'SIM' if st_data.get('lockdown') else 'NÃO'}")
            print(f"  Falhas Recentes:          {st_data.get('recent_failures', 0)} / 3")
        print("=" * 60)
        sys.exit(0 if active else 1)

    elif args.command == "sync":
        exe_path = get_bridge_exe()
        lookahead = getattr(args, "lookahead", 10)
        if exe_path.exists():
            cmd = [str(exe_path), "sync", "--otp", args.otp, "--lookahead", str(lookahead)]
        else:
            cmd = [sys.executable, str(BASE_DIR / "app.py"), "sync", "--otp", args.otp, "--lookahead", str(lookahead)]
        res = subprocess.run(cmd)
        sys.exit(res.returncode)

    elif args.command == "history":
        if not AUTH_LOG_FILE.exists():
            print("Nenhum histórico encontrado.")
            sys.exit(0)
        print("=" * 70)
        print("         HISTÓRICO RECENTE DE EXECUÇÕES & AUDITORIA")
        print("=" * 70)
        try:
            with open(AUTH_LOG_FILE, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()
            for line in reversed(lines[-20:]):
                print("  " + line.strip())
        except Exception as e:
            print(f"Erro ao ler log: {e}")
        print("=" * 70)
        sys.exit(0)

    elif args.command == "start":
        started = ensure_app_running()
        if started:
            print("Central iniciada com sucesso!")
            sys.exit(0)
        else:
            print("[ERRO] Falha ao iniciar a Central automaticamente.", file=sys.stderr)
            sys.exit(1)

    elif args.command == "setup":
        exe_path = get_bridge_exe()
        if exe_path.exists():
            cmd = [str(exe_path), "setup"]
        else:
            cmd = [sys.executable, str(BASE_DIR / "app.py"), "setup"]
        if getattr(args, "password", None):
            cmd.extend(["--password", args.password])
        res = subprocess.run(cmd)
        sys.exit(res.returncode)

    elif args.command == "reset":
        exe_path = get_bridge_exe()
        if exe_path.exists():
            cmd = [str(exe_path), "reset"]
        else:
            cmd = [sys.executable, str(BASE_DIR / "app.py"), "reset"]
        res = subprocess.run(cmd)
        sys.exit(res.returncode)

    elif args.command == "uninstall":
        exe_path = get_bridge_exe()
        if exe_path.exists():
            cmd = [str(exe_path), "uninstall"]
        else:
            cmd = [sys.executable, str(BASE_DIR / "app.py"), "uninstall"]
        if getattr(args, "force", False):
            cmd.append("--force")
        res = subprocess.run(cmd)
        sys.exit(res.returncode)

    elif args.command == "preauth":
        exe_path = get_bridge_exe()
        if exe_path.exists():
            cmd = [str(exe_path), "preauth", "--otp", args.otp, "--lifetime", str(args.lifetime)]
        else:
            cmd = [sys.executable, str(BASE_DIR / "app.py"), "preauth", "--otp", args.otp, "--lifetime", str(args.lifetime)]
        res = subprocess.run(cmd)
        sys.exit(res.returncode)

    elif args.command == "run":
        result = submit_request(
            title=args.title,
            description=args.description,
            script_type=args.type,
            code=args.code,
            otp=args.otp,
            preauth_token=getattr(args, "preauth_token", None),
            timeout=args.timeout
        )
        try:
            print(json.dumps(result, indent=2, ensure_ascii=False))
        except UnicodeEncodeError:
            print(json.dumps(result, indent=2, ensure_ascii=True))
        sys.exit(0 if result.get("status") == "approved" and result.get("exit_code") == 0 else 1)


if __name__ == "__main__":
    main()
