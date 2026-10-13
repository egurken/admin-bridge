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
REQUESTS_DIR = BASE_DIR / "queue" / "requests"
RESPONSES_DIR = BASE_DIR / "queue" / "responses"
HEARTBEAT_FILE = BASE_DIR / "queue" / "heartbeat.json"


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


def ensure_app_running(timeout_wait: float = 12.0) -> bool:
    """Verifica se o utilitário está ativo; se não estiver, inicia-o interativamente via tarefa agendada."""
    if check_heartbeat(5.0):
        return True

    print("[*] Central offline. Iniciando a Central no desktop...", file=sys.stderr)
    try:
        res = subprocess.run(["schtasks", "/run", "/tn", "AntigravityAdminBridge"], capture_output=True, text=True)
        if res.returncode != 0:
            vbs_path = BASE_DIR / "iniciar.vbs"
            if vbs_path.exists():
                subprocess.Popen(["wscript.exe", str(vbs_path)], cwd=str(BASE_DIR))
            exe_path = BASE_DIR / "AntigravityBridge.exe"
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


def submit_request(title: str, description: str, script_type: str, code: str, otp: str = None, timeout: int = 120) -> dict:
    """Envia uma requisição de script para o utilitário desktop e aguarda a resposta."""
    REQUESTS_DIR.mkdir(parents=True, exist_ok=True)
    RESPONSES_DIR.mkdir(parents=True, exist_ok=True)

    is_running = ensure_app_running()
    if not is_running:
        print("[AVISO] Não foi possível confirmar a inicialização do utilitário desktop.", file=sys.stderr)
        print("Caso a janela não apareça, execute 'C:\\Utilitario\\iniciar.bat'.", file=sys.stderr)

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

    print(f"[*] Solicitação [{req_id}] enviada para o utilitário desktop.")
    print(f"[*] Título: {title}")
    print(f"[*] Aguardando aprovação do usuário na interface (timeout: {timeout}s)...")

    start_time = time.time()
    while time.time() - start_time < timeout:
        if res_file.exists():
            try:
                with open(res_file, "r", encoding="utf-8") as f:
                    response = json.load(f)
                
                # Remove os arquivos de fila após leitura bem-sucedida
                try:
                    res_file.unlink(missing_ok=True)
                except Exception:
                    pass
                try:
                    req_file.unlink(missing_ok=True)
                except Exception:
                    pass

                return response
            except (json.JSONDecodeError, PermissionError):
                time.sleep(0.3)
                continue

        time.sleep(0.5)

    # Caso atinja o timeout
    try:
        req_file.unlink(missing_ok=True)
    except Exception:
        pass

    return {
        "id": req_id,
        "status": "timeout",
        "error": f"Tempo limite de {timeout}s excedido aguardando resposta do usuário.",
        "exit_code": -1,
        "output": ""
    }


def main():
    parser = argparse.ArgumentParser(description="Cliente CLI do Antigravity para execução com aprovação administrativa.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Subcomando: status
    subparsers.add_parser("status", help="Verifica se o utilitário desktop está ativo")

    # Subcomando: start
    subparsers.add_parser("start", help="Inicia o utilitário desktop silenciosamente em segundo plano")

    # Subcomando: run
    run_parser = subparsers.add_parser("run", help="Envia um script para aprovação e execução")
    run_parser.add_argument("--title", required=True, help="Título amigável da tarefa")
    run_parser.add_argument("--description", required=True, help="Explicação do porquê o comando é necessário")
    run_parser.add_argument("--type", choices=["bat", "cmd", "ps1"], default="bat", help="Tipo de script")
    run_parser.add_argument("--code", required=True, help="Conteúdo do código a ser executado")
    run_parser.add_argument("--otp", default=None, help="Código de uso único HOTP (RFC 4226)")
    run_parser.add_argument("--timeout", type=int, default=120, help="Tempo limite em segundos")

    # Subcomando: run-file
    file_parser = subparsers.add_parser("run-file", help="Envia um arquivo de script existente")
    file_parser.add_argument("file_path", help="Caminho do arquivo a executar")
    file_parser.add_argument("--title", required=True, help="Título amigável da tarefa")
    file_parser.add_argument("--description", required=True, help="Explicação do porquê o comando é necessário")
    file_parser.add_argument("--otp", default=None, help="Código de uso único HOTP (RFC 4226)")
    file_parser.add_argument("--timeout", type=int, default=120, help="Tempo limite em segundos")

    args = parser.parse_args()

    if args.command == "status":
        active = check_heartbeat()
        if active:
            print("STATUS: ONLINE (O utilitário desktop está ativo e respondendo)")
            sys.exit(0)
        else:
            print("STATUS: OFFLINE (O utilitário desktop não está em execução)")
            sys.exit(1)

    elif args.command == "start":
        started = ensure_app_running()
        if started:
            print("Central iniciada com sucesso e pronta para uso!")
            sys.exit(0)
        else:
            print("[ERRO] Falha ao iniciar a Central automaticamente.", file=sys.stderr)
            sys.exit(1)

    elif args.command == "run":
        result = submit_request(
            title=args.title,
            description=args.description,
            script_type=args.type,
            code=args.code,
            otp=args.otp,
            timeout=args.timeout
        )
        try:
            print(json.dumps(result, indent=2, ensure_ascii=False))
        except UnicodeEncodeError:
            print(json.dumps(result, indent=2, ensure_ascii=True))
        sys.exit(0 if result.get("status") == "approved" and result.get("exit_code") == 0 else 1)

    elif args.command == "run-file":
        path = Path(args.file_path)
        if not path.exists():
            print(f"[ERRO] Arquivo '{args.file_path}' não encontrado.", file=sys.stderr)
            sys.exit(1)

        script_type = path.suffix.lstrip(".").lower()
        if script_type not in ["bat", "cmd", "ps1"]:
            script_type = "bat"

        with open(path, "r", encoding="utf-8", errors="replace") as f:
            code = f.read()

        result = submit_request(
            title=args.title,
            description=args.description,
            script_type=script_type,
            code=code,
            otp=args.otp,
            timeout=args.timeout
        )
        try:
            print(json.dumps(result, indent=2, ensure_ascii=False))
        except UnicodeEncodeError:
            print(json.dumps(result, indent=2, ensure_ascii=True))
        sys.exit(0 if result.get("status") == "approved" and result.get("exit_code") == 0 else 1)


if __name__ == "__main__":
    main()
