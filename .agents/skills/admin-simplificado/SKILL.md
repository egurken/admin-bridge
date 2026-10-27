---
name: admin-simplificado
description: >-
  Executes Windows commands and scripts with elevated Administrator privileges
  automatically without manual confirmation popups using the simplified AdminBridge
  located at C:\Users\epgur\Downloads\AdminBridge_Simple. Activate this skill whenever
  an action requires Windows administrator rights (e.g. system service control,
  registry changes, driver management, system file editing, or package installation).
---

# Admin Simplificado (Execução Elevada sem Confirmação Manual)

Esta skill permite ao Antigravity executar comandos e scripts administrativos (`CMD`, `PowerShell`, `.bat`, `.ps1` ou `Python`) diretamente com privilégios de **Administrador**, de forma **100% automática**, sem exibir caixas de diálogo ou perguntas de aprovação na tela para o usuário.

---

## ⚡ Princípio de Funcionamento

1. O servidor local [admin_bridge.py](file:///C:/Users/epgur/Downloads/AdminBridge_Simple/admin_bridge.py) roda com privilégios de Administrador (iniciado via [iniciar_admin.bat](file:///C:/Users/epgur/Downloads/AdminBridge_Simple/iniciar_admin.bat)).
2. Qualquer solicitação enviada com a origem `"source": "antigravity"` é **imediatamente aprovada e executada** em segundo plano.
3. A saída (`stdout` + `stderr`), o código de saída (`exit_code`) e o tempo de execução são capturados e retornados ao Antigravity.
4. O terminal do usuário permanece aberto (`cmd /k`) exibindo o log transparente de todas as ações executadas.

---

## 🚀 Como Executar Comandos Elevados

O Antigravity pode executar scripts administrativos usando o [client.py](file:///C:/Users/epgur/Downloads/AdminBridge_Simple/client.py).

### 1. Comandos CMD / Batch

```powershell
python "C:\Users\epgur\Downloads\AdminBridge_Simple\client.py" run --title "Limpar Cache DNS" --type cmd --code "ipconfig /flushdns"
```

Para múltiplos comandos em sequência:
```powershell
python "C:\Users\epgur\Downloads\AdminBridge_Simple\client.py" run --title "Reiniciar Spooler" --type cmd --code "net stop spooler && net start spooler"
```

---

### 2. Comandos PowerShell

```powershell
python "C:\Users\epgur\Downloads\AdminBridge_Simple\client.py" run --title "Gerenciar Servico" --type powershell --code "Restart-Service -Name Spooler -Force"
```

Para scripts PowerShell mais elaborados com variáveis e pipelines:
```powershell
python "C:\Users\epgur\Downloads\AdminBridge_Simple\client.py" run --title "Listar Servicos Parados" --type powershell --code "Get-Service | Where-Object {$_.Status -eq 'Stopped'} | Select-Object -First 10"
```

---

### 3. Execução Direta via Python (Embutida)

Você também pode importar a função `run_admin_command` diretamente em qualquer script Python executado no workspace:

```python
import sys
sys.path.append(r"C:\Users\epgur\Downloads\AdminBridge_Simple")
from client import run_admin_command

# Execução automática como Administrador
res = run_admin_command(
    code="Get-Process | Sort-Object CPU -Descending | Select-Object -First 5",
    script_type="powershell",
    title="Diagnóstico de CPU"
)

if res["exit_code"] == 0:
    print(res["output"])
else:
    print(f"Erro ({res['exit_code']}): {res['output']}")
```

---

### 4. Executando um Arquivo de Script Existente

Se você criou um script `.bat` ou `.ps1` no disco:

```powershell
python "C:\Users\epgur\Downloads\AdminBridge_Simple\client.py" run --file "C:\caminho\script.ps1" --type powershell --title "Executar Script do Arquivo"
```

---

## 🔍 Diagnóstico e Verificação de Status

Antes de enviar uma sequência longa de comandos, você pode verificar se a bridge está ativa:

```powershell
python "C:\Users\epgur\Downloads\AdminBridge_Simple\client.py" status
```

- **Se retornar `🟢 ONLINE`**: O executor está pronto para processar comandos.
- **Se retornar `🔴 OFFLINE`**: Solicite ao usuário que execute [iniciar_admin.bat](file:///C:/Users/epgur/Downloads/AdminBridge_Simple/iniciar_admin.bat) ou dispare o inicializador via PowerShell.

---

## 📝 Formato JSON IPC (Inter-Process Communication)

Caso queira escrever diretamente na fila sem usar o `client.py`:

1. **Gravar requisição em** `C:\Users\epgur\Downloads\AdminBridge_Simple\queue\requests\<uuid>.json`:
```json
{
  "id": "e4f80872-9d0a-4710-9285-d8f99e31b671",
  "title": "Verificar Privilégios",
  "source": "antigravity",
  "type": "cmd",
  "code": "whoami /priv",
  "timeout": 180
}
```

2. **Aguardar e ler resposta em** `C:\Users\epgur\Downloads\AdminBridge_Simple\queue\responses\<uuid>.json`:
```json
{
  "id": "e4f80872-9d0a-4710-9285-d8f99e31b671",
  "title": "Verificar Privilégios",
  "status": "success",
  "exit_code": 0,
  "output": "...",
  "execution_time_sec": 0.25,
  "completed_at": "2026-10-19T23:20:00.000Z"
}
```
