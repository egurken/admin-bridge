# Relatório de Auditoria de Segurança e Verificação de Controles (Security Assessment & QA)

**Aplicação Auditada:** Admin Bridge (`C:\Utilitario`)  
**Data da Auditoria:** 14 de Outubro de 2026  
**Perfil de Avaliação:** Usuário Local Padrão / Não-Elevado (`WORKGROUP\AdminUser`, Medium Integrity) vs. Daemon de Serviço (`NT AUTHORITY\SYSTEM`, PID `38116`, System Integrity)  
**Metodologia:** Testes de caixa-branca (*source code review*) combinados com testes ativos em tempo de execução (*dynamic inspection & control verification*).

---

## 1. Sumário Executivo de Controles

| ID | Área Auditada | Status do Controle | Severidade | Resumo do Achado |
| :--- | :--- | :---: | :---: | :--- |
| **SEC-01** | Permissões NTFS e Isolamento de Arquivos | ❌ **Falha Crítica** | **Alta** | Permissões herdadas da raiz `C:\` ativas (`Authenticated Users: Modify`). Usuários comuns podem ler metadados/configurações e criar/modificar arquivos em `C:\Utilitario`. |
| **SEC-02** | Travas de Kernel em Arquivos e Processo | ⚠️ **Parcialmente Eficaz** | **Média** | `hw_salt.bin` está bloqueado contra leitura em runtime (`dwShareMode=0`), e o processo daemon está protegido contra `kill`. Porém, `hotp_config.json` é legível em runtime e `hw_salt.bin` fica vulnerável offline se o daemon for desligado. |
| **SEC-03** | IPC na Fila e Condições de Corrida (TOCTOU) | ❌ **Falha Crítica** | **Alta** | DPAPI em trânsito com escopo de máquina (`CRYPTPROTECT_LOCAL_MACHINE`) permite a qualquer usuário decifrar OTPs/tokens alheios em trânsito e sequestrar a fila para executar comandos como SYSTEM. |
| **SEC-04** | Filtro de Auto-Proteção (`is_self_targeting_command`) | ❌ **Falha Crítica** | **Média/Alta** | O filtro de linha de comando foi burlado em **12 de 16 variações testadas** utilizando curingas (`*`), variáveis de ambiente, caminhos relativos e concatenação de strings. |

---

## 2. Auditoria Detalhada por Controle

### 2.1. Permissões NTFS e Isolamento de Segredos (SEC-01)

#### Evidências Coletadas no Ambiente
A inspeção das listas de controle de acesso (DACL) via `icacls` revelou que a remoção de herança (`/inheritance:r`) **nunca foi aplicada**. Todos os diretórios e arquivos mantêm permissões herdadas `(I)` de `C:\`:

```powershell
C:\Utilitario                   AUTORIDADE NT\Usuários autenticados:(I)(M)
C:\Utilitario\config            AUTORIDADE NT\Usuários autenticados:(I)(M)
C:\Utilitario\queue\requests    AUTORIDADE NT\Usuários autenticados:(I)(M)
C:\Utilitario\queue\processing  AUTORIDADE NT\Usuários autenticados:(I)(M)
C:\Utilitario\AdminBridge.exe   AUTORIDADE NT\Usuários autenticados:(I)(M)
```

Testes práticos executados diretamente pela conta não-privilegiada confirmaram:
1. **Leitura não-autorizada de segredos e configurações:**
   * `C:\Utilitario\config\hotp_config.json` -> **LIDO COM SUCESSO** (1.593 bytes de metadados e blobs DPAPI expostos).
   * `C:\Utilitario\config\owner_anchor.json` -> **LIDO COM SUCESSO** (383 bytes da âncora do proprietário expostos).
   * `C:\Utilitario\config\canary.bin` -> **LIDO COM SUCESSO** (32 bytes expostos).
2. **Escrita arbitrária na raiz do utilitário:**
   * Criação bem-sucedida do arquivo `C:\Utilitario\test_write.tmp` por usuário comum.
3. **Ausência do selo de blindagem:**
   * O arquivo `C:\Utilitario\config\.acl_seal` **não existe** (`Test-Path` retornou `False`), comprovando que `check_config_acl_isolation()` falha em todas as checagens.

#### Causa Raiz no Código-Fonte
Em [`hotp_crypto.py`](hotp_crypto.py#L1225-L1330), na função `apply_isolated_bridge_ntfs_acls()`, os comandos externos falham silenciosamente devido a incompatibilidades de sintaxe do Windows:
* **Linha 1225:**
  ```python
  subprocess.run(["takeown", "/f", str(base_dir), "/d", "y"], capture_output=True, check=False)
  ```
  *Falha:* No utilitário `takeown.exe`, o modificador `/d y` é estritamente proibido sem o parâmetro recursivo `/r`. Retorna código `1`: `ERRO: /D só deve ser especificado com /R.`
* **Linhas 1227, 1241, 1264, 1278, 1291, 1309, 1323:**
  ```python
  subprocess.run(["cmd.exe", "/c", f'icacls "{base_dir}" /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)(F)" ... /c /q'], ...)
  ```
  *Falha:* A passagem da linha de comando com aspas embutidas via `cmd.exe /c` faz com que as aspas sejam duplicadas pela API do Windows (`""*S-1-5-18:(OI)(CI)(F)""`). O utilitário `icacls` rejeita os argumentos com código de erro `87` (`ERROR_INVALID_PARAMETER`): `Parâmetro inválido ""*S-1-5-18:(OI)(CI)(F)""`.
* Como o código engloba as operações em blocos `try: ... except Exception: pass` com `check=False`, as falhas foram completamente omitidas, mantendo as permissões desprotegidas.

---

### 2.2. Travas de Kernel e DACL de Processo (SEC-02)

#### Evidências Coletadas no Ambiente
Com o serviço ativo sob o PID `38116` (executando como `NT AUTHORITY\SYSTEM`):
* **`hw_salt.bin`:** Bloqueado com sucesso pelo `KernelFileGuard` (`dwShareMode = 0` / `NO_SHARING`).  
  *Resultado:* Tentativas de leitura por processos de menor integridade retornam erro de violação de compartilhamento: `O processo não pode acessar o arquivo 'hw_salt.bin' porque ele está sendo usado por outro processo.` (**Bloqueado conforme esperado em runtime**).
* **`hotp_config.json`:** Aberto pelo kernel com `FILE_SHARE_READ`.  
  *Resultado:* Bloqueia modificação e exclusão, mas **permite leitura direta em disco por qualquer processo**, revelando a contagem do contador e os blobs criptografados.
* **`AdminBridge.exe`:** Bloqueado contra escrita/exclusão pelo mapeamento de memória do kernel (`PE Section mapping`) e pelo handle de leitura. Tentativas de sobrescrita retornam `Acesso negado`.
* **DACL do Processo Daemon (`PID 38116`):**
  * Chamada `Get-Process -Id 38116 | Stop-Process` a partir de processo não-elevado: **Bloqueado com Acesso Negado**.
  * A blindagem via `harden_process_dacl()` em [`hotp_crypto.py:1139`](hotp_crypto.py#L1139) remove efetivamente permissões de encerramento (`PROCESS_TERMINATE`) e injeção de memória para contas padrão.

---

### 2.3. Condições de Corrida (TOCTOU) e IPC na Fila (SEC-03)

#### Evidências Coletadas no Ambiente e Código
* **Quebra de Confidencialidade de Tokens em Trânsito:**  
  Em [`client.py:88-90`](client.py#L88-L90), tokens e OTPs são cifrados com a função `protect_transit_token()`.  
  Essa função utiliza a DPAPI do Windows com a flag `CRYPTPROTECT_LOCAL_MACHINE` (linha 57 de `hotp_crypto.py`) e uma entropia composta de parâmetros conhecidos:
  $$\text{Entropy} = \text{SHA-256}(\text{"AntigravityQueueTransitProtectionV2"} \parallel \text{req\_id} \parallel \text{code\_hash})$$
  Como o `req_id` e o `code_hash` são gravados em texto claro no arquivo JSON da requisição, **qualquer processo não-privilegiado local consegue derivar a mesma entropia e invocar `CryptUnprotectData` com sucesso**:
  ```python
  # Teste prático realizado por processo não-elevado:
  dec = unprotect_transit_token(enc_b64, req_id, code_hash)
  # Resultado: OTP "123456" recuperado com sucesso!
  ```

* **Vetor de Sequestro de Fila e Escalação de Privilégios (TOCTOU / Race Condition):**  
  Como a pasta `queue\requests` possui permissão de leitura e escrita para todos os usuários autenticados (Item 2.1), um processo malicioso pode:
  1. Monitorar a pasta `C:\Utilitario\queue\requests\` via `ReadDirectoryChangesW`.
  2. Ao detectar um novo arquivo `<legit_id>.json`, ler o arquivo e decifrar o OTP legítimo em trânsito.
  3. Criar imediatamente um arquivo concorrente ordenado lexicograficamente antes do legítimo (ex.: `000_attack.json`), contendo seu próprio código malicioso assinado com o OTP roubado:
     $$\text{code} = \text{"net localgroup Administrators Attacker /add"}$$
  4. O daemon em [`app.py:2467-2469`](app.py#L2467-L2469) seleciona `req_files[0]`, valida o OTP no comando malicioso, executa o comando como `SYSTEM` e avança o contador HOTP (+1).
  5. A requisição legítima original falha subsequentemente com erro de dessincronização de contador.

* **Falsificação de Identidade do Ticket de Pré-Autorização:**  
  Em [`app.py:2588-2598`](app.py#L2588-L2598) e [`hotp_auth.py:1229-1231`](hotp_auth.py#L1229-L1231), a validação do remetente do ticket de 45 minutos restringe-se a:
  ```python
  if expected_user and caller_user and str(expected_user).lower() != str(caller_user).lower():
      return False, "Ticket pertence a outro usuario"
  ```
  O valor de `caller_user` é lido diretamente do campo `caller.user` do payload JSON fornecido pelo cliente, sem validação do token real de logon do Windows (`OpenProcessToken` / `TokenUser`). Qualquer usuário local que intercepte um token de pré-autorização pode forjar `caller: {"user": "AdminUser"}` e executar comandos administrativos sem o consentimento do proprietário.

---

### 2.4. Teste do Filtro de Auto-Proteção (`is_self_targeting_command`) (SEC-04)

O teste avaliou se o filtro baseado em expressões regulares e listas negras em [`app.py:241-297`](app.py#L241-L297) impede o direcionamento a `C:\Utilitario`, seus binários ou suas tarefas agendadas.

Foram submetidas 16 variações de comandos; **12 conseguiram burlar o filtro (75% de taxa de evasão)**:

```
[BRECHA IDENTIFICADA] Wildcard na tarefa agendada: schtasks /delete /tn Admin* /f
[BRECHA IDENTIFICADA] Wildcard no comando taskkill: taskkill /f /im Admin* /t
[BRECHA IDENTIFICADA] Wildcard em cmdlet PowerShell: powershell -Command "Get-Process Admin* | Stop-Process -Force"
[BRECHA IDENTIFICADA] Wildcard no caminho de diretório: dir C:\U* /s
[BRECHA IDENTIFICADA] Travessia relativa com curingas: cmd.exe /c "cd \ && cd Ut* && cd con* && dir"
[BRECHA IDENTIFICADA] Variável de ambiente no CMD: cmd.exe /c "set X=Utilitario" && cmd.exe /c "dir C:\%X%"
[BRECHA IDENTIFICADA] Concatenação em tempo de execução: powershell -Command "$p = 'C:\' + 'Utili' + 'tario'; Get-ChildItem $p"
[BRECHA IDENTIFICADA] Permissões com wildcard via icacls: icacls C:\U* /grant Everyone:F
[BRECHA IDENTIFICADA] Alteração de Registro com wildcard: reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\Admin*" /f
[BRECHA IDENTIFICADA] Consulta WMI com predicado LIKE: wmic process where "name like 'Admin%'" delete
[BRECHA IDENTIFICADA] Payload Base64 sem identificador literal: powershell -enc RwBlAHQALQBQAHIAbwBjAGUAcwBzACAALQBOAGEAbQBlACAAQQBkAG0AaQBuACoA
[BRECHA IDENTIFICADA] Subexpressão dinâmica de caminho: powershell -e RwBlAHQALQBDAGgAaQBsAGQASQB0AGUAbQAgACIASgBvAGkAbgAtAFAAYQB0AGgAIgA=
[BLOQUEADO] Join-Path com concatenação literal: powershell -Command "Get-Content (Join-Path 'C:\' ('Uti'+'litario\config\hotp_config.json'))"
[BLOQUEADO] Caminho NT UNC verbatim: type \\?\C:\Utilitario\config\hotp_config.json
[BLOQUEADO] LiteralPath NT UNC no PowerShell: powershell -Command "Get-Content -LiteralPath '\\?\C:\Utilitario\config\hotp_config.json'"
[BLOQUEADO] Consulta direta do registro: reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\AdminBridge.exe"
```

#### Motivo das Evasões
1. **Padrão de Regex Insuficiente:** A regra `re.search(r"c:[\\/]+uti[a-z0-9*?~]*", candidate)` só valida strings que comecem estritamente por `uti`. Padrões como `C:\U*`, `C:\*util*` ou `C:\?tilitario` são ignorados.
2. **Dependência de Nomes Estáticos:** A lista negra busca por `adminbridge`, mas não por prefixos curinga (`admin*`, `*bridge*`), permitindo que `schtasks`, `taskkill` e consultas WMI manipulem a tarefa agendada e os processos.
3. **Ausência de Resolução Dinâmica:** Variáveis de ambiente (`%VAR%`) e concatenações do PowerShell (`+`, `Join-Path`) não são expandidas antes da filtragem textual.

---

## 3. Matriz de Remediação Defensiva

### 3.1. Correção Defensiva 1: Blindagem Efetiva de Permissões NTFS
Substituir todas as chamadas `cmd.exe /c icacls ...` em [`hotp_crypto.py`](hotp_crypto.py#L1225-L1330) por chamadas diretas ao binário `icacls.exe`, corrigindo também o uso de `takeown.exe`:

```python
# Correção em hotp_crypto.py (apply_isolated_bridge_ntfs_acls):

# 1. Posse do diretório raiz (sem /d y isolado)
subprocess.run(["takeown", "/f", str(base_dir)], capture_output=True, check=False)

# 2. Remoção de herança e concessão explícita (sem envolver em cmd.exe /c)
subprocess.run([
    "icacls", str(base_dir),
    "/inheritance:r",
    "/grant:r", "*S-1-5-18:(OI)(CI)(F)",
    "/grant", "*S-1-5-32-544:(OI)(CI)(RX)",
    "/grant", "*S-1-5-32-545:(OI)(CI)(RX)",
    "/c", "/q"
], capture_output=True, check=False)

# 3. Isolamento estrito de C:\Utilitario\config (Apenas SYSTEM e Administradores)
subprocess.run(["takeown", "/f", str(config_dir), "/r", "/d", "y"], capture_output=True, check=False)
subprocess.run([
    "icacls", str(config_dir),
    "/inheritance:r",
    "/grant:r", "*S-1-5-18:(OI)(CI)(F)",
    "/grant", "*S-1-5-32-544:(OI)(CI)(F)",
    "/t", "/c", "/q"
], capture_output=True, check=False)

# 4. Fila requests: Usuários comuns podem apenas CRIAR arquivos, sem ler arquivos de terceiros
# SDDL equivalente: SYSTEM (F), Administradores (F), Usuários (CreateFiles/WriteData - sem List/Read)
subprocess.run([
    "icacls", str(req_dir),
    "/inheritance:r",
    "/grant:r", "*S-1-5-18:(OI)(CI)(F)",
    "/grant", "*S-1-5-32-544:(OI)(CI)(F)",
    "/grant", "*S-1-5-32-545:(CI)(WD,AD)",  # Write Data, Append Data (Drop-box seguro)
    "/c", "/q"
], capture_output=True, check=False)
```

### 3.2. Correção Defensiva 2: Isolamento Criptográfico do IPC na Fila
1. **DPAPI com Escopo de Usuário:** Não utilizar `CRYPTPROTECT_LOCAL_MACHINE` para proteger segredos em trânsito. Em ambientes de máquina compartilhada, o cliente deve autenticar o canal via chave de sessão efêmera derivada no pareamento ou via **Named Pipe local seguro** (`\\.\pipe\AdminBridgeIPC`) com `SECURITY_DESCRIPTOR` restrito a `SYSTEM` e `Administradores`.
2. **Validação Criptográfica do Remetente do Ticket:** Em `app.py`, ao consumir `preauth_ticket`, o daemon deve obter o SID real do proprietário do processo cliente via `OpenProcessToken` e comparar criptograficamente com o SID registrado na criação do ticket, eliminando a dependência do campo inseguro `caller.user`.

### 3.3. Correção Defensiva 3: Endurecimento do Filtro de Auto-Proteção
Em [`app.py:241-297`](app.py#L241-L297), expandir a função `is_self_targeting_command`:

```python
def is_self_targeting_command(cmd_text: str, _depth: int = 0) -> bool:
    if not cmd_text or _depth > 3:
        return False

    raw = cmd_text.lower()
    # Expande variáveis de ambiente do sistema antes da análise
    try:
        raw = os.path.expandvars(raw)
    except Exception:
        pass

    deobfuscated = raw.translate(str.maketrans("", "", "\"\x27^`$()+"))

    forbidden_patterns = [
        r"c:[\\/]+u[a-z0-9*?~]*",                      # C:\Utilitario, C:\U*, etc.
        r"[\\/]+utilit",                               # /utilitario, \utilitario
        r"adminbridge",                                # Nome do executável e tarefa
        r"antigravity",                                # Nomes legados
        r"schtasks.*(?:admin|bridge)",                 # Manipulação da tarefa por curinga
        r"taskkill.*(?:admin|bridge)",                 # Encerramento por curinga
        r"get-process.*(?:admin|bridge)",              # PowerShell stop por curinga
        r"stop-process",                               # Tentativa de matar processos
        r"hw_salt|hotp_config|owner_anchor|preauth",   # Arquivos sensíveis
        r"wmic.*process.*(?:admin|bridge)"             # WMI queries
    ]

    for candidate in (raw, deobfuscated):
        for pat in forbidden_patterns:
            if re.search(pat, candidate):
                return True

    return False
```

---
*Relatório concluído e emitido para a equipe de desenvolvimento.*
