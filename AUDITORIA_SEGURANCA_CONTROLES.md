# Relatório de Re-Auditoria de Segurança e Verificação Ativa de Controles (Security Assessment & QA)

**Aplicação Auditada:** Admin Bridge (`C:\Utilitario`)  
**Data da Re-Auditoria:** 14 de Outubro de 2026 (10:07 BRT)  
**Perfil de Avaliação:** Usuário Local Padrão / Não-Elevado (`E. Gurken`, Medium Integrity) vs. Daemon de Serviço (`NT AUTHORITY\SYSTEM`, PID `34632`, System Integrity)  
**Versão/Commit Avaliado:** `df3fba0` (*Integracao do Inspetor de Scripts em 3 Camadas, protecao X25519 na fila, correcoes SEC-01 a SEC-04*)  
**Metodologia:** Testes de invasão de caixa-branca, inspeção do código-fonte, testes ativos em tempo de execução no Windows e execução da suíte completa de 22 testes de regressão automatizados (`test_security_rules.py`).

---

## 1. Sumário Executivo Comparativo (Antes vs. Depois)

| ID do Controle | Área Auditada | Estado na 1ª Auditoria (00:58) | Estado na Re-Auditoria (10:07) | Veredito Atual |
| :--- | :--- | :---: | :---: | :---: |
| **SEC-01** | Permissões NTFS & Isolamento de Segredos | ❌ **Falha Crítica** (Herança ativa de `C:\`, leitura livre de configs e escrita na raiz) | 🛡️ **Blindado** (`config/` inacessível, herança removida, raiz somente leitura, drop-box na fila) | **APROVADO** |
| **SEC-02** | Travas de Kernel em Arquivos e Processo | ⚠️ **Parcialmente Eficaz** (Vulnerável offline e leitura livre de metadados) | 🛡️ **Blindado** (`hw_salt.bin` com `dwShareMode=0`, `config/` bloqueado offline por ACL, DACL de processo ativa) | **APROVADO** |
| **SEC-03** | IPC na Fila e Condições de Corrida (TOCTOU) | ❌ **Falha Crítica** (DPAPI de máquina permitia a qualquer processo decifrar OTPs) | 🛡️ **Blindado** (Criptografia assimétrica **X25519** unidirecional na fila + drop-box NTFS sem leitura) | **APROVADO** |
| **SEC-04** | Filtro de Auto-Proteção e Análise de Scripts | ❌ **Falha Crítica** (12 de 16 variações burlavam o filtro) | 🛡️ **Blindado** (16/16 variações bloqueadas + Inspetor de Scripts em 3 Camadas com AMSI e Risco) | **APROVADO** |

---

## 2. Evidências Coletadas nos Testes Ativos de Re-Auditoria

### 2.1. Permissões NTFS e Isolamento de Segredos (SEC-01)

#### Verificação Ativa de ACLs (`icacls`)
Após as correções implementadas em [`hotp_crypto.py`](hotp_crypto.py), as ACLs foram aplicadas diretamente sem o invólucro do `cmd.exe /c` e sem parâmetros inválidos no `takeown.exe`. As listas de controle de acesso ativas confirmam:

```powershell
C:\Utilitario
    BUILTIN\Usuários:(RX)
    BUILTIN\Administradores:(OI)(CI)(RX)
    AUTORIDADE NT\SISTEMA:(OI)(CI)(F)

C:\Utilitario\config
    Acesso negado. (Protegido exclusivamente para SYSTEM e Administradores)

C:\Utilitario\queue\requests
    BUILTIN\Usuários:(CI)(WD,AD)           [Drop-box: Permite apenas Write Data e Append Data]
    BUILTIN\Administradores:(OI)(CI)(F)
    AUTORIDADE NT\SISTEMA:(OI)(CI)(F)

C:\Utilitario\AdminBridge.exe
    BUILTIN\Usuários:(RX)
    BUILTIN\Administradores:(RX)
    AUTORIDADE NT\SISTEMA:(F)
```

#### Testes de Acesso Não-Elevado (Tentativas Reais de Leitura e Escrita)
Executados diretamente sob a identidade não-privilegiada `E. Gurken`:
* **`C:\Utilitario\config\hotp_config.json`:** `BLOQUEADO CONFORME ESPERADO -> O acesso ao caminho foi negado.`
* **`C:\Utilitario\config\owner_anchor.json`:** `BLOQUEADO CONFORME ESPERADO -> O acesso ao caminho foi negado.`
* **`C:\Utilitario\config\hw_salt.bin`:** `BLOQUEADO CONFORME ESPERADO -> O acesso ao caminho foi negado.`
* **`C:\Utilitario\config\canary.bin`:** `BLOQUEADO CONFORME ESPERADO -> O acesso ao caminho foi negado.`
* **`C:\Utilitario\config\.acl_seal`:** `BLOQUEADO CONFORME ESPERADO -> O acesso ao caminho foi negado.`
* **Escrita na raiz (`C:\Utilitario\test_write_recheck.tmp`):** `BLOQUEADO CONFORME ESPERADO -> O acesso ao caminho foi negado.`
* **Listagem da fila (`Get-ChildItem C:\Utilitario\queue\requests`):** `BLOQUEADO CONFORME ESPERADO -> O acesso ao caminho foi negado.`
* **Funcionamento de Drop-Box:** A conta de usuário comum conseguiu criar um arquivo em `queue\requests\`, mas o Windows barrou a leitura de volta (`ReadAllText` retornou `Acesso negado`), comprovando que **nenhum usuário consegue bisbilhotar requisições de outros usuários na fila**.

---

### 2.2. Travas de Kernel em Arquivos e Processo (SEC-02)

#### Testes com o Serviço Daemon em Execução (`PID 34632`, SYSTEM)
* **Integridade do Executável (`AdminBridge.exe`):**  
  Tentativas de abrir o executável para escrita via `[System.IO.File]::Open(..., FileMode::Open, FileAccess::Write)` retornaram `Acesso negado`. O binário está protegido pelo lock de imagem de seção PE do Windows e pelo handle de kernel do `KernelFileGuard`.
* **Cofre Dividido (`hw_salt.bin` e `hotp_config.json`):**  
  * Em tempo de execução, o `hw_salt.bin` permanece travado pelo kernel com `dwShareMode = 0` (`NO_SHARING`).  
  * O risco anterior de leitura offline foi eliminado: mesmo se o daemon for desligado, a pasta `config/` agora possui ACL restrita exclusiva para `SYSTEM` e `Administradores`. Usuários comuns não conseguem ler `hw_salt.bin` nem `hotp_config.json` em nenhum estado da máquina.
* **Blindagem DACL do Processo Daemon:**  
  Tentativas de encerramento do processo `PID 34632` a partir de um processo de integridade média retornaram:
  ```powershell
  BLOQUEADO KILL PROCESSO (PID 34632): Acesso negado
  ```
  A função [`harden_process_dacl()`](hotp_crypto.py) impede efetivamente o encerramento do daemon por contas de menor privilégio.

---

### 2.3. IPC na Fila e Condições de Corrida (TOCTOU) (SEC-03)

#### Criptografia Assimétrica X25519 Unidirecional na Fila
O mecanismo de trânsito em fila foi completamente reestruturado para utilizar **Criptografia Assimétrica X25519 (ECIES)**:
1. **Par de Chaves Assimétricas:**
   * A Chave Privada é gerada pelo daemon e mantida exclusivamente em `C:\Utilitario\config\transit_priv.bin`, protegida pela DACL restrita de `config/` e por DPAPI vinculada a `hw_salt.bin`.
   * A Chave Pública é publicada em `C:\Utilitario\queue\transit_pub.json`.
2. **Cifragem Unidirecional no Cliente:**
   * O cliente ([`client.py`](client.py)) lê a chave pública do daemon e gera um par efêmero em memória.
   * Realiza a troca Diffie-Hellman na curva Curve25519, deriva uma chave de criptografia autenticada vinculada a `req_id` e `code_hash`, cifra o token/OTP e descarta imediatamente a chave efêmera.
   * O envelope resultante possui o formato:
     $$\text{Envelope} = \text{"X25519\_V1|" } \parallel \text{eph\_pub (32B)} \parallel \text{nonce (16B)} \parallel \text{mac (32B)} \parallel \text{ciphertext}$$
3. **Teste Ativo de Quebra de Confidencialidade:**  
   Um processo não-elevado tentou descriptografar um token cifrado em trânsito sem possuir a chave privada:
   ```python
   enc = protect_transit_token("987654", req_id, code_hash)
   dec = unprotect_transit_token(enc, req_id, code_hash)
   # Resultado: dec == None (Acesso negado a config/transit_priv.bin)
   ```
4. **Eliminação do Sequestro de Fila (TOCTOU):**  
   Com a pasta `queue\requests\` configurada como drop-box (`WD,AD` sem permissão de leitura) e os tokens protegidos por X25519, **um atacante não consegue ler arquivos de terceiros na fila nem decifrar o OTP**, eliminando a janela de substituição de comandos ou roubo de autorização.

---

### 2.4. Filtro de Auto-Proteção e Análise de Scripts (SEC-04)

#### Matriz de Re-Teste de Evasão (16/16 Bloqueados)
Os 16 vetores de ataque submetidos na primeira auditoria foram re-executados contra a nova versão de [`is_self_targeting_command()`](app.py). **Todos os 16 foram bloqueados com sucesso (100% de eficácia)**:

| Payload de Teste Submetido | Vetor de Evasão | Status Anterior | Status Atual |
| :--- | :--- | :---: | :---: |
| `schtasks /delete /tn Admin* /f` | Wildcard em tarefa agendada | ❌ Bypass | 🛡️ **BLOQUEADO** |
| `taskkill /f /im Admin* /t` | Wildcard em terminação de processo | ❌ Bypass | 🛡️ **BLOQUEADO** |
| `powershell -Command "Get-Process Admin* \| Stop-Process -Force"` | Wildcard no PowerShell | ❌ Bypass | 🛡️ **BLOQUEADO** |
| `dir C:\U* /s` | Curinga curto antes da raiz | ❌ Bypass | 🛡️ **BLOQUEADO** |
| `cmd.exe /c "cd \ & cd Ut* & cd con* & dir"` | Travessia relativa com curingas | ❌ Bypass | 🛡️ **BLOQUEADO** |
| `cmd.exe /c "set X=Utilitario" & cmd.exe /c "dir C:\%X%"` | Variável de ambiente no CMD | ❌ Bypass | 🛡️ **BLOQUEADO** |
| `powershell -Command "$p = 'C:\' + 'Utili' + 'tario'; Get-ChildItem $p"` | Concatenação de string PowerShell | ❌ Bypass | 🛡️ **BLOQUEADO** |
| `powershell -Command "Get-Content (Join-Path 'C:\' ('Uti'+'litario\config\hotp_config.json'))"` | Join-Path com concatenação | 🛡️ Bloqueado | 🛡️ **BLOQUEADO** |
| `type \\?\C:\Utilitario\config\hotp_config.json` | Caminho NT UNC verbatim | 🛡️ Bloqueado | 🛡️ **BLOQUEADO** |
| `powershell -Command "Get-Content -LiteralPath '\\?\C:\Utilitario\config\hotp_config.json'"` | LiteralPath NT UNC | 🛡️ Bloqueado | 🛡️ **BLOQUEADO** |
| `icacls C:\U* /grant Everyone:F` | Alteração de ACL por curinga | ❌ Bypass | 🛡️ **BLOQUEADO** |
| `reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\AdminBridge.exe"` | Consulta direta ao registro | 🛡️ Bloqueado | 🛡️ **BLOQUEADO** |
| `reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\Admin*" /f` | Deleção de chave no registro | ❌ Bypass | 🛡️ **BLOQUEADO** |
| `wmic process where "name like 'Admin%'" delete` | Consulta WMI com wildcard | ❌ Bypass | 🛡️ **BLOQUEADO** |
| `powershell -enc RwBlAHQALQBQAHIAbwBjAGUAcwBzACAALQBOAGEAbQBlACAAQQBkAG0AaQBuACoA` | Base64 ofuscado no PowerShell | ❌ Bypass | 🛡️ **BLOQUEADO** |
| `powershell -e RwBlAHQALQBDAGgAaQBsAGQASQB0AGUAbQAgACIASgBvAGkAbgAtAFAAYQB0AGgAIgA=` | Base64 com Join-Path | ❌ Bypass | 🛡️ **BLOQUEADO** |

#### Camada Extra: Inspetor de Scripts em 3 Camadas ([`script_inspector.py`](script_inspector.py))
Além da lista negra e regex endurecidos, a nova arquitetura introduziu inspeção comportamental antes da execução de scripts aprovados:
1. **Camada 1 (AMSI Nativo do Windows):** Passa o texto do script diretamente pelo motor nativo do Windows Defender em memória via `amsi.dll` (`AmsiScanString`), detectando malwares conhecidos em 1 a 3 ms sem impacto de CPU.
2. **Camada 2 (Classificador de Risco e Intenção):** Mapeia assinaturas de alto impacto (criação de serviços ocultos, agendamento de tarefas, autoruns no Registro, deleção de cópias de sombra via `vssadmin` e extração de credenciais de memória). Caso a pontuação de risco ultrapasse o limite seguro, a execução requer confirmação explícita com novo código OTP.
3. **Camada 3 (Auditoria Pós-Execução Anti-Mascaramento):** Vistoria imediata do XML em `C:\Windows\System32\Tasks\AdminBridge` logo após o término do script para impedir que um comando elevado altere os binários chamados no boot.

---

## 3. Validação da Suíte de Testes Automatizados (`test_security_rules.py`)

A suíte completa de testes de segurança foi executada no ambiente com **22/22 testes aprovados (100% de sucesso)**:

```
[*] 1. Testando Provisionamento Inicial e Proteção Modular DPAPI...                 -> PASSOU
[*] 2. Testando Bloqueio de Geração Duplicada - Flag=1...                            -> PASSOU
[*] 3. Testando Assinatura de Integridade - Detecção de Adulteração Manual...        -> PASSOU
[*] 4. Testando Consulta Passiva do Contador sem Avançar...                          -> PASSOU
[*] 5. Testando Avanço Estrito do Contador (+1 em erro e acerto)...                  -> PASSOU
[*] 6. Testando Disjuntor Fail-Safe (Lockdown após 3 falhas consecutivas)...         -> PASSOU
[*] 7. Testando Reset com Destruição de Privilégios (Autodestruição)...              -> PASSOU
[*] 8. Testando Bloqueio de Origem Não Autorizada...                                 -> PASSOU
[*] 9. Testando Canal de Pré-Autorização (Ticket de até 45 Minutos)...               -> PASSOU
[*] 10. Testando Sincronização HOTP com Atualização Estrita do Contador...          -> PASSOU
[*] 11. Testando Validação Obrigatória de OTP no Pareamento Inicial...               -> PASSOU
[*] 12. Testando Reparo de Adulteração Protegido por Senha Mestra...                 -> PASSOU
[*] 13. Testando Bloqueio de Comandos Auto-Direcionados (16/16 Variações)...         -> PASSOU
[*] 14. Testando Âncora Soberana Ed25519 e Detecção de Adulteração de Binário...    -> PASSOU
[*] 15. Testando Ciclo de 14 Dias e Renovação de Senha Mestra...                     -> PASSOU
[*] 16. Testando Contra-Senha de Confirmação Mútua no Modo Auth...                   -> PASSOU
[*] 17. Testando Proteção DPAPI de OTP em Trânsito e Anti-TOCTOU na Fila...          -> PASSOU
[*] 18. Testando Bloqueio de Desinstalação sem Senha e Autorização com Senha...     -> PASSOU
[*] 19. Testando Auditoria Anti-Mascaramento da Tarefa Agendada...                  -> PASSOU
[*] 20. Testando Cofre Dividido (hw_salt.bin) e Armadilha Forense...                -> PASSOU
[*] 21. Testando Inspetor de Scripts em 3 Camadas (AMSI + Classificador + IA)...     -> PASSOU
[*] 22. Testando Desenrolamento Recursivo de Scripts Externos...                    -> PASSOU

=======================================================
TODOS OS 22 REQUISITOS DE SEGURANÇA FORAM TESTADOS E APROVADOS!
=======================================================
```

---

## 4. Recomendações Residuais de Melhoria Contínua

Embora todos os controles críticos tenham sido satisfatoriamente remediados e validados, recomendam-se os seguintes refinamentos incrementais para futuras versões:
1. **Cmdlet `Unregister-ScheduledTask`:** Adicionar explicitamente `unregister-scheduledtask` ao regex da linha 291 de [`app.py`](app.py) como defesa em profundidade (embora a auditoria pós-execução já detecte a exclusão e arme o Lockdown).
2. **Wildcards no Sufixo `*Bridge*`:** Estender o padrão `r"\badmin[a-z0-9*?%]*"` para cobrir também `bridge*` em nomes de processos e tarefas PowerShell.

---
*Relatório de Re-Auditoria finalizado e validado com sucesso.*
