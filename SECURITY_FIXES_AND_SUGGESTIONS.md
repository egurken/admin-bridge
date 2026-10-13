# Auditoria de Segurança, Correções Aplicadas e Recomendações Arquiteturais — Admin Bridge

Este documento detalha as vulnerabilidades identificadas na auditoria do código-fonte do **Admin Bridge**, as correções implementadas diretamente no repositório para mitigar a **extração/roubo do código HOTP por usuários comuns** e a **adulteração do executável ou da pasta `C:\Utilitario` por administradores**, além das recomendações arquiteturais para endurecimento em nível de Sistema Operacional no Windows.

## 1. Resumo das Vulnerabilidades Corrigidas no Código

| ID | Severidade | Ameaça / Vetor | Arquivo(s) Afetado(s) | Problema Original | Correção Implementada |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **V1** | **Crítica** | Roubo de OTP em Trânsito e TOCTOU na Fila por Usuário Comum | `client.py`, `app.py`, `hotp_crypto.py` | `queue/requests/<id>.json` gravava `"otp"` e `"preauth_token"` em texto claro e dava permissão de modificação `(M)` a todos os usuários em `queue`. | **Criptografia DPAPI em trânsito (`protect_transit_token` / `unprotect_transit_token`)** vinculada criptograficamente ao `req_id` e ao `code_hash` (SHA-256 do comando), além de isolamento NTFS por `CREATOR OWNER` (`*S-1-3-0`) em `requests/` e bloqueio total de `processing/` para usuários comuns. |
| **V2** | **Crítica** | Substituição do `.exe` ou *DLL Hijacking* em `C:\Utilitario` por Usuário Comum | `hotp_crypto.py`, `app.py` | A pasta raiz `C:\Utilitario` e `AdminBridge.exe` não removiam a herança NTFS (`/inheritance:r`), permitindo criar DLLs maliciosas ou sobrescrever o binário. | Remoção explícita de herança (`/inheritance:r`) e `takeown` em `C:\Utilitario` e `AdminBridge.exe`, concedendo escrita apenas a `SYSTEM` (`*S-1-5-18:(F)`), atributo `+r` no `.exe`, bloqueio de cópia não-admin em `ensure_environment_installed()` e ativação de `SetDllDirectoryW("")` + `SetProcessMitigationPolicy`. |
| **V3** | **Crítica** | *Race Condition* (TOCTOU) no Provisionamento da Chave HOTP | `hotp_auth.py`, `hotp_crypto.py` | `provision()` gravava `hotp_config.json` no disco antes de aplicar `apply_isolated_bridge_ntfs_acls()`, abrindo janela para leitura de `secret_dpapi`. | Aplicação das ACLs NTFS restritas e geração de `hw_salt.bin` **antes** de criar ou gravar `hotp_config.json` e `owner_anchor.json` em disco. |
| **V4** | **Crítica** | Substituição Silenciosa do Executável ou Tarefa Agendada por Admin | `hotp_crypto.py`, `hotp_auth.py`, `app.py` | `verify_owner_anchor()` nunca era chamado na execução real e comparava a assinatura apenas com o hash salvo no próprio JSON, sem recalcular o hash atual do disco. | `verify_owner_anchor()` e `check_integrity_mac()` agora recalculam `get_static_mesh_hash()` em tempo real (SHA-256 de `AdminBridge.exe` + XML da Tarefa Agendada) e são verificados obrigatoriamente em `_load_config_raw()`, `read_passive_metadata()` e no loop do daemon, acionando `trigger_incident_lockdown()` em caso de divergência. |
| **V5** | **Alta** | Exclusão de `owner_anchor.json` ou `.sig` Ignorada | `hotp_crypto.py` | Se `owner_anchor.json` ou `hotp_config.json.sig` fossem apagados, as funções retornavam `True` (válido). | A ausência de `owner_anchor.json` ou de `hotp_config.json.sig` quando `provisioned_flag == 1` agora retorna `False` e dispara `SecurityError` / Lockdown imediato. |
| **V6** | **Alta** | Bypass do Filtro `is_self_targeting_command()` e Diretório de Trabalho Inseguro | `app.py` | Comandos com curingas (`C:\Uti*`), aspas/circunflexos (`C:\Util"i"tario`), caminhos relativos (`type config\*.json`) ou `-e` passavam pelo filtro, e `subprocess.run` herdava `C:\Utilitario` como `cwd`. | Desofuscação de caracteres de escape (`"`, `'`, `^`, `` ` ``), bloqueio por regex de curingas (`c:\uti*`) e subpastas relativas (`config\`, `queue\`, `scripts\`), decodificação recursiva de qualquer variante de `-EncodedCommand`/`FromBase64String`, e execução forçada com `cwd=C:\Windows\System32`. |
| **V7** | **Alta** | Conflito GUI vs. Daemon e Queima de OTP Antes de Validar `code_hash` | `app.py` | A GUI rodando como usuário comum disputava arquivos em `requests/` com o daemon `SYSTEM`, e o daemon consumia o OTP antes de conferir `code_hash`. | A GUI não-elevada ignora requisições autenticadas (deixando-as exclusivamente para o daemon `SYSTEM`), e o daemon valida `code_hash` e `check_forensic_integrity()` **antes** de avançar ou consumir o OTP. |
| **V8** | **Alta** | Falsificação de PID/Executável em `verify_caller_origin()` e Oráculo em `sync` | `hotp_crypto.py`, `hotp_auth.py` | `verify_caller_origin()` confiava cegamente no JSON enviado pelo cliente; `diagnose_otp_sync()` ignorava `lockdown` e não registrava falhas no *Fail-Safe*. | `verify_caller_origin()` agora consulta o caminho real da imagem do PID ativo no kernel do Windows via `OpenProcess` + `QueryFullProcessImageNameW`. `diagnose_otp_sync()` bloqueia execução durante `lockdown`, limita `max_lookback` e contabiliza falhas no *Fail-Safe*. |
| **V9** | **Média** | Vazamento da Chave Secreta HOTP em Objetos `bytes` Imutáveis na RAM | `hotp_crypto.py`, `hotp_auth.py` | `dpapi_unprotect()` usava `ctypes.string_at()`, criando um objeto `bytes` imutável no heap do Python que `wipe_buffer()` não conseguia zerar. | `dpapi_unprotect()` agora copia os bytes diretamente do buffer nativo da Win32 API para um `bytearray` mutável usando `ctypes.memmove`, trava a página física com `VirtualLock` (`lock_memory_page`) e zera o buffer nativo imediatamente. |

## 2. Detalhamento Técnico das Correções Implementadas

### 2.1. Proteção Criptográfica do OTP na Fila e Prevenção de TOCTOU (`hotp_crypto.py`, `client.py`, `app.py`)
No modelo anterior, quando o cliente executava `AdminBridge.exe run --code "..." --otp 123456`, o código OTP era gravado em texto claro dentro de `C:\Utilitario\queue\requests\<uuid>.json`. Qualquer processo rodando sob uma conta de usuário comum podia monitorar essa pasta, ler o código OTP antes do daemon e substituir o comando no arquivo JSON.

Com a correção:
1. Foram criadas as funções `protect_transit_token(token_str, req_id, code_hash)` e `unprotect_transit_token(enc_b64, req_id, code_hash)`.
2. O cliente calcula o `code_hash = sha256(code)` e criptografa o OTP via DPAPI usando uma entropia derivada de `DPAPI_QUEUE_ENTROPY | req_id | code_hash`.
3. O arquivo JSON em `queue/requests/` armazena apenas `"otp_dpapi"` (com `"otp": null`) e é gravado atomicamente via arquivo `.tmp` renomeado.
4. Se qualquer processo tentar alterar o campo `"code"` ou `"code_hash"` no JSON após o envio, a entropia muda e a chamada `unprotect_transit_token()` no daemon falha imediatamente, abortando a execução **antes** de consumir o OTP.
5. As permissões NTFS de `queue/processing` foram revogadas para usuários comuns (restritas apenas a `SYSTEM` e `Administradores`), e `queue/requests` e `queue/responses` utilizam `CREATOR OWNER` (`*S-1-3-0:(IO)(F)`).

### 2.2. Detecção Real de Alteração do Executável e da Tarefa Agendada (`hotp_crypto.py`, `hotp_auth.py`, `app.py`)
No código original, a função `verify_owner_anchor()` continha um erro lógico: ela lia `recorded_mesh = anchor_data.get("static_mesh_hash")` de dentro do próprio `owner_anchor.json` e verificava a assinatura Ed25519 sobre essa string estática, sem nunca comparar com o hash real do `AdminBridge.exe` em disco (`get_static_mesh_hash()`). Além disso, `verify_owner_anchor()` nunca era chamada fora da suíte de testes.

Com a correção:
1. `verify_owner_anchor()` e `check_integrity_mac()` agora chamam `get_static_mesh_hash()` a cada validação, comparando em tempo constante (`hmac.compare_digest`) o hash SHA-256 atual de `C:\Utilitario\AdminBridge.exe` e de `C:\Windows\System32\Tasks\AdminBridge` com o hash assinado pela chave privada Ed25519 do proprietário no momento do provisionamento.
2. `_load_config_raw()`, `read_passive_metadata()`, `check_forensic_integrity()` e o loop principal de `run_daemon_loop()` validam obrigatoriamente a âncora.
3. Qualquer modificação no binário `AdminBridge.exe`, na Tarefa Agendada ou a remoção de `owner_anchor.json` / `hotp_config.json.sig` dispara `SecurityError` e aciona o protocolo `trigger_incident_lockdown()`, removendo a tarefa elevada do Windows e bloqueando o utilitário até que o proprietário valide a Senha Mestra na opção **Corrigir**.

### 2.3. Blindagem NTFS da Raiz `C:\Utilitario` e Mitigação de *DLL Hijacking*
1. `apply_isolated_bridge_ntfs_acls()` agora remove a herança da pasta raiz `C:\Utilitario` (`/inheritance:r`) e concede Controle Total `(F)` exclusivamente a `SYSTEM` (`*S-1-5-18`), deixando `Administradores` (`*S-1-5-32-544`) e `Usuários` (`*S-1-5-32-545`) apenas com Leitura e Execução `(RX)` na raiz e no executável `AdminBridge.exe`. Isso impede que usuários comuns plantem DLLs maliciosas na pasta da aplicação ou renomeiem o executável.
2. `configure_anti_dump_mitigations()` chama `kernel32.SetDllDirectoryW("")` (removendo o diretório atual da ordem de busca de DLLs) e ativa `SetProcessMitigationPolicy` (`ProcessImageLoadPolicy` = `NoRemoteImages | NoLowMandatoryLabelImages`), impedindo que o processo elevado carregue bibliotecas gravadas por usuários de baixa integridade.

## 3. Recomendações Arquiteturais Avançadas (Próximos Passos no Windows)

Para elevar a segurança do **Admin Bridge** ao nível máximo contra atacantes que já possuam privilégios administrativos na máquina ou acesso físico/local avançado, recomendo as seguintes evoluções arquiteturais:

### 3.1. Substituir (ou Complementar) a Semente Simétrica HOTP por Assinatura Assimétrica (Desafio-Resposta)
* **Por que fazer:** O algoritmo HOTP (RFC 4226) é **simétrico** — tanto o seu celular quanto o computador precisam conhecer a mesma chave secreta de 20 bytes (`secret_dpapi`). No Windows, um usuário com poderes de `Administrador` ou `SYSTEM` sempre pode depurar o processo do serviço na memória RAM ou invocar `CryptUnprotectData` como `SYSTEM` para extrair a semente simétrica e cloná-la.
* **Como evoluir:** Se você utilizar **autenticação assimétrica baseada em Desafio-Resposta (Ed25519 / ECDSA / FIDO2 / WebAuthn)**:
  1. O computador armazena **apenas a Chave Pública** em `C:\Utilitario\config`.
  2. A **Chave Privada** fica exclusivamente no seu celular ou chave de segurança física (YubiKey / Passkey).
  3. Mesmo que um Administrador copie toda a pasta `C:\Utilitario` e faça um *dump* completo da memória RAM do serviço `SYSTEM`, **é matematicamente impossível extrair a chave privada ou gerar códigos futuros**, pois o PC só possui a chave pública verificadora.

### 3.2. Criptografar `secret_dpapi` com Chave Efêmera Derivada da Senha Mestra em RAM
* Caso mantenha o HOTP (RFC 4226) para usar com apps como Google Authenticator / Aegis:
  * Em vez de cifrar a semente HOTP apenas com `dpapi_protect()` (que o `SYSTEM` consegue descriptografar sozinho a qualquer momento após o boot), cifre a semente com **AES-256-GCM** usando uma chave derivada via `scrypt` da sua **Senha Mestra**, e mantenha essa chave derivada **exclusivamente na memória RAM (`VirtualLock`) do processo daemon `SYSTEM`**.
  * Ao ligar o computador, o daemon solicita uma única vez a Senha Mestra para carregar a chave em RAM. Se um administrador copiar `C:\Utilitario\config\hotp_config.json` para outra pasta ou tentar descriptografá-lo offline, o arquivo será indecifrável sem a Senha Mestra.

### 3.3. Migrar a Comunicação da Fila de Arquivos (`queue/`) para Named Pipes com *Impersonation*
* Embora tenhamos criptografado o OTP em trânsito com DPAPI (`otp_dpapi`), a comunicação via arquivos em disco (`C:\Utilitario\queue\requests`) ainda permite que processos locais tentem causar negação de serviço (enchendo a pasta de requisições falsas).
* **Como evoluir:** Substitua a fila de arquivos por um **Named Pipe do Windows (`\\.\pipe\AdminBridgeService`)**:
  * O cliente envia o comando e o OTP diretamente pela memória do kernel para o serviço `SYSTEM`.
  * O servidor chama as APIs nativas `GetNamedPipeClientProcessId()` e `ImpersonateNamedPipeClient()` da `advapi32.dll`, obtendo a identidade real do usuário e o PID diretamente do kernel do Windows com 0% de chance de falsificação (*spoofing*) e sem nunca tocar o disco.

### 3.4. Assinatura Digital Authenticode + AppLocker / WDAC
* Para impedir que outro Administrador substitua `C:\Utilitario\AdminBridge.exe` no próprio Windows:
  1. Assine o executável `AdminBridge.exe` gerado pelo PyInstaller com um certificado **Authenticode** próprio (`signtool.exe sign /fd SHA256 ...`).
  2. Configure uma política do **Windows Defender Application Control (WDAC)** ou **AppLocker** exigindo que a tarefa `AdminBridge` execute apenas binários assinados pelo seu certificado e bloqueando a execução de binários não assinados em `C:\Utilitario`.
  3. Para uso diário (inclusive onde o agente de IA roda), opere sempre em uma **Conta de Usuário Padrão (*Standard User*)** do Windows, mantendo a conta de Administrador separada por senha.
