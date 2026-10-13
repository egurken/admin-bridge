---
name: elevated-executor
description: >-
  Executes Windows commands and scripts with elevated Administrator privileges
  via the local Human-in-the-Loop approval bridge (C:\Utilitario). Activate this
  skill whenever an action requires administrative permissions (e.g. system
  service management, modifying protected registry keys, installing system-wide
  software, or editing protected directories like System32 or Program Files).
---

# Elevated Executor (Human-in-the-Loop Admin Bridge)

This skill allows Antigravity to request the execution of administrative commands and scripts (`.bat`, `.cmd`, or `.ps1`) safely through the local desktop approval utility located at `C:\Utilitario`.

## Behavior & Auto-Start

The bridge utility runs silently in the background (via `pythonw` without any black terminal console window) with a modern dark GUI and custom icon.
- If the bridge is not running when a request is made, `client.py` will **automatically launch it in the background**.
- You do **not** need to ask the user to start it manually; just submit the command!

---

## Hybrid Execution Model & HOTP Authentication (RFC 4226)

The bridge operates in a **Hybrid Mode** with reinforced security:

1. **Automated Mode with OTP**:
   - When the user sends `OTP: 123456` in the chat, pass `--otp <digits>` to `client.py`.
   - The bridge validates the HOTP atomically.
   - On success, the counter advances and execution runs **100% automatically in background** (`CREATE_NO_WINDOW`), auto-closing within 1.5s.
   - On failure, execution is blocked immediately and the counter **advances as well** (preventing brute-force/replay attacks).

2. **Interactive Mode without OTP (UAC Fallback)**:
   - If no OTP is provided, the bridge falls back to interactive UAC approval.
   - The central UI opens with "Aprovar & Executar via UAC" and "Rejeitar".
   - The user must explicitly authorize the execution via the official Windows UAC dialog (`-Verb RunAs`).

---

## 10 Security Rules Enforced by the Bridge

1. **Single-Provisioning**: Key is generated only once during initial setup.
2. **DPAPI / TPM Protection**: Secret key and recovery password hash are encrypted using Windows DPAPI (backed by LSASS and TPM).
3. **Locked State (Flag = 1)**: While `provisioned_flag == 1`, generating a new key is strictly forbidden.
4. **Strict Reset Requirements**: Resetting the key requires BOTH:
   - Correct Recovery Password (verified via PBKDF2 with 600.000 iterations).
   - Confirmed physical presence on the machine (interactive challenge-response on the physical screen).
5. **Flag Lifecycle**: Reset unlocks flag to 0 -> generates new key -> relocks flag to 1.
6. **Strict Counter Advancement**: The counter advances on **EVERY** validation attempt (both SUCCESS and FAIL).
7. **Atomic Operations**: Thread-safe and process-safe validation using Windows Named Mutex and file locks.
8. **Position Query Without Advance**: `python C:\Utilitario\gerar_otp.py --status` checks counter without computing or advancing OTP.
9. **Origin Verification**: Requests are validated against caller PID and approved script paths.
10. **Full Audit Logging**: All operations logged in `C:\Utilitario\logs\auth.log` with timestamp, caller, before/after counter, and masked OTP.

---

## How to Execute Commands

### 1. With User OTP (100% Automated):
```powershell
python C:\Utilitario\client.py run --title "Titulo da Tarefa" --description "Descricao" --type bat --code "ipconfig /flushdns" --otp "123456"
```

### 2. Without OTP (Prompts Windows UAC):
```powershell
python C:\Utilitario\client.py run --title "Titulo da Tarefa" --description "Descricao" --type bat --code "ipconfig /flushdns"
```

### 3. Consult Counter Position Without Advancing:
```powershell
python C:\Utilitario\gerar_otp.py --status
```
