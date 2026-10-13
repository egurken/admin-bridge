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

## Execution Workflows

### Workflow A (Recommended): 2-Step Chat Pre-Authorization (Valid for 45 min)
Use this workflow whenever the user provides an OTP in chat before or during a task:
1. **Immediate Pre-Authorization** (first action upon receiving the OTP):
   ```powershell
   & "C:\Utilitario\AntigravityBridge.exe" preauth --otp "123456"
   # Or via client:
   python C:\Utilitario\client.py preauth --otp "123456"
   ```
   - This validates the OTP immediately and advances the HOTP counter.
   - Generates a secure single-use ticket in `C:\Utilitario\queue\preauth_ticket.json` valid for **45 minutes** (2700s).
   - Prevents counter desynchronization and OTP expiration while planning or formulating scripts.

2. **Subsequent Execution** (within the 45-minute window):
   ```powershell
   & "C:\Utilitario\AntigravityBridge.exe" run --title "Titulo da Tarefa" --description "Descricao" --type cmd --code "ipconfig /flushdns"
   # Or via client:
   python C:\Utilitario\client.py run --title "Titulo da Tarefa" --description "Descricao" --type cmd --code "ipconfig /flushdns"
   ```
   - The daemon automatically validates and atomically consumes the pre-authorization ticket.
   - Execution runs **100% in the background** (`CREATE_NO_WINDOW`) without user interaction on the computer screen.

---

### Workflow B: Legacy 1-Step Immediate Execution
If the command and script are already prepared when the OTP is received:
```powershell
& "C:\Utilitario\AntigravityBridge.exe" run --title "Titulo da Tarefa" --description "Descricao" --type cmd --code "ipconfig /flushdns" --otp "123456"
# Or via client:
python C:\Utilitario\client.py run --title "Titulo da Tarefa" --description "Descricao" --type cmd --code "ipconfig /flushdns" --otp "123456"
```

---

### Workflow C: Interactive UAC Fallback (Without OTP)
If no OTP or pre-auth ticket is present:
```powershell
& "C:\Utilitario\AntigravityBridge.exe" run --title "Titulo da Tarefa" --description "Descricao" --type cmd --code "ipconfig /flushdns"
```
The central UI opens a prompt on the desktop requesting physical confirmation via Windows UAC.

---

## 10 Security Rules Enforced by the Bridge

1. **Single-Provisioning**: Key is generated only once during initial setup.
2. **DPAPI Machine-Level Protection**: Secret key and recovery password hash are encrypted using Windows DPAPI with `CRYPTPROTECT_LOCAL_MACHINE` and custom application entropy, allowing system service operation while strictly bound to hardware TPM/LSASS.
3. **Locked State (Flag = 1)**: While `provisioned_flag == 1`, generating a new key is strictly forbidden.
4. **Strict Reset Requirements**: Resetting the key requires BOTH:
   - Correct Recovery Password (verified via PBKDF2 with 600.000 iterations).
   - Confirmed physical presence on the machine (interactive challenge-response on the physical screen).
5. **Flag Lifecycle**: Reset unlocks flag to 0 -> generates new key -> relocks flag to 1.
6. **Strict Counter Advancement**: The counter advances on **EVERY** validation attempt (both SUCCESS and FAIL).
7. **Atomic Operations**: Thread-safe and process-safe validation using Windows Named Mutex and file locks.
8. **Position Query Without Advance**: `& "C:\Utilitario\AntigravityBridge.exe" status` checks counter and service state without advancing OTP.
9. **Origin Verification & ACL Isolation**:
   - `C:\Utilitario\config\` is restricted strictly to `SYSTEM` and `Administrators`. Standard users cannot read configuration files directly.
   - `C:\Utilitario\queue\` and `logs\` allow execution submission from any machine user.
   - Pre-auth tickets are bound to the caller's Windows username and token SHA-256 hash.
10. **Full Audit Logging**: All operations logged in `C:\Utilitario\logs\auth.log` with timestamp, caller, before/after counter, and masked OTP.

---

## Utility Status & Diagnostics

### Consult Bridge Status & Counter:
```powershell
& "C:\Utilitario\AdminBridge.exe" status
# Or:
python C:\Utilitario\client.py status
```

### Test Authenticator Counter Sync (Passive Diagnostic - Does Not Advance Counter):
```powershell
& "C:\Utilitario\AdminBridge.exe" sync --otp "123456"
# Or:
python C:\Utilitario\client.py sync --otp "123456"
```

### Consult Audit History (Local Timezone):
```powershell
& "C:\Utilitario\AdminBridge.exe" history
# Or:
python C:\Utilitario\client.py history
```
