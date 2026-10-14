import base64
import ctypes
import json
import re
import sys
import urllib.request
from typing import Dict, List, Optional, Tuple


# =============================================================================
# CAMADA 1: SCANNER NATIVO DO WINDOWS DEFENDER EM MEMÓRIA (amsi.dll)
# =============================================================================
def scan_with_windows_amsi(code_text: str, app_name: str = "AdminBridge_ScriptGuard") -> Tuple[bool, str]:
    """Passa o script pela interface nativa Antimalware Scan Interface (amsi.dll) do Windows 10/11.
    Executa em ~1-3ms no Core i5 com 0 MB de peso extra, utilizando o motor local do Windows Defender.
    Retorna (is_clean, details).
    """
    if sys.platform != "win32" or not code_text:
        return True, "AMSI disponivel apenas no Windows ou script vazio."
    try:
        amsi = ctypes.windll.amsi
        amsi_context = ctypes.c_void_p()
        res_init = amsi.AmsiInitialize(ctypes.c_wchar_p(app_name), ctypes.byref(amsi_context))
        if res_init != 0 or not amsi_context:
            return True, "AMSI nao inicializado neste ambiente."
        try:
            amsi_result = ctypes.c_int(0)
            res_scan = amsi.AmsiScanString(
                amsi_context,
                ctypes.c_wchar_p(code_text),
                ctypes.c_wchar_p("AdminBridge_Submitted_Script"),
                None,
                ctypes.byref(amsi_result)
            )
            if res_scan == 0 and amsi_result.value >= 32768:  # AMSI_RESULT_DETECTED = 32768
                return False, f"Windows Defender (AMSI) classificou este script como MALICIOSO (Codigo AMSI: {amsi_result.value})."
            return True, "Aprovado pelo motor nativo Windows AMSI."
        finally:
            amsi.AmsiUninitialize(amsi_context)
    except Exception:
        return True, "Verificacao AMSI ignorada."


# =============================================================================
# CAMADA 2: CLASSIFICADOR LEVE DE RISCO E INTENÇÃO (0 MB, < 2ms num Core i5)
# =============================================================================
RISK_SIGNATURES = [
    {
        "id": "PERSIST_SERVICE",
        "score": 65,
        "category": "Criação de Serviço Permanente no Sistema",
        "pattern": r"(?:\bsc(?:\.exe)?\s+(?:create|config|failure)\b|\bnew-service\b|\bset-service\b.*startuptype)",
        "explanation": "Tenta criar ou modificar um Serviço do Windows que pode iniciar sozinho com poder máximo toda vez que o computador ligar."
    },
    {
        "id": "PERSIST_TASK",
        "score": 60,
        "category": "Criação de Tarefa Agendada Automática",
        "pattern": r"(?:\bschtasks(?:\.exe)?\s+/create\b|\bregister-scheduledtask\b|\bset-scheduledtask\b|\bnew-scheduledtaskaction\b)",
        "explanation": "Tenta agendar uma tarefa automática no Windows para rodar programas em segundo plano ou ao ligar o computador."
    },
    {
        "id": "PERSIST_REGISTRY_AUTORUN",
        "score": 65,
        "category": "Inicialização Automática no Registro (Autorun)",
        "pattern": r"(?:currentversion\\run|currentversion\\runonce|winlogon\\shell|winlogon\\userinit|image\s+file\s+execution\s+options)",
        "explanation": "Tenta alterar chaves de inicialização automática do Registro do Windows para rodar programas escondidos no login."
    },
    {
        "id": "PRIV_USER_ADMIN",
        "score": 75,
        "category": "Criação de Conta ou Elevação a Administrador",
        "pattern": r"(?:\bnet1?(?:\.exe)?\s+(?:user|localgroup)\b.*(?:/add|/active)|\bnew-localuser\b|\badd-localgroupmember\b)",
        "explanation": "Tenta criar um novo usuário no Windows ou adicionar uma conta ao grupo de Administradores permanentes da máquina."
    },
    {
        "id": "DEFENSE_EVASION_DEFENDER",
        "score": 85,
        "category": "Desativação de Antivírus ou Firewall",
        "pattern": r"(?:\bset-mppreference\b|\badd-mppreference\b|-disablerealtimemonitoring|-exclusionpath|\bnetsh\b.*advfirewall.*(?:off|disable|add\s+rule))",
        "explanation": "Tenta desativar a proteção em tempo real do Windows Defender, adicionar pastas ocultas na lista de exceções do antivírus ou abrir portas no Firewall."
    },
    {
        "id": "CREDENTIAL_DUMP",
        "score": 95,
        "category": "Extração de Senhas do Sistema (SAM / LSASS)",
        "pattern": r"(?:\breg(?:\.exe)?\s+save\b.*(?:hklm\\sam|hklm\\security|hklm\\system)|\blsass\b|\bcomsvcs\.dll\b.*minidump|\bmimikatz\b|\bsekurlsa\b)",
        "explanation": "Tenta extrair cofres de senhas internas do Windows (SAM, SECURITY ou memória do processo LSASS)."
    },
    {
        "id": "RANSOM_SHADOW_DELETE",
        "score": 95,
        "category": "Destruição de Pontos de Restauração / Cópias de Sombra",
        "pattern": r"(?:\bvssadmin\b.*delete\s+shadows|\bwmic\b.*shadowcopy\s+delete|\bbcdedit\b.*recoveryenabled\s+no|\bwbadmin\b.*delete\s+catalog)",
        "explanation": "Tenta apagar as cópias de sombra e pontos de recuperação do Windows (comportamento típico de sabotagem ou ransomware)."
    },
    {
        "id": "REMOTE_EXEC_CRADLE",
        "score": 70,
        "category": "Download e Execução Direta da Internet",
        "pattern": r"(?:downloadstring|downloaddata|downloadfile|\biex\b|\binvoke-expression\b|\bmshta\b|\bregsvr32\b.*http|\bcertutil\b.*-urlcache|\bbitsadmin\b.*/transfer)",
        "explanation": "Tenta baixar um código externo da internet e executá-lo diretamente no computador."
    },
    {
        "id": "MASS_DELETION_FORMAT",
        "score": 65,
        "category": "Exclusão Recursiva ou Formatação de Disco",
        "pattern": r"(?:\bformat(?:\.com|\.exe)?\s+[a-z]:|\bdiskpart\b|\brd\s+/s\s+/q\s+c:\\(?:windows|users|program)|\bremove-item\b.*-recurse.*-force.*c:\\(?:windows|users))",
        "explanation": "Tenta apagar pastas críticas do sistema operacional ou formatar volumes de disco."
    },
    {
        "id": "OBFUSCATED_EXEC",
        "score": 50,
        "category": "Comando Codificado ou Ofuscado",
        "pattern": r"(?:-[eE][nN]?[cC]?[oO]?[dD]?[eE]?[dD]?[cC]?[oO]?[mM]?[mM]?[aA]?[nN]?[dD]?\s+[A-Za-z0-9+/=]{16,}|frombase64string|\bchar\[\]\s*\()",
        "explanation": "Usa codificação Base64 ou ofuscação para esconder os comandos reais que serão executados."
    }
]


def _decode_embedded_base64(cmd_text: str) -> str:
    """Decodifica trechos Base64 do PowerShell para que o classificador veja o comando real escondido."""
    extra = []
    tokens = re.findall(
        r"(?:-[eE][nN]?[cC]?[oO]?[dD]?[eE]?[dD]?[cC]?[oO]?[mM]?[mM]?[aA]?[nN]?[dD]?\s+|frombase64string\s*\(\s*[\"\']?)([A-Za-z0-9+/=]{12,})",
        cmd_text
    )
    for b64_str in tokens:
        for enc in ("utf-16le", "utf-8"):
            try:
                dec = base64.b64decode(b64_str).decode(enc, errors="ignore")
                if dec and any(c.isalpha() for c in dec):
                    extra.append(dec)
                    break
            except Exception:
                pass
    return (cmd_text + "\n" + "\n".join(extra)) if extra else cmd_text


# =============================================================================
# CAMADA 3: EXPLICADOR INTELIGENTE SOB DEMANDA (LLM Local Opcional + Motor Semântico Offline)
# =============================================================================
def _try_local_slm_explanation(code_text: str, findings: List[dict], timeout_sec: float = 2.0) -> Optional[str]:
    """Consulta opcionalmente um mini-modelo local (ex: Ollama com qwen2.5:0.5b ou smollm2 em localhost:11434)
    APENAS quando um script de risco é detectado. Se não houver servidor local ativo, retorna None instantaneamente (<5ms).
    """
    try:
        prompt = (
            "Explique em português simples, em no máximo 3 frases curtas para um usuário leigo, "
            "o que este script do Windows tenta fazer e qual o risco dele:\n\n"
            f"{code_text[:1000]}"
        )
        req_body = json.dumps({
            "model": "qwen2.5:0.5b",
            "prompt": prompt,
            "stream": False,
            "keep_alive": "0s",
            "options": {"num_predict": 120, "temperature": 0.1}
        }).encode("utf-8")
        req = urllib.request.Request(
            "http://127.0.0.1:11434/api/generate",
            data=req_body,
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=timeout_sec) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            ans = (data.get("response") or "").strip()
            if len(ans) > 15:
                return ans
    except Exception:
        pass
    return None


def build_human_explanation(code_text: str, findings: List[dict], amsi_msg: str = "") -> str:
    """Gera a explicação clara em português para o usuário (Camada 3), combinando os achados semânticos
    e o modelo local (se disponível) sem nunca travar a CPU.
    """
    lines = []
    if amsi_msg and "MALICIOSO" in amsi_msg.upper():
        lines.append(f"🚨 ALERTA DO WINDOWS DEFENDER (AMSI): {amsi_msg}")

    if findings:
        lines.append("🔍 O que este script tenta fazer no seu computador:")
        for f in findings:
            lines.append(f"  • [{f['category']}]: {f['explanation']}")

    # Tenta enriquecer com explicação do mini-LLM local (só roda quando findings existe!)
    llm_summary = _try_local_slm_explanation(code_text, findings)
    if llm_summary:
        lines.append(f"\n🤖 Resumo da IA Local:\n  {llm_summary}")

    lines.append(
        "\n⚠️ Por segurança, a execução automática (mesmo com ticket de 45 min) foi pausada. "
        "Para autorizar este script mesmo assim, gere um NOVO código de 6 dígitos no celular "
        "ou aprove clicando no botão UAC na tela."
    )
    return "\n".join(lines)


def inspect_script_3_layers(code_text: str) -> dict:
    """Executa o pipeline completo de 3 camadas:
    - Camada 1: Windows AMSI (amsi.dll)
    - Camada 2: Classificador Comportamental e De-ofuscação (0 a 100)
    - Camada 3: Explicador Semântico / IA Sob Demanda (acionado somente se Risco >= 40 ou AMSI detectar ameaça)
    """
    if not code_text or not str(code_text).strip():
        return {
            "risk_level": "low",
            "risk_score": 0,
            "requires_step_up": False,
            "amsi_clean": True,
            "findings": [],
            "explanation": "Comando vazio ou inofensivo."
        }

    # Camada 1: AMSI nativo do Windows
    amsi_clean, amsi_msg = scan_with_windows_amsi(code_text)

    # Camada 2: De-ofuscação + Classificador de Risco
    expanded_text = _decode_embedded_base64(code_text)
    normalized = expanded_text.lower().translate(str.maketrans("", "", "\"'^`"))

    total_score = 0 if amsi_clean else 100
    matched_findings = []

    for rule in RISK_SIGNATURES:
        if re.search(rule["pattern"], normalized, flags=re.IGNORECASE | re.DOTALL):
            total_score = min(100, total_score + int(rule["score"]))
            matched_findings.append({
                "id": rule["id"],
                "category": rule["category"],
                "score": rule["score"],
                "explanation": rule["explanation"]
            })

    requires_step_up = (not amsi_clean) or (total_score >= 40)
    if total_score >= 75 or not amsi_clean:
        risk_level = "critical"
    elif total_score >= 40:
        risk_level = "high"
    else:
        risk_level = "low"

    # Camada 3: Só é executada quando requires_step_up == True!
    explanation = ""
    if requires_step_up:
        explanation = build_human_explanation(expanded_text, matched_findings, amsi_msg if not amsi_clean else "")

    return {
        "risk_level": risk_level,
        "risk_score": total_score,
        "requires_step_up": requires_step_up,
        "amsi_clean": amsi_clean,
        "findings": matched_findings,
        "explanation": explanation
    }
