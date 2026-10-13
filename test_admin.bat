@echo off
echo ======================================================
echo        CONSULTA ADMINISTRATIVA DO SISTEMA
echo ======================================================
echo Horario: %time%
echo Usuario atual: %username%
echo Verificando status do servico Spooler...
sc query Spooler | findstr /i "STATE"
echo Verificando integridade de permissao administrativa...
net session >nul 2>&1
if %errorlevel% == 0 (
    echo [SUCESSO] Acesso elevado confirmado e validado!
) else (
    echo [FALHA] Sem privilegios de Administrador.
)
echo ======================================================
