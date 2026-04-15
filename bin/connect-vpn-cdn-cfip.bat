@echo off
:: NixaVPN System VPN — CF CDN через лучший CF edge IP (cfip)
:: Сканирует CF IP, выбирает лучший, подключается через него.
:: ВАЖНО: запускать от АДМИНИСТРАТОРА

net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] Требуются права администратора.
    echo     ПКМ на этот файл -^> "Запуск от имени администратора"
    pause
    exit /b 1
)

set DOMAIN=datacanvases.com
set PUBKEY=f60ab13060efc8cefca431f0f847add47e5c913627a37c62835fd90c3779af51

echo ============================================
echo   NixaVPN — System VPN (CDN + CF IP Scan)
echo ============================================
echo.
echo [1/2] Сканируем лучший CF edge IP...
echo.

:: Сканируем 15 IP, 10 сек каждый, 5 воркеров
set BEST_IP=
for /f "tokens=*" %%a in ('"%~dp0cf-scanner.exe" -domain %DOMAIN% -n 15 -duration 10s -workers 5 2^>^&1 ^| findstr /C:"Best IP:"') do (
    for /f "tokens=3" %%b in ("%%a") do set BEST_IP=%%b
)

if not defined BEST_IP (
    echo [!] CF IP сканер не нашёл рабочий IP.
    echo     Пробуем без cfip...
    echo.
    set SL_URL=sl://%PUBKEY%@%DOMAIN%:443?tls=1^&cdn=%DOMAIN%
) else (
    echo.
    echo [OK] Лучший CF IP: %BEST_IP%
    echo.
    set SL_URL=sl://%PUBKEY%@%DOMAIN%:443?tls=1^&cdn=%DOMAIN%^&cfip=%BEST_IP%
)

echo [2/2] Подключаемся...
echo      URL: %SL_URL%
echo.

"%~dp0nixavpn-client.exe" connect ^
    -import "%SL_URL%" ^
    -system-vpn ^
    -check-ip ^
    -verbose

pause
