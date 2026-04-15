@echo off
:: NixaVPN System VPN — автовыбор лучшего CF edge IP + подключение
:: ВАЖНО: запускать от АДМИНИСТРАТОРА

net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] Требуются права администратора.
    echo     ПКМ на этот файл -^> "Запуск от имени администратора"
    pause
    exit /b 1
)

set SL_URL=sl://f60ab13060efc8cefca431f0f847add47e5c913627a37c62835fd90c3779af51@datacanvases.com:443?tls=1^&cdn=datacanvases.com

echo ============================================
echo   NixaVPN — System VPN (CDN + Auto CF IP)
echo ============================================
echo.
echo [1/2] Сканируем CF edge IP (15 сек)...
echo.

:: Сканируем 10 IP, 15 сек каждый, 3 воркера. Ловим лучший IP из вывода.
set BEST_IP=
for /f "tokens=2 delims=:" %%i in ('"%~dp0cf-scanner.exe" -import "%SL_URL%" -n 10 -duration 15s -workers 3 2^>^&1 ^| findstr /C:"cfip="') do (
    set BEST_IP=%%i
)

:: Убираем пробелы если есть
if defined BEST_IP set BEST_IP=%BEST_IP: =%

if not defined BEST_IP (
    echo.
    echo [!] Не удалось найти CF IP. Подключаемся без cfip...
    echo.
    "%~dp0nixavpn-client.exe" connect ^
        -import "%SL_URL%" ^
        -system-vpn ^
        -check-ip ^
        -verbose
) else (
    echo.
    echo [2/2] Лучший CF IP: %BEST_IP%
    echo       Подключаемся через него...
    echo.
    "%~dp0nixavpn-client.exe" connect ^
        -import "%SL_URL%^&cfip=%BEST_IP%" ^
        -system-vpn ^
        -check-ip ^
        -verbose
)

pause
