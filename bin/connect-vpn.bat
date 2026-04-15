@echo off
:: NixaVPN System VPN — весь трафик через ShadowLink
:: ВАЖНО: запускать от АДМИНИСТРАТОРА (ПКМ -> Запуск от имени администратора)

net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] Требуются права администратора для создания TUN-интерфейса.
    echo     ПКМ на этот файл -^> "Запуск от имени администратора"
    pause
    exit /b 1
)

echo ============================================
echo   NixaVPN — System VPN (ShadowLink Direct)
echo ============================================
echo.

"%~dp0nixavpn-client.exe" connect ^
    -import "sl://f60ab13060efc8cefca431f0f847add47e5c913627a37c62835fd90c3779af51@datacanvases.com:443?tls=1&cdn=datacanvases.com&origin=104.222.177.67" ^
    -system-vpn ^
    -check-ip ^
    -verbose

pause
