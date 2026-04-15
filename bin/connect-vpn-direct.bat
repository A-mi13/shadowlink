@echo off
:: NixaVPN System VPN — ПРЯМОЕ подключение (без Cloudflare CDN)
:: Handshake и WS идут напрямую на origin IP 104.222.177.67.
:: TLS SNI = datacanvases.com (для nginx server_name matching и маскировки).
:: ВАЖНО: запускать от АДМИНИСТРАТОРА

net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] Требуются права администратора.
    echo     ПКМ -^> "Запуск от имени администратора"
    pause
    exit /b 1
)

echo ============================================
echo   NixaVPN — System VPN (ShadowLink DIRECT)
echo   Режим: прямое подключение к origin (без CF)
echo ============================================
echo.

"%~dp0nixavpn-client.exe" connect ^
    -import "sl://f60ab13060efc8cefca431f0f847add47e5c913627a37c62835fd90c3779af51@104.222.177.67:443?tls=1&sni=datacanvases.com" ^
    -system-vpn ^
    -check-ip ^
    -verbose

pause
