@echo off
:: NixaVPN SOCKS5 only — без системного VPN, только прокси
:: Не требует прав администратора

echo ============================================
echo   NixaVPN — SOCKS5 Proxy (ShadowLink + CDN)
echo ============================================
echo.

"%~dp0nixavpn-client.exe" connect ^
    -import "sl://4f262835877e4c82be2129ddfadc1bb1799d39315850e2fbbc0d9d3806a9a26c@dev-metrics-hub.net:443?tls=1&cdn=dev-metrics-hub.net" ^
    -socks "127.0.0.1:1080" ^
    -check-ip ^
    -verbose

pause
