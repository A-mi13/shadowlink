@echo off
title ShadowLink CDN Test (no TUN)
echo Testing ShadowLink CDN transport without system VPN...
echo.

cd /d %~dp0
nixavpn-client.exe connect --import "sl://4f262835877e4c82be2129ddfadc1bb1799d39315850e2fbbc0d9d3806a9a26c@dev-metrics-hub.net:443?tls=1&ws=1&cdn=dev-metrics-hub.net" --verbose --socks 127.0.0.1:1080

pause
