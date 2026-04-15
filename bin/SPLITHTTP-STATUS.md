# SplitHTTP System VPN через CF CDN — Статус

## Дата: 2026-04-09 (сессия 5)

## SSE Download Delivery — DONE

Download stream теперь использует настоящий SSE формат:
- Сервер: `data: <base64(encrypted_frame)>\n\n` (pre-alloc буфер, без аллокаций на hot path)
- Клиент: `bufio.Scanner` + base64 decode + 45s timeout
- CF стримит SSE без буферизации

## Stability Fixes — DONE

- CloseStream: sync send с 3s timeout (было fire-and-forget → crash при ~120 горутинах)
- closeTunnel: закрывает OutgoingUDP (было утечка горутин при закрытии tunnel)

## Следующий шаг: деплой и тестирование через CF CDN

1. scp shadowlink-server-linux на 213.155.12.69
2. systemctl restart shadowlink
3. Запустить клиент, проверить что download stream работает
4. Замерить скорость (target: 50-100 Mbps)

## Конфигурация (без изменений)

- nginx: `proxy_buffering off; gzip off;` в location
- CF: orange cloud, SSL Full (strict), WebSockets ON
- ShadowLink: `--udp-listen :56001`, `--behind-proxy`
