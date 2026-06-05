# Обход РФ-цензуры через мимикрию под видеозвонки VK Calls / Яндекс.Телемост — состояние на июнь 2026

> Разведка (НЕ реализация). Дата: 2026-06-05. Контекст: РФ-операторы вводят allowlist (белые списки) на мобильных; видеозвонки VK/Телемост — в whitelist. В нашем проекте это уже делали (WhitePass = Pion TURN+DTLS через VK Calls, WB TURN через Wildberries) и **вырезали в апреле 2026** из-за peer-IP фильтра (403 Forbidden), DTLS JA3/JA4 ban. Юзер сообщает: первый разработчик усовершенствовал код, энтузиасты говорят «мало-мальски пашет» снова.

---

## КРАТКИЙ ВЕРДИКТ

- **Работает ли VK-обход в июне 2026: ЧАСТИЧНО / ХРУПКО.** VK-плечо живо и используется в нескольких активных проектах (1.4k★ репо обновляются в мае 2026). Скорость 10–25 Мбит/с (один поток у VK капается ~5 Мбит/с). Но: **Яндекс.Телемост ЗАКРЫТ** (`UPD. ТЕЛЕМОСТ ЗАКРЫЛИ`), стабильность на мобиле плохая (Wi-Fi ок, LTE — таймауты), Мегафон/Tele2 фильтруют жёстче. Это PoC-уровень, не продакшн.
- **Что доработали против peer-IP фильтра:** сменили саму архитектуру relay — вместо «внешний TURN, который надо явно адресовать» теперь **используют SFU/TURN-инфраструктуру самой платформы как relay**. Клиент в РФ соединяется ТОЛЬКО с whitelisted IP медиа-сервера VK; на тот же SFU/TURN подключается «creator» за рубежом, и **платформа сама пересылает байты между ними**. Цензор не видит peer-IP заграничного сервера — клиент его никогда не адресует. TURN-креды генерятся из ссылки на звонок (легитимная сессия). Плюс DTLS-обфускация + ChaCha20/XChaCha20 поверх, чтобы убить Pion-fingerprint.
- **Произвольный трафик или только их relay:** прячут **ПРОИЗВОЛЬНЫЙ** трафик (SOCKS5 / WireGuard / VLESS до СВОЕГО origin/VPS за рубежом), но **физически проходит через relay платформы** (SFU VK / TURN VK). То есть «свой origin» достижим, НО только потому что VK media-сервер выступает форвардером. Это и есть эфемерность: жив пока VK не зарежет (rate-limit, ToS-бан аккаунта, DTLS-fingerprint, peer-фильтр на SFU).

### Топ-3 источника
1. https://github.com/kulikov0/whitelist-bypass — главный активный проект (SFU-подход, v0.3.5 / 30 мая 2026, 1.4k★)
2. https://github.com/cacggghp/vk-turn-proxy — TURN+DTLS+WireGuard/VLESS (v1.8.3 / апрель 2026); прямо пишет «Телемост закрыли», 5 Мбит/с лимит VK
3. https://github.com/amurcanov/proxy-turn-vk-android — WDTT, Android WireGuard-over-VK-TURN/DTLS (v1.1.8), детальная архитектура peer-IP обхода

---

## 1. Актуальные проекты / репозитории (2025–2026)

Сложилась целая экосистема. Два архитектурных лагеря: **SFU-DataChannel/Video** и **TURN-relay+DTLS**.

| Проект | Подход | Платформы | Статус | Заметки |
|---|---|---|---|---|
| **kulikov0/whitelist-bypass** | SFU: Pion открывает SCTP DataChannel ИЛИ публикует VP8-видеотрек на SFU платформы | VK Call, Yandex Telemost, WB Stream (LiveKit) | v0.3.5, 30.05.2026, 1.4k★, 92 коммита | headless Go (Pion) на обоих концах, ChaCha20, VP8 pacing. Главный/эталонный. |
| **kulikov0/whitelist-bypass-iran** | то же, для иранского Bale | Bale SFU | активен | добавлен 4-байт seq + 16-frame reorder buffer (Bale SFU переупорядочивает фреймы) |
| **cacggghp/vk-turn-proxy** | TURN+STUN ChannelData: WireGuard/Hysteria шифруются DTLS 1.2 → параллельные TCP/UDP потоки на VK TURN | VK (Телемост закрыт) | v1.8.3, апрель 2026, ~70 open issues | VLESS-режим через KCP+smux; -no-dtls = риск бана; 5 Мбит/с на поток |
| **kiper292/vk-turn-proxy** | форк cacggghp, другая реализация Multi-Stream DTLS Tunnel для WireGuard | VK | форк | альтернативный мультистрим |
| **amurcanov/proxy-turn-vk-android (WDTT)** | Android-приложение: WireGuard GoBackend → UDP 127.0.0.1:9000 → WRAP RTP AEAD → VK TURN/DTLS → wdtt-server на VPS | VK | v1.1.8 | автокапча (Go v2 solver/WebView), fallback по 2 client_id (6287487/8202606), до 4 call-hash / 108 потоков, DTLS keepalive |
| **zarazaex69/olcRTC (olcrtc)** | encrypted TCP-over-WebRTC: SOCKS5 → cnc → WebRTC/SFU → srv → инет. XChaCha20-Poly1305 + smux | Jitsi, Yandex Telemost, WbStream | Beta, 843 коммита, 1.4k★, 18 contrib | транспорты: datachannel / vp8channel / seichannel / videochannel. Linux/mac/Win/Android/Docker/Go-lib |
| **samosvalishe/free-turn-proxy** | client/server ядра, speed-shaping bypass | VK TURN | частые апдейты | упоминается как «качественные ядра с частыми обновлениями» |
| **Moroka8/vk-turn-proxy** | ещё один форк/ядро | VK | — | упоминается рядом с free-turn-proxy |
| **nil2x/cheburnet** | НЕ медиа: проксирование через ВК сообщения/посты/комменты (текст) | VK API | — | минимальный трафик, не для видео — отдельная ветка идей |

Сообщество/обсуждения: ntc.party (треды «VK Tunnel» /19952, «Turnable: VPN/прокси через TURN» /24402, «Белые списки / че делать» /23468, «Обход белого списка через ВК сообщения» /23445), 4pda /1110469 «Суверенный интернет, белые списки», Hacker News Show HN #48199039, Habr 985674/990206/1021160, Xeovo Hub /144, kort0881/russia-whitelist Discussion #21.

> Примечание: проект под именем «Turnable» фигурирует в названии ntc-треда (/24402), но отдельного репозитория с таким именем найти не удалось — вероятно это обсуждение TURN-подхода в целом (vk-turn-proxy/WDTT/free-turn-proxy).

---

## 2. Что КОНКРЕТНО доработали против denied-peer-ip фильтра

Это ключевое изменение со времён нашего WhitePass. Раньше peer-IP фильтр (wb.ru → 403 Forbidden, VK в процессе) убивал схему, потому что relay был «снаружи» и его IP попадал под фильтр разрешённых peer'ов. Что изменилось:

### (а) Смена relay: SFU/TURN платформы вместо внешнего TURN (главное)
- **kulikov0/whitelist-bypass**: трафик идёт через **SFU самой платформы** (Selective Forwarding Unit), который в whitelist. «Traffic goes through the platform's SFU, which is on the government whitelist. To DPI it looks like a normal video call.» Клиент в РФ публикует/принимает DataChannel или VP8-трек НА SFU; зарубежный creator подключён к ТОМУ ЖЕ звонку/SFU. **Клиент никогда не адресует IP зарубежного сервера — единственный peer-IP у клиента это IP медиа-сервера VK** (whitelisted). Peer-IP фильтр нечего блокировать.
- **WDTT (amurcanov)** формулирует прямо: «routing ensures all client traffic routes exclusively through VK TURN relay servers, **never directly contacting the VPS IP address** — effectively defeating geolocation-based filtering that blocks foreign server connections.»

### (б) Легитимные TURN-креды из ссылки на звонок
- vk-turn-proxy: «Login/password генерируются из ссылки на звонок» — сессия выглядит как настоящий участник конференции, STUN/TURN-протокол соблюдён, relay-allocation легитимна. WDTT извлекает temporary TURN credentials из VK call signaling.

### (в) Параллельные потоки (распыление сигнатуры)
- vk-turn-proxy: DTLS 1.2 → «параллельными потоками через TCP или UDP на TURN сервер» — снижает per-connection детект-сигнатуру и обходит per-thread 5 Мбит/с лимит VK мультиплексированием.

### (г) DTLS-обфускация + AEAD поверх (против Pion-fingerprint)
- WRAP RTP AEAD (ChaCha20-Poly1305, ключ из пароля через HKDF, не хардкод) маскирует пакеты под WebRTC audio с OPUS payload type (WDTT).
- kulikov0: ChaCha20-обфускация + configurable VP8 pacing (тайминг-резистентность).
- olcRTC: XChaCha20-Poly1305 + smux.
- Все предупреждают: `-no-dtls` (без обфускации) = риск бана от VK/Яндекс — т.к. голый Pion DTLS ClientHello детектится TSPU.

**Итог:** peer-IP фильтр не «обошли» в лоб — его **сделали неприменимым**, переместив relay внутрь whitelisted-инфраструктуры платформы. Цензор не может зарезать peer-IP, не сломав сам VK Calls для всех.

---

## 3. Текущий статус (июнь 2026): реально ли пашет

- **VK-плечо: живо, но хрупко.** Throughput 10–25 Мбит/с (Xeovo Hub), один поток VK капается ~5 Мбит/с (vk-turn-proxy `-n 1`), мультистрим обходит лимит. Это всё ещё PoC, терминальные приложения; авторы kulikov/Xeovo прямо говорят: «если станет популярным/коммерциализируется — зарежут/зашейпят очень быстро», commercialization отвергнута намеренно.
- **Яндекс.Телемост: ЗАКРЫТ.** vk-turn-proxy README: `UPD. ТЕЛЕМОСТ ЗАКРЫЛИ`. (olcRTC/kulikov ещё перечисляют Telemost как target, но рабочесть под вопросом — вероятно устарело либо иной путь.)
- **Операторы:** Wi-Fi обычно ок; на LTE — постоянные таймауты/обрывы (блок по протоколу, не по IP). **Мегафон и Tele2 фильтруют жёстче** (Tele2 проверяет, в whitelist ли сервер; «продвинутые блокеры»). Есть прогноз, что отвалится «начиная с Мегафона».
- **Аккаунты/регистрация:**
  - VK: нужны cookies (экспорт JSON) — т.е. **залогиненный аккаунт VK** (привязан к номеру телефона — болевая точка, на ntc отмечают что VK жёстко завязан на номер).
  - Telemost: нужны cookies (но закрыт).
  - WB Stream (LiveKit): **anonymous guest tokens, аккаунт НЕ нужен** — самый низкий порог входа.
  - WDTT: автокапча, fallback по двум VK client_id.
- **Стабильность:** DTLS keepalive для долгих сессий (WDTT), но в целом сообщество описывает как «мало-мальски / push-start с рефрешами». Сам app VK Calls в RuStore (апрель 2026) получает плохие отзывы (заикание звука 3с/1с, фризы) — намёк что и легитимный сервис нестабилен.

---

## 4. Как именно allowlist пропускает видеозвонки

- **По IP/CIDR медиа-серверов (SFU/TURN) платформы.** Whitelist в РФ — это «реестр социально значимых сервисов» (с сентября 2025, ~57 доменов: RIA, банки, Госуслуги, VK, OK, Mail.ru, Max, Yandex, Ozon/WB/Avito). VK/Yandex media-инфраструктура попадает под whitelisted CIDR. net4people/bbs #490: цензор применяет whitelist по CIDR назначения; вне whitelist соединение замораживается после ~25 пакетов в каждую сторону (~16 КБ payload).
- **Не только IP:** на мобиле фильтрация ещё и **по протоколу/поведению** — «blocking on operator's side by protocol, not by IP» (поэтому Wi-Fi работает, LTE нет). Tele2 проверяет, отдаёт ли сервер whitelisted-контент.
- **SNI** упоминается отдельно (Reality-маскировка под vkvideo.ru/max.ru), но это другой класс обхода (не медиа-туннель); палёные SNI режутся.
- Whitelisted именно потому, что **WebRTC-звонок структурно = двунаправленный шифрованный медиапоток между peer'ами через доверенный оператором SFU**. Цензор «доверился» SFU → туннель этим пользуется.

---

## 5. Произвольный трафик или только их relay (ключевой вопрос)

**Прячут ПРОИЗВОЛЬНЫЙ трафик до своего origin — НО физически через relay платформы.**

- Схемы:
  - kulikov0: joiner (РФ) поднимает SOCKS5 / VpnService+tun2socks → DataChannel/VP8 на SFU → creator (за рубежом) на том же SFU → открытый инет. Туннелируется любой TCP/UDP.
  - WDTT: WireGuard до **вашего личного VPS** через VK TURN/DTLS. Произвольный трафик (весь WG-туннель).
  - vk-turn-proxy: WireGuard/Hysteria, плюс VLESS-режим (TCP через KCP+smux) до вашего сервера.
  - olcRTC: SOCKS5 → cnc → SFU → srv (ваш) → инет, произвольный TCP.
- **Origin — ВАШ** (VPS за рубежом), это не «их relay как endpoint». НО **transit обязательно идёт через SFU/TURN VK** — клиент в РФ не может достичь вашего origin напрямую (его IP не в whitelist). VK media-сервер = форвардер между клиентом и вашим creator/VPS.
- **Следствие — эфемерность:** работает ровно пока VK позволяет relay-allocation чужого трафика. Это не свойство «мы спрятались под звонок к whitelisted IP и дальше сами», а «мы паразитируем на форвардинге VK». Векторы убийства: rate-limit, ToS-бан аккаунта (`-no-dtls` → бан), peer-IP фильтр на стороне SFU (если VK начнёт проверять, что allocated-peer не настоящий участник), DTLS-fingerprint. Именно это и было причиной вырезания WhitePass — сейчас отодвинуто, но не устранено.

> Вывод по нашему гипотетическому подходу (спрятать наш ShadowLink-origin под видом звонка к whitelisted media-IP БЕЗ использования VK как форвардера): **нежизнеспособно** на текущем threat model. Чтобы клиент в РФ дошёл до НАШЕГО media-IP, этот IP должен быть в whitelist — а whitelist это конкретные CIDR VK/Yandex/банков, наш IP туда не попадёт. Единственный рабочий путь — паразитировать на ИХ SFU/TURN (как все эти проекты), что эфемерно и банится.

---

## 6. Уязвимости подхода / чем цензор это убивает

1. **DTLS / Pion ClientHello fingerprint (главное, исторически).** TSPU с декабря 2021 фингерпринтит Pion DTLS (та же либа в Tor Snowflake): сравнение байтов `00 1D 00 17 00 18` на offset 0x6e и 0x59 (Elliptic Curves в ClientHello). ValdikSS PR в pion/dtls #474 — шафл порядка кривых. FOCI 2025 (Midtlien): цензоры предпочитают дешёвый детерминированный fingerprint, не ML. Standalone non-browser Pion оставляет residual distinguishers (версия DTLS, порядок cipher suites, CN сертификата «WebRTC», 30-дн validity, выбор STUN-серверов, ICE-последовательность). → Контрмера проектов: DTLS-обфускация + AEAD; `-no-dtls` = бан.
2. **Peer-IP / STUN-IP фильтр на стороне SFU.** Если VK начнёт валидировать, что relay-allocated peer — настоящий участник звонка (а не форвардер чужого трафика), схема рушится. Это ровно то, что WB сделал (denied-peer-ip 403). Сейчас отодвинуто use-of-own-SFU, но SFU может ввести то же.
3. **Поведенческий анализ медиапотока.** Реальный звонок ≠ bulk download. Признаки: bitrate-профиль не как у OPUS/VP8, отсутствие реальной аудио/видео-энтропии, FPS за пределами 120–240 (триггерит congestion control SFU → столлы), пакеты не как Binding/Allocate. Контрмера: VP8 pacing, RTP AEAD под OPUS PT — но это «parrot is dead», точная конформность WebRTC крайне трудна для не-браузера.
4. **Rate-limit / шейпинг.** VK 5 Мбит/с на поток; операторы шейпят по объёму («днём плохо, ночью ок — смотрят на объём»). 25-пакетная заморозка для non-whitelist.
5. **ToS / аккаунт-бан.** VK явно банит за aбьюз (особенно `-no-dtls`), завязка на номер телефона = дорогой ресурс, капчи множатся.
6. **Закрытие плеча целиком.** Telemost уже закрыли. XHTTP/websocket через VK/Edge CDN — вырезаны + ToS-запрет. Авторы единодушны: все решения temporary, «cat-and-mouse».

---

## Источники (URL)

- https://github.com/kulikov0/whitelist-bypass — SFU DataChannel/Video, эталон (v0.3.5)
- https://github.com/kulikov0/whitelist-bypass/blob/main/README.md
- https://github.com/kulikov0/whitelist-bypass-iran — Bale, seq+reorder buffer
- https://github.com/cacggghp/vk-turn-proxy — TURN+DTLS+WG/VLESS, «Телемост закрыли»
- https://github.com/cacggghp/vk-turn-proxy/blob/main/README.md
- https://github.com/kiper292/vk-turn-proxy — форк Multi-Stream DTLS
- https://github.com/amurcanov/proxy-turn-vk-android — WDTT Android WG-over-VK-TURN
- https://github.com/zarazaex69/olcRTC — Yandex/Jitsi/WbStream SFU, XChaCha20+smux
- https://ntc.party/t/vk-tunnel/19952
- https://ntc.party/t/turnable-vpn%D0%BF%D1%80%D0%BE%D0%BA%D1%81%D0%B8-%D1%87%D0%B5%D1%80%D0%B5%D0%B7-turn-%D0%BE%D0%B1%D1%85%D0%BE%D0%B4-%D0%B1%D1%81/24402
- https://ntc.party/t/cidr-вайтлист-на-билайне-кто-нибудь-смог-обойти/19408
- https://github.com/net4people/bbs/issues/490 — whitelist по CIDR, 25-пакетная заморозка
- https://news.ycombinator.com/item?id=48199039 — Show HN: VPN over WebRTC, threat model
- https://hub.xeovo.com/posts/144-russia-whitelist-bypass-idea — 10–25 Мбит/с, PoC
- https://4pda.to/forum/index.php?showtopic=1110469 — WireGuard/Hysteria через VK TURN DTLS 1.2
- https://habr.com/ru/articles/985674/ , /990206/ , /1021160/ — гайды по chain/whitelist
- https://github.com/kort0881/russia-whitelist/discussions/21 — peer-IP/exit-IP проблемы на мобиле
- https://github.com/pion/dtls/pull/474 — ValdikSS shuffle Elliptic Curves vs РФ DPI
- https://petsymposium.org/foci/2025/foci-2025-0006.pdf — Fingerprint-resistant DTLS (Snowflake/Pion)
- https://arxiv.org/pdf/1605.08805 — Fingerprintability of WebRTC (STUN/peer/packet-type сигналы)
- https://cs.uwaterloo.ca/~dbarrada/papers/figueira_asiaccs22.pdf — Stegozoa (video covert channel vs gateway MITM)
- https://www.usenix.org/system/files/usenixsecurity24-bocovich.pdf — Snowflake (WebRTC proxies)
- https://github.com/samosvalishe/free-turn-proxy , https://github.com/nil2x/cheburnet (упоминания)
