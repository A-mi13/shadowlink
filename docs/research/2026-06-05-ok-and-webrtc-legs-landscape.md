# WhiteCall разведка: Одноклассники как плечо + валидация «звонок = WebRTC всегда»

Дата: 2026-06-05. Метод: WebSearch + WebFetch (habr, github, ok.ru, ntc.party, dev-доки). Контекст проекта: туннелирование через SFU/TURN whitelisted-видеозвонков для обхода РФ allowlist (уже изучены VK Calls, WB Stream, Yandex Telemost, Jitsi).

---

## ВОПРОС 1 — ОДНОКЛАССНИКИ (OK.ru / VK-экосистема)

### 1.1 Есть ли звонки? Групповые конференции? Web + app?
ДА, полноценные. OK развивает платформу голосовых/видеозвонков с 2018 г. Факты:
- Групповые конференции **до 100 участников**.
- Демонстрация экрана, запись звонков, трансляция в прямой эфир, AR-маски, размытие фона.
- Длительность звонка **не ограничена**.
- Работает в **веб-версии (браузер)** + приложения iOS/Android. Беседы синхронизируются между устройствами.
- Поддерживаемые браузеры: Edge, Chrome, Safari, Opera.
- Масштаб: >10 млн MAU звонков, >2 млн звонков/сутки.

Источники: [vk.company групповые до 100](https://vk.company/ru/press/releases/10333/), [ok.ru/videocalls](https://ok.ru/videocalls), [RG.ru 100 собеседников](https://rg.ru/2018/08/14/v-odnoklassnikah-poiavilis-videozvonki-dlia-100-sobesednikov.html)

### 1.2 Стек — WebRTC? Свой SFU/TURN? Тот же бэкенд что VK?
- **WebRTC — ДА.** Изначально были на решении Adobe (2010-2012), затем «пару лет назад полностью переделали на WebRTC», совместимость с WebRTC сохранена → групповые звонки работают и в браузере. [habr 479852](https://habr.com/ru/company/odnoklassniki/blog/479852/)
- **Свой SFU/сервер конференций — ДА.** «Со всеми нашими претензиями к топологии ничего готового не нашли и решили делать сами». Топология гибридная: до 3-4 участников Mesh (P2P), свыше — серверная (транскодирование + сервер раздачи). HD через end-mixing/ретрансляцию, SD через централизованное транскодирование. У OK заявлен «собственный протокол серверной конференц-связи».
- **TURN/relay обязателен.** OK измеряли NAT-типы реальных юзеров: почти все за Symmetric NAT или Port-restricted cone → **только ~1/3 могут установить P2P**, остальные идут через relay. Это критично для нас: relay-кандидат (как у WB/VK) — основной режим, значит туннель через TURN-relay реалистичен. [habr 428217 «Миллион видеозвонков в сутки»](https://habr.com/ru/companies/odnoklassniki/articles/428217/)
- **Общий ли бэкенд с VK?** Прямого подтверждения «единый media-бэкенд VK+OK» не найдено (поиск явно не подтвердил консолидацию). НО есть сильная косвенная связь: мессенджер MAX (от VK) официально использует «пакеты прикладных программ, ранее использовавшиеся в **ТамТам и Одноклассниках**» — то есть media-наследие OK/TamTam переиспользуется внутри VK-экосистемы. Вывод: OK media-стек родственен, но это **отдельная инсталляция SFU/TURN** со своими доменами, не буквально тот же кластер что VK Calls. (не подтверждено документально — помечено как гипотеза)

### 1.3 Доступ: аккаунт? гостевой? номер?
**Гостевой звонок по ссылке БЕЗ регистрации — ДА** (это ключевой плюс для нас):
- Аккаунт OK нужен **только инициатору** звонка.
- Остальные приглашаются по ссылке; гостю без аккаунта достаточно **указать имя** чтобы присоединиться.
- Доступно в десктоп-вебе + iOS/Android.
- Внутрисетевые «классические» звонки требуют дружбы+онлайн, но **звонок-по-ссылке этого не требует** — это отдельный режим конференции.

Источники: [vk.company пресс-релиз — без авторизации](https://vk.company/ru/press/releases/10626/), [vc.ru](https://vc.ru/social/129705-odnoklassniki-razreshili-uchastvovat-v-videozvonkah-polzovatelyam-ne-zaregistrirovannym-v-socseti), [insideok.ru](https://insideok.ru/blog/odnoklassniki-razreshili-podklyuchatsya-k-zvonku-po-priglasheniyu-bez-avtorizacii-v-socseti/)

### 1.4 В whitelist ли OK?
**ДА — с первой волны.** Белый список заработал начало сентября 2025; в первый этап (≈20 сервисов) вошли «ВКонтакте, **Одноклассники**, Mail.ru и мессенджер Max, Госуслуги, Яндекс». К апрелю 2026 список вырос до >500. OK = соцсеть с серверами в РФ = социально значимый ресурс. Media-домены OK — семейство **mycdn.me** (CDN/медиа OK) + ok.ru. (точная схема поддоменов TURN/relay на mycdn.me публично не задокументирована — нужен `chrome://webrtc-internals` на живом звонке).
Источники: [gogov.ru белый список](https://gogov.ru/articles/site-white-list), [Forbes Минцифры](https://www.forbes.ru/tekhnologii/559771-mincifry-rassirilo-belyj-spisok-dostupnyh-pri-otklucenii-interneta-sajtov), [tadviser](https://www.tadviser.ru/index.php/%D0%A1%D1%82%D0%B0%D1%82%D1%8C%D1%8F:%D0%91%D0%B5%D0%BB%D1%8B%D0%B9_%D1%81%D0%BF%D0%B8%D1%81%D0%BE%D0%BA_%D1%86%D0%B8%D1%84%D1%80%D0%BE%D0%B2%D1%8B%D1%85_%D0%BF%D0%BB%D0%B0%D1%82%D1%84%D0%BE%D1%80%D0%BC)

### 1.5 Есть ли проекты обхода через OK?
**НЕТ — OK ещё никто не делал.** Все существующие проекты используют только VK / Telemost / WB / Jitsi / Salute Jazz. Проверены:
- **olcrtc** (openlibrecommunity) — поддержка `jitsi / telemost / wbstream`. OK и VK НЕ в списке. Каналы: `datachannel / vp8channel / seichannel / videochannel`. Шифрование XChaCha20-Poly1305. [github olcrtc](https://github.com/openlibrecommunity/olcrtc/blob/master/readme.md)
- **whitelist-bypass** (kulikov0) — VK + Telemost SFU, на **Pion**, SCTP DataChannel + video-track (VP8) туннель. [github](https://github.com/kulikov0/whitelist-bypass)
- **vk-turn-proxy** (cacggghp) — TURN VK Calls + Telemost, заворачивает WireGuard/Hysteria. [github](https://github.com/cacggghp/vk-turn-proxy)
- **lionheart** (jaykaiperson) — WB Stream (LiveKit), Pion + KCP + yamux. **АРХИВИРОВАН** автором: WB-инженеры заметят «пустые комнаты» и закроют за день. [github lionheart](https://github.com/jaykaiperson/lionheart), [habr 1017410](https://habr.com/ru/articles/1017410/)

Статья «6 способов обхода» перечисляет плечи: Telemost, Salute Jazz (salutejazz.ru), WB Stream — **OK не упомянут**. [habr 1027276](https://habr.com/ru/articles/1027276/)

**ВЕРДИКТ ПРИГОДНОСТИ OK: высокий потенциал, незанятая ниша.** Плюсы: в whitelist с волны 1, гостевой звонок по ссылке без регистрации, web/Chrome (headless-эмуляция), 100 участников, неограниченная длительность, свой TURN-relay (~2/3 трафика идёт через relay → удобно). Минусы/риски: свой проприетарный сервер-конференции (НЕ open-source LiveKit как WB → реверс signaling сложнее, чем WB; ближе по сложности к VK), media-домены mycdn.me публично не задокументированы (нужен ручной перехват через webrtc-internals/puppeteer-sniffer), та же системная уязвимость что у всех — оператор может заметить аномальные «пустые» комнаты. OK ещё никто не реверсил → это и преимущество (свежее плечо), и стоимость входа (всё с нуля).

---

## ВОПРОС 2 — «ЗВОНОК = WEBRTC ВСЕГДА?»

### 2.1 / 2.2 Все ли РФ-звонки на WebRTC? Исключения?
**ПОДТВЕРЖДЕНО: практически все — на WebRTC (ICE/DTLS/SRTP/SCTP), но почти никто не использует «ванильный» WebRTC — у всех форк/модификация.** Сводка:

| Сервис | WebRTC? | Нюанс |
|---|---|---|
| **VK Звонки** | Да | Свой SFU + транскодинг, не off-the-shelf; модифицированный WebRTC |
| **OK / Одноклассники** | Да | Свой SFU (гибрид Mesh+server), WebRTC-совместим (браузер работает) |
| **Yandex Telemost** | Да | WebRTC + SFU, DataChannel (SCTP over DTLS), трафик через серверы Яндекса |
| **WB Stream** | Да | **LiveKit** (open-source SFU), publisher-track всегда video |
| **Jitsi** | Да | Jitsi Videobridge SFU (open-source) |
| **Salute Jazz (Сбер)** | Да | WebRTC/SFU |
| **MAX (VK)** | Да, но... | **Модифицированный** WebRTC на libjingle (`libjingle_peerconnection_so.so`), кодек H.264 + собств. noLACE-аудио, **сигналинг — закрытый бинарный протокол** (10-байт заголовок + MessagePack), наследие ТамТам/OK. E2E нет. Сложнее для эмуляции. |
| **Telegram** | Да, но... | **tgcalls** = форк WebRTC (**tg_owt**); старый libtgvoip (проприетарный, OPUS) deprecated с 2022. Сигналинг свой (MTProto). DTLS-SRTP наследует от WebRTC. |

**ИСКЛЮЧЕНИЯ (важно):**
- **Чисто не-WebRTC сегодня нет** среди живых РФ-сервисов: даже Telegram перешёл с собственного libtgvoip на WebRTC-форк tg_owt. Zoom (проприетарный протокол) упомянут OK как контраст, но Zoom не РФ-плечо.
- **«WebRTC с оговоркой»**: MAX и Telegram = WebRTC-media-ядро (DTLS/SRTP/ICE стандартны), НО **сигналинг закрытый/нестандартный** (MAX — бинарный MessagePack; Telegram — MTProto). Для туннелирования media-транспорт у них стандартный, но обвязка (как получить креды/SFU-адрес) сильно проприетарна → дорого реверсить.

Источники: [habr VK 846634](https://habr.com/ru/companies/vk/articles/846634/), [habr OK 479852](https://habr.com/ru/company/odnoklassniki/blog/479852/), [Wikipedia MAX](https://ru.wikipedia.org/wiki/Max_(%D0%BC%D0%B5%D1%81%D1%81%D0%B5%D0%BD%D0%B4%D0%B6%D0%B5%D1%80)), [codeby реверс MAX](https://codeby.net/threads/max-sledit-za-vpn-revers-inzhiniring-protiv-ofitsial-nykh-poyasnenii-kto-vret.92425/), [github tgcalls](https://github.com/MarshalX/tgcalls), [github libtgvoip](https://github.com/grishka/libtgvoip)

### 2.3 Одно ли transport-ядро на все плечи?
**ДА — частично подтверждено, с оговоркой.** Media-transport-ядро может быть ОДНО (Pion: ICE + DTLS + SRTP + SCTP DataChannel + TURN-relay) на ВСЕ WebRTC-плечи. Это уже доказано на практике: olcrtc одним ядром закрывает jitsi+telemost+wbstream; whitelist-bypass одним Pion-конвейером — VK+Telemost. Различается только **signaling/обвязка** (per-service адаптер):
- как залогиниться / получить токен,
- WebSocket-эндпоинт сигналинга и его формат (LiveKit protobuf у WB; свой у Telemost/VK/OK),
- как получить ICE-серверы/TURN-креды из JoinResponse,
- какой канал данных разрешён (DataChannel vs video-track — Telemost режет DC → нужен VP8-track; WB всегда video).

**Оговорка:** «одно ядро» верно для сервисов со стандартным WebRTC-media + WebSocket-signaling (VK, OK, Telemost, WB, Jitsi, Salute). Для **MAX и Telegram** media-ядро тоже WebRTC-форк, но обвязка настолько проприетарна (бинарный/MTProto сигналинг), что адаптер становится крупным самостоятельным реверс-проектом, а не «тонкой обвязкой». Архитектурная гипотеза юзера ПОДТВЕРЖДЕНА для «нормального» WebRTC-сегмента (VK/OK/Telemost/WB/Jitsi/Salute), и ОПРОВЕРГНУТА как универсальная для MAX/Telegram (там обвязка ≫ ядро).

### 2.4 Какие SFU-движки?
- **WB Stream → LiveKit** (open-source, protobuf-over-WS, документирован → проще всех реверсить; почти прямой relay).
- **Jitsi → Jitsi Videobridge** (open-source).
- **VK Звонки → собственный SFU** + серверный транскодинг (off-the-shelf SFU «разваливается на ~50 участниках» — поэтому свой).
- **OK → собственный SFU** (гибрид Mesh+end-mixing+транскодинг, «свой протокол конференц-связи»).
- **Telemost → свой SFU** (WebRTC + DataChannel SCTP/DTLS).
- **Salute Jazz → свой/WebRTC SFU.**

Разные движки = разные нюансы туннелирования: open-source (LiveKit/Jitsi) → протокол публичный, легко; свои (VK/OK/Telemost) → нужен sniffer (puppeteer + monkey-patch RTCPeerConnection/WebSocket) для реверса signaling. Канальные ограничения: Telemost лимитирует DataChannel (→ VP8-track), WB требует video-track. Источник: [habr lionheart 1017410](https://habr.com/ru/articles/1017410/), [habr VK 846634](https://habr.com/ru/companies/vk/articles/846634/)

### 2.5 Web (браузер) vs приложение — что проще для headless?
**Web проще для headless-эмуляции (Pion прикидывается браузером).** Подтверждено практикой проектов: реверс делали через puppeteer-скрипт, открывавший настоящий Chrome на веб-версиях платформ, логировал HTTP + перехватывал WebRTC через monkey-patching `RTCPeerConnection`/`WebSocket`. Браузерный звонок = стандартный WebRTC-стек, который Pion воспроизводит. Приложения (особенно MAX) используют нативные модификации (libjingle.so, бинарный протокол) — реверсить тяжелее. **Для OK веб-версия работает в Chrome и поддерживает гостя-по-ссылке → идеальная мишень для headless Pion-клиента.**

---

## СВОДКА КАНДИДАТОВ-ПЛЕЧ (по убыванию пригодности)

| Плечо | В whitelist | Гостевой | SFU | Реверс | Статус |
|---|---|---|---|---|---|
| WB Stream | да | — | LiveKit (open) | лёгкий | сделано (lionheart, архив) |
| Telemost | да | да | свой | средний | сделано (olcrtc/vk-turn) |
| VK Calls | да | да | свой | средний | сделано (vk-turn-proxy) |
| Jitsi | да(?) | да | Videobridge (open) | лёгкий | сделано (olcrtc) |
| **OK / Одноклассники** | **да (волна 1)** | **да, по ссылке** | свой | средний-выше | **НИКЕМ не сделано** |
| Salute Jazz (Сбер) | да | да | свой | средний | НЕ сделано как туннель |
| MAX | да (волна 1) | — | модиф. WebRTC | тяжёлый (бинарь) | НЕ сделано |

---

## ИТОГОВЫЕ ВЫВОДЫ ДЛЯ ПРОЕКТА
1. **OK = жизнеспособное новое плечо**: в whitelist с сентября 2025, гостевой звонок по ссылке без регистрации, веб-Chrome (headless), 100 участников, неограниченная длительность, ~2/3 трафика через свой TURN-relay (mycdn.me). Не занято конкурентами. Стоимость входа = реверс собственного signaling OK (sniffer puppeteer), домены mycdn.me снять через webrtc-internals.
2. **«Звонок = WebRTC» — ПОДТВЕРЖДЕНО** для всего РФ-сегмента (даже Telegram перешёл на WebRTC-форк). Чистых не-WebRTC звонилок среди живых сервисов нет.
3. **Одно transport-ядро (Pion) на все плечи — ДА** для VK/OK/Telemost/WB/Jitsi/Salute (различие только в signaling-адаптере). НЕ для MAX/Telegram — там обвязка проприетарна (бинарный/MTProto сигналинг ≫ ядро).
4. **Топ-2 НОВЫХ кандидата кроме VK/WB**: (1) **Одноклассники (OK.ru)** — в whitelist, гость по ссылке, web, незанято; (2) **Salute Jazz / SberJazz (salutejazz.ru)** — упоминается в whitelist-туннелях как сервис, но как полноценное туннель-плечо ещё не реализовано; гостевой доступ, WebRTC SFU. (MAX отвергнут как топ-кандидат: в whitelist, но закрытый бинарный сигналинг = тяжёлый реверс.)
