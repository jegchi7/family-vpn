# Матрица клиентских форматов · исследование PRE-04

Проверено по первичным источникам 05.10.2026. Это матрица **нашего importer**, а не заявление о прохождении тестов на iOS/Android/Windows.

| Формат | Импорт v0.14 | Что проверено | Что ещё открыто |
|---|---|---|---|
| `vless-reality-uri` | Да, ограниченный subset | Структура по Xray #716; клиентские REALITY поля по Project X; parser + byte-exact encrypted storage round-trip | Actual RU peer, сетевой handshake, реальные приложения и их версии |
| `awg-3.1-conf` | Да, ограниченный subset | Все перечисленные 3.1 поля, client-only parser, exact encrypted bytes/rotation, uniqueness по derived public key | Actual peer/адреса, нативный round-trip и реальные версии клиентов |
| Amnezia `vpn://` client/full-access wrappers | Нет | Не входят в разрешённый URI subset | Разделение форматов и проверка client-only schema |
| Xray/sing-box JSON, subscriptions, Base64/Age wrappers | Нет | Не входят в allowlist | Самостоятельный parser/schema review при необходимости |
| VLESS XHTTP/gRPC/FinalMask/ML-KEM/PQV | Нет | Наш текущий subset ограничен TCP/Vision | Проверка обязательных параметров и точного клиентского round-trip |

## Поддерживаемый subset

Одна ASCII URI `vless://UUID@host:port?...#label`, с optional единственным LF/CRLF в конце файла. UUID 128-bit, port 1…65535; hostname ASCII/punycode или bracketed IPv6. Требуются `type=tcp`, `security=reality`, `flow=xtls-rprx-vision`, `fp=chrome`, явный DNS `sni`, `pbk` и явный `sid` (может быть пустым). `pbk` проверяется как 32-byte raw Base64URL; `sid` — hex до 8 bytes, чётное число цифр. `encryption` может отсутствовать либо быть `none`. Разрешены optional `spx` path/query и legacy `headerType=none`.

Это собственная консервативная политика проекта. Источник допускает более широкий набор: дополнительные транспорты/поля, другие fingerprints/SNI варианты. Наш validator не принимает его автоматически. Unknown и duplicate query keys, password userinfo, JSON/server fields, insecure options, wrappers/multiple URIs, control characters и неправильные escapes отвергаются. Label ограничен 128 буквами/цифрами/пробелами и `._()-`; emoji/другие символы пока не входят в subset. Percent encoding имён query keys и `+` вместо encoded spaces не принимаются.

Original bytes хранятся без нормализации/переупорядочивания, включая конечный LF/CRLF. Byte-different повтор конфликтует даже при эквивалентной URI: importer не пересериализует секреты. Один UUID резервируется одному неотозванному profile во всей локальной БД; это политика нашего семейного MVP, не требование протокола. Endpoint не проверяется по сети и ещё не сверяется с RU inventory.

## Первичные источники

- [Xray-core discussion #716: share-link proposal](https://github.com/XTLS/Xray-core/discussions/716) — URI structure, регистр/duplicates/encoding, параметры. Это upstream proposal; parser scope закреплён в этом документе и tests.
- [Project X: REALITY](https://xtls.github.io/config/transports/reality.html) — различие client/server fields, password/public-key mapping и short ID requirements. `pbk` является чувствительным client authentication материалом и не включается в отчёты.
- [Amnezia Docs: AmneziaWG](https://docs.amnezia.org/documentation/amnezia-wg/) и [upstream amneziawg-go](https://github.com/amnezia-vpn/amneziawg-go) — HeaderProtectionKey, ContentPaddingAddition и другие новые поля. Нельзя применять serializer прежней версии без отдельного round-trip review.

Источники живые; перед расширением subset сверить изменения и pinned реализации клиентов. Исследование PRE-04 остаётся In progress. Совпадение имени протокола и синтаксическая валидация не являются проверкой приложения или доступности из РФ.

## AWG 3.1 client-only subset

Формат `awg-3.1-conf`, размер до 64 KiB. Один Interface, затем один Peer; порядок ключей внутри секции свободный. Имена секций/полей сравниваются без учёта регистра; duplicate keys, включая разные регистры, отклоняются. LF/CRLF и конечная строка без newline допустимы. `#` — комментарий; UTF-8 допускается в комментариях, control/bidi characters запрещены. Запись сохраняется целиком, без нормализации.

| Секция | Поля | Проверка |
|---|---|---|
| Interface | PrivateKey, HeaderProtectionKey | Обязательные nonzero 32-byte canonical padded Base64 |
| Interface | Address, DNS | Обязательные; 1–8 distinct IP/CIDR адресов или IP DNS без hostname/search domains, unspecified/multicast/mapped IPv6 |
| Interface | Jc/Jmin/Jmax, S1–S4, H1–H4 | Обязательные; uint16, Jmin≤Jmax; каждый S≥12 для Header Protection; H uint32 scalar/range, lo≤hi, диапазоны не пересекаются |
| Interface | MTU, ListenPort | Optional; MTU 576…65535, port 0…65535 |
| Interface | ContentPaddingAddition, RekeyAfterTime, RekeyTimeout, RejectAfterTime, KeepaliveTimeout, MaxHandshakeAttempts | Optional uint16 scalar/range, lo≤hi; ноль сохраняется |
| Interface | RandomTrailers, DisableCookies | Optional `on`/`off`; при RandomTrailers=on importer требует равные S1–S4 |
| Interface | I1–I5 | Optional CPS tags b/t/r/rc/rd: contiguous tags, hex bytes, один timestamp, random length1…1000, до128 tags/4096 generated bytes per packet |
| Peer | PublicKey, Endpoint, AllowedIPs | Обязательные; nonzero32-byte Base64, hostname/IP+port1…65535 без zone, IPv4 full tunnel `0.0.0.0/0`, optional `::/0`, no duplicates |
| Peer | PresharedKey, PersistentKeepalive, AdvancedSecurity | Optional32-byte nonzero Base64, uint16 scalar/range, `on` |

Консервативные ограничения (full tunnel, обязательные DNS/HPK/S/H/J, equal S с trailers, CPS пределы и `on/off`) — политика нашего importer. Это не универсальная спецификация допустимых upstream конфигураций. Неизвестные поля, несколько peers, server wrappers, PostUp/PreUp/PostDown/PreDown, SaveConfig/Table/FwMark отклоняются; никакие строки не выполняются. Дополнительные extensions требуют отдельного review, а не удаления параметров из экспорта.

`PrivateKey` — identity клиента: сравнивается derived X25519 public key. Это учитывает clamping, поэтому изменение игнорируемых битов не позволяет повторно выдать тот же ключ. Проверка уникальности остаётся внутри writer transaction, после расшифровки других client records; ключи/identity не появляются в отчёте.

[AmneziaWG upstream config.c](https://github.com/amnezia-vpn/amneziawg-tools/blob/master/src/config.c) подтверждает названия полей, Base64 key parser, uint16 ranges/timers и peer PersistentKeepalive range. [Официальные параметры](https://docs.amnezia.org/documentation/amnezia-wg/) описывают HeaderProtectionKey/S≥12, CPS и trailers. Источники сверены 05.10.2026; master — живой источник, не pinned native test. Реальные native importer/handshake/leak checks ещё не выполнены.

Обновление v0.19: консервативная VLESS credential uniqueness учитывает UUID wire aliases bytes6/7 по pinned Xray contract, сохраняя exact UUID/export bytes. Snapshot/users readback отвергают duplicate wire identity; alias не exact match. Partial users CLI описан в profile-xray-users-runbook.md; enumeration/core identity/revision/transport/client/ready не подтверждены. Это не general VLESS compatibility acceptance.
