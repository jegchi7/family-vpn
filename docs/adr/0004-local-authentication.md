# ADR-0004: первый пользовательский auth slice

Статус: реализован в v0.3.0 на локальном HTTPS стенде. Не разрешает production deployment. Дополняет ADR-0002: **demo** по-прежнему read-only, **local-auth** получает запись только в отдельную portal DB для credentials/sessions/tokens/audit/rate limits.

## Граница

`--demo` и `--local-auth` взаимоисключающие; оба требуют numeric loopback. Auth запускается только в portal, с TLS certificate/key, отдельным dataset `local-auth-v1`. Demo dataset не может стать auth автоматически. Без флага режима процесс завершается. Административные endpoints в auth router отсутствуют; password login разрешает только active user. Admin + password без MFA всегда отклоняется, включая существующую user session после изменения роли.

Авторизованный новый пользователь видит пустой собственный кабинет. Реальных профилей, создания устройств, admin UI, recovery и passkey в этом slice нет. Данные пользователя получаются из сессии, не из query/header/body. Control DB и сетевые агенты процессу не передаются. Изоляцию разными Unix UID ещё нужно проверить отдельно.

## Пароль и токены

Argon2id из `golang.org/x/crypto v0.57.0`: 19 MiB, 2 iterations, parallelism 1, salt 16 random bytes, output 32 bytes. Параметры зафиксированы в PHC representation и строго ограничены parser; содержимое БД не может увеличить стоимость до произвольного значения. Это стартовый выбор для стенда 2 ГБ, не измеренное выполнение NFR по ресурсам. Одновременно не более двух password KDF на процесс, остальные запросы получают 429. Для неизвестного/disabled/admin аккаунта выполняется dummy verification с теми же параметрами; статистическая timing-эквивалентность не заявляется.

Новый пароль: минимум 12 Unicode characters, максимум 1024 UTF-8 bytes; без неявного trim. Login нормализуется в lowercase ASCII, 3–64 символа `a-z0-9._-`. Blocklist скомпрометированных паролей и rehash policy ещё впереди.

Invite и session token — 32 криптографически случайных байта, base64url без padding. В SQLite только SHA-256; в audit нет plaintext токенов, паролей и password hashes. CLI выводит приглашение один раз для ручной передачи; его нельзя сохранять в общий лог. Новый login фиксируется CLI, публичной регистрации нет.

## Атомарность и сессии

`invite consume → user activate → credential → session → audit` в одной SQLite transaction. Ошибка, включая запись сессии, откатывает всё. Конкурентный повтор получает AUTH_FAILED. Login после KDF повторно проверяет user state/role и актуальный password hash внутри writer transaction, чтобы не обходить параллельный reset.

Сессия по умолчанию 30 дней absolute / 7 дней idle; параметры `--session-ttl` и `--session-idle`, positive idle ≤ ttl ≤ 30 дней. Каждый authenticated request проверяет user state/role, revoke, absolute и idle expiry. GET не продлевает idle и не меняет DB; отдельный CSRF-protected POST touch обновляет activity. UI вызывает его при загрузке и раз в 5 минут, пока вкладка видима. Absolute expiry не продлевается. Logout записывает revocation и очищает cookie; старое значение cookie после этого не работает.

Уже отозванная сессия запрещает следующие запросы; прекращение уже исполняющегося GET задним числом не обеспечивается. VPN-доступ и browser session — разные сущности: logout не отзывает VPN-ключи.

## HTTP и браузер

TLS ≥1.3 в локальном runner. `__Host-fvpn_session`: Secure, HttpOnly, SameSite=Lax, Path=/, без Domain. Token выдаётся только Set-Cookie, не JSON. CSRF derivation — стандартный HMAC-SHA256 с session token как ключом и фиксированным domain label; JS держит CSRF только в памяти. GET /me выдаёт его для восстановления формы после reload; same-origin policy, запрет CORS и no-store обязательны.

До входа GET /auth/bootstrap выдаёт случайный preauth token в HttpOnly Secure `__Host-fvpn_preauth` cookie и JSON, SameSite=Strict, browser Max-Age 10 минут. Это double-submit CSRF, не credential и не приглашение; сервер не считает его самостоятельным доказательством личности. POST login/accept требуют совпадения cookie/header, exact Origin, JSON. После успеха preauth cookie удаляется. Мутации с сессией требуют session-derived CSRF. Duplicate cookies отклоняются. Origin сравнивается с фактическим настроенным `https://<numeric-host:port>`, Forwarded/X-Forwarded-* не используются. Cross-site Sec-Fetch-Site отклоняется для mutations. Host проверяется точно.

Обычный JSON ограничен 64 KiB; неизвестные поля и trailing JSON отклоняются. Все ответы no-store, no-referrer и CSP. Invite вручную вставляется в форму, query с auth data запрещён; URL fragment не используется и удаляется UI без чтения значения. Этот flow не выполняет автоматическую доставку приглашений и не отправляет сообщений.

## Ограничение попыток

SQLite fixed windows: 5 попыток/5 минут на normalized login (или invite fingerprint), 30/5 минут на socket IP. X-Forwarded-For игнорируется. Учитываются и успешные попытки. Перезапуск не снимает лимит; после 5 минут окно освобождается. Хеши scopes, удаление истёкших записей, максимум 4096 активных scopes; переполнение fail-closed 429. Общий NAT может получить общий лимит. KDF semaphore не распределён между процессами; для нескольких portal workers потребуется отдельное решение. Retry-After=300 — консервативный срок, не точный остаток окна.

## Следующее

DEV-05: WebAuthn, admin MFA и bootstrap, одноразовое recovery, fresh auth, password policy/rehash. DEV-04: закрыть перенос на deployment origin и независимую QA-01; runtime code сам по себе production gate не закрывает. Нужны session retention/cleanup, настройка reverse proxy, trusted origin/RP ID, backup recovery, ограничения UID и измерение ресурсов.

Источники проверены 2026-09-29:
- https://pkg.go.dev/golang.org/x/crypto/argon2 — поддерживаемая Go реализация IDKey.
- https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html — базовые параметры Argon2id.

## Дополнение v0.4.0

ADR-0005 реализует user recovery и invite reissue. Историческое указание выше об отсутствии recovery относится к v0.3; admin/MFA/passkey recovery по-прежнему отсутствует. Portal schema v3 добавляет token revocation, не инвалидируя старые sessions/invites при миграции.
