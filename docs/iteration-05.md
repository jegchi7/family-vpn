# Итерация 05 — администратор: пароль + TOTP

Дата поставки: 2026-09-30. `family-vpn-starter-v0.5.0.zip`, продолжение v0.4.0. Локальная разработка и тесты, без публикации Git и изменения VPS.

## Реализовано

- Отдельный HTTPS admin listener `127.0.0.1:9443`, отдельная admin auth SQLite DB/application_id/schema v1. Admin process открывает пользовательскую portal DB read-only. Public process не открывает admin DB/master key; control DB и agent socket не подключены.
- Admin password → bounded одноразовый TOTP challenge → сессия только после второго фактора. Challenge 3 минуты, привязан к preauth cookie и account revision, максимум 5 проверок. Новый password login заменяет прежний challenge аккаунта.
- TOTP через pquerna/otp v1.5.0: SHA1/6 цифр/30 секунд, ±1 step. Успешный step сохраняется в DB и повторно не принимается. Concurrent finish, challenge consumption, counter/session/audit выполняются под одной writer transaction.
- TOTP secret шифруется AES-256-GCM стандартной Go AEAD с random nonce и AAD account/purpose/key ID. Master key вне admin state root. Проверки permissions/owner/symlink, runtime startup fail-closed при отсутствующем или неподходящем ключе. Password-only fallback отсутствует.
- Trusted CLI: `admin-key-create`, `admin-init`, `admin-enroll`, `admin-confirm`, `admin-reset`, `admin-disable`. Enrollment действует 10 минут, без подтверждённого authenticator вход закрыт. Reset сохраняет admin ID и отзывает прежние password/TOTP/sessions/challenges; disable не требует master key. Пароль/код принимаются через stdin, интерактивный Python getpass wrapper скрывает ввод.
- Отдельная admin cookie Secure/HttpOnly/SameSite=Strict. Сессии 12h absolute / 30m idle, проверка Origin/Host/CSRF/JSON, persistent rate limiting и два KDF slots/process. Preauth/CSRF/challenge в браузерной памяти, без localStorage/URL. User auth cookie и DB не принимают admin sessions.
- Форма password/TOTP и read-only admin overview, mobile layout. Пароль/код очищаются после отправки. Screenshots без заполненных секретных полей.
- Реализованный OpenAPI и generated TS, ADR-0006, CLI/runbook, README, next iteration и CI job обновлены. Обsolete draft admin login paths удалены, фактические paths находятся в `openapi.json`.

Portal schema остаётся v3, control v2: существующие пользовательские данные не требуют новой миграции. Новая admin DB создаётся trusted CLI. Файлы нормативных spec/backlog сохранены без изменений.

## Проверки

| Проверка | Результат |
|---|---|
| `npm run check` | PASS: Go vet/race tests, generated API drift, Svelte/TS 0 errors / 0 warnings, Vite build |
| `npm run build` | PASS: frontend и 6 Go executables |
| `npm run test:persistence` | PASS: сохранение, revision conflict, ownership, readiness, разделение demo listeners |
| Demo E2E | 4/4 PASS, desktop/mobile |
| User auth E2E | 4/4 PASS: invite/login/logout/recovery, desktop/mobile |
| Admin E2E | 2/2 PASS: CLI enrollment/confirm → password без session → TOTP → dashboard/reload/logout → disable pending challenge, desktop/mobile 320 px |
| MFA lifecycle | PASS: pending account, enrollment expiry/replay, wrong binding, replaced/expired/exhausted challenge, повтор TOTP между challenges |
| Concurrency/rollback | PASS: finish через два DB handles — один успех; failed login audit не потребляет proof; failed reset audit сохраняет credentials/session |
| Reset/disable | PASS: identity сохранён, session/challenge отозваны, stale password snapshot не создаёт новый challenge |
| Session lifetime | PASS: idle expiry и отсутствие resurrection; регулярный touch не продлевает absolute 12h |
| Key boundary | PASS: разные random ciphertext, AAD substitution/tamper rejection, missing/wrong key, exclusive create, symlink/permissions rejection |
| DB/router boundary | PASS: admin DB не открывается как portal; admin token не работает через user cookie/public router; user recovery отсутствует на admin listener |
| Python helper | Syntax PASS; интерактивная работа с реальным TTY вручную не проверена. CLI stdin flow проверен E2E |

Браузерный тест обнаружил и помог исправить ошибку Svelte interpolation в HTML pattern TOTP: форма не отправляла корректные 6 цифр. После исправления полный admin flow прошёл. Неверные запросы и проверка policy не заменялись ослаблением TLS/CSRF/MFA.

Среда проверок: Linux x86_64, Go 1.27.1, Node 24.19.0, npm 11.9.0, Playwright 1.63.0, Chromium 153.0.8010.0. Использован внешний launch config для доступного local Chromium, как ранее; в поставке обычные Playwright configs. При повторном прогоне после паузы локальный Chromium оказался усечён и завершался до запуска теста; восстановление из исходного bundled Brotli вернуло успешный admin E2E без изменения приложения. Self-signed TLS допускается только тестовыми browser configs. Удалённый CI не запускался. Frontend JS gzip около 22.66 kB, CSS 2.22 kB — размер bundle, не измерение RSS/KDF на VPS.

## Статус бэклога

| Задача | Фактическое продвижение |
|---|---|
| DEV-02 | Добавлена отдельная admin DB и boundary tests; разные service UID ещё не проверены |
| DEV-03 | Реализован local admin password/challenge/TOTP contract; production/mutations/agent ещё частично |
| DEV-04 | Сохранён user flow, расширены router/HTTP regressions; production origin/proxy gate открыт |
| DEV-05 | Частично: password, user recovery, admin TOTP и trusted console reset готовы локально. Recovery codes, passkey, fresh auth впереди |
| DEV-06/09…13 | Прежний read-only/prototype scope; real lifecycle устройств/профилей не готов |
| DEV-07/08, DEV-14…26 | Не закрыты; отдельные audit events не закрывают весь DEV-22 |
| GW-01…08 | Backlog, ADR/metadata без runtime pairing/pull/apply |
| PRE/NET/ROL | Реальные серверы не изменялись |

Новых полностью закрытых исходных задач не заявлено: эта итерация завершает локальный password+TOTP slice DEV-05, а не весь AUTH. G0/G1 и последующие gates остаются открыты.

## Ограничения и следующий этап

Действующий admin UI только читает: опасных HTTP mutations нет, fresh-auth proof ещё не реализован. Recovery codes/WebAuthn, ротация master key, безопасный backup/restore с учётом replay после DB rollback, password blocklist/rehash, retention/rate-limit capacity analysis и KDF benchmarking требуют продолжения. Видимая вкладка отправляет session touch, поэтому idle не означает отсутствие человеческого ввода.

Windows admin MFA fail-closed до поддержки ACL; macOS не проверялся. Все локальные процессы используют один UID: production isolation не доказана. Реальные VPN-клиенты, маршрутизация, сетевой fail-closed, серверный deployment, resource limits и доступность из РФ в этой итерации не проверялись. Следующий scope: `docs/next-iteration.md`.
