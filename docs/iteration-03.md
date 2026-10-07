# Итерация 03 — пользовательские приглашения и сессии

Дата: 2026-09-29. Поставка `family-vpn-starter-v0.3.0.zip`. Продолжение v0.2.0, локальный исходный проект. Репозиторий не опубликован, к VPS не подключались, сетевые настройки не менялись.

## Что теперь работает

- Отдельный HTTPS режим `npm run auth`, numeric loopback :8443, self-signed сертификат для теста. Отдельная auth DB; demo нельзя незаметно превратить в auth.
- Создание обычного пользователя и одноразового приглашения через trusted CLI. Нет публичной регистрации. Приглашение имеет 256 бит random entropy, TTL 24 часа и хранится только как hash.
- Атомарная активация: consume invite, activate user, Argon2id credential, новая session и audit. Повтор/гонка/просроченный token отклоняются; ошибка записи откатывает весь переход.
- Парольный вход обычного пользователя: Argon2id из `golang.org/x/crypto v0.57.0`, случайный salt, фиксированные bounded параметры. Ограничение параллельных KDF и persistent rate limits по login/invite и socket IP.
- Серверные opaque sessions: hash в SQLite; Secure/HttpOnly/SameSite cookie, 30 дней absolute / 7 дней idle по умолчанию, конфигурируемые в пределах ADR. Logout отзывает session; повтор старого cookie не работает.
- Exact Host/Origin, anonymous bootstrap CSRF, session CSRF, no CORS, JSON limit/strict decoding, generic auth/storage errors. Proxy headers не доверяются. GET не меняет last_seen; отдельный POST touch поддерживает activity.
- API выбирает владельца из session; UI входа/активации/выхода, восстановление session после reload. Секреты не пишутся в localStorage. Новый кабинет честно пуст: устройств и конфигов ещё нет.
- Portal schema v2: unique password per user, session/token indexes, persistent bounded counters. Миграция v1→v2 сохраняет существующие demo edits; HTTP startup сам не мигрирует.
- Обновлены implemented OpenAPI, generated TS, ADR, runbook, CI, screenshots и следующий этап. Исходные требования и оригинальные 63 задачи не переписаны; GW-дополнение 8 задач сохранено.

## Статус backlog

| Задача | Результат этой итерации |
|---|---|
| DEV-01 | Каркас/локальная сборка работает; CI расширен auth E2E, remote run ещё не выполнялся |
| DEV-02 | Portal migration v2 и upgrade-проверка добавлены; production isolation разных UID всё ещё не пройдена |
| DEV-03 | Implemented contract расширен пользовательским auth slice; полные WebAuthn/admin/mutation/agent schemas впереди |
| DEV-04 | Пользовательские invite/session/expiry/logout/Origin/CSRF/rate-limit реализованы и проверены локально. Deployment origin/proxy и независимая QA-01 впереди |
| DEV-05 | Частично: password Argon2id и запрет password-only admin. Passkey, admin MFA, recovery/fresh auth не реализованы |
| DEV-06 | Session ownership read routes проверены; CRUD/lifecycle устройств впереди |
| DEV-07/08, DEV-14…26 | Не реализованы |
| DEV-09/10/11/12/13 | Demo/prototype; реальные профили, клиентские инструкции и live measurements отсутствуют |
| GW-01…08 | Backlog: только ранее подготовленные ADR/metadata schema; межсерверного обмена ещё нет |
| PRE/NET/ROL | Не выполнялись на реальных серверах |

G0/G1 и последующие gates не закрыты. Это рабочий локальный auth slice, не production-ready система и не завершение всех AUTH требований. Admin demo остаётся demo; в auth mode административных routes вообще нет.

## Проверено

| Проверка | Результат |
|---|---|
| `npm run check` | PASS: go vet, go test -race, API generation drift, Svelte 0 errors/0 warnings, Vite |
| `npm run build` | PASS: все 6 Go executables и frontend |
| `npm run test:persistence` | PASS: CLI changes, repeat seed, SQLite API, revision conflict |
| Existing demo E2E | 4/4 PASS, desktop + mobile |
| Auth E2E | 2/2 PASS: desktop + 320 px, invite → cabinet → reload → logout → replay rejection → password login; cookie flags, no localStorage и admin 404 |
| Invite concurrency/rollback | PASS: одна активация на двух DB connections; session insert failure откатывает token/credential |
| Sessions | PASS: close/reopen, logout/replayed cookie, idle и absolute expiry, GET без записи, запрет touch resurrection |
| Ownership | PASS: два реальных SQL пользователя/устройства; API берёт session owner, чужой query user_id игнорируется; чужие device/profile 404 |
| Roles/states | PASS: admin и disabled user не входят через user password endpoint; прежняя session после изменения роли/state отвергается |
| Rate limit | PASS: account/IP limits, сохранение после reopen, expiry окна |
| HTTP boundary | PASS: cookie flags, Origin/CSRF, trailing JSON, HTTP despite forwarded HTTPS, Host и generic DB failure |
| Migration | PASS: upgrade portal v1→v2 сохраняет edited demo; runtime old schema rejected, missing DB не создаётся |
| Binary mode guard | PASS: запуск без режима, public bind, mixed modes, missing TLS, demo DB as auth, admin local-auth отклоняются |
| Визуальный просмотр | Auth login 320 px и desktop cabinet просмотрены; screenshots login/invitation/cabinet без заполненных secrets |

Среда: Linux x86_64, Go 1.27.1, Node 24.19.0, npm 11.9.0, Playwright 1.63.0, Chromium 153.0.8010.0. Browser runtime и launch-config внешние локальные, как в предыдущих итерациях. Self-signed cert verification bypass только для локальных tests/capture; обычное приложение использует TLS. Remote CI, Windows/macOS, настоящий iPhone/Android VPN, production certificate/origin, разные UID, KDF performance на VPS и сетевой fail-closed не проверялись.

Frontend build: JS gzip около 21.00 kB, CSS 2.19 kB, HTML 0.30 kB; это размер bundle, не нагрузочный тест NFR. Скриншоты в `docs/screenshots/` не загружаются самим приложением.

## Ограничения для следующего разработчика

Не расширять bind и не подключать реальные конфиги до следующих gates. Password blocklist/rehash, session retention/cleanup, admin bootstrap/MFA, recovery и WebAuthn ещё нужны. Fixed-window rate limits могут мешать общему NAT, настройки требуют стенда. Есть process-local KDF semaphore, но нет распределённой координации workers. Свежая auth для опасных действий не реализована — самих опасных endpoints также нет. Скриншоты старых demo экранов обновлены; отчёты iteration-01/02 — исторические.

Следующий шаг: `docs/next-iteration.md`. Запуск: `docs/auth-runbook.md`.
