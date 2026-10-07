# Итерация 02 — SQLite и проектирование обмена шлюзов

Дата: 2026-09-29. Поставка: `family-vpn-starter-v0.2.0.zip`. Локальный исходный проект, не production release. Исходные требования и 63 задачи сохранены; отдельное GW-дополнение добавляет ещё 8 задач.

## Реализовано

- Две SQLite БД: portal и control; runtime driver modernc.org/sqlite v1.60.0 (pure Go), закреплённые go.mod/go.sum.
- Embedded migrations: portal v1 и control v2. Application identity, последовательность версий и SHA-256 history проверяются до применения; несовместимая/чужая БД отклоняется. Все pending migrations применяются в одной транзакции с rollback при ошибке. WAL, foreign keys и busy timeout включены.
- Таблицы с ownership, unique/check/FK constraints, generation/revision, desired/applied metadata и append-only revocation tombstones. Это хранение состояния, не фактический отзыв VPN-доступа; владелец DB может изменить схему/триггеры.
- Repository interface и SQLite adapter подключены к API. HTTP процессы открывают только portal DB read-only; control path им не передаётся. Ошибки чтения возвращаются как generic 503, без SQL. `/readyz` проверяет доступность DB; `/healthz` — живость процесса.
- `vpnctl demo-init`, `db-status`, `demo-rename`. Инициализация повторяема, не перезаписывает имя и timestamps. Изменение имени проверяет владельца и expected revision, сохраняет audit в той же транзакции. Это локальный CLI, публичных mutation endpoints ещё нет.
- Приватные файлы и каталоги на POSIX; отказ от symlink aliases и уже существующих permissive файлов. Проверки Windows ACL не реализованы.
- Обновлены OpenAPI реализованного subset, generated TypeScript, README, runbook, следующий шаг и CI. Добавлен smoke test собранных CLI/HTTP процессов.

## Проектные материалы, без работающих обработчиков

- `api/planned-auth.openapi.json`: password invitation/login/recovery, admin password challenge + TOTP и logout. Это часть DEV-03; WebAuthn и полный production контракт ещё нужны.
- ADR-0003: автоматический обмен RU↔Foreign через доверенные identities, mTLS, bootstrap с внешней проверкой, versioned descriptor, capabilities, prepare/test/commit/ACK и ротацию. Собственная криптография не предлагается.
- `api/gateway/envelope-v1.schema.json`: черновик metadata envelope. Подпись, передача secrets, семантические проверки replay/expiry и runtime parser ещё не реализованы. Foreign private key не должен передаваться RU.
- Control migration v2 хранит metadata peers/sync. Никаких подключений между серверами, pairing, live status или запуска протоколов она не делает.
- `docs/gateway-backlog.md`: GW-01…08, зависимости и критерии приёмки; все задачи ещё Backlog.

## Статус backlog

| Задача | Фактический статус |
|---|---|
| DEV-01 | Локальный каркас работает; remote CI run ожидает загрузки в Git |
| DEV-02 | Код локальных хранилищ и миграций реализован и проверен. Полная приёмка не закрыта: публичный UID должен быть проверенно лишён доступа к control DB на стенде |
| DEV-03 | Частично: реализованный demo API плюс проектные auth/gateway schemas. Полный контракт остаётся в работе |
| DEV-04/05/07/08, DEV-14…26 | Не реализованы |
| DEV-06/09/10/11/12/13 | Demo/prototype, не production приёмка |
| GW-01…08 | Backlog; есть ADR и черновая metadata schema |
| PRE/NET/ROL | На реальных серверах не выполнялись |

G0/G1 и последующие gates не пройдены. Fixed identity не является авторизацией; read-only DB connection не заменяет изоляцию по системным UID. Семейные VPN-конфиги, секреты и реальные сетевые измерения в эту поставку не входят.

## Проверки

- `npm run check`: Go vet и race tests, актуальность generated API types, Svelte/TypeScript (0 ошибок/предупреждений), Vite build — PASS.
- `npm run build`: все шесть Go executables и frontend — PASS.
- `npm run test:persistence`: независимые CLI процессы → повторная инициализация → чтение сохранённого имени через HTTP; stale revision и чужое устройство отклоняются — PASS.
- Store tests: повторный seed, reopen/read-only, stale health, future version, checksum/history/kind mismatch, rollback failed migration, concurrent expected revision, constraints, tombstones, permissions/symlinks, unmarked store и unowned version rejection — PASS.
- HTTP SQLite integration: своё/чужое устройство, отсутствие admin routes на public router, ready и generic storage failure — PASS.
- Draft auth: openapi-typescript generation — PASS. Это проверка обработки схемы генератором, не полная security validation.
- Gateway metadata draft: JSON Schema 2020-12 metaschema и compilation — PASS (проверка структуры, без runtime/date-format/semantic validation).
- Browser E2E: 4/4 PASS, desktop 1365×900 и mobile 320×800; SQLite runtime, скачивание памятки, инструкции, simulated status, отдельный admin listener.

Среда: Linux x86_64, Go 1.27.1, Node 24.19.0, npm 11.9.0, Playwright 1.63.0, Chromium 153.0.8010.0. Использована внешняя локальная launch-конфигурация браузера из первой итерации. Первый прогон был заблокирован повреждённым runtime binary (SIGSEGV до открытия страницы); после восстановления бинарника из исходного пакета повтор прошёл. Браузерные runtime-файлы не поставляются в архиве; для обычного компьютера и CI предусмотрен стандартный Playwright install.

Обновлённые demo скриншоты находятся в `screenshots/`. Исторический отчёт iteration-01.md относится к v0.1.0. Windows/macOS, реальные мобильные VPN-клиенты, отдельные UID, remote CI, backup/restore и сетевой fail-closed не проверялись.
