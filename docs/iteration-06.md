# Итерация 06 · v0.6.0

Дата поставки: 4 октября 2026. Приоритеты согласованы владельцем 30 сентября 2026: устройства и конфиги раньше дополнительных механизмов авторизации. Существующие password login, invitations, recovery и admin TOTP сохранены; WebAuthn, recovery codes и fresh auth отложены.

## Выполнено

- Пользовательский кабинет: создание заявки с названием и ОС, переименование, подтверждаемая отмена ещё не выданной заявки, обновление списка и активная квота. Desktop и экран 320 px; кнопки действий высотой не менее 44 px.
- SQLite сохраняет pending-устройство и два pending-слота AWG/REALITY. Ключи, IP, peers и installed revision не создаются. Pending-профиль нельзя скачать как рабочий конфиг.
- Owner берётся из сессии; чужое и отсутствующее устройство одинаково отвечают 404. Запись доступна только на пользовательском local-auth listener. Demo остаётся read-only, admin не получает эти mutation routes.
- Повтор создания с тем же request ID и нормализованным содержимым возвращает текущее устройство. Изменённое содержимое даёт конфликт; повтор после отмены не восстанавливает заявку. Проверка идемпотентности предшествует проверке квоты.
- Квота учитывает pending и другие неотозванные устройства. Writer transaction не допускает занятия последнего слота двумя независимыми DB handles. До retention действует отдельный предел истории 200 записей на аккаунт.
- Переименование и отмена используют expected revision. Устаревший запрос не перезаписывает изменение из другой вкладки. Audit выполняется в той же транзакции; его ошибка откатывает действие.
- Отмена проверяет все поколения профилей, наличие адреса, ciphertext, installed revision и подписки. Разрешены только невыданные заявки нового flow. Legacy-записи не получают обход этого ограничения.
- Portal schema v4: request metadata и индексы. CLI migration v3→v4 сохраняет аккаунты, сессии, устройства и профили. Runtime не мигрирует БД автоматически; control остаётся v2, admin v1.
- Обновлены OpenAPI, generated TypeScript, README, AGENTS, device runbook и ADR-0007.

Отмена здесь освобождает локальный слот, а не отзывает работающий VPN. Сетевых изменений и вызовов node-agent нет. Request ID формы хранится в памяти до подтверждённого успеха; после reload перед повторной отправкой нужно проверить список.

## Основной бэклог

Обновлён именно `vpn-platform-backlog-v1.0.md`: содержимое версии 1.1, прежнее имя для существующих ссылок. Все 63 исходные карточки получили фактический статус при сохранённых ID и критериях приёмки: **50 Backlog, 11 In progress, 2 Verification, 0 Done по полным исходным критериям**. Дополнительные GW-01…08 остаются Backlog.

DEV-06 продвинут локальным request/rename/cancel slice; IP allocation, административный lifecycle и сетевой revoke ещё впереди. DEV-05 частично реализован, оставшиеся усиления auth отложены внутри карточки. Исправлена прежняя привязка audit к DEV-22: исходная DEV-22 — manual override; audit/read-only admin относится к DEV-13. Исторические отчёты не переписаны.

Очередь: **DEV-06 → DEV-07 → DEV-08/09 → DEV-12 → GW/agent**. Текущие статусы — в основном бэклоге, ближайшая работа — в `next-iteration.md`, результаты этой поставки — здесь.

## Проверки

| Проверка | Результат |
|---|---|
| `npm run check` | PASS: Go vet/race tests, API generation drift, Svelte/TS 0 errors / 0 warnings, Vite build |
| `npm run build` | PASS: frontend и 6 Go executables |
| `npm run test:persistence` | PASS: сохранение, revision conflict, ownership, readiness, разделение demo listeners |
| Demo E2E | 4/4 PASS, desktop/mobile |
| User auth и device E2E | 6/6 PASS: invite/login/logout/recovery и request/reload/conflict/rename/cancel/quota, desktop/mobile |
| Admin E2E | 2/2 PASS: password/TOTP, dashboard/session и lifecycle regression |
| После изменения размеров кнопок | Svelte check/build и 2 device browser flows PASS; финальный mobile screenshot просмотрен |
| Idempotency и concurrency | PASS: одинаковый запрос возвращает одну запись; конфликт payload; последний слот через два DB handles получает один запрос |
| Revision и owner | PASS: stale revision, owner isolation, foreign/missing 404, запрещённый owner в JSON |
| Cancel boundary | PASS: отказ при ready, address, installed revision, ciphertext. Дополнительные поколения и subscription guard проверены чтением кода, без отдельного интеграционного сценария |
| Audit rollback | PASS: неудачная запись audit не оставляет устройство/профили и не расходует request ID |
| Upgrade v3→v4 | PASS: сохранены старые устройства/revision/session; старый runtime schema запрещён, legacy cancel отклонён, новая заявка работает |
| HTTP listener boundary | PASS: auth/Origin/CSRF guards, pending download 409, чужой download 404, demo mutation 405, admin mutation route 404 |

Всего полный браузерный набор — 12 проверок; затем повторно проверены 2 device flows после правки кнопок. Среда: Linux x86_64, Go 1.27.1, Node 24.19.0, npm 11.9.0, Playwright 1.63.0, Chromium 153.0.8010.0. Для доступного локального Chromium использовались внешние launch configs; в поставке обычные Playwright configs. Допуск self-signed TLS ограничен локальными browser tests.

Скриншоты без введённых секретов: `screenshots/iteration06/devices-{form,pending}-{desktop,mobile}.png`. Архив содержит source и документацию; runtime DB, TLS/master keys, credentials, зависимости и executables исключены.

## Ограничения и следующий результат

Production gates G0/G1 и последующие остаются открыты. Реальные VPS, firewall/routes/SSH, удалённый Git/CI и настоящие VPN-клиенты не проверялись и не изменялись. Локальные процессы с одним UID не доказывают production isolation; Windows/macOS не проверены.

Следующий результат — **DEV-07 encrypted client-profile store и DEV-08/09 trusted client-only import**: отдельный ключ вне DB, привязка ciphertext к profile/generation, dry-run, проверка владельца и формата, затем выдача готового профиля. Совместимость AWG 3.1 и подтверждение установки peer требуют отдельного проверенного образца/формата и PRE-04. Автоматический RU↔Foreign pairing/pull/apply ещё не реализован.
