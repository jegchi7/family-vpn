# Итерация 04 — восстановление пользовательского доступа

Дата: 2026-09-29. Поставка: `family-vpn-starter-v0.4.0.zip`. Продолжение v0.3.0, локальный исходный проект. Git не публиковался, VPS/SSH/firewall не менялись.

## Реализовано

- `vpnctl auth-recovery --login ...`: trusted CLI выдаёт короткоживущий одноразовый recovery token. Старый password credential и все browser sessions отключаются сразу; token hash, revocation и audit записываются атомарно. По умолчанию 15 минут, максимум 1 час.
- `POST /api/v1/auth/recovery/consume`: проверка purpose/TTL/revocation/consumption и user role/state; новый Argon2id password, одноразовое потребление, отзыв остальных sessions/tokens и audit в одной transaction. Ответ 204, cookies очищаются, автоматического входа нет.
- Работающий UI «Забыли пароль?»: code/new password/confirmation, сообщения об ошибках, переход к обычному login после успеха, обновление CSRF формы. Токены не передаются в URL и не пишутся в localStorage.
- Recovery сохраняет user id, устройства и profiles. Доступ VPN не отзывается этим действием. Admin, disabled, invited и будущие MFA/passkey credentials не допускаются в password-only recovery.
- `vpnctl auth-reissue-invite --login ...`: новый invite для неактивированного пользователя, прежний код отзывается, user id/login сохраняются. Active account нельзя переактивировать через invite.
- Portal schema v3: revoked_at для one-time tokens, отдельно от consumed_at. Upgrade v2→v3 сохраняет существующие accounts/sessions/invitations; runtime сам migrations не применяет.
- Rate limiting recovery, bounded KDF, Origin/CSRF, JSON limit и generic errors используют существующую auth boundary. Нет анонимного HTTP endpoint выдачи кода или password reset по одному login.
- Implemented OpenAPI/TS, ADR-0005, runbooks, README, тесты и screenshots обновлены. Для auth E2E теперь создаётся отдельный временный root на каждый запуск, чтобы предыдущие попытки не давали ложные rate-limit failures при повторном прогоне.

## Фактические проверки

| Проверка | Результат |
|---|---|
| `npm run check` | PASS: go vet, Go race tests, API drift, Svelte/TypeScript 0 errors / 0 warnings, Vite build |
| `npm run build` | PASS: frontend и 6 Go executables |
| `npm run test:persistence` | PASS, portal schema v3 |
| Existing demo E2E | 4/4 PASS: desktop/mobile |
| Auth E2E | 4/4 PASS: старый invite/login flow + recovery flow на desktop/mobile 320 px; повтор после изоляции test state также PASS |
| Recovery lifecycle | PASS: немедленный отзыв двух sessions и старого password, сохранение соседнего пользователя/устройства/profile, no auto-login, новый login, отказ replay |
| Concurrency | PASS: два consume через разные DB connections дают один успех; закешированный до reset password hash не создаёт session после reset |
| Transaction rollback | PASS: failed issuance audit сохраняет прежние credentials/sessions; failed new credential insert не потребляет recovery token |
| Expiry/purpose/reissue | PASS: просроченный/заменённый token, несовместимый purpose, replacement expired invitation, сохранение user id |
| Role/credential restrictions | PASS: admin, disabled, invited и passkey credential не обходят запреты recovery |
| Rate limit | PASS: лимит recovery attempts и возможность использовать код после окончания окна, если TTL ещё не истёк |
| HTTP | PASS: Origin, CSRF, wrong Content-Type, oversized/trailing JSON, query rejection, generic errors, cookies cleared, no session after 204 |
| Upgrade v2→v3 | PASS отдельно с race: existing session и pending invite сохранены, recovery старого user работает |
| Visual | Mobile recovery screenshot просмотрен; формы без горизонтального overflow, code/password поля в screenshots пустые |

Среда: Linux x86_64, Go 1.27.1, Node 24.19.0, npm 11.9.0, Playwright 1.63.0, Chromium 153.0.8010.0. Использован внешний local browser launch config, как в предыдущих поставках. Для local self-signed certificate test config допускает ignoreHTTPSErrors; в production ничего подобного не включалось. CI workflow подготовлен, удалённый GitHub Actions run ещё не выполнялся.

Frontend: JS gzip около 21.53 kB, CSS 2.22 kB, HTML 0.30 kB. Это bundle measurement, не тест VPS resource limits. Screenshot assets не загружаются приложением.

## Бэклог после поставки

| Задача | Статус |
|---|---|
| DEV-02 | Миграция v3/upgrade покрыты; настоящая изоляция UID ещё впереди |
| DEV-03 | Реализованный контракт включает user recovery; admin/MFA/WebAuthn/agent/mutations остаются частичными |
| DEV-04 | Локальный user auth работает, расширены regression tests. Production origin/proxy/QA-01 ещё нужны |
| DEV-05 | Частично: password + trusted-CLI user recovery готово. Admin MFA, passkey, recovery codes и fresh auth впереди |
| DEV-06/09…13 | Прежний local read-only/prototype scope; настоящий lifecycle устройств/профилей не реализован |
| DEV-07/08, DEV-14…26 | Не реализованы; отдельные safe audit events не закрывают DEV-22 |
| GW-01…08 | Backlog, ранее подготовленные ADR/metadata drafts без runtime pairing |
| PRE/NET/ROL | Реальные серверы в этой итерации не трогались |

G0/G1 и последующие gates не закрыты. Реальный admin listener с MFA в эту поставку не включён: следующий отдельный этап должен решить хранение TOTP secret, bootstrap, challenges и session policy вместе. Recovery обычного пользователя не является обходом будущего MFA.

Не проверялись: Windows/macOS ACL/run, real mobile VPN clients, production certificates/origin, различные service UID, backup/restore, сетевой fail-closed, KDF performance на VPS, статистические timing/DoS свойства. Password blocklist/rehash и retention по-прежнему нужны. Процессные/сетевые операции после уже начавшегося GET не отменяются задним числом.

Запуск и последствия reset: `docs/recovery-runbook.md`. Следующий этап: `docs/next-iteration.md`. Отчёты iteration-01…03 сохранены как история, нормативные исходные spec/backlog не изменялись.
